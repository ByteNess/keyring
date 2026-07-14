package protonpass

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
)

// Proton Pass PAT read model: the chain is symmetric AES-256-GCM, rooted at the
// PAT's "::<key>" half. A PAT session uses no OpenPGP and no /core/v4/keys (that
// endpoint 403s for a PAT).
//
//	PAT "::<key>"  --base64url-->  32-byte AES key (encKey)
//	  └─ opens the share key   (GET /pass/v1/share/{id}/key, AAD "sharekey")
//	       └─ opens an item's ItemKey   (AAD "itemkey")
//	            └─ opens the item Content (AAD "itemcontent") -> protobuf Item
//
// Older items carry no ItemKey; their Content opens with the share key directly.
// Each step prepends a 12-byte nonce and authenticates the PassEncryptionTag as AAD.

// PassEncryptionTag values are AES-GCM associated-data domain separators.
const (
	TagItemContent  = "itemcontent"
	TagItemKey      = "itemkey"
	TagVaultContent = "vaultcontent"
	TagShareKey     = "sharekey"
)

const (
	aesKeyBytes   = 32 // AES-256
	gcmNonceBytes = 12 // prepended to the ciphertext
)

// PATKey decodes the "::<key>" half of a compound "pst_<token>::<key>" PAT into its
// raw 32-byte AES-256 key. For a PAT session this key is the symmetric root that
// opens the share key (see OpenShareKey); it is used directly: no salt, no KDF.
func PATKey(pat string) ([]byte, error) {
	i := strings.Index(pat, "::")
	if i < 0 {
		return nil, errors.New(`pat: missing "::<key>" half`)
	}
	keyPart := pat[i+2:]
	if keyPart == "" {
		return nil, errors.New(`pat: empty key after "::"`)
	}
	raw, err := base64.RawURLEncoding.DecodeString(keyPart)
	if err != nil {
		return nil, fmt.Errorf("pat: decode key half: %w", err)
	}
	return raw, nil
}

// DecryptAESGCM opens Proton's symmetric envelope: nonce(12) || ciphertext+tag(16),
// AES-256-GCM, with tag as additional authenticated data.
func DecryptAESGCM(key, blob []byte, tag string) ([]byte, error) {
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	if len(blob) < gcmNonceBytes+gcm.Overhead() {
		return nil, errors.New("aes-gcm: ciphertext too short")
	}
	nonce, ciphertext := blob[:gcmNonceBytes], blob[gcmNonceBytes:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, []byte(tag))
	if err != nil {
		return nil, fmt.Errorf("aes-gcm open (tag %q): %w", tag, err)
	}
	return plaintext, nil
}

// EncryptAESGCM produces nonce || ciphertext+tag. nonce must be 12 bytes and unique
// per key.
func EncryptAESGCM(key, plaintext, nonce []byte, tag string) ([]byte, error) {
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	if len(nonce) != gcmNonceBytes {
		return nil, fmt.Errorf("aes-gcm: nonce must be %d bytes, got %d", gcmNonceBytes, len(nonce))
	}
	return gcm.Seal(nonce, nonce, plaintext, []byte(tag)), nil
}

func newGCM(key []byte) (cipher.AEAD, error) {
	if len(key) != aesKeyBytes {
		return nil, fmt.Errorf("aes-gcm: key must be %d bytes, got %d", aesKeyBytes, len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// OpenItemKey decrypts a base64 ItemKey (from an item revision) with the share key.
func OpenItemKey(shareKey []byte, encItemKeyB64 string) ([]byte, error) {
	blob, err := b64decode(encItemKeyB64)
	if err != nil {
		return nil, fmt.Errorf("item key: %w", err)
	}
	return DecryptAESGCM(shareKey, blob, TagItemKey)
}

// OpenItemContent decrypts a base64 item Content with its item key, yielding the
// raw protobuf-encoded Item bytes.
func OpenItemContent(itemKey []byte, encContentB64 string) ([]byte, error) {
	blob, err := b64decode(encContentB64)
	if err != nil {
		return nil, fmt.Errorf("item content: %w", err)
	}
	return DecryptAESGCM(itemKey, blob, TagItemContent)
}

// OpenVaultContent decrypts a base64 vault Content (Share.Content) with the share key.
func OpenVaultContent(shareKey []byte, encContentB64 string) ([]byte, error) {
	blob, err := b64decode(encContentB64)
	if err != nil {
		return nil, fmt.Errorf("vault content: %w", err)
	}
	return DecryptAESGCM(shareKey, blob, TagVaultContent)
}

// OpenShareKey decrypts a share key (an entry from GET /pass/v1/share/{id}/key) into
// its raw 32-byte AES key, using the PAT enc-key (from PATKey) and AAD "sharekey".
func OpenShareKey(sk ShareKey, encKey []byte) ([]byte, error) {
	blob, err := b64decode(sk.Key)
	if err != nil {
		return nil, fmt.Errorf("share key: %w", err)
	}
	shareKey, err := DecryptAESGCM(encKey, blob, TagShareKey)
	if err != nil {
		return nil, fmt.Errorf("share key: %w", err)
	}
	if len(shareKey) != aesKeyBytes {
		return nil, fmt.Errorf("share key: want %d-byte AES key, got %d", aesKeyBytes, len(shareKey))
	}
	return shareKey, nil
}

// b64decode tolerates standard and raw (unpadded) base64 for Proton's blobs.
func b64decode(s string) ([]byte, error) {
	if b, err := base64.StdEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	return base64.RawStdEncoding.DecodeString(s)
}

// The write path reverses the read chain: a fresh per-item key seals the item
// content (AAD "itemcontent"), and the share key wraps that item key (AAD
// "itemkey"). Each seal prepends a fresh random 12-byte nonce.

// NewItemKey returns a fresh random 32-byte AES-256 key for one item.
func NewItemKey() ([]byte, error) {
	key := make([]byte, aesKeyBytes)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("generate item key: %w", err)
	}
	return key, nil
}

// NewItemUUID returns a fresh random RFC 4122 v4 UUID string, used for an item's
// metadata.item_uuid on create.
func NewItemUUID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("generate item uuid: %w", err)
	}
	b[6] = (b[6] & 0x0f) | 0x40 // version 4
	b[8] = (b[8] & 0x3f) | 0x80 // variant 10
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16]), nil
}

// seal encrypts plaintext under key with a fresh random nonce, returning
// nonce(12) || ciphertext+tag(16).
func seal(key, plaintext []byte, tag string) ([]byte, error) {
	nonce := make([]byte, gcmNonceBytes)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("generate nonce: %w", err)
	}
	return EncryptAESGCM(key, plaintext, nonce, tag)
}

// SealItemContent encrypts an item's protobuf plaintext under its item key
// (AAD "itemcontent"), returning the base64 blob for ItemRevision.Content. It
// is the inverse of OpenItemContent.
func SealItemContent(itemKey, plaintext []byte) (string, error) {
	blob, err := seal(itemKey, plaintext, TagItemContent)
	if err != nil {
		return "", fmt.Errorf("seal item content: %w", err)
	}
	return base64.StdEncoding.EncodeToString(blob), nil
}

// SealItemKey wraps a per-item key with the share key (AAD "itemkey"),
// returning the base64 blob for ItemRevision.ItemKey. It is the inverse of
// OpenItemKey.
func SealItemKey(shareKey, itemKey []byte) (string, error) {
	if len(itemKey) != aesKeyBytes {
		return "", fmt.Errorf("seal item key: item key must be %d bytes, got %d", aesKeyBytes, len(itemKey))
	}
	blob, err := seal(shareKey, itemKey, TagItemKey)
	if err != nil {
		return "", fmt.Errorf("seal item key: %w", err)
	}
	return base64.StdEncoding.EncodeToString(blob), nil
}
