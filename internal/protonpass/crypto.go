package protonpass

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"errors"
	"fmt"
)

// Proton Pass key hierarchy (re-expressed from Proton's published security model
// and the WebClients crypto types; clean-room spec, not copied source):
//
//	user OpenPGP key
//	  └─ decrypts the share/vault key   (GET /pass/v1/share/{id}/key -> base64, OpenPGP-armored to UserKeyID)
//	       ├─ decrypts the vault Content (AES-256-GCM, AAD "vaultcontent")
//	       └─ decrypts each item's ItemKey (AES-256-GCM, AAD "itemkey")
//	            └─ decrypts the item Content (AES-256-GCM, AAD "itemcontent") -> protobuf Item
//
// Every symmetric step is AES-256-GCM with a 12-byte nonce prepended to the
// ciphertext and a PassEncryptionTag string supplied as additional authenticated
// data. Those steps are implemented and tested here. The OpenPGP step
// (OpenShareKey) is Phase 2's remaining work — see its doc comment.

// PassEncryptionTag values are AES-GCM associated-data domain separators.
const (
	TagItemContent  = "itemcontent"
	TagItemKey      = "itemkey"
	TagVaultContent = "vaultcontent"
	TagShareKey     = "sharekey"
)

const (
	aesKeyBytes   = 32 // AES-256
	gcmNonceBytes = 12 // 96-bit GCM nonce, prepended to the ciphertext
)

// ErrCryptoNotImplemented marks crypto steps still to be implemented (the OpenPGP
// share-key unwrap and the PAT-specific key delivery).
var ErrCryptoNotImplemented = errors.New("protonpass crypto: step not yet implemented")

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

// EncryptAESGCM produces nonce || ciphertext+tag. nonce must be 12 bytes (caller
// supplies a unique one). Used by the write path (Phase 3) and the tests.
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

// OpenShareKey decrypts a share key returned by GET /pass/v1/share/{id}/key.
//
// For a password session the key is OpenPGP-encrypted to a user key (identified by
// UserKeyID), so unwrapping needs gopenpgp plus the decrypted user key. For a
// Personal Access Token session the user's OpenPGP key is unavailable, so Proton
// must deliver the share key via the PAT's "::<key>" half instead — the exact
// mechanism is the open Phase 2 question (resolve from the pass-cli source or a
// captured /share/{id}/key response, then implement here).
func OpenShareKey(_ ShareKey, _ []byte) ([]byte, error) {
	return nil, ErrCryptoNotImplemented
}

// b64decode tolerates standard and raw (unpadded) base64 for Proton's blobs.
func b64decode(s string) ([]byte, error) {
	if b, err := base64.StdEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	return base64.RawStdEncoding.DecodeString(s)
}
