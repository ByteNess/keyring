package keyring

// Implementation of the oo7 keyring file format (version 1), as written by
// oo7-daemon and the oo7 client library (https://github.com/linux-credentials/oo7).
//
// A keyring file is the 16 byte header "GnomeKeyring\n\r\0\n", a major and a
// minor version byte, then a GVariant structure (uayutua(a{say}ay)):
// salt size, salt, PBKDF2 iteration count, modified time, usage count and the
// items. Every item carries its attributes hashed with HMAC-SHA256 under the
// keyring key (so they can be searched without decrypting) and an opaque blob:
// AES-128-CBC-PKCS7 ciphertext of the GVariant item (a{ss}sttay), followed by
// the 16 byte IV, followed by the 32 byte HMAC-SHA256 of ciphertext||IV.
// The key is PBKDF2-HMAC-SHA256(secret, salt, iterations) truncated to 16 bytes.

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	oo7FileHeader   = "GnomeKeyring\n\r\x00\n"
	oo7MajorVersion = 1
	oo7MinorVersion = 0

	oo7DefaultIterationCount = 100000
	oo7DefaultSaltSize       = 32
	oo7MinIterationCount     = 100000
	oo7MinSaltSize           = 32

	oo7KeyLen = 16
	oo7IVLen  = 16
	oo7MacLen = 32

	oo7ContentTypeAttribute = "xdg:content-type"
	oo7SchemaAttribute      = "xdg:schema"
	oo7GenericSchema        = "org.freedesktop.Secret.Generic"
	oo7DefaultContentType   = "application/octet-stream"
)

var (
	// ErrOO7IncorrectSecret is returned when none of the items in an oo7 keyring
	// file can be decrypted with the supplied secret.
	ErrOO7IncorrectSecret = errors.New("oo7: incorrect keyring secret")
	// ErrOO7Unencrypted is returned for oo7 keyring files written without a secret.
	ErrOO7Unencrypted = errors.New("oo7: unencrypted keyrings are not supported")

	errOO7MAC           = errors.New("oo7: item MAC verification failed")
	errOO7TargetChanged = errors.New("oo7: keyring file changed on disk")
)

// OO7DefaultKeyringPath returns the file an oo7 backend uses for name when no
// path is configured: $XDG_DATA_HOME/<name>/keyrings/default.keyring, falling
// back to ~/.local/share for the data directory. That is the layout oo7 gives
// a sandboxed application inside its own data directory, with name standing
// in for the application ID. It deliberately stays out of
// $XDG_DATA_HOME/keyrings/v1, which oo7-daemon scans on startup, loading
// every keyring found there as one of its collections. name becomes a single
// folder, so it must not contain a path separator or be "." or "..".
func OO7DefaultKeyringPath(name string) (string, error) {
	if name == "" || name == "." || name == ".." || strings.ContainsAny(name, `/\`) {
		return "", fmt.Errorf("oo7: %q cannot be used as a folder name for the default keyring path", name)
	}
	dataDir := os.Getenv("XDG_DATA_HOME")
	if dataDir == "" || !filepath.IsAbs(dataDir) {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		dataDir = filepath.Join(home, ".local", "share")
	}
	return filepath.Join(dataDir, name, "keyrings", "default.keyring"), nil
}

// oo7File is the decoded contents of a keyring file.
type oo7File struct {
	salt           []byte
	iterationCount uint32
	modifiedTime   uint64
	usageCount     uint32
	items          []oo7EncryptedItem
}

// oo7EncryptedItem is an item as stored on disk.
type oo7EncryptedItem struct {
	hashedAttributes map[string][]byte
	blob             []byte
}

// oo7Item is a decrypted item.
type oo7Item struct {
	attributes map[string]string
	label      string
	created    uint64
	modified   uint64
	secret     []byte
}

func newOO7File() (*oo7File, error) {
	salt := make([]byte, oo7DefaultSaltSize)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	return &oo7File{
		salt:           salt,
		iterationCount: oo7DefaultIterationCount,
		modifiedTime:   uint64(time.Now().Unix()),
	}, nil
}

func parseOO7File(data []byte) (*oo7File, error) {
	if len(data) < len(oo7FileHeader)+2 || string(data[:len(oo7FileHeader)]) != oo7FileHeader {
		return nil, errors.New("oo7: not a keyring file")
	}
	major, minor := data[len(oo7FileHeader)], data[len(oo7FileHeader)+1]
	if major != oo7MajorVersion || minor != oo7MinorVersion {
		return nil, fmt.Errorf("oo7: unsupported keyring version %d.%d", major, minor)
	}
	members, err := gvDecodeStruct(data[len(oo7FileHeader)+2:], []gvMemberType{
		gvTypeU32, gvTypeBytes, gvTypeU32, gvTypeU64, gvTypeU32, gvTypeBytes,
	})
	if err != nil {
		return nil, err
	}
	f := &oo7File{}
	saltSize, err := gvDecodeU32(members[0])
	if err != nil {
		return nil, err
	}
	f.salt = append([]byte(nil), members[1]...)
	if int(saltSize) != len(f.salt) {
		return nil, fmt.Errorf("oo7: salt size mismatch: %d != %d", saltSize, len(f.salt))
	}
	if f.iterationCount, err = gvDecodeU32(members[2]); err != nil {
		return nil, err
	}
	if f.modifiedTime, err = gvDecodeU64(members[3]); err != nil {
		return nil, err
	}
	if f.usageCount, err = gvDecodeU32(members[4]); err != nil {
		return nil, err
	}
	rawItems, err := gvDecodeArray(members[5], 1)
	if err != nil {
		return nil, err
	}
	f.items = make([]oo7EncryptedItem, 0, len(rawItems))
	for _, raw := range rawItems {
		parts, err := gvDecodeStruct(raw, []gvMemberType{gvTypeBytes, gvTypeBytes})
		if err != nil {
			return nil, err
		}
		attrs, err := gvDecodeBytesDict(parts[0])
		if err != nil {
			return nil, err
		}
		f.items = append(f.items, oo7EncryptedItem{
			hashedAttributes: attrs,
			blob:             append([]byte(nil), parts[1]...),
		})
	}
	return f, nil
}

func (f *oo7File) marshal() []byte {
	items := make([][]byte, 0, len(f.items))
	for _, it := range f.items {
		items = append(items, gvEncodeStruct([]gvMember{
			{data: gvEncodeBytesDict(it.hashedAttributes), align: 1},
			{data: it.blob, align: 1},
		}))
	}
	body := gvEncodeStruct([]gvMember{
		{data: gvU32(uint32(len(f.salt))), align: 4, fixed: true},
		{data: f.salt, align: 1},
		{data: gvU32(f.iterationCount), align: 4, fixed: true},
		{data: gvU64(f.modifiedTime), align: 8, fixed: true},
		{data: gvU32(f.usageCount), align: 4, fixed: true},
		{data: gvEncodeArray(items, 1), align: 1},
	})
	out := make([]byte, 0, len(oo7FileHeader)+2+len(body))
	out = append(out, oo7FileHeader...)
	out = append(out, oo7MajorVersion, oo7MinorVersion)
	return append(out, body...)
}

// keyStrength reports whether the keyring's KDF parameters are strong enough
// to write new items, mirroring oo7's WeakKeyError.
func (f *oo7File) keyStrength() error {
	if f.iterationCount < oo7MinIterationCount {
		return fmt.Errorf("oo7: refusing to write: iteration count %d is below the minimum %d", f.iterationCount, oo7MinIterationCount)
	}
	if len(f.salt) < oo7MinSaltSize {
		return fmt.Errorf("oo7: refusing to write: salt of %d bytes is below the minimum %d", len(f.salt), oo7MinSaltSize)
	}
	return nil
}

func (f *oo7File) deriveKey(secret []byte) ([]byte, error) {
	return pbkdf2.Key(sha256.New, string(secret), f.salt, int(f.iterationCount), oo7KeyLen)
}

func oo7ComputeMAC(data, key []byte) []byte {
	m := hmac.New(sha256.New, key)
	m.Write(data)
	return m.Sum(nil)
}

func oo7VerifyMAC(data, key, mac []byte) bool {
	return hmac.Equal(oo7ComputeMAC(data, key), mac)
}

// validateItems mirrors oo7's load-time check: with no decryptable item the
// secret is wrong; with more broken than valid items the file is corrupt.
func (f *oo7File) validateItems(key []byte) error {
	valid, broken := 0, 0
	for i := range f.items {
		if _, err := f.items[i].decrypt(key); err == nil {
			valid++
		} else {
			broken++
		}
	}
	switch {
	case valid == 0 && broken != 0:
		if f.isUnencrypted() {
			return ErrOO7Unencrypted
		}
		return ErrOO7IncorrectSecret
	case broken > valid:
		return fmt.Errorf("oo7: keyring is partially corrupted: %d valid items, %d broken items", valid, broken)
	}
	return nil
}

// isUnencrypted reports whether the items look like they were written with no
// secret, which oo7 does by storing the plaintext item and attribute values.
func (f *oo7File) isUnencrypted() bool {
	for _, it := range f.items {
		item, err := parseOO7Item(it.blob)
		if err != nil {
			return false
		}
		for k, v := range it.hashedAttributes {
			if item.attributes[k] != string(v) {
				return false
			}
		}
	}
	return len(f.items) > 0
}

// matches reports whether every search attribute's MAC equals the stored one.
// A search for the generic schema matches items with no schema attribute.
func (e *oo7EncryptedItem) matches(attributes map[string]string, key []byte) bool {
	for k, v := range attributes {
		stored, ok := e.hashedAttributes[k]
		if !ok {
			if k == oo7SchemaAttribute && v == oo7GenericSchema {
				continue
			}
			return false
		}
		if !hmac.Equal(stored, oo7ComputeMAC([]byte(v), key)) {
			return false
		}
	}
	return true
}

func (e *oo7EncryptedItem) decrypt(key []byte) (*oo7Item, error) {
	if len(e.blob) < oo7MacLen+oo7IVLen || (len(e.blob)-oo7MacLen-oo7IVLen)%aes.BlockSize != 0 {
		return nil, errOO7MAC
	}
	n := len(e.blob) - oo7MacLen
	if !oo7VerifyMAC(e.blob[:n], key, e.blob[n:]) {
		return nil, errOO7MAC
	}
	ciphertext, iv := e.blob[:n-oo7IVLen], e.blob[n-oo7IVLen:n]
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	plaintext := make([]byte, len(ciphertext))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(plaintext, ciphertext)
	plaintext, err = oo7Unpad(plaintext)
	if err != nil {
		return nil, err
	}
	item, err := parseOO7Item(plaintext)
	if err != nil {
		return nil, err
	}
	for k, mac := range e.hashedAttributes {
		v, ok := item.attributes[k]
		if !ok || !hmac.Equal(mac, oo7ComputeMAC([]byte(v), key)) {
			return nil, fmt.Errorf("oo7: hashed attribute %q does not match", k)
		}
	}
	return item, nil
}

func (it *oo7Item) encrypt(key []byte) (oo7EncryptedItem, error) {
	iv := make([]byte, oo7IVLen)
	if _, err := rand.Read(iv); err != nil {
		return oo7EncryptedItem{}, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return oo7EncryptedItem{}, err
	}
	plaintext := oo7Pad(it.marshal())
	blob := make([]byte, len(plaintext), len(plaintext)+oo7IVLen+oo7MacLen)
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(blob, plaintext)
	blob = append(blob, iv...)
	blob = append(blob, oo7ComputeMAC(blob, key)...)

	hashed := make(map[string][]byte, len(it.attributes))
	for k, v := range it.attributes {
		hashed[k] = oo7ComputeMAC([]byte(v), key)
	}
	return oo7EncryptedItem{hashedAttributes: hashed, blob: blob}, nil
}

func newOO7Item(label string, attributes map[string]string, secret []byte, contentType string) *oo7Item {
	attrs := make(map[string]string, len(attributes)+1)
	for k, v := range attributes {
		attrs[k] = v
	}
	if _, ok := attrs[oo7ContentTypeAttribute]; !ok {
		attrs[oo7ContentTypeAttribute] = contentType
	}
	now := uint64(time.Now().Unix())
	return &oo7Item{attributes: attrs, label: label, created: now, modified: now, secret: secret}
}

func parseOO7Item(data []byte) (*oo7Item, error) {
	members, err := gvDecodeStruct(data, []gvMemberType{
		{align: 1, size: -1}, gvTypeString, gvTypeU64, gvTypeU64, gvTypeBytes,
	})
	if err != nil {
		return nil, err
	}
	item := &oo7Item{}
	if item.attributes, err = gvDecodeStringDict(members[0]); err != nil {
		return nil, err
	}
	if item.label, err = gvDecodeString(members[1]); err != nil {
		return nil, err
	}
	if item.created, err = gvDecodeU64(members[2]); err != nil {
		return nil, err
	}
	if item.modified, err = gvDecodeU64(members[3]); err != nil {
		return nil, err
	}
	item.secret = append([]byte(nil), members[4]...)
	if _, ok := item.attributes[oo7ContentTypeAttribute]; !ok {
		item.attributes[oo7ContentTypeAttribute] = oo7DefaultContentType
	}
	return item, nil
}

func (it *oo7Item) marshal() []byte {
	return gvEncodeStruct([]gvMember{
		{data: gvEncodeStringDict(it.attributes), align: 1},
		{data: gvString(it.label), align: 1},
		{data: gvU64(it.created), align: 8, fixed: true},
		{data: gvU64(it.modified), align: 8, fixed: true},
		{data: it.secret, align: 1},
	})
}

func oo7Pad(data []byte) []byte {
	n := aes.BlockSize - len(data)%aes.BlockSize
	return append(data, bytes.Repeat([]byte{byte(n)}, n)...)
}

func oo7Unpad(data []byte) ([]byte, error) {
	if len(data) == 0 || len(data)%aes.BlockSize != 0 {
		return nil, errOO7MAC
	}
	n := int(data[len(data)-1])
	if n == 0 || n > aes.BlockSize {
		return nil, errOO7MAC
	}
	for _, b := range data[len(data)-n:] {
		if int(b) != n {
			return nil, errOO7MAC
		}
	}
	return data[:len(data)-n], nil
}

// removeOO7File deletes path unless its modification time no longer matches
// mtime, the same backstop write applies.
func removeOO7File(path string, mtime time.Time) error {
	stat, err := os.Stat(path)
	switch {
	case os.IsNotExist(err):
		if !mtime.IsZero() {
			return errOO7TargetChanged
		}
		return nil
	case err != nil:
		return err
	case !stat.ModTime().Equal(mtime):
		return errOO7TargetChanged
	}
	return os.Remove(path)
}

// readOO7File loads path. A missing file yields a fresh empty keyring and a
// zero modification time, so the first write creates it.
func readOO7File(path string) (*oo7File, time.Time, error) {
	fh, err := os.Open(path)
	if os.IsNotExist(err) {
		f, err := newOO7File()
		return f, time.Time{}, err
	}
	if err != nil {
		return nil, time.Time{}, err
	}
	defer func() { _ = fh.Close() }()
	// Stat the open handle so the mtime belongs to the bytes we read even if
	// another process replaces the file meanwhile.
	stat, err := fh.Stat()
	if err != nil {
		return nil, time.Time{}, err
	}
	data, err := io.ReadAll(fh)
	if err != nil {
		return nil, time.Time{}, err
	}
	f, err := parseOO7File(data)
	if err != nil {
		return nil, time.Time{}, err
	}
	return f, stat.ModTime(), nil
}

// write atomically replaces path, refusing if its modification time no longer
// matches mtime (the value observed by readOO7File). Writers in this library
// serialise through the lock taken in oo7Store.update; the mtime check is a
// backstop against tools such as oo7-cli, which do not take that lock, having
// rewritten the file meanwhile.
func (f *oo7File) write(path string, mtime time.Time) error {
	if err := f.keyStrength(); err != nil {
		return err
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	var rnd [8]byte
	if _, err := rand.Read(rnd[:]); err != nil {
		return err
	}
	tmpPath := filepath.Join(dir, ".tmpkeyring"+hex.EncodeToString(rnd[:]))

	tmp, err := os.OpenFile(tmpPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	modifiedTime, usageCount := f.modifiedTime, f.usageCount
	f.modifiedTime = uint64(time.Now().Unix())
	f.usageCount++
	discard := func(err error) error {
		f.modifiedTime, f.usageCount = modifiedTime, usageCount
		_ = tmp.Close()
		_ = os.Remove(tmpPath)
		return err
	}
	if _, err := tmp.Write(f.marshal()); err != nil {
		return discard(err)
	}
	if err := tmp.Sync(); err != nil {
		return discard(err)
	}
	if err := tmp.Close(); err != nil {
		return discard(err)
	}

	stat, err := os.Stat(path)
	switch {
	case os.IsNotExist(err):
		if !mtime.IsZero() {
			return discard(errOO7TargetChanged)
		}
	case err != nil:
		return discard(err)
	case !stat.ModTime().Equal(mtime):
		return discard(errOO7TargetChanged)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return discard(err)
	}
	return nil
}
