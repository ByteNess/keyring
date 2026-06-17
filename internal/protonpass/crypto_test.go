package protonpass

import (
	"bytes"
	"encoding/base64"
	"errors"
	"testing"
)

func key32(b byte) []byte { return bytes.Repeat([]byte{b}, aesKeyBytes) }
func nonce12() []byte     { return bytes.Repeat([]byte{0x42}, gcmNonceBytes) }

func TestAESGCMRoundTrip(t *testing.T) {
	key := key32(0x01)
	plaintext := []byte("aws-vault secret blob")

	blob, err := EncryptAESGCM(key, plaintext, nonce12(), TagItemContent)
	if err != nil {
		t.Fatalf("EncryptAESGCM: %v", err)
	}
	if len(blob) <= gcmNonceBytes {
		t.Fatalf("ciphertext envelope too short: %d bytes", len(blob))
	}

	got, err := DecryptAESGCM(key, blob, TagItemContent)
	if err != nil {
		t.Fatalf("DecryptAESGCM: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("round-trip mismatch: got %q want %q", got, plaintext)
	}
}

func TestAESGCMTagIsAuthenticated(t *testing.T) {
	key := key32(0x02)
	blob, err := EncryptAESGCM(key, []byte("x"), nonce12(), TagItemContent)
	if err != nil {
		t.Fatal(err)
	}
	// Wrong AAD tag must fail (GCM authenticates the associated data).
	if _, err := DecryptAESGCM(key, blob, TagItemKey); err == nil {
		t.Fatal("decrypt with wrong tag must fail")
	}
	// Wrong key must fail.
	if _, err := DecryptAESGCM(key32(0x03), blob, TagItemContent); err == nil {
		t.Fatal("decrypt with wrong key must fail")
	}
}

func TestAESGCMInputValidation(t *testing.T) {
	if _, err := DecryptAESGCM(key32(0x04), []byte("short"), TagItemContent); err == nil {
		t.Error("too-short ciphertext must fail")
	}
	if _, err := DecryptAESGCM([]byte("not-32-bytes"), bytes.Repeat([]byte{0}, 40), TagItemContent); err == nil {
		t.Error("wrong key size must fail")
	}
	if _, err := EncryptAESGCM(key32(0x05), []byte("x"), []byte("short-nonce"), TagItemContent); err == nil {
		t.Error("wrong nonce size must fail")
	}
}

// TestUnwrapChain exercises the share-key -> item-key -> item-content composition
// (everything below the OpenPGP step), matching how a real item decrypts.
func TestUnwrapChain(t *testing.T) {
	shareKey := key32(0x10)
	itemKey := key32(0x20)
	contentPlain := []byte("serialized-item-protobuf")

	encItemKey, err := EncryptAESGCM(shareKey, itemKey, nonce12(), TagItemKey)
	if err != nil {
		t.Fatal(err)
	}
	encContent, err := EncryptAESGCM(itemKey, contentPlain, nonce12(), TagItemContent)
	if err != nil {
		t.Fatal(err)
	}

	gotItemKey, err := OpenItemKey(shareKey, base64.StdEncoding.EncodeToString(encItemKey))
	if err != nil {
		t.Fatalf("OpenItemKey: %v", err)
	}
	if !bytes.Equal(gotItemKey, itemKey) {
		t.Fatal("OpenItemKey did not recover the item key")
	}

	gotContent, err := OpenItemContent(gotItemKey, base64.StdEncoding.EncodeToString(encContent))
	if err != nil {
		t.Fatalf("OpenItemContent: %v", err)
	}
	if !bytes.Equal(gotContent, contentPlain) {
		t.Fatalf("OpenItemContent mismatch: got %q want %q", gotContent, contentPlain)
	}
}

func TestOpenShareKeyNotImplemented(t *testing.T) {
	if _, err := OpenShareKey(ShareKey{}, nil); !errors.Is(err, ErrCryptoNotImplemented) {
		t.Fatalf("OpenShareKey err = %v, want ErrCryptoNotImplemented", err)
	}
}
