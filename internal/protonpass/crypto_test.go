package protonpass

import (
	"bytes"
	"encoding/base64"
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

// TestUnwrapChain exercises the share-key -> item-key -> item-content composition,
// matching how a real item decrypts.
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

func TestOpenShareKeyRoundTrip(t *testing.T) {
	encKey := key32(0xee)   // the PAT "::<key>" enc-key
	shareKey := key32(0x5a) // the 32-byte share key we expect to recover

	blob, err := EncryptAESGCM(encKey, shareKey, nonce12(), TagShareKey)
	if err != nil {
		t.Fatal(err)
	}
	sk := ShareKey{KeyRotation: 1, Key: base64.StdEncoding.EncodeToString(blob)}

	got, err := OpenShareKey(sk, encKey)
	if err != nil {
		t.Fatalf("OpenShareKey: %v", err)
	}
	if !bytes.Equal(got, shareKey) {
		t.Fatalf("recovered %x, want %x", got, shareKey)
	}

	if _, err := OpenShareKey(sk, key32(0x01)); err == nil {
		t.Fatal("OpenShareKey with wrong enc-key must fail")
	}

	short, err := EncryptAESGCM(encKey, []byte("not thirty-two bytes"), nonce12(), TagShareKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := OpenShareKey(ShareKey{Key: base64.StdEncoding.EncodeToString(short)}, encKey); err == nil {
		t.Fatal("OpenShareKey must reject a non-32-byte share key")
	}
}

func TestNewItemKey(t *testing.T) {
	a, err := NewItemKey()
	if err != nil {
		t.Fatalf("NewItemKey: %v", err)
	}
	if len(a) != aesKeyBytes {
		t.Fatalf("item key len = %d, want %d", len(a), aesKeyBytes)
	}
	b, err := NewItemKey()
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(a, b) {
		t.Fatal("two NewItemKey calls returned identical keys")
	}
}

// TestSealChain seals an item the way the write path does (fresh item key wraps
// content, share key wraps the item key) and opens it back via the read path.
func TestSealChain(t *testing.T) {
	shareKey := key32(0x5a)
	itemKey, err := NewItemKey()
	if err != nil {
		t.Fatal(err)
	}
	proto := []byte("serialized-item-protobuf")

	encContent, err := SealItemContent(itemKey, proto)
	if err != nil {
		t.Fatalf("SealItemContent: %v", err)
	}
	encItemKey, err := SealItemKey(shareKey, itemKey)
	if err != nil {
		t.Fatalf("SealItemKey: %v", err)
	}

	gotItemKey, err := OpenItemKey(shareKey, encItemKey)
	if err != nil {
		t.Fatalf("OpenItemKey: %v", err)
	}
	if !bytes.Equal(gotItemKey, itemKey) {
		t.Fatal("OpenItemKey did not recover the sealed item key")
	}
	gotContent, err := OpenItemContent(gotItemKey, encContent)
	if err != nil {
		t.Fatalf("OpenItemContent: %v", err)
	}
	if !bytes.Equal(gotContent, proto) {
		t.Fatalf("content round-trip mismatch: got %q want %q", gotContent, proto)
	}

	// A fresh nonce per call means two seals of the same plaintext differ.
	again, err := SealItemContent(itemKey, proto)
	if err != nil {
		t.Fatal(err)
	}
	if again == encContent {
		t.Fatal("two SealItemContent calls produced identical ciphertext (nonce reuse)")
	}
}

func TestSealItemKeyRejectsBadKey(t *testing.T) {
	if _, err := SealItemKey(key32(0x5a), []byte("not-32-bytes")); err == nil {
		t.Fatal("SealItemKey must reject a non-32-byte item key")
	}
}

func TestPATKey(t *testing.T) {
	raw := bytes.Repeat([]byte{0x7f}, aesKeyBytes)
	pat := "pst_0123456789abcdef::" + base64.RawURLEncoding.EncodeToString(raw)

	got, err := PATKey(pat)
	if err != nil {
		t.Fatalf("PATKey: %v", err)
	}
	if !bytes.Equal(got, raw) {
		t.Fatalf("PATKey decoded %x, want %x", got, raw)
	}

	for _, bad := range []string{"pst_nokey", "pst_tok::", "pst_tok::!!!not base64!!!"} {
		if _, err := PATKey(bad); err == nil {
			t.Errorf("PATKey(%q) must fail", bad)
		}
	}
}
