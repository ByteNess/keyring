//go:build windows
// +build windows

package winhello

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"testing"
)

type insecureFakeWinHelloKeyWrapper struct {
	expectedContext string
	wrongCEK        bool
	wrapErr         error
	unwrapErr       error
}

func (w insecureFakeWinHelloKeyWrapper) WrapKey(cek []byte) ([]byte, error) {
	if w.wrapErr != nil {
		return nil, w.wrapErr
	}

	wrapped := make([]byte, 0, len("wrapped:")+len(cek))
	wrapped = append(wrapped, []byte("wrapped:")...)
	wrapped = append(wrapped, cek...)
	return wrapped, nil
}

func (w insecureFakeWinHelloKeyWrapper) UnwrapKey(wrapped []byte, context string) ([]byte, error) {
	if w.unwrapErr != nil {
		return nil, w.unwrapErr
	}
	if w.expectedContext != "" && context != w.expectedContext {
		return nil, fmt.Errorf("unexpected context %q", context)
	}
	if !bytes.HasPrefix(wrapped, []byte("wrapped:")) {
		return nil, errors.New("invalid wrapped key")
	}

	cek := bytes.Clone(wrapped[len("wrapped:"):])
	if w.wrongCEK && len(cek) > 0 {
		cek[0] ^= 0xff
	}
	return cek, nil
}

type failingReader struct {
	err error
}

func (r failingReader) Read(_ []byte) (int, error) {
	return 0, r.err
}

type sequentialReader struct {
	readers []any
	index   int
}

func (r *sequentialReader) Read(p []byte) (int, error) {
	if r.index >= len(r.readers) {
		return 0, errors.New("no reader configured")
	}

	current := r.readers[r.index]
	r.index++
	switch reader := current.(type) {
	case []byte:
		n := copy(p, reader)
		return n, nil
	case error:
		return 0, reader
	default:
		return 0, fmt.Errorf("unsupported reader type %T", current)
	}
}

type mutatingWinHelloKeyWrapper struct {
	insecureFakeWinHelloKeyWrapper
}

func (w mutatingWinHelloKeyWrapper) WrapKey(cek []byte) ([]byte, error) {
	wrapped, err := w.insecureFakeWinHelloKeyWrapper.WrapKey(cek)
	if err != nil {
		return nil, err
	}

	for i := range cek {
		cek[i] ^= 0xff
	}

	return wrapped, nil
}

func TestWinHelloAAD(t *testing.T) {
	got := winHelloAAD("test-service", "test-key")

	var decoded winHelloAADData
	if err := json.Unmarshal(got, &decoded); err != nil {
		t.Fatalf("winHelloAAD() returned invalid json: %v", err)
	}
	if decoded.Backend != "winhello" {
		t.Fatalf("backend = %q, want %q", decoded.Backend, "winhello")
	}
	if decoded.Version != winHelloEnvelopeVersion {
		t.Fatalf("version = %d, want %d", decoded.Version, winHelloEnvelopeVersion)
	}
	if decoded.ServiceName != "test-service" {
		t.Fatalf("service_name = %q, want %q", decoded.ServiceName, "test-service")
	}
	if decoded.ItemKey != "test-key" {
		t.Fatalf("item_key = %q, want %q", decoded.ItemKey, "test-key")
	}

	a := winHelloAAD("a:b", "c")
	b := winHelloAAD("a", "b:c")
	if bytes.Equal(a, b) {
		t.Fatal("winHelloAAD() produced colliding encodings")
	}
}

func TestWinHelloCryptoRoundTrip(t *testing.T) {
	plaintext := []byte("loose lips sink ships")
	aad := winHelloAAD("test-service", "roundtrip-key")
	context := "test-context"
	wrapper := insecureFakeWinHelloKeyWrapper{expectedContext: context}

	encoded, err := encryptWinHelloEnvelope(plaintext, aad, "roundtrip-key", wrapper)
	if err != nil {
		t.Fatalf("encrypt failed: %v", err)
	}

	decrypted, err := decryptWinHelloEnvelope(encoded, aad, "roundtrip-key", wrapper, context)
	if err != nil {
		t.Fatalf("decrypt failed: %v", err)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Fatalf("plaintext mismatch: got %q want %q", decrypted, plaintext)
	}

	envelope, err := parseWinHelloEnvelope(encoded)
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	if envelope.KeyName != "roundtrip-key" {
		t.Fatalf("key name = %q, want %q", envelope.KeyName, "roundtrip-key")
	}
}

func TestWinHelloCryptoWrongAADFails(t *testing.T) {
	aad := winHelloAAD("test-service", "test-key")
	encoded, err := encryptWinHelloEnvelope([]byte("secret"), aad, "test-key", insecureFakeWinHelloKeyWrapper{})
	if err != nil {
		t.Fatalf("encrypt failed: %v", err)
	}

	_, err = decryptWinHelloEnvelope(encoded, winHelloAAD("other-service", "test-key"), "test-key", insecureFakeWinHelloKeyWrapper{}, "")
	if !errors.Is(err, errWinHelloAADMismatch) {
		t.Fatalf("decrypt error = %v, want %v", err, errWinHelloAADMismatch)
	}
}

func TestWinHelloCryptoTamperedCiphertextFails(t *testing.T) {
	aad := winHelloAAD("test-service", "test-key")
	encoded, err := encryptWinHelloEnvelope([]byte("secret"), aad, "test-key", insecureFakeWinHelloKeyWrapper{})
	if err != nil {
		t.Fatalf("encrypt failed: %v", err)
	}

	envelope, err := parseWinHelloEnvelope(encoded)
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	envelope.Ciphertext[0] ^= 0xff
	encoded, err = json.Marshal(envelope)
	if err != nil {
		t.Fatalf("json marshal failed: %v", err)
	}

	_, err = decryptWinHelloEnvelope(encoded, aad, "test-key", insecureFakeWinHelloKeyWrapper{}, "")
	if !errors.Is(err, errWinHelloDecrypt) {
		t.Fatalf("decrypt error = %v, want %v", err, errWinHelloDecrypt)
	}
}

func TestWinHelloCryptoTamperedNonceFails(t *testing.T) {
	aad := winHelloAAD("test-service", "test-key")
	encoded, err := encryptWinHelloEnvelope([]byte("secret"), aad, "test-key", insecureFakeWinHelloKeyWrapper{})
	if err != nil {
		t.Fatalf("encrypt failed: %v", err)
	}

	envelope, err := parseWinHelloEnvelope(encoded)
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	envelope.Nonce[0] ^= 0xff
	encoded, err = json.Marshal(envelope)
	if err != nil {
		t.Fatalf("json marshal failed: %v", err)
	}

	_, err = decryptWinHelloEnvelope(encoded, aad, "test-key", insecureFakeWinHelloKeyWrapper{}, "")
	if !errors.Is(err, errWinHelloDecrypt) {
		t.Fatalf("decrypt error = %v, want %v", err, errWinHelloDecrypt)
	}
}

func TestWinHelloCryptoTamperedWrappedCEKFails(t *testing.T) {
	aad := winHelloAAD("test-service", "test-key")
	encoded, err := encryptWinHelloEnvelope([]byte("secret"), aad, "test-key", insecureFakeWinHelloKeyWrapper{})
	if err != nil {
		t.Fatalf("encrypt failed: %v", err)
	}

	envelope, err := parseWinHelloEnvelope(encoded)
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	envelope.WrappedCEK = []byte("tampered")
	encoded, err = json.Marshal(envelope)
	if err != nil {
		t.Fatalf("json marshal failed: %v", err)
	}

	_, err = decryptWinHelloEnvelope(encoded, aad, "test-key", insecureFakeWinHelloKeyWrapper{}, "")
	if !errors.Is(err, errWinHelloUnwrapKey) {
		t.Fatalf("decrypt error = %v, want %v", err, errWinHelloUnwrapKey)
	}
}

func TestWinHelloCryptoWrongWrappedCEKFails(t *testing.T) {
	aad := winHelloAAD("test-service", "test-key")
	encoded, err := encryptWinHelloEnvelope([]byte("secret"), aad, "test-key", insecureFakeWinHelloKeyWrapper{})
	if err != nil {
		t.Fatalf("encrypt failed: %v", err)
	}

	_, err = decryptWinHelloEnvelope(encoded, aad, "test-key", insecureFakeWinHelloKeyWrapper{wrongCEK: true}, "")
	if !errors.Is(err, errWinHelloDecrypt) {
		t.Fatalf("decrypt error = %v, want %v", err, errWinHelloDecrypt)
	}
}

func TestWinHelloCryptoEmptyPlaintextWorks(t *testing.T) {
	aad := winHelloAAD("test-service", "empty-key")
	encoded, err := encryptWinHelloEnvelope(nil, aad, "empty-key", insecureFakeWinHelloKeyWrapper{})
	if err != nil {
		t.Fatalf("encrypt failed: %v", err)
	}

	decrypted, err := decryptWinHelloEnvelope(encoded, aad, "empty-key", insecureFakeWinHelloKeyWrapper{}, "")
	if err != nil {
		t.Fatalf("decrypt failed: %v", err)
	}
	if len(decrypted) != 0 {
		t.Fatalf("plaintext length = %d, want 0", len(decrypted))
	}
}

func TestWinHelloCryptoLargePlaintextWorks(t *testing.T) {
	plaintext := bytes.Repeat([]byte("0123456789abcdef"), 1<<12)
	aad := winHelloAAD("large-service", "large-key")
	encoded, err := encryptWinHelloEnvelope(plaintext, aad, "large-key", insecureFakeWinHelloKeyWrapper{})
	if err != nil {
		t.Fatalf("encrypt failed: %v", err)
	}

	decrypted, err := decryptWinHelloEnvelope(encoded, aad, "large-key", insecureFakeWinHelloKeyWrapper{}, "")
	if err != nil {
		t.Fatalf("decrypt failed: %v", err)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Fatalf("plaintext mismatch after round-trip")
	}
}

func TestWinHelloCryptoWrapKeyMutationDoesNotAffectCiphertext(t *testing.T) {
	plaintext := []byte("secret")
	aad := winHelloAAD("test-service", "test-key")
	wrapper := mutatingWinHelloKeyWrapper{
		insecureFakeWinHelloKeyWrapper: insecureFakeWinHelloKeyWrapper{},
	}

	encoded, err := encryptWinHelloEnvelope(plaintext, aad, "test-key", wrapper)
	if err != nil {
		t.Fatalf("encrypt failed: %v", err)
	}

	decrypted, err := decryptWinHelloEnvelope(encoded, aad, "test-key", insecureFakeWinHelloKeyWrapper{}, "")
	if err != nil {
		t.Fatalf("decrypt failed: %v", err)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Fatalf("plaintext mismatch: got %q want %q", decrypted, plaintext)
	}
}

func TestWinHelloCryptoNilWrapperFails(t *testing.T) {
	_, err := encryptWinHelloEnvelope([]byte("secret"), winHelloAAD("test-service", "test-key"), "test-key", nil)
	if !errors.Is(err, errWinHelloKeyWrapper) {
		t.Fatalf("encrypt error = %v, want %v", err, errWinHelloKeyWrapper)
	}

	_, err = decryptWinHelloEnvelope([]byte("{}"), winHelloAAD("test-service", "test-key"), "test-key", nil, "")
	if !errors.Is(err, errWinHelloKeyWrapper) {
		t.Fatalf("decrypt error = %v, want %v", err, errWinHelloKeyWrapper)
	}
}

func TestWinHelloCryptoEmptyAADFails(t *testing.T) {
	_, err := encryptWinHelloEnvelope([]byte("secret"), nil, "test-key", insecureFakeWinHelloKeyWrapper{})
	if !errors.Is(err, errWinHelloMissingAAD) {
		t.Fatalf("encrypt error = %v, want %v", err, errWinHelloMissingAAD)
	}

	_, err = decryptWinHelloEnvelope([]byte("{}"), nil, "test-key", insecureFakeWinHelloKeyWrapper{}, "")
	if !errors.Is(err, errWinHelloMissingAAD) {
		t.Fatalf("decrypt error = %v, want %v", err, errWinHelloMissingAAD)
	}
}

func TestWinHelloCryptoEmptyKeyNameFails(t *testing.T) {
	aad := winHelloAAD("test-service", "test-key")
	_, err := encryptWinHelloEnvelope([]byte("secret"), aad, "", insecureFakeWinHelloKeyWrapper{})
	if !errors.Is(err, errWinHelloEnvelopeKeyName) {
		t.Fatalf("encrypt error = %v, want %v", err, errWinHelloEnvelopeKeyName)
	}

	encoded, err := encryptWinHelloEnvelope([]byte("secret"), aad, "test-key", insecureFakeWinHelloKeyWrapper{})
	if err != nil {
		t.Fatalf("encrypt failed: %v", err)
	}

	_, err = decryptWinHelloEnvelope(encoded, aad, "", insecureFakeWinHelloKeyWrapper{}, "")
	if !errors.Is(err, errWinHelloEnvelopeKeyName) {
		t.Fatalf("decrypt error = %v, want %v", err, errWinHelloEnvelopeKeyName)
	}
}

func TestWinHelloCryptoWrongExpectedKeyNameFails(t *testing.T) {
	aad := winHelloAAD("test-service", "test-key")
	encoded, err := encryptWinHelloEnvelope([]byte("secret"), aad, "test-key", insecureFakeWinHelloKeyWrapper{})
	if err != nil {
		t.Fatalf("encrypt failed: %v", err)
	}

	_, err = decryptWinHelloEnvelope(encoded, aad, "other-key", insecureFakeWinHelloKeyWrapper{}, "")
	if !errors.Is(err, errWinHelloKeyNameMismatch) {
		t.Fatalf("decrypt error = %v, want %v", err, errWinHelloKeyNameMismatch)
	}
}

func TestWinHelloCryptoWrapKeyErrorFails(t *testing.T) {
	wantErr := errors.New("wrap failed")
	_, err := encryptWinHelloEnvelope([]byte("secret"), winHelloAAD("test-service", "test-key"), "test-key", insecureFakeWinHelloKeyWrapper{wrapErr: wantErr})
	if !errors.Is(err, errWinHelloWrapKey) {
		t.Fatalf("encrypt error = %v, want %v", err, errWinHelloWrapKey)
	}
	if !errors.Is(err, wantErr) {
		t.Fatalf("encrypt error = %v, want wrapped error %v", err, wantErr)
	}
}

func TestWinHelloCryptoUnwrapKeyErrorFails(t *testing.T) {
	wantErr := errors.New("unwrap failed")
	aad := winHelloAAD("test-service", "test-key")
	encoded, err := encryptWinHelloEnvelope([]byte("secret"), aad, "test-key", insecureFakeWinHelloKeyWrapper{})
	if err != nil {
		t.Fatalf("encrypt failed: %v", err)
	}

	_, err = decryptWinHelloEnvelope(encoded, aad, "test-key", insecureFakeWinHelloKeyWrapper{unwrapErr: wantErr}, "")
	if !errors.Is(err, errWinHelloUnwrapKey) {
		t.Fatalf("decrypt error = %v, want %v", err, errWinHelloUnwrapKey)
	}
	if !errors.Is(err, wantErr) {
		t.Fatalf("decrypt error = %v, want wrapped error %v", err, wantErr)
	}
}

func TestWinHelloCryptoRandomCEKGenerationFails(t *testing.T) {
	oldRand := winHelloRandReader
	winHelloRandReader = failingReader{err: errors.New("boom")}
	t.Cleanup(func() {
		winHelloRandReader = oldRand
	})

	_, err := encryptWinHelloEnvelope([]byte("secret"), winHelloAAD("test-service", "test-key"), "test-key", insecureFakeWinHelloKeyWrapper{})
	if !errors.Is(err, errWinHelloRandom) {
		t.Fatalf("encrypt error = %v, want %v", err, errWinHelloRandom)
	}
}

func TestWinHelloCryptoRandomNonceGenerationFails(t *testing.T) {
	oldRand := winHelloRandReader
	winHelloRandReader = &sequentialReader{
		readers: []any{
			bytes.Repeat([]byte{0x42}, winHelloCEKSize),
			errors.New("boom"),
		},
	}
	t.Cleanup(func() {
		winHelloRandReader = oldRand
	})

	_, err := encryptWinHelloEnvelope([]byte("secret"), winHelloAAD("test-service", "test-key"), "test-key", insecureFakeWinHelloKeyWrapper{})
	if !errors.Is(err, errWinHelloRandom) {
		t.Fatalf("encrypt error = %v, want %v", err, errWinHelloRandom)
	}
}
