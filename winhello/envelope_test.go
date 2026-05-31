package winhello

import (
	"encoding/json"
	"errors"
	"reflect"
	"testing"
)

func newValidWinHelloEnvelope() winHelloEnvelope {
	return winHelloEnvelope{
		Version:    winHelloEnvelopeVersion,
		Provider:   winHelloProviderPassportKSP,
		KeyName:    "test-key",
		ContentAlg: winHelloContentAlgAES256GCM,
		WrapAlg:    winHelloWrapAlgRSAPKCS1v15,
		Nonce:      []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12},
		WrappedCEK: []byte{4, 5, 6},
		Ciphertext: []byte{7, 8, 9},
		AAD:        []byte("keyring:winhello:v1:test-service:test-key"),
	}
}

func TestWinHelloEnvelopeRoundTrip(t *testing.T) {
	envelope := newValidWinHelloEnvelope()

	encoded, err := envelope.marshal()
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}

	var raw map[string]any
	if err := json.Unmarshal(encoded, &raw); err != nil {
		t.Fatalf("json payload is invalid: %v", err)
	}
	if _, ok := raw["nonce"].(string); !ok {
		t.Fatalf("nonce JSON field is %T, want string", raw["nonce"])
	}

	decoded, err := parseWinHelloEnvelope(encoded)
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	if !reflect.DeepEqual(decoded, envelope) {
		t.Fatalf("round-trip mismatch: got %#v want %#v", decoded, envelope)
	}
}

func TestWinHelloEnvelopeValidate(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*winHelloEnvelope)
		wantErr error
	}{
		{
			name: "missing key name",
			mutate: func(envelope *winHelloEnvelope) {
				envelope.KeyName = ""
			},
			wantErr: errWinHelloEnvelopeKeyName,
		},
		{
			name: "missing nonce",
			mutate: func(envelope *winHelloEnvelope) {
				envelope.Nonce = nil
			},
			wantErr: errWinHelloEnvelopeNonce,
		},
		{
			name: "wrong nonce length",
			mutate: func(envelope *winHelloEnvelope) {
				envelope.Nonce = []byte{1}
			},
			wantErr: errWinHelloEnvelopeNonce,
		},
		{
			name: "missing wrapped cek",
			mutate: func(envelope *winHelloEnvelope) {
				envelope.WrappedCEK = nil
			},
			wantErr: errWinHelloEnvelopeWrappedCEK,
		},
		{
			name: "missing ciphertext",
			mutate: func(envelope *winHelloEnvelope) {
				envelope.Ciphertext = nil
			},
			wantErr: errWinHelloEnvelopeCiphertext,
		},
		{
			name: "missing aad",
			mutate: func(envelope *winHelloEnvelope) {
				envelope.AAD = nil
			},
			wantErr: errWinHelloEnvelopeAAD,
		},
		{
			name: "wrong version",
			mutate: func(envelope *winHelloEnvelope) {
				envelope.Version = 99
			},
			wantErr: errWinHelloEnvelopeVersion,
		},
		{
			name: "unknown content alg",
			mutate: func(envelope *winHelloEnvelope) {
				envelope.ContentAlg = "AES-128-GCM"
			},
			wantErr: errWinHelloEnvelopeContentAlg,
		},
		{
			name: "unknown wrap alg",
			mutate: func(envelope *winHelloEnvelope) {
				envelope.WrapAlg = "RSA-OAEP"
			},
			wantErr: errWinHelloEnvelopeWrapAlg,
		},
		{
			name: "wrong provider",
			mutate: func(envelope *winHelloEnvelope) {
				envelope.Provider = "Other Provider"
			},
			wantErr: errWinHelloEnvelopeProvider,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			envelope := newValidWinHelloEnvelope()
			test.mutate(&envelope)

			_, err := envelope.marshal()
			if !errors.Is(err, test.wantErr) {
				t.Fatalf("marshal error = %v, want %v", err, test.wantErr)
			}
		})
	}
}

func TestParseWinHelloEnvelopeRejectsInvalidJSON(t *testing.T) {
	_, err := parseWinHelloEnvelope([]byte("{"))
	if err == nil {
		t.Fatal("parse error = nil, want error")
	}
}

func TestParseWinHelloEnvelopeRejectsEmptyInput(t *testing.T) {
	_, err := parseWinHelloEnvelope(nil)
	if err == nil {
		t.Fatal("parse error = nil, want error")
	}
}

func TestParseWinHelloEnvelopeRejectsInvalidEnvelope(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*winHelloEnvelope)
		wantErr error
	}{
		{
			name: "missing key name",
			mutate: func(envelope *winHelloEnvelope) {
				envelope.KeyName = ""
			},
			wantErr: errWinHelloEnvelopeKeyName,
		},
		{
			name: "missing aad",
			mutate: func(envelope *winHelloEnvelope) {
				envelope.AAD = nil
			},
			wantErr: errWinHelloEnvelopeAAD,
		},
		{
			name: "wrong provider",
			mutate: func(envelope *winHelloEnvelope) {
				envelope.Provider = "Other Provider"
			},
			wantErr: errWinHelloEnvelopeProvider,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			envelope := newValidWinHelloEnvelope()
			test.mutate(&envelope)

			encoded, err := json.Marshal(envelope)
			if err != nil {
				t.Fatalf("json marshal failed: %v", err)
			}

			_, err = parseWinHelloEnvelope(encoded)
			if !errors.Is(err, test.wantErr) {
				t.Fatalf("parse error = %v, want %v", err, test.wantErr)
			}
		})
	}
}
