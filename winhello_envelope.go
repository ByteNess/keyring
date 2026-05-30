package keyring

import (
	"encoding/json"
	"errors"
	"fmt"
)

const (
	winHelloEnvelopeVersion = 1

	winHelloProviderPassportKSP = "Microsoft Passport Key Storage Provider"

	winHelloContentAlgAES256GCM = "AES-256-GCM"
	winHelloWrapAlgRSAPKCS1v15  = "RSAES-PKCS1-v1_5"
)

var (
	errWinHelloEnvelopeVersion    = errors.New("winhello envelope has unsupported version")
	errWinHelloEnvelopeProvider   = errors.New("winhello envelope has unsupported provider")
	errWinHelloEnvelopeKeyName    = errors.New("winhello envelope is missing key name")
	errWinHelloEnvelopeContentAlg = errors.New("winhello envelope has unsupported content algorithm")
	errWinHelloEnvelopeWrapAlg    = errors.New("winhello envelope has unsupported wrap algorithm")
	errWinHelloEnvelopeNonce      = errors.New("winhello envelope is missing nonce")
	errWinHelloEnvelopeWrappedCEK = errors.New("winhello envelope is missing wrapped cek")
	errWinHelloEnvelopeCiphertext = errors.New("winhello envelope is missing ciphertext")
	errWinHelloEnvelopeAAD        = errors.New("winhello envelope is missing aad")
)

type winHelloEnvelope struct {
	Version    int    `json:"version"`
	Provider   string `json:"provider"`
	KeyName    string `json:"key_name"`
	ContentAlg string `json:"content_alg"`
	WrapAlg    string `json:"wrap_alg"`
	Nonce      []byte `json:"nonce"`
	WrappedCEK []byte `json:"wrapped_cek"`
	Ciphertext []byte `json:"ciphertext"`
	AAD        []byte `json:"aad"`
}

func (e winHelloEnvelope) validate() error {
	if e.Version != winHelloEnvelopeVersion {
		return fmt.Errorf("%w: %d", errWinHelloEnvelopeVersion, e.Version)
	}
	if e.Provider != winHelloProviderPassportKSP {
		return fmt.Errorf("%w: %q", errWinHelloEnvelopeProvider, e.Provider)
	}
	if e.KeyName == "" {
		return errWinHelloEnvelopeKeyName
	}
	if e.ContentAlg != winHelloContentAlgAES256GCM {
		return fmt.Errorf("%w: %q", errWinHelloEnvelopeContentAlg, e.ContentAlg)
	}
	if e.WrapAlg != winHelloWrapAlgRSAPKCS1v15 {
		return fmt.Errorf("%w: %q", errWinHelloEnvelopeWrapAlg, e.WrapAlg)
	}
	if len(e.Nonce) == 0 {
		return errWinHelloEnvelopeNonce
	}
	if len(e.WrappedCEK) == 0 {
		return errWinHelloEnvelopeWrappedCEK
	}
	if len(e.Ciphertext) == 0 {
		return errWinHelloEnvelopeCiphertext
	}
	if len(e.AAD) == 0 {
		return errWinHelloEnvelopeAAD
	}

	return nil
}

func (e winHelloEnvelope) marshal() ([]byte, error) {
	if err := e.validate(); err != nil {
		return nil, err
	}

	return json.Marshal(e)
}

func parseWinHelloEnvelope(data []byte) (winHelloEnvelope, error) {
	var envelope winHelloEnvelope
	if err := json.Unmarshal(data, &envelope); err != nil {
		return winHelloEnvelope{}, err
	}
	if err := envelope.validate(); err != nil {
		return winHelloEnvelope{}, err
	}

	return envelope, nil
}
