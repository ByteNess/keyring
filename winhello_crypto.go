package keyring

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

const winHelloCEKSize = 32

var (
	errWinHelloWrapKey         = errors.New("winhello wrap key failed")
	errWinHelloUnwrapKey       = errors.New("winhello unwrap key failed")
	errWinHelloEncrypt         = errors.New("winhello content encryption failed")
	errWinHelloDecrypt         = errors.New("winhello content decryption failed")
	errWinHelloRandom          = errors.New("winhello random generation failed")
	errWinHelloAADMismatch     = errors.New("winhello envelope aad mismatch")
	errWinHelloKeyNameMismatch = errors.New("winhello envelope key name mismatch")
	errWinHelloKeyWrapper      = errors.New("winhello key wrapper is required")
	errWinHelloMissingAAD      = errors.New("winhello aad is required")
)

var winHelloRandReader = rand.Reader

type winHelloAADData struct {
	Backend     string `json:"backend"`
	Version     int    `json:"version"`
	ServiceName string `json:"service_name"`
	ItemKey     string `json:"item_key"`
}

type winHelloKeyWrapper interface {
	WrapKey(cek []byte) ([]byte, error)
	UnwrapKey(wrapped []byte, context string) ([]byte, error)
}

func winHelloAAD(serviceName, itemKey string) []byte {
	aad, err := json.Marshal(winHelloAADData{
		Backend:     "winhello",
		Version:     winHelloEnvelopeVersion,
		ServiceName: serviceName,
		ItemKey:     itemKey,
	})
	if err != nil {
		// Since json.Marshal on this fixed struct cannot realistically fail, the panic is acceptable.
		panic(fmt.Sprintf("marshal winhello AAD: %v", err))
	}

	return aad
}

func encryptWinHelloEnvelope(
	plaintext []byte,
	aad []byte,
	keyName string,
	wrapper winHelloKeyWrapper,
) ([]byte, error) {
	if wrapper == nil {
		return nil, errWinHelloKeyWrapper
	}
	if len(aad) == 0 {
		return nil, errWinHelloMissingAAD
	}
	if keyName == "" {
		return nil, errWinHelloEnvelopeKeyName
	}

	cek := make([]byte, winHelloCEKSize)
	defer zeroBytes(cek) // Clear the generated CEK from memory as soon as possible after use
	if _, err := io.ReadFull(winHelloRandReader, cek); err != nil {
		return nil, fmt.Errorf("%w: %w", errWinHelloRandom, err)
	}

	block, err := aes.NewCipher(cek)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", errWinHelloEncrypt, err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", errWinHelloEncrypt, err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(winHelloRandReader, nonce); err != nil {
		return nil, fmt.Errorf("%w: %w", errWinHelloRandom, err)
	}

	ciphertext := gcm.Seal(nil, nonce, plaintext, aad)

	wrappedCEK, err := wrapper.WrapKey(bytes.Clone(cek))
	if err != nil {
		return nil, fmt.Errorf("%w: %w", errWinHelloWrapKey, err)
	}

	envelope := winHelloEnvelope{
		Version:    winHelloEnvelopeVersion,
		Provider:   winHelloProviderPassportKSP,
		KeyName:    keyName,
		ContentAlg: winHelloContentAlgAES256GCM,
		WrapAlg:    winHelloWrapAlgRSAPKCS1v15,
		Nonce:      nonce,
		WrappedCEK: wrappedCEK,
		Ciphertext: ciphertext,
		AAD:        bytes.Clone(aad),
	}

	encoded, err := envelope.marshal()
	if err != nil {
		return nil, err
	}

	return encoded, nil
}

func decryptWinHelloEnvelope(
	encoded []byte,
	aad []byte,
	expectedKeyName string,
	wrapper winHelloKeyWrapper,
	context string,
) ([]byte, error) {
	if wrapper == nil {
		return nil, errWinHelloKeyWrapper
	}
	if len(aad) == 0 {
		return nil, errWinHelloMissingAAD
	}
	if expectedKeyName == "" {
		return nil, errWinHelloEnvelopeKeyName
	}

	envelope, err := parseWinHelloEnvelope(encoded)
	if err != nil {
		return nil, err
	}

	// Reject tampered envelopes by validating expected values before unwrapping or decryption
	if envelope.KeyName != expectedKeyName {
		return nil, errWinHelloKeyNameMismatch
	}
	if !bytes.Equal(envelope.AAD, aad) {
		return nil, errWinHelloAADMismatch
	}

	cek, err := wrapper.UnwrapKey(envelope.WrappedCEK, context)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", errWinHelloUnwrapKey, err)
	}
	defer zeroBytes(cek) // Clear the unwrapped CEK from memory as soon as possible after use

	block, err := aes.NewCipher(cek)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", errWinHelloDecrypt, err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", errWinHelloDecrypt, err)
	}

	plaintext, err := gcm.Open(nil, envelope.Nonce, envelope.Ciphertext, aad)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", errWinHelloDecrypt, err)
	}

	return plaintext, nil
}

func zeroBytes(buf []byte) {
	for i := range buf {
		buf[i] = 0
	}
}
