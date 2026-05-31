//go:build windows
// +build windows

package keyring

import (
	"errors"
	"fmt"
)

const winHelloPassportDefaultUnwrapContext = "Unlock keyring secret"

var (
	errWinHelloPassportKeyRequired     = errors.New("winhello passport key is required")
	errWinHelloPassportKeyNameRequired = errors.New("winhello passport key name is required")

	winHelloNCryptEncryptFunc = winHelloNCryptEncrypt
	winHelloNCryptDecryptFunc = winHelloNCryptDecrypt
)

func (key *winHelloPassportKey) WrapKey(cek []byte) ([]byte, error) {
	var wrapped []byte

	err := key.withOperationKey(func(handle ncryptHandle) error {
		var err error
		wrapped, err = winHelloNCryptEncryptFunc(handle, cek, nil, winHelloNCryptPadPKCS1Flag)
		if err != nil {
			return fmt.Errorf("wrap CEK with Passport key %q: %w", key.keyName, err)
		}

		return nil
	})
	if err != nil {
		return nil, err
	}

	return wrapped, nil
}

func (key *winHelloPassportKey) UnwrapKey(wrapped []byte, context string) ([]byte, error) {
	var cek []byte

	err := key.withOperationKey(func(handle ncryptHandle) error {
		if err := winHelloPreparePassportUnwrap(handle, key.hwnd, context); err != nil {
			return fmt.Errorf("prepare Passport key %q for unwrap: %w", key.keyName, err)
		}

		var err error
		cek, err = winHelloNCryptDecryptFunc(handle, wrapped, nil, winHelloNCryptPadPKCS1Flag)
		if err != nil {
			return fmt.Errorf("unwrap CEK with Passport key %q: %w", key.keyName, err)
		}

		return nil
	})
	if err != nil {
		return nil, err
	}

	return cek, nil
}

// withOperationKey reopens the persisted Passport key for each cryptographic
// operation so the wrapper never shares NCrypt handles across calls.
func (key *winHelloPassportKey) withOperationKey(run func(handle ncryptHandle) error) error {
	if key == nil {
		return errWinHelloPassportKeyRequired
	}
	if key.keyName == "" {
		return errWinHelloPassportKeyNameRequired
	}

	provider, err := winHelloNCryptOpenStorageProviderFunc(winHelloProviderPassportKSP)
	if err != nil {
		return fmt.Errorf("open Passport provider: %w", err)
	}
	_ = winHelloSetWindowHandleIfPresent(provider, key.hwnd)

	openedKey, err := winHelloNCryptOpenKeyFunc(provider, key.keyName, 0, 0)
	if err != nil {
		_ = winHelloNCryptFreeObjectFunc(provider)
		if isWinHelloNCryptKeyNotFound(err) {
			return ErrKeyNotFound
		}
		return fmt.Errorf("open Passport key %q: %w", key.keyName, err)
	}

	if err := run(openedKey); err != nil {
		_ = winHelloNCryptFreeObjectFunc(openedKey)
		_ = winHelloNCryptFreeObjectFunc(provider)
		return err
	}
	if err := winHelloNCryptFreeObjectFunc(openedKey); err != nil {
		_ = winHelloNCryptFreeObjectFunc(provider)
		return fmt.Errorf("free Passport key %q: %w", key.keyName, err)
	}
	if err := winHelloNCryptFreeObjectFunc(provider); err != nil {
		return fmt.Errorf("free Passport provider for %q: %w", key.keyName, err)
	}

	return nil
}

// Passport private-key unwraps should request interactive approval rather than
// relying on any ambient pin cache state or background prompt ownership.
func winHelloPreparePassportUnwrap(handle ncryptHandle, hwnd uintptr, context string) error {
	_ = winHelloSetWindowHandleIfPresent(handle, hwnd)

	if context == "" {
		context = winHelloPassportDefaultUnwrapContext
	}
	if err := winHelloNCryptSetStringPropertyFunc(handle, winHelloNCryptUseContextProperty, context); err != nil {
		return err
	}
	if err := winHelloNCryptSetUint32PropertyFunc(handle, winHelloNCryptPinCacheIsGestureRequiredProperty, 1); err != nil {
		return err
	}

	return nil
}
