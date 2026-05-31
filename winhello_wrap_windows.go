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
	errWinHelloInvalidCEKSize          = errors.New("winhello CEK must be 32 bytes")

	winHelloNCryptEncryptFunc = winHelloNCryptEncrypt
	winHelloNCryptDecryptFunc = winHelloNCryptDecrypt
)

func (key *winHelloPassportKey) WrapKey(cek []byte) ([]byte, error) {
	if len(cek) != winHelloCEKSize {
		return nil, fmt.Errorf("%w: got %d bytes", errWinHelloInvalidCEKSize, len(cek))
	}

	var wrapped []byte

	err := key.withOperationKey(func(handle ncryptHandle) error {
		// Public-key encrypt should not prompt, but keep prompt ownership aligned
		// with the active window if the provider ever surfaces UI during use.
		_ = winHelloSetWindowHandleIfPresent(handle, key.hwnd)

		var err error
		wrapped, err = winHelloNCryptEncryptFunc(handle, cek, nil, winHelloNCryptPadPKCS1Flag)
		if err != nil {
			return fmt.Errorf("wrap CEK with Passport key: %w", err)
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
			return fmt.Errorf("prepare Passport key for unwrap: %w", err)
		}

		var err error
		cek, err = winHelloNCryptDecryptFunc(handle, wrapped, nil, winHelloNCryptPadPKCS1Flag)
		if err != nil {
			return fmt.Errorf("unwrap CEK with Passport key: %w", err)
		}
		if len(cek) != winHelloCEKSize {
			return fmt.Errorf("%w after unwrap: got %d bytes", errWinHelloInvalidCEKSize, len(cek))
		}

		return nil
	})
	if err != nil {
		return nil, err
	}

	return cek, nil
}

// withOperationKey reopens the persisted Passport key for each cryptographic
// operation so the wrapper never shares NCrypt handles across calls. Handle
// cleanup is best-effort because this descriptor is stateless and the caller's
// actionable failure is the cryptographic operation itself.
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
	defer func() {
		_ = winHelloNCryptFreeObjectFunc(provider)
	}()
	_ = winHelloSetWindowHandleIfPresent(provider, key.hwnd)

	openedKey, err := winHelloNCryptOpenKeyFunc(provider, key.keyName, 0, 0)
	if err != nil {
		if isWinHelloNCryptKeyNotFound(err) {
			return errWinHelloPassportKeyNotFound
		}
		return fmt.Errorf("open Passport key: %w", err)
	}
	defer func() {
		_ = winHelloNCryptFreeObjectFunc(openedKey)
	}()

	return run(openedKey)
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
