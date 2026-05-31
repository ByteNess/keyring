//go:build windows
// +build windows

package keyring

import (
	"errors"
	"fmt"
)

const (
	winHelloPassportKeyBits       = 2048
	winHelloPassportCreateContext = "Create keyring winhello key"
)

// winHelloPassportKey keeps only stable metadata needed to reopen the
// Passport-backed key on demand. Each cryptographic operation should open its
// own provider/key handles rather than sharing NCrypt handles across calls.
type winHelloPassportKey struct {
	keyName string
	hwnd    uintptr
}

var (
	winHelloNCryptOpenStorageProviderFunc = winHelloNCryptOpenStorageProvider
	winHelloNCryptOpenKeyFunc             = winHelloNCryptOpenKey
	winHelloNCryptCreatePersistedKeyFunc  = winHelloNCryptCreatePersistedKey
	winHelloNCryptSetUint32PropertyFunc   = winHelloNCryptSetUint32Property
	winHelloNCryptSetStringPropertyFunc   = winHelloNCryptSetStringProperty
	winHelloNCryptSetHandlePropertyFunc   = winHelloNCryptSetHandleProperty
	winHelloNCryptFinalizeKeyFunc         = winHelloNCryptFinalizeKey
	winHelloNCryptFreeObjectFunc          = winHelloNCryptFreeObject
)

func openWinHelloPassportKey(logicalName string, hwnd uintptr) (*winHelloPassportKey, error) {
	provider, keyName, err := winHelloOpenPassportProvider(logicalName, hwnd)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = winHelloNCryptFreeObjectFunc(provider)
	}()

	// A successful open here is only a probe that confirms the persisted
	// Passport key already exists.
	keyHandle, err := winHelloNCryptOpenKeyFunc(provider, keyName, 0, 0)
	if err != nil {
		if isWinHelloNCryptKeyNotFound(err) {
			return nil, ErrKeyNotFound
		}
		return nil, fmt.Errorf("open Passport key %q: %w", keyName, err)
	}
	if err := winHelloNCryptFreeObjectFunc(keyHandle); err != nil {
		return nil, fmt.Errorf("free Passport key %q: %w", keyName, err)
	}

	return &winHelloPassportKey{
		keyName: keyName,
		hwnd:    hwnd,
	}, nil
}

func ensureWinHelloPassportKey(logicalName string, hwnd uintptr) (*winHelloPassportKey, error) {
	passportKey, err := openWinHelloPassportKey(logicalName, hwnd)
	if err == nil {
		return passportKey, nil
	}
	if !errors.Is(err, ErrKeyNotFound) {
		return nil, err
	}

	// Passport KSP expects an NGC-style name plus a small set of provider-
	// specific properties before FinalizeKey will succeed for Windows Hello.
	// NGC-style = <SID>//<domain>/<namespace>/<logicalName>
	provider, keyName, err := winHelloOpenPassportProvider(logicalName, hwnd)
	if err != nil {
		return nil, err
	}

	createdKey, err := winHelloNCryptCreatePersistedKeyFunc(provider, winHelloNCryptRSAAlgorithm, keyName, 0, 0)
	if err != nil {
		_ = winHelloNCryptFreeObjectFunc(provider)
		return nil, fmt.Errorf("create Passport key %q: %w", keyName, err)
	}

	if err := winHelloInitializePassportKey(createdKey, hwnd); err != nil {
		_ = winHelloNCryptFreeObjectFunc(createdKey)
		_ = winHelloNCryptFreeObjectFunc(provider)
		return nil, fmt.Errorf("initialize Passport key %q: %w", keyName, err)
	}
	if err := winHelloNCryptFinalizeKeyFunc(createdKey, 0); err != nil {
		_ = winHelloNCryptFreeObjectFunc(createdKey)
		_ = winHelloNCryptFreeObjectFunc(provider)
		return nil, fmt.Errorf("finalize Passport key %q: %w", keyName, err)
	}
	if err := winHelloNCryptFreeObjectFunc(createdKey); err != nil {
		_ = winHelloNCryptFreeObjectFunc(provider)
		return nil, fmt.Errorf("free Passport key %q after finalize: %w", keyName, err)
	}
	if err := winHelloNCryptFreeObjectFunc(provider); err != nil {
		return nil, fmt.Errorf("free Passport provider after create %q: %w", keyName, err)
	}

	return &winHelloPassportKey{
		keyName: keyName,
		hwnd:    hwnd,
	}, nil
}

func (key *winHelloPassportKey) Close() error {
	if key == nil {
		return nil
	}
	return nil
}

func winHelloOpenPassportProvider(logicalName string, hwnd uintptr) (ncryptHandle, string, error) {
	keyName, err := winHelloPassportKeyName(logicalName)
	if err != nil {
		return 0, "", err
	}

	provider, err := winHelloNCryptOpenStorageProviderFunc(winHelloProviderPassportKSP)
	if err != nil {
		return 0, "", fmt.Errorf("open Passport provider: %w", err)
	}
	// When the caller can supply an HWND, tie any Windows Hello prompt to it so
	// the UX is foregrounded and owned by the right window. This is best-effort:
	// prompt ownership should not block otherwise valid Passport operations.
	_ = winHelloSetWindowHandleIfPresent(provider, hwnd)

	return provider, keyName, nil
}

func winHelloInitializePassportKey(key ncryptHandle, hwnd uintptr) error {
	// Key-level prompt ownership is also best-effort for the same reason.
	_ = winHelloSetWindowHandleIfPresent(key, hwnd)
	// These properties are the Passport-specific creation shape validated by the
	// PoC: RSA-2048, decrypt/sign usage, NGC cache policy, and a Use Context
	// string that Windows Hello can surface in the prompt.
	if err := winHelloNCryptSetUint32PropertyFunc(key, winHelloNCryptLengthProperty, winHelloPassportKeyBits); err != nil {
		return err
	}
	if err := winHelloNCryptSetUint32PropertyFunc(key, winHelloNCryptKeyUsageProperty, winHelloNCryptAllowDecryptFlag|winHelloNCryptAllowSigningFlag); err != nil {
		return err
	}
	if err := winHelloSetPassportNgcCacheType(key); err != nil {
		return err
	}
	if err := winHelloNCryptSetStringPropertyFunc(key, winHelloNCryptUseContextProperty, winHelloPassportCreateContext); err != nil {
		return err
	}

	return nil
}

func winHelloSetPassportNgcCacheType(key ncryptHandle) error {
	err := winHelloNCryptSetUint32PropertyFunc(key, winHelloNCryptNgcCacheTypeProperty, winHelloNCryptNgcCacheTypeAuthMandatory)
	if err == nil {
		return nil
	}

	// Some systems accept the older property name instead, so keep the fallback
	// local here rather than scattering the compatibility branch across callers.
	legacyErr := winHelloNCryptSetUint32PropertyFunc(key, winHelloNCryptNgcCacheTypeLegacyProperty, winHelloNCryptNgcCacheTypeAuthMandatory)
	if legacyErr == nil {
		return nil
	}

	return fmt.Errorf(
		"set %s: %w; fallback %s: %v",
		winHelloNCryptNgcCacheTypeProperty,
		err,
		winHelloNCryptNgcCacheTypeLegacyProperty,
		legacyErr,
	)
}

func winHelloSetWindowHandleIfPresent(handle ncryptHandle, hwnd uintptr) error {
	if hwnd == 0 {
		hwnd = winHelloParentHWNDFunc()
	}
	if hwnd == 0 {
		return nil
	}

	if err := winHelloNCryptSetHandlePropertyFunc(handle, winHelloNCryptWindowHandleProperty, hwnd); err != nil {
		return fmt.Errorf("set Passport window handle: %w", err)
	}

	return nil
}
