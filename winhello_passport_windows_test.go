//go:build windows
// +build windows

package keyring

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"
)

type winHelloPassportPropertyCall struct {
	handle   ncryptHandle
	property string
	value    any
}

func TestWinHelloPassportOpenMissingKeyReturnsNotFound(t *testing.T) {
	restore := stubWinHelloPassportNCryptHooks(t)
	defer restore()

	winHelloNCryptOpenStorageProviderFunc = func(providerName string) (ncryptHandle, error) {
		if providerName != winHelloProviderPassportKSP {
			t.Fatalf("provider = %q, want %q", providerName, winHelloProviderPassportKSP)
		}
		return ncryptHandle(11), nil
	}
	winHelloNCryptOpenKeyFunc = func(provider ncryptHandle, keyName string, legacyKeySpec uint32, flags uint32) (ncryptHandle, error) {
		if provider != ncryptHandle(11) {
			t.Fatalf("provider handle = %d, want %d", provider, ncryptHandle(11))
		}
		if legacyKeySpec != 0 || flags != 0 {
			t.Fatalf("open key args = (%d, %d), want (0, 0)", legacyKeySpec, flags)
		}
		if !strings.Contains(keyName, "/missing-key") {
			t.Fatalf("key name = %q, want derived logical name suffix", keyName)
		}
		return 0, errWinHelloNCryptNoKey
	}

	passportKey, err := openWinHelloPassportKey("missing-key", 0)
	if !errors.Is(err, ErrKeyNotFound) {
		t.Fatalf("error = %v, want %v", err, ErrKeyNotFound)
	}
	if passportKey != nil {
		t.Fatalf("passport key = %#v, want nil", passportKey)
	}
}

func TestWinHelloPassportEnsureCreatesKey(t *testing.T) {
	restore := stubWinHelloPassportNCryptHooks(t)
	defer restore()

	var created bool
	var finalized bool
	var properties []winHelloPassportPropertyCall
	var freed []ncryptHandle

	winHelloNCryptOpenStorageProviderFunc = func(providerName string) (ncryptHandle, error) {
		if providerName != winHelloProviderPassportKSP {
			t.Fatalf("provider = %q, want %q", providerName, winHelloProviderPassportKSP)
		}
		return ncryptHandle(21), nil
	}
	winHelloNCryptOpenKeyFunc = func(provider ncryptHandle, keyName string, _ uint32, _ uint32) (ncryptHandle, error) {
		if provider != ncryptHandle(21) {
			t.Fatalf("provider handle = %d, want %d", provider, ncryptHandle(21))
		}
		if !strings.Contains(keyName, "/step7-create") {
			t.Fatalf("key name = %q, want derived logical name suffix", keyName)
		}
		if created {
			return ncryptHandle(22), nil
		}
		return 0, errWinHelloNCryptNotFound
	}
	winHelloNCryptCreatePersistedKeyFunc = func(provider ncryptHandle, algorithm string, keyName string, legacyKeySpec uint32, flags uint32) (ncryptHandle, error) {
		created = true
		if provider != ncryptHandle(21) {
			t.Fatalf("provider handle = %d, want %d", provider, ncryptHandle(21))
		}
		if algorithm != winHelloNCryptRSAAlgorithm {
			t.Fatalf("algorithm = %q, want %q", algorithm, winHelloNCryptRSAAlgorithm)
		}
		if legacyKeySpec != 0 || flags != 0 {
			t.Fatalf("create key args = (%d, %d), want (0, 0)", legacyKeySpec, flags)
		}
		if !strings.Contains(keyName, "/step7-create") {
			t.Fatalf("key name = %q, want derived logical name suffix", keyName)
		}
		return ncryptHandle(22), nil
	}
	winHelloNCryptSetHandlePropertyFunc = func(handle ncryptHandle, property string, value uintptr) error {
		properties = append(properties, winHelloPassportPropertyCall{handle: handle, property: property, value: value})
		return nil
	}
	winHelloNCryptSetUint32PropertyFunc = func(handle ncryptHandle, property string, value uint32) error {
		properties = append(properties, winHelloPassportPropertyCall{handle: handle, property: property, value: value})
		if property == winHelloNCryptNgcCacheTypeProperty {
			return errors.New("primary property unsupported")
		}
		return nil
	}
	winHelloNCryptSetStringPropertyFunc = func(handle ncryptHandle, property string, value string) error {
		properties = append(properties, winHelloPassportPropertyCall{handle: handle, property: property, value: value})
		return nil
	}
	winHelloNCryptFinalizeKeyFunc = func(key ncryptHandle, flags uint32) error {
		if key != ncryptHandle(22) || flags != 0 {
			t.Fatalf("finalize args = (%d, %d), want (%d, 0)", key, flags, ncryptHandle(22))
		}
		finalized = true
		return nil
	}
	winHelloNCryptFreeObjectFunc = func(handle ncryptHandle) error {
		freed = append(freed, handle)
		return nil
	}

	passportKey, err := ensureWinHelloPassportKey("step7-create", 99)
	if err != nil {
		t.Fatalf("ensureWinHelloPassportKey() failed: %v", err)
	}
	defer func() {
		if err := passportKey.Close(); err != nil {
			t.Fatalf("Close() failed: %v", err)
		}
	}()

	if !created {
		t.Fatal("expected key creation path to run")
	}
	if !finalized {
		t.Fatal("expected finalize to run")
	}
	if passportKey.provider != ncryptHandle(21) {
		t.Fatalf("provider handle = %d, want %d", passportKey.provider, ncryptHandle(21))
	}
	if passportKey.hwnd != 99 {
		t.Fatalf("hwnd = %d, want %d", passportKey.hwnd, 99)
	}

	assertPassportPropertyCall(t, properties, ncryptHandle(21), winHelloNCryptWindowHandleProperty, uintptr(99))
	assertPassportPropertyCall(t, properties, ncryptHandle(22), winHelloNCryptWindowHandleProperty, uintptr(99))
	assertPassportPropertyCall(t, properties, ncryptHandle(22), winHelloNCryptLengthProperty, uint32(winHelloPassportKeyBits))
	assertPassportPropertyCall(t, properties, ncryptHandle(22), winHelloNCryptKeyUsageProperty, uint32(winHelloNCryptAllowDecryptFlag|winHelloNCryptAllowSigningFlag))
	assertPassportPropertyCall(t, properties, ncryptHandle(22), winHelloNCryptNgcCacheTypeProperty, uint32(winHelloNCryptNgcCacheTypeAuthMandatory))
	assertPassportPropertyCall(t, properties, ncryptHandle(22), winHelloNCryptNgcCacheTypeLegacyProperty, uint32(winHelloNCryptNgcCacheTypeAuthMandatory))
	assertPassportPropertyCall(t, properties, ncryptHandle(22), winHelloNCryptUseContextProperty, winHelloPassportCreateContext)
	if !containsPassportHandle(freed, ncryptHandle(22)) {
		t.Fatalf("freed handles = %v, want created key handle to be freed", freed)
	}
}

func TestWinHelloPassportEnsurePropagatesInvalidParameter(t *testing.T) {
	restore := stubWinHelloPassportNCryptHooks(t)
	defer restore()

	createCalled := false
	winHelloNCryptOpenStorageProviderFunc = func(_ string) (ncryptHandle, error) {
		return ncryptHandle(31), nil
	}
	winHelloNCryptOpenKeyFunc = func(_ ncryptHandle, _ string, _ uint32, _ uint32) (ncryptHandle, error) {
		return 0, errWinHelloNCryptInvalidParameter
	}
	winHelloNCryptCreatePersistedKeyFunc = func(_ ncryptHandle, _ string, _ string, _ uint32, _ uint32) (ncryptHandle, error) {
		createCalled = true
		return 0, errors.New("unexpected create")
	}

	passportKey, err := ensureWinHelloPassportKey("invalid-parameter", 0)
	if err == nil {
		t.Fatal("ensureWinHelloPassportKey() error = nil, want non-nil")
	}
	if createCalled {
		t.Fatal("create path was called for invalid-parameter open failure")
	}
	if passportKey != nil {
		t.Fatalf("passport key = %#v, want nil", passportKey)
	}
	if errors.Is(err, ErrKeyNotFound) {
		t.Fatalf("error %v unexpectedly classified as ErrKeyNotFound", err)
	}
	if !strings.Contains(err.Error(), "open Passport key") {
		t.Fatalf("error = %v, want open Passport key context", err)
	}
}

func TestWinHelloPassportCreateAndReopen(t *testing.T) {
	requireWinHelloPassportIntegration(t)

	logicalName := fmt.Sprintf("keyring-winhello-step7-%d", time.Now().UnixNano())
	t.Cleanup(func() {
		cleanupWinHelloPassportKey(t, logicalName)
	})

	passportKey, err := ensureWinHelloPassportKey(logicalName, 0)
	if err != nil {
		t.Fatalf("ensureWinHelloPassportKey() failed: %v", err)
	}
	if err := passportKey.Close(); err != nil {
		t.Fatalf("Close() failed: %v", err)
	}

	reopenedKey, err := openWinHelloPassportKey(logicalName, 0)
	if err != nil {
		t.Fatalf("openWinHelloPassportKey() failed: %v", err)
	}
	t.Cleanup(func() {
		if err := reopenedKey.Close(); err != nil {
			t.Fatalf("Close() failed: %v", err)
		}
	})
}

func TestWinHelloPassportCreateMissingKeyIsNotFound(t *testing.T) {
	requireWinHelloPassportIntegration(t)

	logicalName := fmt.Sprintf("keyring-winhello-step7-missing-%d", time.Now().UnixNano())
	passportKey, err := openWinHelloPassportKey(logicalName, 0)
	if !errors.Is(err, ErrKeyNotFound) {
		if passportKey != nil {
			_ = passportKey.Close()
		}
		t.Fatalf("error = %v, want %v", err, ErrKeyNotFound)
	}
}

func stubWinHelloPassportNCryptHooks(t *testing.T) func() {
	t.Helper()

	oldOpenStorageProvider := winHelloNCryptOpenStorageProviderFunc
	oldOpenKey := winHelloNCryptOpenKeyFunc
	oldCreatePersistedKey := winHelloNCryptCreatePersistedKeyFunc
	oldSetUint32Property := winHelloNCryptSetUint32PropertyFunc
	oldSetStringProperty := winHelloNCryptSetStringPropertyFunc
	oldSetHandleProperty := winHelloNCryptSetHandlePropertyFunc
	oldFinalizeKey := winHelloNCryptFinalizeKeyFunc
	oldFreeObject := winHelloNCryptFreeObjectFunc

	winHelloNCryptFreeObjectFunc = func(_ ncryptHandle) error {
		return nil
	}

	return func() {
		winHelloNCryptOpenStorageProviderFunc = oldOpenStorageProvider
		winHelloNCryptOpenKeyFunc = oldOpenKey
		winHelloNCryptCreatePersistedKeyFunc = oldCreatePersistedKey
		winHelloNCryptSetUint32PropertyFunc = oldSetUint32Property
		winHelloNCryptSetStringPropertyFunc = oldSetStringProperty
		winHelloNCryptSetHandlePropertyFunc = oldSetHandleProperty
		winHelloNCryptFinalizeKeyFunc = oldFinalizeKey
		winHelloNCryptFreeObjectFunc = oldFreeObject
	}
}

func assertPassportPropertyCall(t *testing.T, calls []winHelloPassportPropertyCall, handle ncryptHandle, property string, value any) {
	t.Helper()
	for _, call := range calls {
		if call.handle == handle && call.property == property && call.value == value {
			return
		}
	}
	t.Fatalf("property call (%d, %q, %v) not found in %v", handle, property, value, calls)
}

func containsPassportHandle(handles []ncryptHandle, want ncryptHandle) bool {
	for _, handle := range handles {
		if handle == want {
			return true
		}
	}

	return false
}

func requireWinHelloPassportIntegration(t *testing.T) {
	t.Helper()
	if os.Getenv("KEYRING_WINHELLO_TEST") != "1" {
		t.Skip("set KEYRING_WINHELLO_TEST=1 to run WinHello Passport integration tests")
	}
}

func cleanupWinHelloPassportKey(t *testing.T, logicalName string) {
	t.Helper()

	keyName, err := winHelloPassportKeyName(logicalName)
	if err != nil {
		t.Fatalf("winHelloPassportKeyName() failed: %v", err)
	}

	provider, err := winHelloNCryptOpenStorageProvider(winHelloProviderPassportKSP)
	if err != nil {
		t.Fatalf("open Passport provider failed: %v", err)
	}
	defer func() {
		if err := winHelloNCryptFreeObject(provider); err != nil {
			t.Fatalf("free Passport provider failed: %v", err)
		}
	}()

	key, err := winHelloNCryptOpenKey(provider, keyName, 0, 0)
	if err != nil {
		if isWinHelloNCryptKeyNotFound(err) {
			return
		}
		t.Fatalf("open Passport key failed: %v", err)
	}
	if err := winHelloNCryptDeleteKey(key, 0); err != nil {
		_ = winHelloNCryptFreeObject(key)
		t.Fatalf("delete Passport key failed: %v", err)
	}
}
