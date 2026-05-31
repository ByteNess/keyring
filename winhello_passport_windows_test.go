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

const winHelloPassportTestLogicalNamePrefix = "keyring-winhello-test-"

func TestWinHelloPassportCloseIsIdempotent(t *testing.T) {
	restore := stubWinHelloPassportNCryptHooks(t)
	defer restore()

	var freed []ncryptHandle
	winHelloNCryptFreeObjectFunc = func(handle ncryptHandle) error {
		freed = append(freed, handle)
		return nil
	}

	passportKey := &winHelloPassportKey{keyName: "close-idempotent"}
	if err := passportKey.Close(); err != nil {
		t.Fatalf("first Close() failed: %v", err)
	}
	if err := passportKey.Close(); err != nil {
		t.Fatalf("second Close() failed: %v", err)
	}

	if len(freed) != 0 {
		t.Fatalf("freed handles = %v, want none", freed)
	}
}

func TestWinHelloPassportOpenMissingKeyReturnsPassportKeyNotFound(t *testing.T) {
	restore := stubWinHelloPassportNCryptHooks(t)
	defer restore()

	var freed []ncryptHandle

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
	winHelloNCryptFreeObjectFunc = func(handle ncryptHandle) error {
		freed = append(freed, handle)
		return nil
	}

	passportKey, err := openWinHelloPassportKey("missing-key", 0)
	if !errors.Is(err, errWinHelloPassportKeyNotFound) {
		t.Fatalf("error = %v, want %v", err, errWinHelloPassportKeyNotFound)
	}
	if errors.Is(err, ErrKeyNotFound) {
		t.Fatalf("error %v unexpectedly classified as ErrKeyNotFound", err)
	}
	if passportKey != nil {
		t.Fatalf("passport key = %#v, want nil", passportKey)
	}
	if !containsPassportHandle(freed, ncryptHandle(11)) {
		t.Fatalf("freed handles = %v, want provider handle to be freed", freed)
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
	if passportKey.keyName == "" {
		t.Fatal("key name = empty, want derived key name")
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
	if !containsPassportHandle(freed, ncryptHandle(21)) {
		t.Fatalf("freed handles = %v, want provider handle to be freed", freed)
	}
}

func TestWinHelloPassportEnsureIgnoresProviderWindowHandleError(t *testing.T) {
	runPassportEnsureWindowHandleErrorTest(t, passportWindowHandleErrorTestCase{
		logicalName:      "hwnd-provider",
		providerHandle:   ncryptHandle(51),
		createdKeyHandle: ncryptHandle(52),
		hwnd:             uintptr(99),
		failingHandle:    ncryptHandle(51),
		failureText:      "provider hwnd rejected",
		wantAttempt:      ncryptHandle(51),
	})
}

func TestWinHelloPassportEnsureIgnoresKeyWindowHandleError(t *testing.T) {
	runPassportEnsureWindowHandleErrorTest(t, passportWindowHandleErrorTestCase{
		logicalName:      "hwnd-key",
		providerHandle:   ncryptHandle(61),
		createdKeyHandle: ncryptHandle(62),
		hwnd:             uintptr(99),
		failingHandle:    ncryptHandle(62),
		failureText:      "key hwnd rejected",
		wantAttempt:      ncryptHandle(62),
	})
}

func TestWinHelloPassportEnsurePropagatesInvalidParameter(t *testing.T) {
	restore := stubWinHelloPassportNCryptHooks(t)
	defer restore()

	createCalled := false
	var freed []ncryptHandle

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
	winHelloNCryptFreeObjectFunc = func(handle ncryptHandle) error {
		freed = append(freed, handle)
		return nil
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
	if !containsPassportHandle(freed, ncryptHandle(31)) {
		t.Fatalf("freed handles = %v, want provider handle to be freed", freed)
	}
}

func TestWinHelloPassportOpenExistingKeyFreesProbeHandle(t *testing.T) {
	restore := stubWinHelloPassportNCryptHooks(t)
	defer restore()

	var freed []ncryptHandle

	winHelloNCryptOpenStorageProviderFunc = func(providerName string) (ncryptHandle, error) {
		if providerName != winHelloProviderPassportKSP {
			t.Fatalf("provider = %q, want %q", providerName, winHelloProviderPassportKSP)
		}
		return ncryptHandle(71), nil
	}
	winHelloNCryptOpenKeyFunc = func(provider ncryptHandle, keyName string, legacyKeySpec uint32, flags uint32) (ncryptHandle, error) {
		if provider != ncryptHandle(71) {
			t.Fatalf("provider handle = %d, want %d", provider, ncryptHandle(71))
		}
		if legacyKeySpec != 0 || flags != 0 {
			t.Fatalf("open key args = (%d, %d), want (0, 0)", legacyKeySpec, flags)
		}
		if !strings.Contains(keyName, "/existing-key") {
			t.Fatalf("key name = %q, want derived logical name suffix", keyName)
		}
		return ncryptHandle(72), nil
	}
	winHelloNCryptFreeObjectFunc = func(handle ncryptHandle) error {
		freed = append(freed, handle)
		return nil
	}

	passportKey, err := openWinHelloPassportKey("existing-key", 0)
	if err != nil {
		t.Fatalf("openWinHelloPassportKey() failed: %v", err)
	}
	if passportKey.keyName == "" {
		t.Fatal("key name = empty, want derived key name")
	}
	if !containsPassportHandle(freed, ncryptHandle(72)) {
		t.Fatalf("freed handles = %v, want probe key handle to be freed", freed)
	}
	if !containsPassportHandle(freed, ncryptHandle(71)) {
		t.Fatalf("freed handles = %v, want provider handle to be freed during open", freed)
	}
	if err := passportKey.Close(); err != nil {
		t.Fatalf("Close() failed: %v", err)
	}
	if len(freed) != 2 {
		t.Fatalf("freed handles = %v, want only probe key and provider frees", freed)
	}
}

func TestWinHelloPassportEnsureFreesHandlesWhenInitializeFails(t *testing.T) {
	restore := stubWinHelloPassportNCryptHooks(t)
	defer restore()

	var freed []ncryptHandle

	winHelloNCryptOpenStorageProviderFunc = func(_ string) (ncryptHandle, error) {
		return ncryptHandle(81), nil
	}
	winHelloNCryptOpenKeyFunc = func(_ ncryptHandle, _ string, _ uint32, _ uint32) (ncryptHandle, error) {
		return 0, errWinHelloNCryptNotFound
	}
	winHelloNCryptCreatePersistedKeyFunc = func(provider ncryptHandle, algorithm string, keyName string, legacyKeySpec uint32, flags uint32) (ncryptHandle, error) {
		if provider != ncryptHandle(81) || algorithm != winHelloNCryptRSAAlgorithm || legacyKeySpec != 0 || flags != 0 {
			t.Fatalf("unexpected create args: provider=%d algorithm=%q legacy=%d flags=%d", provider, algorithm, legacyKeySpec, flags)
		}
		if !strings.Contains(keyName, "/initialize-failure") {
			t.Fatalf("key name = %q, want derived logical name suffix", keyName)
		}
		return ncryptHandle(82), nil
	}
	winHelloNCryptSetUint32PropertyFunc = func(handle ncryptHandle, property string, value uint32) error {
		if handle != ncryptHandle(82) {
			t.Fatalf("uint32 property handle = %d, want %d", handle, ncryptHandle(82))
		}
		if property == winHelloNCryptLengthProperty {
			if value != uint32(winHelloPassportKeyBits) {
				t.Fatalf("length value = %d, want %d", value, uint32(winHelloPassportKeyBits))
			}
			return errors.New("length rejected")
		}
		return nil
	}
	winHelloNCryptFreeObjectFunc = func(handle ncryptHandle) error {
		freed = append(freed, handle)
		if handle == ncryptHandle(82) {
			return errors.New("created key free failed")
		}
		return nil
	}

	passportKey, err := ensureWinHelloPassportKey("initialize-failure", 0)
	if err == nil {
		t.Fatal("ensureWinHelloPassportKey() error = nil, want non-nil")
	}
	if passportKey != nil {
		t.Fatalf("passport key = %#v, want nil", passportKey)
	}
	if !strings.Contains(err.Error(), "initialize Passport key") {
		t.Fatalf("error = %v, want initialize Passport key context", err)
	}
	if !containsPassportHandle(freed, ncryptHandle(82)) || !containsPassportHandle(freed, ncryptHandle(81)) {
		t.Fatalf("freed handles = %v, want created key and provider handles to be freed", freed)
	}
}

func TestWinHelloPassportEnsureFreesHandlesWhenFinalizeFails(t *testing.T) {
	restore := stubWinHelloPassportNCryptHooks(t)
	defer restore()

	var freed []ncryptHandle

	winHelloNCryptOpenStorageProviderFunc = func(_ string) (ncryptHandle, error) {
		return ncryptHandle(91), nil
	}
	winHelloNCryptOpenKeyFunc = func(_ ncryptHandle, _ string, _ uint32, _ uint32) (ncryptHandle, error) {
		return 0, errWinHelloNCryptNotFound
	}
	winHelloNCryptCreatePersistedKeyFunc = func(provider ncryptHandle, algorithm string, keyName string, legacyKeySpec uint32, flags uint32) (ncryptHandle, error) {
		if provider != ncryptHandle(91) || algorithm != winHelloNCryptRSAAlgorithm || legacyKeySpec != 0 || flags != 0 {
			t.Fatalf("unexpected create args: provider=%d algorithm=%q legacy=%d flags=%d", provider, algorithm, legacyKeySpec, flags)
		}
		if !strings.Contains(keyName, "/finalize-failure") {
			t.Fatalf("key name = %q, want derived logical name suffix", keyName)
		}
		return ncryptHandle(92), nil
	}
	winHelloNCryptSetUint32PropertyFunc = func(handle ncryptHandle, property string, value uint32) error {
		if handle != ncryptHandle(92) {
			t.Fatalf("uint32 property handle = %d, want %d", handle, ncryptHandle(92))
		}
		switch property {
		case winHelloNCryptLengthProperty:
			if value != uint32(winHelloPassportKeyBits) {
				t.Fatalf("length value = %d, want %d", value, uint32(winHelloPassportKeyBits))
			}
		case winHelloNCryptKeyUsageProperty:
			if value != uint32(winHelloNCryptAllowDecryptFlag|winHelloNCryptAllowSigningFlag) {
				t.Fatalf("key usage value = %d, want %d", value, uint32(winHelloNCryptAllowDecryptFlag|winHelloNCryptAllowSigningFlag))
			}
		case winHelloNCryptNgcCacheTypeProperty:
			if value != uint32(winHelloNCryptNgcCacheTypeAuthMandatory) {
				t.Fatalf("NGC cache value = %d, want %d", value, uint32(winHelloNCryptNgcCacheTypeAuthMandatory))
			}
		default:
			t.Fatalf("unexpected uint32 property %q", property)
		}
		return nil
	}
	winHelloNCryptSetStringPropertyFunc = func(handle ncryptHandle, property string, value string) error {
		if handle != ncryptHandle(92) {
			t.Fatalf("string property handle = %d, want %d", handle, ncryptHandle(92))
		}
		if property != winHelloNCryptUseContextProperty {
			t.Fatalf("string property = %q, want %q", property, winHelloNCryptUseContextProperty)
		}
		if value != winHelloPassportCreateContext {
			t.Fatalf("use context = %q, want %q", value, winHelloPassportCreateContext)
		}
		return nil
	}
	winHelloNCryptFinalizeKeyFunc = func(key ncryptHandle, flags uint32) error {
		if key != ncryptHandle(92) || flags != 0 {
			t.Fatalf("finalize args = (%d, %d), want (%d, 0)", key, flags, ncryptHandle(92))
		}
		return errors.New("finalize rejected")
	}
	winHelloNCryptFreeObjectFunc = func(handle ncryptHandle) error {
		freed = append(freed, handle)
		if handle == ncryptHandle(92) {
			return errors.New("created key free failed")
		}
		return nil
	}

	passportKey, err := ensureWinHelloPassportKey("finalize-failure", 0)
	if err == nil {
		t.Fatal("ensureWinHelloPassportKey() error = nil, want non-nil")
	}
	if passportKey != nil {
		t.Fatalf("passport key = %#v, want nil", passportKey)
	}
	if !strings.Contains(err.Error(), "finalize Passport key") {
		t.Fatalf("error = %v, want finalize Passport key context", err)
	}
	if !containsPassportHandle(freed, ncryptHandle(92)) || !containsPassportHandle(freed, ncryptHandle(91)) {
		t.Fatalf("freed handles = %v, want created key and provider handles to be freed", freed)
	}
}

func TestWinHelloPassportNgcCacheTypeDoesNotUseLegacyWhenPrimarySucceeds(t *testing.T) {
	restore := stubWinHelloPassportNCryptHooks(t)
	defer restore()

	var properties []string
	winHelloNCryptSetUint32PropertyFunc = func(handle ncryptHandle, property string, value uint32) error {
		if handle != ncryptHandle(101) {
			t.Fatalf("handle = %d, want %d", handle, ncryptHandle(101))
		}
		if value != uint32(winHelloNCryptNgcCacheTypeAuthMandatory) {
			t.Fatalf("value = %d, want %d", value, uint32(winHelloNCryptNgcCacheTypeAuthMandatory))
		}
		properties = append(properties, property)
		return nil
	}

	if err := winHelloSetPassportNgcCacheType(ncryptHandle(101)); err != nil {
		t.Fatalf("winHelloSetPassportNgcCacheType() failed: %v", err)
	}
	if len(properties) != 1 || properties[0] != winHelloNCryptNgcCacheTypeProperty {
		t.Fatalf("properties = %v, want only %q", properties, winHelloNCryptNgcCacheTypeProperty)
	}
}

type passportWindowHandleErrorTestCase struct {
	logicalName      string
	providerHandle   ncryptHandle
	createdKeyHandle ncryptHandle
	hwnd             uintptr
	failingHandle    ncryptHandle
	failureText      string
	wantAttempt      ncryptHandle
}

func runPassportEnsureWindowHandleErrorTest(t *testing.T, testCase passportWindowHandleErrorTestCase) {
	t.Helper()

	restore := stubWinHelloPassportNCryptHooks(t)
	defer restore()

	var windowHandleAttempts []ncryptHandle

	winHelloNCryptOpenStorageProviderFunc = func(providerName string) (ncryptHandle, error) {
		if providerName != winHelloProviderPassportKSP {
			t.Fatalf("provider = %q, want %q", providerName, winHelloProviderPassportKSP)
		}
		return testCase.providerHandle, nil
	}
	winHelloNCryptOpenKeyFunc = func(provider ncryptHandle, keyName string, legacyKeySpec uint32, flags uint32) (ncryptHandle, error) {
		if provider != testCase.providerHandle {
			t.Fatalf("provider handle = %d, want %d", provider, testCase.providerHandle)
		}
		if legacyKeySpec != 0 || flags != 0 {
			t.Fatalf("open key args = (%d, %d), want (0, 0)", legacyKeySpec, flags)
		}
		if !strings.Contains(keyName, "/"+testCase.logicalName) {
			t.Fatalf("key name = %q, want derived logical name suffix", keyName)
		}
		return 0, errWinHelloNCryptNotFound
	}
	winHelloNCryptCreatePersistedKeyFunc = func(provider ncryptHandle, algorithm string, keyName string, legacyKeySpec uint32, flags uint32) (ncryptHandle, error) {
		if provider != testCase.providerHandle {
			t.Fatalf("provider handle = %d, want %d", provider, testCase.providerHandle)
		}
		if algorithm != winHelloNCryptRSAAlgorithm {
			t.Fatalf("algorithm = %q, want %q", algorithm, winHelloNCryptRSAAlgorithm)
		}
		if legacyKeySpec != 0 || flags != 0 {
			t.Fatalf("create key args = (%d, %d), want (0, 0)", legacyKeySpec, flags)
		}
		if !strings.Contains(keyName, "/"+testCase.logicalName) {
			t.Fatalf("key name = %q, want derived logical name suffix", keyName)
		}
		return testCase.createdKeyHandle, nil
	}
	winHelloNCryptSetHandlePropertyFunc = func(handle ncryptHandle, property string, value uintptr) error {
		if property != winHelloNCryptWindowHandleProperty {
			t.Fatalf("property = %q, want %q", property, winHelloNCryptWindowHandleProperty)
		}
		if value != testCase.hwnd {
			t.Fatalf("value = %d, want %d", value, testCase.hwnd)
		}
		windowHandleAttempts = append(windowHandleAttempts, handle)
		if handle == testCase.failingHandle {
			return errors.New(testCase.failureText)
		}
		return nil
	}
	winHelloNCryptSetUint32PropertyFunc = func(handle ncryptHandle, property string, value uint32) error {
		if handle != testCase.createdKeyHandle {
			t.Fatalf("uint32 property handle = %d, want %d", handle, testCase.createdKeyHandle)
		}
		switch property {
		case winHelloNCryptLengthProperty:
			if value != uint32(winHelloPassportKeyBits) {
				t.Fatalf("length value = %d, want %d", value, uint32(winHelloPassportKeyBits))
			}
		case winHelloNCryptKeyUsageProperty:
			if value != uint32(winHelloNCryptAllowDecryptFlag|winHelloNCryptAllowSigningFlag) {
				t.Fatalf("key usage value = %d, want %d", value, uint32(winHelloNCryptAllowDecryptFlag|winHelloNCryptAllowSigningFlag))
			}
		case winHelloNCryptNgcCacheTypeProperty:
			if value != uint32(winHelloNCryptNgcCacheTypeAuthMandatory) {
				t.Fatalf("NGC cache value = %d, want %d", value, uint32(winHelloNCryptNgcCacheTypeAuthMandatory))
			}
		default:
			t.Fatalf("unexpected uint32 property %q", property)
		}
		return nil
	}
	winHelloNCryptSetStringPropertyFunc = func(handle ncryptHandle, property string, value string) error {
		if handle != testCase.createdKeyHandle {
			t.Fatalf("string property handle = %d, want %d", handle, testCase.createdKeyHandle)
		}
		if property != winHelloNCryptUseContextProperty {
			t.Fatalf("string property = %q, want %q", property, winHelloNCryptUseContextProperty)
		}
		if value != winHelloPassportCreateContext {
			t.Fatalf("use context = %q, want %q", value, winHelloPassportCreateContext)
		}
		return nil
	}
	winHelloNCryptFinalizeKeyFunc = func(key ncryptHandle, flags uint32) error {
		if key != testCase.createdKeyHandle || flags != 0 {
			t.Fatalf("finalize args = (%d, %d), want (%d, 0)", key, flags, testCase.createdKeyHandle)
		}
		return nil
	}

	passportKey, err := ensureWinHelloPassportKey(testCase.logicalName, testCase.hwnd)
	if err != nil {
		t.Fatalf("ensureWinHelloPassportKey() failed: %v", err)
	}
	defer func() {
		if err := passportKey.Close(); err != nil {
			t.Fatalf("Close() failed: %v", err)
		}
	}()

	if !containsPassportHandle(windowHandleAttempts, testCase.wantAttempt) {
		t.Fatalf("window handle attempts = %v, want attempt on %d", windowHandleAttempts, testCase.wantAttempt)
	}
}

func TestWinHelloPassportCreateAndReopen(t *testing.T) {
	requireWinHelloPassportIntegration(t)

	logicalName := newWinHelloPassportTestLogicalName("step7")
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
			t.Errorf("Close() failed: %v", err)
		}
	})
}

func TestWinHelloPassportCreateMissingKeyReturnsPassportKeyNotFound(t *testing.T) {
	requireWinHelloPassportIntegration(t)

	logicalName := newWinHelloPassportTestLogicalName("missing")
	passportKey, err := openWinHelloPassportKey(logicalName, 0)
	if !errors.Is(err, errWinHelloPassportKeyNotFound) {
		if passportKey != nil {
			_ = passportKey.Close()
		}
		t.Fatalf("error = %v, want %v", err, errWinHelloPassportKeyNotFound)
	}
	if errors.Is(err, ErrKeyNotFound) {
		t.Fatalf("error %v unexpectedly classified as ErrKeyNotFound", err)
	}
}

// Tests using these global NCrypt hooks must not run in parallel.
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
	oldParentHWND := winHelloParentHWNDFunc

	winHelloNCryptFreeObjectFunc = func(_ ncryptHandle) error {
		return nil
	}
	winHelloParentHWNDFunc = func() uintptr {
		return 0
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
		winHelloParentHWNDFunc = oldParentHWND
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

func newWinHelloPassportTestLogicalName(label string) string {
	return fmt.Sprintf("%s%s-%d", winHelloPassportTestLogicalNamePrefix, label, time.Now().UnixNano())
}

func requireWinHelloPassportTestLogicalName(t *testing.T, logicalName string) {
	t.Helper()
	if !strings.HasPrefix(logicalName, winHelloPassportTestLogicalNamePrefix) {
		t.Fatalf("refusing to use non-test Passport logical name %q; tests must use %q prefix", logicalName, winHelloPassportTestLogicalNamePrefix)
	}
}

func cleanupWinHelloPassportKey(t *testing.T, logicalName string) {
	t.Helper()
	requireWinHelloPassportTestLogicalName(t, logicalName)

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
