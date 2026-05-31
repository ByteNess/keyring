//go:build windows
// +build windows

package winhello

import (
	"bytes"
	"encoding/base64"
	"errors"
	"os"
	"os/exec"
	"strings"
	"testing"
	"unsafe"
)

const (
	winHelloSilentUnwrapChildEnv   = "KEYRING_WINHELLO_SILENT_UNWRAP_CHILD"
	winHelloSilentUnwrapLogicalEnv = "KEYRING_WINHELLO_SILENT_UNWRAP_LOGICAL_NAME"
	winHelloSilentUnwrapWrappedEnv = "KEYRING_WINHELLO_SILENT_UNWRAP_WRAPPED_CEK"
)

func TestWinHelloWrapKeyUsesPKCS1(t *testing.T) {
	restore := stubWinHelloWrapNCryptHooks(t)
	defer restore()

	var operations []string
	cek := newWinHelloWrapTestCEK()

	winHelloNCryptOpenStorageProviderFunc = func(providerName string) (ncryptHandle, error) {
		if providerName != winHelloProviderPassportKSP {
			t.Fatalf("provider = %q, want %q", providerName, winHelloProviderPassportKSP)
		}
		operations = append(operations, "open-provider")
		return ncryptHandle(201), nil
	}
	winHelloNCryptSetHandlePropertyFunc = func(handle ncryptHandle, property string, value uintptr) error {
		if property != winHelloNCryptWindowHandleProperty {
			t.Fatalf("property = %q, want %q", property, winHelloNCryptWindowHandleProperty)
		}
		if value != uintptr(123) {
			t.Fatalf("value = %d, want %d", value, uintptr(123))
		}
		switch handle {
		case ncryptHandle(201):
			operations = append(operations, "set-provider-hwnd")
		case ncryptHandle(202):
			operations = append(operations, "set-key-hwnd")
		default:
			t.Fatalf("window handle target = %d, want provider or key", handle)
		}
		return nil
	}
	winHelloNCryptOpenKeyFunc = func(provider ncryptHandle, keyName string, legacyKeySpec uint32, flags uint32) (ncryptHandle, error) {
		if provider != ncryptHandle(201) {
			t.Fatalf("provider handle = %d, want %d", provider, ncryptHandle(201))
		}
		if keyName != "passport-key-name" {
			t.Fatalf("key name = %q, want %q", keyName, "passport-key-name")
		}
		if legacyKeySpec != 0 || flags != 0 {
			t.Fatalf("open args = (%d, %d), want (0, 0)", legacyKeySpec, flags)
		}
		operations = append(operations, "open-key")
		return ncryptHandle(202), nil
	}
	winHelloNCryptEncryptFunc = func(handle ncryptHandle, plaintext []byte, paddingInfo unsafe.Pointer, flags uint32) ([]byte, error) {
		if handle != ncryptHandle(202) {
			t.Fatalf("encrypt handle = %d, want %d", handle, ncryptHandle(202))
		}
		if paddingInfo != nil {
			t.Fatalf("padding info = %v, want nil", paddingInfo)
		}
		if flags != winHelloNCryptPadPKCS1Flag {
			t.Fatalf("flags = %#x, want %#x", flags, winHelloNCryptPadPKCS1Flag)
		}
		if !bytes.Equal(plaintext, cek) {
			t.Fatalf("plaintext = %x, want %x", plaintext, cek)
		}
		operations = append(operations, "encrypt")
		return []byte("wrapped-cek"), nil
	}
	winHelloNCryptFreeObjectFunc = func(handle ncryptHandle) error {
		switch handle {
		case ncryptHandle(202):
			operations = append(operations, "free-key")
		case ncryptHandle(201):
			operations = append(operations, "free-provider")
		default:
			t.Fatalf("free handle = %d, want opened key or provider", handle)
		}
		return nil
	}

	passportKey := &winHelloPassportKey{keyName: "passport-key-name", hwnd: 123}
	wrapped, err := passportKey.WrapKey(cek)
	if err != nil {
		t.Fatalf("WrapKey() failed: %v", err)
	}
	if !bytes.Equal(wrapped, []byte("wrapped-cek")) {
		t.Fatalf("wrapped = %q, want %q", wrapped, []byte("wrapped-cek"))
	}

	wantOperations := []string{"open-provider", "set-provider-hwnd", "open-key", "set-key-hwnd", "encrypt", "free-key", "free-provider"}
	if !equalStringSlices(operations, wantOperations) {
		t.Fatalf("operations = %v, want %v", operations, wantOperations)
	}
}

func TestWinHelloWrapKeyRejectsInvalidCEKSize(t *testing.T) {
	restore := stubWinHelloWrapNCryptHooks(t)
	defer restore()

	winHelloNCryptOpenStorageProviderFunc = func(_ string) (ncryptHandle, error) {
		t.Fatal("WrapKey should reject invalid CEK size before opening the provider")
		return 0, errors.New("unexpected provider open")
	}

	for _, testCase := range []struct {
		name string
		size int
	}{
		{name: "31-bytes", size: winHelloCEKSize - 1},
		{name: "33-bytes", size: winHelloCEKSize + 1},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			passportKey := &winHelloPassportKey{keyName: "passport-key-name"}
			_, err := passportKey.WrapKey(bytes.Repeat([]byte{0x7a}, testCase.size))
			if !errors.Is(err, errWinHelloInvalidCEKSize) {
				t.Fatalf("error = %v, want %v", err, errWinHelloInvalidCEKSize)
			}
			if !strings.Contains(err.Error(), "got ") {
				t.Fatalf("error = %v, want size detail", err)
			}
		})
	}
}

func TestWinHelloWrapUnwrapKeyPreparesPromptAndUsesPKCS1(t *testing.T) {
	restore := stubWinHelloWrapNCryptHooks(t)
	defer restore()

	var operations []string
	cek := newWinHelloWrapTestCEK()

	winHelloNCryptOpenStorageProviderFunc = func(_ string) (ncryptHandle, error) {
		operations = append(operations, "open-provider")
		return ncryptHandle(301), nil
	}
	winHelloNCryptOpenKeyFunc = func(provider ncryptHandle, keyName string, legacyKeySpec uint32, flags uint32) (ncryptHandle, error) {
		if provider != ncryptHandle(301) || keyName != "passport-key-name" || legacyKeySpec != 0 || flags != 0 {
			t.Fatalf("unexpected open args: provider=%d key=%q legacy=%d flags=%d", provider, keyName, legacyKeySpec, flags)
		}
		operations = append(operations, "open-key")
		return ncryptHandle(302), nil
	}
	winHelloNCryptSetHandlePropertyFunc = func(handle ncryptHandle, property string, value uintptr) error {
		if property != winHelloNCryptWindowHandleProperty {
			t.Fatalf("property = %q, want %q", property, winHelloNCryptWindowHandleProperty)
		}
		if value != uintptr(123) {
			t.Fatalf("value = %d, want %d", value, uintptr(123))
		}
		switch handle {
		case ncryptHandle(301):
			operations = append(operations, "set-provider-hwnd")
		case ncryptHandle(302):
			operations = append(operations, "set-key-hwnd")
		default:
			t.Fatalf("window handle target = %d, want provider or key", handle)
		}
		return nil
	}
	winHelloNCryptSetStringPropertyFunc = func(handle ncryptHandle, property string, value string) error {
		if handle != ncryptHandle(302) {
			t.Fatalf("string property handle = %d, want %d", handle, ncryptHandle(302))
		}
		if property != winHelloNCryptUseContextProperty {
			t.Fatalf("property = %q, want %q", property, winHelloNCryptUseContextProperty)
		}
		if value != "Unlock this test CEK" {
			t.Fatalf("value = %q, want %q", value, "Unlock this test CEK")
		}
		operations = append(operations, "set-use-context")
		return nil
	}
	winHelloNCryptSetUint32PropertyFunc = func(handle ncryptHandle, property string, value uint32) error {
		if handle != ncryptHandle(302) {
			t.Fatalf("uint32 property handle = %d, want %d", handle, ncryptHandle(302))
		}
		if property != winHelloNCryptPinCacheIsGestureRequiredProperty {
			t.Fatalf("property = %q, want %q", property, winHelloNCryptPinCacheIsGestureRequiredProperty)
		}
		if value != 1 {
			t.Fatalf("value = %d, want %d", value, 1)
		}
		operations = append(operations, "set-pin-cache")
		return nil
	}
	winHelloNCryptDecryptFunc = func(handle ncryptHandle, ciphertext []byte, paddingInfo unsafe.Pointer, flags uint32) ([]byte, error) {
		if handle != ncryptHandle(302) {
			t.Fatalf("decrypt handle = %d, want %d", handle, ncryptHandle(302))
		}
		if !bytes.Equal(ciphertext, []byte("wrapped-cek")) {
			t.Fatalf("ciphertext = %q, want %q", ciphertext, []byte("wrapped-cek"))
		}
		if paddingInfo != nil {
			t.Fatalf("padding info = %v, want nil", paddingInfo)
		}
		if flags != winHelloNCryptPadPKCS1Flag {
			t.Fatalf("flags = %#x, want %#x", flags, winHelloNCryptPadPKCS1Flag)
		}
		operations = append(operations, "decrypt")
		return cek, nil
	}
	winHelloNCryptFreeObjectFunc = func(handle ncryptHandle) error {
		switch handle {
		case ncryptHandle(302):
			operations = append(operations, "free-key")
		case ncryptHandle(301):
			operations = append(operations, "free-provider")
		default:
			t.Fatalf("free handle = %d, want opened key or provider", handle)
		}
		return nil
	}

	passportKey := &winHelloPassportKey{keyName: "passport-key-name", hwnd: 123}
	cek, err := passportKey.UnwrapKey([]byte("wrapped-cek"), "Unlock this test CEK")
	if err != nil {
		t.Fatalf("UnwrapKey() failed: %v", err)
	}
	if !bytes.Equal(cek, newWinHelloWrapTestCEK()) {
		t.Fatalf("cek = %x, want %x", cek, newWinHelloWrapTestCEK())
	}

	wantOperations := []string{"open-provider", "set-provider-hwnd", "open-key", "set-key-hwnd", "set-use-context", "set-pin-cache", "decrypt", "free-key", "free-provider"}
	if !equalStringSlices(operations, wantOperations) {
		t.Fatalf("operations = %v, want %v", operations, wantOperations)
	}
}

func TestWinHelloWrapUnwrapKeyUsesDefaultContext(t *testing.T) {
	restore := stubWinHelloWrapNCryptHooks(t)
	defer restore()

	cek := newWinHelloWrapTestCEK()

	winHelloNCryptOpenStorageProviderFunc = func(_ string) (ncryptHandle, error) {
		return ncryptHandle(351), nil
	}
	winHelloNCryptOpenKeyFunc = func(_ ncryptHandle, _ string, _ uint32, _ uint32) (ncryptHandle, error) {
		return ncryptHandle(352), nil
	}
	winHelloNCryptSetStringPropertyFunc = func(handle ncryptHandle, property string, value string) error {
		if handle != ncryptHandle(352) || property != winHelloNCryptUseContextProperty {
			t.Fatalf("unexpected string property call: handle=%d property=%q", handle, property)
		}
		if value != winHelloPassportDefaultUnwrapContext {
			t.Fatalf("value = %q, want %q", value, winHelloPassportDefaultUnwrapContext)
		}
		return nil
	}
	winHelloNCryptSetUint32PropertyFunc = func(handle ncryptHandle, property string, value uint32) error {
		if handle != ncryptHandle(352) || property != winHelloNCryptPinCacheIsGestureRequiredProperty || value != 1 {
			t.Fatalf("unexpected uint32 property call: handle=%d property=%q value=%d", handle, property, value)
		}
		return nil
	}
	winHelloNCryptDecryptFunc = func(handle ncryptHandle, ciphertext []byte, paddingInfo unsafe.Pointer, flags uint32) ([]byte, error) {
		if handle != ncryptHandle(352) || !bytes.Equal(ciphertext, []byte("wrapped-cek")) || paddingInfo != nil || flags != winHelloNCryptPadPKCS1Flag {
			t.Fatalf("unexpected decrypt call: handle=%d ciphertext=%x padding=%v flags=%#x", handle, ciphertext, paddingInfo, flags)
		}
		return cek, nil
	}
	winHelloNCryptFreeObjectFunc = func(_ ncryptHandle) error {
		return nil
	}

	passportKey := &winHelloPassportKey{keyName: "passport-key-name"}
	unwrapped, err := passportKey.UnwrapKey([]byte("wrapped-cek"), "")
	if err != nil {
		t.Fatalf("UnwrapKey() failed: %v", err)
	}
	if !bytes.Equal(unwrapped, cek) {
		t.Fatalf("cek = %x, want %x", unwrapped, cek)
	}
}

func TestWinHelloWrapUnwrapKeyIgnoresWindowHandleError(t *testing.T) {
	restore := stubWinHelloWrapNCryptHooks(t)
	defer restore()

	var operations []string
	cek := newWinHelloWrapTestCEK()

	winHelloNCryptOpenStorageProviderFunc = func(_ string) (ncryptHandle, error) {
		return ncryptHandle(401), nil
	}
	winHelloNCryptOpenKeyFunc = func(_ ncryptHandle, _ string, _ uint32, _ uint32) (ncryptHandle, error) {
		return ncryptHandle(402), nil
	}
	winHelloNCryptSetHandlePropertyFunc = func(handle ncryptHandle, property string, value uintptr) error {
		if property != winHelloNCryptWindowHandleProperty || value != uintptr(77) {
			t.Fatalf("unexpected window handle property call: property=%q value=%d", property, value)
		}
		if handle == ncryptHandle(402) {
			operations = append(operations, "set-key-hwnd")
			return errors.New("key window handle rejected")
		}
		operations = append(operations, "set-provider-hwnd")
		return nil
	}
	winHelloNCryptSetStringPropertyFunc = func(handle ncryptHandle, property string, value string) error {
		if handle != ncryptHandle(402) || property != winHelloNCryptUseContextProperty || value != "Prompt text" {
			t.Fatalf("unexpected string property call: handle=%d property=%q value=%q", handle, property, value)
		}
		operations = append(operations, "set-use-context")
		return nil
	}
	winHelloNCryptSetUint32PropertyFunc = func(handle ncryptHandle, property string, value uint32) error {
		if handle != ncryptHandle(402) || property != winHelloNCryptPinCacheIsGestureRequiredProperty || value != 1 {
			t.Fatalf("unexpected uint32 property call: handle=%d property=%q value=%d", handle, property, value)
		}
		operations = append(operations, "set-pin-cache")
		return nil
	}
	winHelloNCryptDecryptFunc = func(handle ncryptHandle, _ []byte, paddingInfo unsafe.Pointer, flags uint32) ([]byte, error) {
		if handle != ncryptHandle(402) || paddingInfo != nil || flags != winHelloNCryptPadPKCS1Flag {
			t.Fatalf("unexpected decrypt call: handle=%d padding=%v flags=%#x", handle, paddingInfo, flags)
		}
		operations = append(operations, "decrypt")
		return cek, nil
	}
	winHelloNCryptFreeObjectFunc = func(_ ncryptHandle) error {
		return nil
	}

	passportKey := &winHelloPassportKey{keyName: "passport-key-name", hwnd: 77}
	cek, err := passportKey.UnwrapKey([]byte("wrapped-cek"), "Prompt text")
	if err != nil {
		t.Fatalf("UnwrapKey() failed: %v", err)
	}
	if !bytes.Equal(cek, newWinHelloWrapTestCEK()) {
		t.Fatalf("cek = %x, want %x", cek, newWinHelloWrapTestCEK())
	}

	wantOperations := []string{"set-provider-hwnd", "set-key-hwnd", "set-use-context", "set-pin-cache", "decrypt"}
	if !equalStringSlices(operations, wantOperations) {
		t.Fatalf("operations = %v, want %v", operations, wantOperations)
	}
}

func TestWinHelloWrapUnwrapKeyRejectsInvalidCEKSize(t *testing.T) {
	restore := stubWinHelloWrapNCryptHooks(t)
	defer restore()

	for _, testCase := range []struct {
		name string
		size int
	}{
		{name: "31-bytes", size: winHelloCEKSize - 1},
		{name: "33-bytes", size: winHelloCEKSize + 1},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			winHelloNCryptOpenStorageProviderFunc = func(_ string) (ncryptHandle, error) {
				return ncryptHandle(451), nil
			}
			winHelloNCryptOpenKeyFunc = func(_ ncryptHandle, _ string, _ uint32, _ uint32) (ncryptHandle, error) {
				return ncryptHandle(452), nil
			}
			winHelloNCryptSetStringPropertyFunc = func(_ ncryptHandle, _ string, _ string) error {
				return nil
			}
			winHelloNCryptSetUint32PropertyFunc = func(_ ncryptHandle, _ string, _ uint32) error {
				return nil
			}
			winHelloNCryptDecryptFunc = func(_ ncryptHandle, _ []byte, _ unsafe.Pointer, _ uint32) ([]byte, error) {
				return bytes.Repeat([]byte{0x2b}, testCase.size), nil
			}
			winHelloNCryptFreeObjectFunc = func(_ ncryptHandle) error {
				return nil
			}

			passportKey := &winHelloPassportKey{keyName: "passport-key-name"}
			_, err := passportKey.UnwrapKey([]byte("wrapped-cek"), "Prompt text")
			if !errors.Is(err, errWinHelloInvalidCEKSize) {
				t.Fatalf("error = %v, want %v", err, errWinHelloInvalidCEKSize)
			}
			if !strings.Contains(err.Error(), "after unwrap") {
				t.Fatalf("error = %v, want after unwrap context", err)
			}
		})
	}
}

func TestWinHelloWrapUnwrapKeyPropagatesUseContextError(t *testing.T) {
	restore := stubWinHelloWrapNCryptHooks(t)
	defer restore()

	decryptCalled := false

	winHelloNCryptOpenStorageProviderFunc = func(_ string) (ncryptHandle, error) {
		return ncryptHandle(501), nil
	}
	winHelloNCryptOpenKeyFunc = func(_ ncryptHandle, _ string, _ uint32, _ uint32) (ncryptHandle, error) {
		return ncryptHandle(502), nil
	}
	winHelloNCryptSetHandlePropertyFunc = func(_ ncryptHandle, _ string, _ uintptr) error {
		return nil
	}
	winHelloNCryptSetStringPropertyFunc = func(handle ncryptHandle, property string, value string) error {
		if handle != ncryptHandle(502) || property != winHelloNCryptUseContextProperty || value != "Prompt text" {
			t.Fatalf("unexpected string property call: handle=%d property=%q value=%q", handle, property, value)
		}
		return errors.New("use context rejected")
	}
	winHelloNCryptSetUint32PropertyFunc = func(_ ncryptHandle, _ string, _ uint32) error {
		t.Fatal("PinCacheIsGestureRequired should not be set after use-context failure")
		return nil
	}
	winHelloNCryptDecryptFunc = func(_ ncryptHandle, _ []byte, _ unsafe.Pointer, _ uint32) ([]byte, error) {
		decryptCalled = true
		return nil, nil
	}
	winHelloNCryptFreeObjectFunc = func(_ ncryptHandle) error {
		return nil
	}

	passportKey := &winHelloPassportKey{keyName: "passport-key-name", hwnd: 77}
	_, err := passportKey.UnwrapKey([]byte("wrapped-cek"), "Prompt text")
	if err == nil {
		t.Fatal("UnwrapKey() error = nil, want non-nil")
	}
	if decryptCalled {
		t.Fatal("decrypt was called after use-context failure")
	}
	if !strings.Contains(err.Error(), "prepare Passport key") || !strings.Contains(err.Error(), "use context rejected") {
		t.Fatalf("error = %v, want prepare Passport key context plus use-context failure", err)
	}
}

func TestWinHelloWrapKeyPropagatesEncryptErrorAndFreesHandles(t *testing.T) {
	restore := stubWinHelloWrapNCryptHooks(t)
	defer restore()

	wantErr := errors.New("encrypt rejected")
	var freed []ncryptHandle

	winHelloNCryptOpenStorageProviderFunc = func(_ string) (ncryptHandle, error) {
		return ncryptHandle(601), nil
	}
	winHelloNCryptOpenKeyFunc = func(_ ncryptHandle, _ string, _ uint32, _ uint32) (ncryptHandle, error) {
		return ncryptHandle(602), nil
	}
	winHelloNCryptSetHandlePropertyFunc = func(_ ncryptHandle, _ string, _ uintptr) error {
		return nil
	}
	winHelloNCryptEncryptFunc = func(_ ncryptHandle, _ []byte, _ unsafe.Pointer, _ uint32) ([]byte, error) {
		return nil, wantErr
	}
	winHelloNCryptFreeObjectFunc = func(handle ncryptHandle) error {
		freed = append(freed, handle)
		return nil
	}

	passportKey := &winHelloPassportKey{keyName: "passport-key-name", hwnd: 1}
	_, err := passportKey.WrapKey(newWinHelloWrapTestCEK())
	if !errors.Is(err, wantErr) {
		t.Fatalf("error = %v, want %v", err, wantErr)
	}
	if !strings.Contains(err.Error(), "wrap CEK with Passport key") {
		t.Fatalf("error = %v, want wrap CEK context", err)
	}
	if !equalHandleSlices(freed, []ncryptHandle{ncryptHandle(602), ncryptHandle(601)}) {
		t.Fatalf("freed handles = %v, want %v", freed, []ncryptHandle{ncryptHandle(602), ncryptHandle(601)})
	}
}

func TestWinHelloWrapUnwrapKeyPropagatesDecryptErrorAndFreesHandles(t *testing.T) {
	restore := stubWinHelloWrapNCryptHooks(t)
	defer restore()

	wantErr := errors.New("decrypt rejected")
	var freed []ncryptHandle

	winHelloNCryptOpenStorageProviderFunc = func(_ string) (ncryptHandle, error) {
		return ncryptHandle(701), nil
	}
	winHelloNCryptOpenKeyFunc = func(_ ncryptHandle, _ string, _ uint32, _ uint32) (ncryptHandle, error) {
		return ncryptHandle(702), nil
	}
	winHelloNCryptSetHandlePropertyFunc = func(_ ncryptHandle, _ string, _ uintptr) error {
		return nil
	}
	winHelloNCryptSetStringPropertyFunc = func(_ ncryptHandle, _ string, _ string) error {
		return nil
	}
	winHelloNCryptSetUint32PropertyFunc = func(_ ncryptHandle, _ string, _ uint32) error {
		return nil
	}
	winHelloNCryptDecryptFunc = func(_ ncryptHandle, _ []byte, _ unsafe.Pointer, _ uint32) ([]byte, error) {
		return nil, wantErr
	}
	winHelloNCryptFreeObjectFunc = func(handle ncryptHandle) error {
		freed = append(freed, handle)
		return nil
	}

	passportKey := &winHelloPassportKey{keyName: "passport-key-name", hwnd: 1}
	_, err := passportKey.UnwrapKey([]byte("wrapped-cek"), "Prompt text")
	if !errors.Is(err, wantErr) {
		t.Fatalf("error = %v, want %v", err, wantErr)
	}
	if !strings.Contains(err.Error(), "unwrap CEK with Passport key") {
		t.Fatalf("error = %v, want unwrap CEK context", err)
	}
	if !equalHandleSlices(freed, []ncryptHandle{ncryptHandle(702), ncryptHandle(701)}) {
		t.Fatalf("freed handles = %v, want %v", freed, []ncryptHandle{ncryptHandle(702), ncryptHandle(701)})
	}
}

func TestWinHelloWithOperationKeyPropagatesOpenProviderError(t *testing.T) {
	restore := stubWinHelloWrapNCryptHooks(t)
	defer restore()

	wantErr := errors.New("provider open rejected")
	runCalled := false

	winHelloNCryptOpenStorageProviderFunc = func(_ string) (ncryptHandle, error) {
		return 0, wantErr
	}

	passportKey := &winHelloPassportKey{keyName: "passport-key-name"}
	err := passportKey.withOperationKey(func(_ ncryptHandle) error {
		runCalled = true
		return nil
	})
	if !errors.Is(err, wantErr) {
		t.Fatalf("error = %v, want %v", err, wantErr)
	}
	if runCalled {
		t.Fatal("run callback was called after provider open failure")
	}
	if !strings.Contains(err.Error(), "open Passport provider") {
		t.Fatalf("error = %v, want provider-open context", err)
	}
}

func TestWinHelloWithOperationKeyPropagatesOpenKeyError(t *testing.T) {
	restore := stubWinHelloWrapNCryptHooks(t)
	defer restore()

	wantErr := errors.New("key open rejected")
	var freed []ncryptHandle

	winHelloNCryptOpenStorageProviderFunc = func(_ string) (ncryptHandle, error) {
		return ncryptHandle(801), nil
	}
	winHelloNCryptOpenKeyFunc = func(_ ncryptHandle, _ string, _ uint32, _ uint32) (ncryptHandle, error) {
		return 0, wantErr
	}
	winHelloNCryptFreeObjectFunc = func(handle ncryptHandle) error {
		freed = append(freed, handle)
		return nil
	}

	passportKey := &winHelloPassportKey{keyName: "passport-key-name"}
	err := passportKey.withOperationKey(func(_ ncryptHandle) error {
		t.Fatal("run callback should not be called after key open failure")
		return nil
	})
	if !errors.Is(err, wantErr) {
		t.Fatalf("error = %v, want %v", err, wantErr)
	}
	if !strings.Contains(err.Error(), "open Passport key") {
		t.Fatalf("error = %v, want key-open context", err)
	}
	if !equalHandleSlices(freed, []ncryptHandle{ncryptHandle(801)}) {
		t.Fatalf("freed handles = %v, want %v", freed, []ncryptHandle{ncryptHandle(801)})
	}
}

func TestWinHelloWithOperationKeyMapsMissingPassportKey(t *testing.T) {
	restore := stubWinHelloWrapNCryptHooks(t)
	defer restore()

	var freed []ncryptHandle

	winHelloNCryptOpenStorageProviderFunc = func(_ string) (ncryptHandle, error) {
		return ncryptHandle(811), nil
	}
	winHelloNCryptOpenKeyFunc = func(_ ncryptHandle, _ string, _ uint32, _ uint32) (ncryptHandle, error) {
		return 0, errWinHelloNCryptNotFound
	}
	winHelloNCryptFreeObjectFunc = func(handle ncryptHandle) error {
		freed = append(freed, handle)
		return nil
	}

	passportKey := &winHelloPassportKey{keyName: "passport-key-name"}
	err := passportKey.withOperationKey(func(_ ncryptHandle) error {
		t.Fatal("run callback should not be called when Passport key is missing")
		return nil
	})
	if !errors.Is(err, errWinHelloPassportKeyNotFound) {
		t.Fatalf("error = %v, want %v", err, errWinHelloPassportKeyNotFound)
	}
	if errors.Is(err, ErrKeyNotFound) {
		t.Fatalf("error %v unexpectedly classified as ErrKeyNotFound", err)
	}
	if !equalHandleSlices(freed, []ncryptHandle{ncryptHandle(811)}) {
		t.Fatalf("freed handles = %v, want %v", freed, []ncryptHandle{ncryptHandle(811)})
	}
}

func TestWinHelloWrapRoundTrip(t *testing.T) {
	requireWinHelloPassportIntegration(t)

	logicalName := newWinHelloPassportTestLogicalName("wrap")
	t.Cleanup(func() {
		cleanupWinHelloPassportKey(t, logicalName)
	})

	passportKey, err := ensureWinHelloPassportKey(logicalName, 0)
	if err != nil {
		t.Fatalf("ensureWinHelloPassportKey() failed: %v", err)
	}
	t.Cleanup(func() {
		if err := passportKey.Close(); err != nil {
			t.Errorf("Close() failed: %v", err)
		}
	})

	cek := []byte{
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
		0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
		0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
	}

	wrapped, err := passportKey.WrapKey(cek)
	if err != nil {
		t.Fatalf("WrapKey() failed: %v", err)
	}
	if len(wrapped) == 0 {
		t.Fatal("wrapped CEK = empty, want ciphertext")
	}

	unwrapped, err := passportKey.UnwrapKey(wrapped, "Unlock keyring CEK wrapping test key")
	if err != nil {
		t.Fatalf("UnwrapKey() failed: %v", err)
	}
	if !bytes.Equal(unwrapped, cek) {
		t.Fatalf("unwrapped CEK mismatch: got %x want %x", unwrapped, cek)
	}
}

// This is validating our security guarantee that a silent unwrap attempt (e.g. by malware) fails rather than unexpectedly succeeding!
func TestWinHelloSilentUnwrapFails(t *testing.T) {
	requireWinHelloPassportIntegration(t)

	if os.Getenv(winHelloSilentUnwrapChildEnv) == "1" {
		runWinHelloSilentUnwrapChild(t)
		return
	}

	logicalName := newWinHelloPassportTestLogicalName("silent")
	t.Cleanup(func() {
		cleanupWinHelloPassportKey(t, logicalName)
	})

	passportKey, err := ensureWinHelloPassportKey(logicalName, 0)
	if err != nil {
		t.Fatalf("ensureWinHelloPassportKey() failed: %v", err)
	}
	t.Cleanup(func() {
		if err := passportKey.Close(); err != nil {
			t.Errorf("Close() failed: %v", err)
		}
	})

	wrapped, err := passportKey.WrapKey(newWinHelloWrapTestCEK())
	if err != nil {
		t.Fatalf("WrapKey() failed: %v", err)
	}

	cmd := exec.Command(os.Args[0], "-test.run=^TestWinHelloSilentUnwrapFails$", "-test.v")
	cmd.Env = append(
		os.Environ(),
		winHelloSilentUnwrapChildEnv+"=1",
		winHelloSilentUnwrapLogicalEnv+"="+logicalName,
		winHelloSilentUnwrapWrappedEnv+"="+base64.StdEncoding.EncodeToString(wrapped),
	)

	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("silent unwrap child failed: %v\n%s", err, output)
	}
}

func runWinHelloSilentUnwrapChild(t *testing.T) {
	t.Helper()

	logicalName := os.Getenv(winHelloSilentUnwrapLogicalEnv)
	if logicalName == "" {
		t.Fatal("silent unwrap child missing logical name")
	}
	wrappedBase64 := os.Getenv(winHelloSilentUnwrapWrappedEnv)
	if wrappedBase64 == "" {
		t.Fatal("silent unwrap child missing wrapped CEK")
	}

	wrapped, err := base64.StdEncoding.DecodeString(wrappedBase64)
	if err != nil {
		t.Fatalf("decode wrapped CEK: %v", err)
	}

	passportKey, err := openWinHelloPassportKey(logicalName, 0)
	if err != nil {
		t.Fatalf("openWinHelloPassportKey() failed: %v", err)
	}
	t.Cleanup(func() {
		if err := passportKey.Close(); err != nil {
			t.Errorf("Close() failed: %v", err)
		}
	})

	_, err = passportKey.unwrapKeyWithFlags(wrapped, "Silent unwrap regression test", winHelloNCryptSilentFlag)
	if err == nil {
		t.Fatal("silent unwrap unexpectedly succeeded")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "silent") {
		t.Fatalf("silent unwrap error = %v, want silent-context failure", err)
	}
}

func stubWinHelloWrapNCryptHooks(t *testing.T) func() {
	t.Helper()

	restorePassport := stubWinHelloPassportNCryptHooks(t)
	oldEncrypt := winHelloNCryptEncryptFunc
	oldDecrypt := winHelloNCryptDecryptFunc

	return func() {
		winHelloNCryptEncryptFunc = oldEncrypt
		winHelloNCryptDecryptFunc = oldDecrypt
		restorePassport()
	}
}

func equalStringSlices(got []string, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range got {
		if got[i] != want[i] {
			return false
		}
	}

	return true
}

func equalHandleSlices(got []ncryptHandle, want []ncryptHandle) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range got {
		if got[i] != want[i] {
			return false
		}
	}

	return true
}

func newWinHelloWrapTestCEK() []byte {
	return []byte{
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
		0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
		0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
	}
}
