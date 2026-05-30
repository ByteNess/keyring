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

func TestWinHelloNCryptErrorZeroIsNil(t *testing.T) {
	if err := winHelloNCryptError(0); err != nil {
		t.Fatalf("winHelloNCryptError(0) = %v, want nil", err)
	}
}

func TestWinHelloNCryptKeyNotFoundClassification(t *testing.T) {
	for _, status := range []uintptr{
		uintptr(errWinHelloNCryptBadKeyset),
		uintptr(errWinHelloNCryptNoKey),
		uintptr(errWinHelloNCryptNotFound),
	} {
		err := winHelloNCryptError(status)
		if !isWinHelloNCryptKeyNotFound(err) {
			t.Fatalf("status %#x not classified as not-found", status)
		}
	}
}

func TestWinHelloNCryptInvalidParameterClassification(t *testing.T) {
	for _, status := range []uintptr{
		uintptr(errWinHelloNCryptInvalidParameter),
		uintptr(errWinHelloWin32InvalidParameter),
	} {
		err := winHelloNCryptError(status)
		if !isWinHelloNCryptInvalidParameter(err) {
			t.Fatalf("status %#x not classified as invalid parameter", status)
		}
	}
}

func TestWinHelloNCryptUserCancelledClassification(t *testing.T) {
	err := winHelloNCryptError(uintptr(errWinHelloNCryptUserCancelled))
	if !isWinHelloNCryptUserCancelled(err) {
		t.Fatalf("status %#x not classified as user-cancelled", uintptr(errWinHelloNCryptUserCancelled))
	}
	if isWinHelloNCryptKeyNotFound(err) {
		t.Fatal("user-cancelled status classified as not-found")
	}
	if isWinHelloNCryptInvalidParameter(err) {
		t.Fatal("user-cancelled status classified as invalid parameter")
	}
}

func TestWinHelloNCryptSetupRequiredClassification(t *testing.T) {
	for _, status := range []uintptr{
		uintptr(errWinHelloNCryptBadKeyset),
		uintptr(errWinHelloNCryptNotSupported),
		uintptr(errWinHelloNCryptDeviceNotReady),
	} {
		err := winHelloNCryptError(status)
		if !isWinHelloNCryptSetupRequired(err) {
			t.Fatalf("status %#x not classified as setup-required", status)
		}
		if !strings.Contains(err.Error(), winHelloNCryptSetupHint) {
			t.Fatalf("status %#x missing setup hint: %v", status, err)
		}
	}
}

func TestWinHelloNCryptSetupHintNotAddedToOtherErrors(t *testing.T) {
	err := winHelloNCryptError(uintptr(errWinHelloNCryptUserCancelled))
	if strings.Contains(err.Error(), winHelloNCryptSetupHint) {
		t.Fatalf("unexpected setup hint on user-cancelled error: %v", err)
	}
}

func TestWinHelloNCryptClassificationsDoNotOverlap(t *testing.T) {
	notFoundErr := winHelloNCryptError(uintptr(errWinHelloNCryptNotFound))
	if isWinHelloNCryptInvalidParameter(notFoundErr) {
		t.Fatal("not-found status classified as invalid parameter")
	}

	invalidErr := winHelloNCryptError(uintptr(errWinHelloNCryptInvalidParameter))
	if isWinHelloNCryptKeyNotFound(invalidErr) {
		t.Fatal("invalid parameter status classified as not-found")
	}
}

func TestWinHelloNCryptFreeObjectZeroHandle(t *testing.T) {
	if err := winHelloNCryptFreeObject(0); err != nil {
		t.Fatalf("winHelloNCryptFreeObject(0) = %v, want nil", err)
	}
}

func TestWinHelloNCryptUnknownStatusPreserved(t *testing.T) {
	err := winHelloNCryptError(0xdeadbeef)
	if err == nil {
		t.Fatal("winHelloNCryptError() = nil, want non-nil")
	}
	if errors.Is(err, errWinHelloNCryptNotFound) {
		t.Fatal("unknown status should not classify as not-found")
	}
}

func TestWinHelloNCryptSoftwareKeyRoundTrip(t *testing.T) {
	provider, err := winHelloNCryptOpenStorageProvider(winHelloNCryptSoftwareProvider)
	if err != nil {
		t.Fatalf("open software provider failed: %v", err)
	}
	t.Cleanup(func() {
		if err := winHelloNCryptFreeObject(provider); err != nil {
			t.Fatalf("free software provider failed: %v", err)
		}
	})

	keyName := fmt.Sprintf("keyring-winhello-step5-%d", time.Now().UnixNano())
	key, err := winHelloNCryptCreatePersistedKey(provider, winHelloNCryptRSAAlgorithm, keyName, 0, 0)
	if err != nil {
		t.Fatalf("create persisted key failed: %v", err)
	}
	createdHandle := key
	t.Cleanup(func() {
		if createdHandle != 0 {
			if err := winHelloNCryptFreeObject(createdHandle); err != nil {
				t.Fatalf("free created key failed: %v", err)
			}
		}
	})

	if err := winHelloNCryptSetUint32Property(key, winHelloNCryptLengthProperty, 2048, 0); err != nil {
		t.Fatalf("set key length property failed: %v", err)
	}
	if err := winHelloNCryptSetUint32Property(key, winHelloNCryptKeyUsageProperty, winHelloNCryptAllowDecryptFlag|winHelloNCryptAllowSigningFlag, 0); err != nil {
		t.Fatalf("set key usage property failed: %v", err)
	}
	if err := winHelloNCryptFinalizeKey(key, 0); err != nil {
		t.Fatalf("finalize key failed: %v", err)
	}

	openedKey, err := winHelloNCryptOpenKey(provider, keyName, 0, 0)
	if err != nil {
		t.Fatalf("open key failed: %v", err)
	}
	openedHandle := openedKey
	t.Cleanup(func() {
		if openedHandle != 0 {
			if err := winHelloNCryptDeleteKey(openedHandle, 0); err != nil {
				t.Fatalf("delete key failed: %v", err)
			}
			openedHandle = 0
		}
	})

	plaintext := []byte("step5 software key roundtrip")
	ciphertext, err := winHelloNCryptEncrypt(key, plaintext, nil, winHelloNCryptPadPKCS1Flag)
	if err != nil {
		t.Fatalf("encrypt failed: %v", err)
	}

	decrypted, err := winHelloNCryptDecrypt(openedKey, ciphertext, nil, winHelloNCryptPadPKCS1Flag)
	if err != nil {
		t.Fatalf("decrypt failed: %v", err)
	}
	if string(decrypted) != string(plaintext) {
		t.Fatalf("plaintext mismatch: got %q want %q", decrypted, plaintext)
	}
}

func TestWinHelloNCryptOpenPassportProvider(t *testing.T) {
	requireWinHelloNCryptIntegration(t)

	provider, err := winHelloNCryptOpenStorageProvider(winHelloProviderPassportKSP)
	if err != nil {
		t.Fatalf("open Passport provider failed: %v", err)
	}
	t.Cleanup(func() {
		if err := winHelloNCryptFreeObject(provider); err != nil {
			t.Fatalf("free Passport provider failed: %v", err)
		}
	})
	if provider == 0 {
		t.Fatal("provider handle = 0, want non-zero")
	}
}

func requireWinHelloNCryptIntegration(t *testing.T) {
	t.Helper()
	if os.Getenv("KEYRING_WINHELLO_TEST") != "1" {
		t.Skip("set KEYRING_WINHELLO_TEST=1 to run WinHello NCrypt integration tests")
	}
}
