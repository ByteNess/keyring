//go:build windows
// +build windows

package keyring_test

import (
	"testing"

	"github.com/byteness/keyring"
)

func TestWinHelloBackendIsAvailableOnWindows(t *testing.T) {
	backends := keyring.AvailableBackends()

	wincredIndex := backendIndex(backends, keyring.WinCredBackend)
	if wincredIndex < 0 {
		t.Fatalf("AvailableBackends() = %v, missing %q", backends, keyring.WinCredBackend)
	}

	winhelloIndex := backendIndex(backends, keyring.WinHelloBackend)
	if winhelloIndex < 0 {
		t.Fatalf("AvailableBackends() = %v, missing %q", backends, keyring.WinHelloBackend)
	}

	if wincredIndex > winhelloIndex {
		t.Fatalf("AvailableBackends() = %v, want %q before %q", backends, keyring.WinCredBackend, keyring.WinHelloBackend)
	}
}

func TestWinHelloBackendOpen(t *testing.T) {
	kr, err := keyring.Open(keyring.Config{
		AllowedBackends: []keyring.BackendType{keyring.WinHelloBackend},
		ServiceName:     "winhello-register-test",
	})
	if err != nil {
		t.Fatalf("Open() failed: %v", err)
	}
	if kr == nil {
		t.Fatal("Open() returned nil keyring")
	}
}

func backendIndex(backends []keyring.BackendType, want keyring.BackendType) int {
	for i, backend := range backends {
		if backend == want {
			return i
		}
	}

	return -1
}
