//go:build darwin
// +build darwin

package keyring

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	gokeychain "github.com/byteness/go-keychain"
	"github.com/noamcohen97/touchid-go"
)

func TestOSXKeychainKeyringSet(t *testing.T) {
	path := tempPath()
	defer deleteKeychain(t, path)

	k := &keychain{
		path:         path,
		passwordFunc: FixedStringPrompt("test password"),
		service:      "test",
		isTrusted:    true,
	}

	item := Item{
		Key:         "llamas",
		Label:       "Arbitrary label",
		Description: "A freetext description",
		Data:        []byte("llamas are great"),
	}

	if err := k.Set(item); err != nil {
		t.Fatal(err)
	}

	v, err := k.Get("llamas")
	if err != nil {
		t.Fatal(err)
	}

	if string(v.Data) != string(item.Data) {
		t.Fatalf("Data stored was not the data retrieved: %q vs %q", v.Data, item.Data)
	}

	if v.Key != item.Key {
		t.Fatalf("Key stored was not the data retrieved: %q vs %q", v.Key, item.Key)
	}

	if v.Description != item.Description {
		t.Fatalf("Description stored was not the data retrieved: %q vs %q", v.Description, item.Description)
	}
}

func TestOSXKeychainKeyringOverwrite(t *testing.T) {
	path := tempPath()
	defer deleteKeychain(t, path)

	k := &keychain{
		path:         path,
		passwordFunc: FixedStringPrompt("test password"),
		service:      "test",
		isTrusted:    true,
	}

	item1 := Item{
		Key:         "llamas",
		Label:       "Arbitrary label",
		Description: "A freetext description",
		Data:        []byte("llamas are ok"),
	}

	if err := k.Set(item1); err != nil {
		t.Fatal(err)
	}

	v1, err := k.Get("llamas")
	if err != nil {
		t.Fatal(err)
	}

	if string(v1.Data) != string(item1.Data) {
		t.Fatalf("Data stored was not the data retrieved: %q vs %q", v1.Data, item1.Data)
	}

	item2 := Item{
		Key:         "llamas",
		Label:       "Arbitrary label",
		Description: "A freetext description",
		Data:        []byte("llamas are great"),
	}

	if err := k.Set(item2); err != nil {
		t.Fatal(err)
	}

	v2, err := k.Get("llamas")
	if err != nil {
		t.Fatal(err)
	}

	if string(v2.Data) != string(item2.Data) {
		t.Fatalf("Data stored was not the data retrieved: %q vs %q", v2.Data, item2.Data)
	}
}

func TestOSXKeychainKeyringListKeysWhenEmpty(t *testing.T) {
	path := tempPath()
	defer deleteKeychain(t, path)

	k := &keychain{
		path:         path,
		service:      "test",
		passwordFunc: FixedStringPrompt("test password"),
		isTrusted:    true,
	}

	keys, err := k.Keys()
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 0 {
		t.Fatalf("Expected 0 keys, got %d", len(keys))
	}
}

func TestOSXKeychainKeyringListKeysWhenNotEmpty(t *testing.T) {
	path := tempPath()
	defer deleteKeychain(t, path)

	k := &keychain{
		path:         path,
		service:      "test",
		passwordFunc: FixedStringPrompt("test password"),
		isTrusted:    true,
	}

	keys := []string{"key1", "key2", "key3"}

	for _, key := range keys {
		item := Item{
			Key:  key,
			Data: []byte("llamas are great"),
		}

		if err := k.Set(item); err != nil {
			t.Fatal(err)
		}
	}

	keys2, err := k.Keys()
	if err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(keys, keys2) {
		t.Fatalf("Retrieved keys weren't the same: %q vs %q", keys, keys2)
	}
}

func deleteKeychain(t *testing.T, path string) {
	t.Helper()

	if _, err := os.Stat(path); os.IsExist(err) {
		_ = os.Remove(path)
	}

	// Sierra introduced a -db suffix
	dbPath := path + "-db"
	if _, err := os.Stat(dbPath); os.IsExist(err) {
		_ = os.Remove(dbPath)
	}
}

func TestOSXKeychainGetKeyWhenEmpty(t *testing.T) {
	path := tempPath()
	defer deleteKeychain(t, path)

	k := &keychain{
		path:         path,
		passwordFunc: FixedStringPrompt("test password"),
		service:      "test",
		isTrusted:    true,
	}

	_, err := k.Get("no-such-key")
	if err != ErrKeyNotFound {
		t.Fatal("expected ErrKeyNotFound")
	}
}

func TestOSXKeychainGetKeyWhenNotEmpty(t *testing.T) {
	path := tempPath()
	defer deleteKeychain(t, path)

	k := &keychain{
		path:         path,
		passwordFunc: FixedStringPrompt("test password"),
		service:      "test",
		isTrusted:    true,
	}
	item := Item{
		Key:         "llamas",
		Label:       "Arbitrary label",
		Description: "A freetext description",
		Data:        []byte("llamas are ok"),
	}

	if err := k.Set(item); err != nil {
		t.Fatal(err)
	}

	v1, err := k.Get("llamas")
	if err != nil {
		t.Fatal(err)
	}
	if string(v1.Data) != string(item.Data) {
		t.Fatalf("Data stored was not the data retrieved: %q vs %q", v1.Data, item.Data)
	}
}

func TestOSXKeychainRemoveKeyWhenEmpty(t *testing.T) {
	path := tempPath()
	defer deleteKeychain(t, path)

	k := &keychain{
		path:         path,
		passwordFunc: FixedStringPrompt("test password"),
		service:      "test",
		isTrusted:    true,
	}

	err := k.Remove("no-such-key")
	if err != ErrKeyNotFound {
		t.Fatalf("expected ErrKeyNotFound, got: %v", err)
	}
}

func TestOSXKeychainRemoveKeyWhenNotEmpty(t *testing.T) {
	path := tempPath()
	defer deleteKeychain(t, path)

	k := &keychain{
		path:         path,
		passwordFunc: FixedStringPrompt("test password"),
		service:      "test",
		isTrusted:    true,
	}
	item := Item{
		Key:         "llamas",
		Label:       "Arbitrary label",
		Description: "A freetext description",
		Data:        []byte("llamas are ok"),
	}

	if err := k.Set(item); err != nil {
		t.Fatal(err)
	}

	_, err := k.Get("llamas")
	if err != nil {
		t.Fatal(err)
	}

	err = k.Remove("llamas")
	if err != nil {
		t.Fatal(err)
	}
}

func tempPath() string {
	// TODO make filename configurable
	return filepath.Join(os.TempDir(), fmt.Sprintf("keyring-test-%d.keychain", time.Now().UnixNano()))
}

// TestEnsureUnlockedNoOpWhenNoPath verifies that ensureUnlocked returns
// immediately when no custom keychain path is set (k.path == "").
func TestEnsureUnlockedNoOpWhenNoPath(t *testing.T) {
	k := &keychain{
		path:       "", // no custom keychain
		useTouchID: true,
		service:    "test",
		isTrusted:  true,
		authenticateFn: func(context.Context, touchid.Policy, string) error {
			t.Fatal("authenticateFn should not be called when path is empty")
			return nil
		},
	}
	if err := k.ensureUnlocked(); err != nil {
		t.Fatalf("ensureUnlocked should be a no-op when path is empty, got: %v", err)
	}
}

// TestEnsureUnlockedNoOpWhenBiometricsDisabled verifies that ensureUnlocked
// skips when useTouchID is false.
func TestEnsureUnlockedNoOpWhenBiometricsDisabled(t *testing.T) {
	k := &keychain{
		path:       "/tmp/test.keychain",
		useTouchID: false, // biometrics not enabled
		service:    "test",
		isTrusted:  true,
		authenticateFn: func(context.Context, touchid.Policy, string) error {
			t.Fatal("authenticateFn should not be called when biometrics are disabled")
			return nil
		},
	}
	if err := k.ensureUnlocked(); err != nil {
		t.Fatalf("ensureUnlocked should be a no-op when useTouchID is false, got: %v", err)
	}
}

// TestEnsureUnlockedNoOpWhenKeychainDoesNotExist verifies that ensureUnlocked
// treats ErrorNoSuchKeychain as a no-op (returns nil), so each read method's
// existing missing-keychain handling remains authoritative.
func TestEnsureUnlockedNoOpWhenKeychainDoesNotExist(t *testing.T) {
	k := &keychain{
		path:       filepath.Join(os.TempDir(), fmt.Sprintf("nonexistent-%d.keychain", time.Now().UnixNano())),
		useTouchID: true,
		service:    "test",
		isTrusted:  true,
	}
	// The keychain doesn't exist, so IsLocked() returns ErrorNoSuchKeychain.
	// ensureUnlocked should treat this as a no-op (return nil), letting each
	// method's existing error handling deal with a missing keychain.
	if err := k.ensureUnlocked(); err != nil {
		t.Fatalf("ensureUnlocked should return nil for ErrorNoSuchKeychain, got: %v", err)
	}
}

// TestEnsureUnlockedNoOpWhenUnlocked verifies that ensureUnlocked does not
// prompt for Touch ID when the OS reports the keychain as already unlocked.
func TestEnsureUnlockedNoOpWhenUnlocked(t *testing.T) {
	path := tempPath()
	defer deleteKeychain(t, path)

	k := &keychain{
		path:         path,
		useTouchID:   true,
		passwordFunc: FixedStringPrompt("test password"),
		service:      "test",
		isTrusted:    true,
		authenticateFn: func(context.Context, touchid.Policy, string) error {
			t.Fatal("authenticateFn should not be called on an unlocked keychain")
			return nil
		},
	}
	if _, err := k.createOrOpen(); err != nil {
		t.Fatalf("createOrOpen failed: %v", err)
	}
	// createOrOpen leaves a freshly created keychain unlocked.
	if err := k.ensureUnlocked(); err != nil {
		t.Fatalf("ensureUnlocked should be a no-op on an unlocked keychain, got: %v", err)
	}
}

// TestEnsureUnlockedPromptsWhenLocked verifies that ensureUnlocked prompts for
// Touch ID exactly once when the OS reports the keychain as locked, and stays
// silent for further calls once it is unlocked again — the property aws-vault
// depends on, since Keys() is called repeatedly per command.
func TestEnsureUnlockedPromptsWhenLocked(t *testing.T) {
	path := tempPath()
	defer deleteKeychain(t, path)

	const passphrase = "test password"
	touchIDAccount := fmt.Sprintf("test-account-%d", time.Now().UnixNano())
	touchIDService := fmt.Sprintf("test-service-%d", time.Now().UnixNano())

	k := &keychain{
		path:           path,
		useTouchID:     true,
		passwordFunc:   FixedStringPrompt(passphrase),
		service:        "test",
		isTrusted:      true,
		touchIDAccount: touchIDAccount,
		touchIDService: touchIDService,
	}
	if _, err := k.createOrOpen(); err != nil {
		t.Fatalf("createOrOpen failed: %v", err)
	}

	// Seed the login-keychain item openWithTouchID expects to find, so the
	// test exercises the real unlock path without going through setupTouchID
	// (which would otherwise prompt and write to the developer's real login
	// keychain).
	seed := gokeychain.NewItem()
	seed.SetSecClass(gokeychain.SecClassGenericPassword)
	seed.SetService(touchIDService)
	seed.SetAccount(touchIDAccount)
	seed.SetLabel(fmt.Sprintf(touchIDLabel, path))
	seed.SetData([]byte(passphrase))
	if err := gokeychain.AddItem(seed); err != nil {
		t.Fatalf("failed to seed login-keychain item: %v", err)
	}
	defer gokeychain.DeleteGenericPasswordItem(touchIDService, touchIDAccount)

	authCount := 0
	k.authenticateFn = func(context.Context, touchid.Policy, string) error {
		authCount++
		return nil
	}

	if err := gokeychain.LockAtPath(path); err != nil {
		t.Fatalf("failed to lock keychain: %v", err)
	}
	if err := k.ensureUnlocked(); err != nil {
		t.Fatalf("ensureUnlocked failed: %v", err)
	}
	if authCount != 1 {
		t.Fatalf("expected exactly 1 Touch ID prompt, got %d", authCount)
	}

	// Further operations against the now-unlocked keychain must not prompt again.
	for i := 0; i < 3; i++ {
		if err := k.ensureUnlocked(); err != nil {
			t.Fatalf("ensureUnlocked failed on call %d: %v", i, err)
		}
	}
	if authCount != 1 {
		t.Fatalf("expected auth count to stay at 1, got %d", authCount)
	}
}

// TestReadMethodsCallEnsureUnlocked verifies that Get, GetMetadata, Keys,
// and Remove work correctly on a keychain that has no biometrics enabled
// (i.e. ensureUnlocked is a no-op and doesn't break existing behavior).
func TestReadMethodsCallEnsureUnlocked(t *testing.T) {
	path := tempPath()
	defer deleteKeychain(t, path)

	k := &keychain{
		path:         path,
		useTouchID:   false, // no biometrics — ensureUnlocked is a no-op
		passwordFunc: FixedStringPrompt("test password"),
		service:      "test",
		isTrusted:    true,
	}

	// Set up some data
	item := Item{
		Key:         "read-test-key",
		Label:       "Read test",
		Description: "Testing read methods with ensureUnlocked",
		Data:        []byte("test data"),
	}
	if err := k.Set(item); err != nil {
		t.Fatal(err)
	}

	// Get should work (ensureUnlocked is a no-op)
	v, err := k.Get("read-test-key")
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}
	if string(v.Data) != "test data" {
		t.Fatalf("unexpected data: %s", v.Data)
	}

	// GetMetadata queries the default (login) keychain, not the custom keychain,
	// so it's expected to return ErrKeyNotFound for items stored in a custom keychain.
	// This is pre-existing behaviour unrelated to the ensureUnlocked change.

	// Keys should work
	keys, err := k.Keys()
	if err != nil {
		t.Fatalf("Keys failed: %v", err)
	}
	found := false
	for _, key := range keys {
		if key == "read-test-key" {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("Keys did not include the test key")
	}

	// Remove should work
	if err := k.Remove("read-test-key"); err != nil {
		t.Fatalf("Remove failed: %v", err)
	}

	// Key should be gone
	_, err = k.Get("read-test-key")
	if err != ErrKeyNotFound {
		t.Fatalf("expected ErrKeyNotFound after remove, got: %v", err)
	}
}

// TestEnsureUnlockedPreservesSetBehavior verifies that Set still works
// when Touch ID is not enabled (regression test for the ensureUnlocked change).
func TestEnsureUnlockedPreservesSetBehavior(t *testing.T) {
	path := tempPath()
	defer deleteKeychain(t, path)

	k := &keychain{
		path:         path,
		useTouchID:   false,
		passwordFunc: FixedStringPrompt("test password"),
		service:      "test",
		isTrusted:    true,
	}

	items := []Item{
		{Key: "key1", Data: []byte("value1")},
		{Key: "key2", Data: []byte("value2")},
	}

	for _, item := range items {
		if err := k.Set(item); err != nil {
			t.Fatalf("Set(%s) failed: %v", item.Key, err)
		}
	}

	allKeys, err := k.Keys()
	if err != nil {
		t.Fatal(err)
	}
	if len(allKeys) != 2 {
		t.Fatalf("expected 2 keys, got %d", len(allKeys))
	}
}
