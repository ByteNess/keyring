//go:build windows
// +build windows

package keyring

import (
	"bytes"
	"errors"
	"fmt"
	"reflect"
	"testing"
	"time"
)

type fakeWinHelloBackendWrapper struct {
	wrapCalls     int
	unwrapCalls   int
	lastWrapped   []byte
	lastContext   string
	wrapErr       error
	unwrapErr     error
	wrappedPrefix []byte
}

func (w *fakeWinHelloBackendWrapper) WrapKey(cek []byte) ([]byte, error) {
	w.wrapCalls++
	if w.wrapErr != nil {
		return nil, w.wrapErr
	}

	prefix := w.wrappedPrefix
	if len(prefix) == 0 {
		prefix = []byte("wrapped:")
	}

	wrapped := append(bytes.Clone(prefix), cek...)
	w.lastWrapped = bytes.Clone(wrapped)
	return wrapped, nil
}

func (w *fakeWinHelloBackendWrapper) UnwrapKey(wrapped []byte, context string) ([]byte, error) {
	w.unwrapCalls++
	w.lastWrapped = bytes.Clone(wrapped)
	w.lastContext = context
	if w.unwrapErr != nil {
		return nil, w.unwrapErr
	}

	prefix := w.wrappedPrefix
	if len(prefix) == 0 {
		prefix = []byte("wrapped:")
	}
	if !bytes.HasPrefix(wrapped, prefix) {
		return nil, errors.New("unexpected wrapped value")
	}

	return bytes.Clone(wrapped[len(prefix):]), nil
}

type fakeWinHelloKeyringCredentialDirectory struct {
	blobs     map[string][]byte
	writeErr  error
	deleteErr error
}

type fakeWinHelloKeyringCredential struct {
	directory *fakeWinHelloKeyringCredentialDirectory
	target    string
	blob      []byte
}

func (c *fakeWinHelloKeyringCredential) Write() error {
	if c.directory.writeErr != nil {
		return c.directory.writeErr
	}
	c.directory.blobs[c.target] = bytes.Clone(c.blob)
	return nil
}

func (c *fakeWinHelloKeyringCredential) Delete() error {
	if c.directory.deleteErr != nil {
		return c.directory.deleteErr
	}
	delete(c.directory.blobs, c.target)
	return nil
}

func (c *fakeWinHelloKeyringCredential) Blob() []byte {
	return bytes.Clone(c.blob)
}

func (c *fakeWinHelloKeyringCredential) SetBlob(data []byte) {
	c.blob = bytes.Clone(data)
}

func (c *fakeWinHelloKeyringCredential) TargetName() string {
	return c.target
}

func TestNewWinHelloKeyringDefaultsServiceName(t *testing.T) {
	restore := stubWinHelloKeyringHooks(t)
	defer restore()

	winHelloPassportLogicalNameFunc = func() string {
		return "keyring-winhello-test-step12-defaults"
	}

	ring, err := newWinHelloKeyring("")
	if err != nil {
		t.Fatalf("newWinHelloKeyring() failed: %v", err)
	}

	if got, want := ring.serviceName, "default"; got != want {
		t.Fatalf("serviceName = %q, want %q", got, want)
	}
	if got, want := ring.store.serviceName, "default"; got != want {
		t.Fatalf("store.serviceName = %q, want %q", got, want)
	}

	wantKeyName, err := winHelloPassportKeyName(ring.logicalName)
	if err != nil {
		t.Fatalf("winHelloPassportKeyName() failed: %v", err)
	}
	if ring.keyName != wantKeyName {
		t.Fatalf("keyName = %q, want %q", ring.keyName, wantKeyName)
	}
}

func TestWinHelloKeyringSetGetKeysAndRemoveRoundTrip(t *testing.T) {
	restore := stubWinHelloKeyringHooks(t)
	defer restore()

	directory := stubWinHelloKeyringStoreHooks(t)
	ring, err := newWinHelloKeyring("svc")
	if err != nil {
		t.Fatalf("newWinHelloKeyring() failed: %v", err)
	}

	wrapper := &fakeWinHelloBackendWrapper{}
	ring.wrapper = wrapper

	item := Item{Key: "item", Data: []byte("super-secret")}
	if err := ring.Set(item); err != nil {
		t.Fatalf("Set() failed: %v", err)
	}
	if wrapper.wrapCalls != 1 {
		t.Fatalf("wrapCalls = %d, want 1", wrapper.wrapCalls)
	}

	rawEnvelope, err := ring.store.Read(item.Key)
	if err != nil {
		t.Fatalf("store.Read() failed: %v", err)
	}
	if bytes.Contains(rawEnvelope, item.Data) {
		t.Fatal("stored envelope contains plaintext")
	}

	envelope, err := parseWinHelloEnvelope(rawEnvelope)
	if err != nil {
		t.Fatalf("parseWinHelloEnvelope() failed: %v", err)
	}
	if envelope.KeyName != ring.keyName {
		t.Fatalf("envelope key name = %q, want %q", envelope.KeyName, ring.keyName)
	}
	if !bytes.Equal(envelope.AAD, winHelloAAD(ring.serviceName, item.Key)) {
		t.Fatalf("envelope AAD = %q, want %q", envelope.AAD, winHelloAAD(ring.serviceName, item.Key))
	}
	if _, ok := directory.blobs[ring.store.credentialName(item.Key)]; !ok {
		t.Fatal("expected envelope to be written to the winhello store")
	}

	got, err := ring.Get(item.Key)
	if err != nil {
		t.Fatalf("Get() failed: %v", err)
	}
	if got.Key != item.Key {
		t.Fatalf("Get() key = %q, want %q", got.Key, item.Key)
	}
	if !bytes.Equal(got.Data, item.Data) {
		t.Fatalf("Get() data = %q, want %q", got.Data, item.Data)
	}
	if wrapper.unwrapCalls != 1 {
		t.Fatalf("unwrapCalls = %d, want 1", wrapper.unwrapCalls)
	}
	if wrapper.lastContext != "" {
		t.Fatalf("unwrap context = %q, want empty string", wrapper.lastContext)
	}

	keys, err := ring.Keys()
	if err != nil {
		t.Fatalf("Keys() failed: %v", err)
	}
	if want := []string{item.Key}; !reflect.DeepEqual(keys, want) {
		t.Fatalf("Keys() = %#v, want %#v", keys, want)
	}

	if err := ring.Remove(item.Key); err != nil {
		t.Fatalf("Remove() failed: %v", err)
	}
	if _, err := ring.store.Read(item.Key); !errors.Is(err, ErrKeyNotFound) {
		t.Fatalf("store.Read() after Remove() error = %v, want %v", err, ErrKeyNotFound)
	}
	if keys, err := ring.Keys(); err != nil {
		t.Fatalf("Keys() after Remove() failed: %v", err)
	} else if len(keys) != 0 {
		t.Fatalf("Keys() after Remove() = %#v, want empty", keys)
	}
}

func TestWinHelloKeyringSetEnsuresPassportKeyLazily(t *testing.T) {
	restore := stubWinHelloKeyringHooks(t)
	defer restore()

	_ = stubWinHelloKeyringStoreHooks(t)
	ring, err := newWinHelloKeyring("svc")
	if err != nil {
		t.Fatalf("newWinHelloKeyring() failed: %v", err)
	}

	wrapper := &fakeWinHelloBackendWrapper{}
	ensureCalls := 0
	openCalls := 0
	winHelloEnsurePassportKeyFunc = func(logicalName string, hwnd uintptr) (winHelloKeyWrapper, error) {
		ensureCalls++
		if logicalName != ring.logicalName {
			t.Fatalf("logicalName = %q, want %q", logicalName, ring.logicalName)
		}
		if hwnd != 0 {
			t.Fatalf("hwnd = %d, want 0", hwnd)
		}
		return wrapper, nil
	}
	winHelloOpenPassportKeyFunc = func(_ string, _ uintptr) (winHelloKeyWrapper, error) {
		openCalls++
		return &fakeWinHelloBackendWrapper{}, nil
	}

	item := Item{Key: "item", Data: []byte("lazy")}
	if err := ring.Set(item); err != nil {
		t.Fatalf("first Set() failed: %v", err)
	}
	if err := ring.Set(Item{Key: "item-2", Data: []byte("lazy-two")}); err != nil {
		t.Fatalf("second Set() failed: %v", err)
	}

	if ensureCalls != 1 {
		t.Fatalf("ensureCalls = %d, want 1", ensureCalls)
	}
	if openCalls != 0 {
		t.Fatalf("openCalls = %d, want 0", openCalls)
	}
	if ring.wrapper != wrapper {
		t.Fatal("Set() did not cache the ensured wrapper")
	}
}

func TestWinHelloKeyringGetMissingReturnsKeyNotFoundWithoutOpeningPassportKey(t *testing.T) {
	restore := stubWinHelloKeyringHooks(t)
	defer restore()

	_ = stubWinHelloKeyringStoreHooks(t)
	ring, err := newWinHelloKeyring("svc")
	if err != nil {
		t.Fatalf("newWinHelloKeyring() failed: %v", err)
	}

	openCalls := 0
	winHelloOpenPassportKeyFunc = func(_ string, _ uintptr) (winHelloKeyWrapper, error) {
		openCalls++
		return &fakeWinHelloBackendWrapper{}, nil
	}

	_, err = ring.Get("missing")
	if !errors.Is(err, ErrKeyNotFound) {
		t.Fatalf("Get() error = %v, want %v", err, ErrKeyNotFound)
	}
	if openCalls != 0 {
		t.Fatalf("openCalls = %d, want 0", openCalls)
	}
}

func TestWinHelloKeyringGetOpensPassportKeyLazily(t *testing.T) {
	restore := stubWinHelloKeyringHooks(t)
	defer restore()

	_ = stubWinHelloKeyringStoreHooks(t)

	encryptingRing, err := newWinHelloKeyring("svc")
	if err != nil {
		t.Fatalf("newWinHelloKeyring() failed: %v", err)
	}
	encryptingRing.wrapper = &fakeWinHelloBackendWrapper{}

	item := Item{Key: "item", Data: []byte("open-lazily")}
	if err := encryptingRing.Set(item); err != nil {
		t.Fatalf("Set() failed: %v", err)
	}

	readingRing, err := newWinHelloKeyring("svc")
	if err != nil {
		t.Fatalf("newWinHelloKeyring() failed: %v", err)
	}

	wrapper := &fakeWinHelloBackendWrapper{}
	ensureCalls := 0
	openCalls := 0
	winHelloEnsurePassportKeyFunc = func(_ string, _ uintptr) (winHelloKeyWrapper, error) {
		ensureCalls++
		return &fakeWinHelloBackendWrapper{}, nil
	}
	winHelloOpenPassportKeyFunc = func(logicalName string, hwnd uintptr) (winHelloKeyWrapper, error) {
		openCalls++
		if logicalName != readingRing.logicalName {
			t.Fatalf("logicalName = %q, want %q", logicalName, readingRing.logicalName)
		}
		if hwnd != 0 {
			t.Fatalf("hwnd = %d, want 0", hwnd)
		}
		return wrapper, nil
	}

	got, err := readingRing.Get(item.Key)
	if err != nil {
		t.Fatalf("Get() failed: %v", err)
	}
	if !bytes.Equal(got.Data, item.Data) {
		t.Fatalf("Get() data = %q, want %q", got.Data, item.Data)
	}
	if ensureCalls != 0 {
		t.Fatalf("ensureCalls = %d, want 0", ensureCalls)
	}
	if openCalls != 1 {
		t.Fatalf("openCalls = %d, want 1", openCalls)
	}
	if readingRing.wrapper != wrapper {
		t.Fatal("Get() did not cache the opened wrapper")
	}
}

func TestWinHelloKeyringKeysRemoveAndMetadataDoNotTouchPassportKey(t *testing.T) {
	restore := stubWinHelloKeyringHooks(t)
	defer restore()

	directory := stubWinHelloKeyringStoreHooks(t)
	ring, err := newWinHelloKeyring("svc")
	if err != nil {
		t.Fatalf("newWinHelloKeyring() failed: %v", err)
	}

	directory.blobs[ring.store.credentialName("item")] = []byte("encrypted-envelope")
	ensureCalls := 0
	openCalls := 0
	winHelloEnsurePassportKeyFunc = func(_ string, _ uintptr) (winHelloKeyWrapper, error) {
		ensureCalls++
		return &fakeWinHelloBackendWrapper{}, nil
	}
	winHelloOpenPassportKeyFunc = func(_ string, _ uintptr) (winHelloKeyWrapper, error) {
		openCalls++
		return &fakeWinHelloBackendWrapper{}, nil
	}

	keys, err := ring.Keys()
	if err != nil {
		t.Fatalf("Keys() failed: %v", err)
	}
	if want := []string{"item"}; !reflect.DeepEqual(keys, want) {
		t.Fatalf("Keys() = %#v, want %#v", keys, want)
	}

	if _, err := ring.GetMetadata("item"); !errors.Is(err, ErrMetadataNotSupported) {
		t.Fatalf("GetMetadata() error = %v, want %v", err, ErrMetadataNotSupported)
	}
	if err := ring.Remove("item"); err != nil {
		t.Fatalf("Remove() failed: %v", err)
	}

	if ensureCalls != 0 {
		t.Fatalf("ensureCalls = %d, want 0", ensureCalls)
	}
	if openCalls != 0 {
		t.Fatalf("openCalls = %d, want 0", openCalls)
	}
}

func TestWinHelloKeyringIntegration(t *testing.T) {
	requireWinHelloPassportIntegration(t)

	restore := stubWinHelloKeyringHooks(t)
	defer restore()

	logicalName := newWinHelloPassportTestLogicalName("step12")
	winHelloPassportLogicalNameFunc = func() string {
		return logicalName
	}
	t.Cleanup(func() {
		cleanupWinHelloPassportKey(t, logicalName)
	})

	serviceName := newWinHelloWinCredTestServiceName("step12")
	ring, err := newWinHelloKeyring(serviceName)
	if err != nil {
		t.Fatalf("newWinHelloKeyring() failed: %v", err)
	}

	key := fmt.Sprintf("item-%d", time.Now().UnixNano())
	plaintext := []byte("step12-integration-secret")
	t.Cleanup(func() {
		_ = ring.Remove(key)
	})

	if err := ring.Set(Item{Key: key, Data: plaintext}); err != nil {
		t.Fatalf("Set() failed: %v", err)
	}

	rawEnvelope, err := ring.store.Read(key)
	if err != nil {
		t.Fatalf("store.Read() failed: %v", err)
	}
	if bytes.Contains(rawEnvelope, plaintext) {
		t.Fatal("stored envelope contains plaintext")
	}

	item, err := ring.Get(key)
	if err != nil {
		t.Fatalf("Get() failed: %v", err)
	}
	if item.Key != key {
		t.Fatalf("Get() key = %q, want %q", item.Key, key)
	}
	if !bytes.Equal(item.Data, plaintext) {
		t.Fatalf("Get() data = %q, want %q", item.Data, plaintext)
	}

	keys, err := ring.Keys()
	if err != nil {
		t.Fatalf("Keys() failed: %v", err)
	}
	if want := []string{key}; !reflect.DeepEqual(keys, want) {
		t.Fatalf("Keys() = %#v, want %#v", keys, want)
	}

	if _, err := ring.GetMetadata(key); !errors.Is(err, ErrMetadataNotSupported) {
		t.Fatalf("GetMetadata() error = %v, want %v", err, ErrMetadataNotSupported)
	}

	if err := ring.Remove(key); err != nil {
		t.Fatalf("Remove() failed: %v", err)
	}
	if _, err := ring.store.Read(key); !errors.Is(err, ErrKeyNotFound) {
		t.Fatalf("store.Read() after Remove() error = %v, want %v", err, ErrKeyNotFound)
	}

	passKey, err := openWinHelloPassportKey(logicalName, 0)
	if err != nil {
		t.Fatalf("Passport key missing after Remove(): %v", err)
	}
	if err := passKey.Close(); err != nil {
		t.Errorf("Close() failed: %v", err)
	}
}

func stubWinHelloKeyringHooks(t *testing.T) func() {
	t.Helper()

	oldLogicalName := winHelloPassportLogicalNameFunc
	oldEnsure := winHelloEnsurePassportKeyFunc
	oldOpen := winHelloOpenPassportKeyFunc

	return func() {
		winHelloPassportLogicalNameFunc = oldLogicalName
		winHelloEnsurePassportKeyFunc = oldEnsure
		winHelloOpenPassportKeyFunc = oldOpen
	}
}

func stubWinHelloKeyringStoreHooks(t *testing.T) *fakeWinHelloKeyringCredentialDirectory {
	t.Helper()

	directory := &fakeWinHelloKeyringCredentialDirectory{blobs: map[string][]byte{}}
	winHelloGetGenericCredentialFunc = func(target string) (winHelloWinCredCredential, error) {
		blob, ok := directory.blobs[target]
		if !ok {
			return nil, elementNotFoundError
		}

		return &fakeWinHelloKeyringCredential{
			directory: directory,
			target:    target,
			blob:      bytes.Clone(blob),
		}, nil
	}
	winHelloNewGenericCredentialFunc = func(target string) winHelloWinCredCredential {
		return &fakeWinHelloKeyringCredential{
			directory: directory,
			target:    target,
		}
	}
	winHelloListCredentialsFunc = func() ([]winHelloWinCredListEntry, error) {
		results := make([]winHelloWinCredListEntry, 0, len(directory.blobs))
		for target := range directory.blobs {
			results = append(results, &winHelloListEntryAdapter{targetName: target})
		}
		return results, nil
	}

	return directory
}
