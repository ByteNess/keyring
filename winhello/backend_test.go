//go:build windows
// +build windows

package winhello

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

	passportLogicalNameFunc = func() string {
		return "keyring-winhello-test-backend-defaults"
	}

	ring, err := New("")
	if err != nil {
		t.Fatalf("New() failed: %v", err)
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
	winHelloParentHWNDFunc = func() uintptr {
		return 1234
	}
	ring, err := New("svc")
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	wrapper := &fakeWinHelloBackendWrapper{}
	ring.wrapper = wrapper

	key := "item"
	data := []byte("super-secret")
	if err := ring.Set(key, data); err != nil {
		t.Fatalf("Set() failed: %v", err)
	}
	if wrapper.wrapCalls != 1 {
		t.Fatalf("wrapCalls = %d, want 1", wrapper.wrapCalls)
	}

	rawEnvelope, err := ring.store.Read(key)
	if err != nil {
		t.Fatalf("store.Read() failed: %v", err)
	}
	if bytes.Contains(rawEnvelope, data) {
		t.Fatal("stored envelope contains plaintext")
	}

	envelope, err := parseWinHelloEnvelope(rawEnvelope)
	if err != nil {
		t.Fatalf("parseWinHelloEnvelope() failed: %v", err)
	}
	if envelope.KeyName != ring.keyName {
		t.Fatalf("envelope key name = %q, want %q", envelope.KeyName, ring.keyName)
	}
	if !bytes.Equal(envelope.AAD, winHelloAAD(ring.serviceName, key)) {
		t.Fatalf("envelope AAD = %q, want %q", envelope.AAD, winHelloAAD(ring.serviceName, key))
	}
	if _, ok := directory.blobs[ring.store.credentialName(key)]; !ok {
		t.Fatal("expected envelope to be written to the winhello store")
	}

	got, err := ring.Get(key)
	if err != nil {
		t.Fatalf("Get() failed: %v", err)
	}
	if !bytes.Equal(got, data) {
		t.Fatalf("Get() data = %q, want %q", got, data)
	}
	if wrapper.unwrapCalls != 1 {
		t.Fatalf("unwrapCalls = %d, want 1", wrapper.unwrapCalls)
	}
	if got, want := wrapper.lastContext, winHelloUseContext(ring.serviceName, key); got != want {
		t.Fatalf("unwrap context = %q, want %q", got, want)
	}

	keys, err := ring.Keys()
	if err != nil {
		t.Fatalf("Keys() failed: %v", err)
	}
	if want := []string{key}; !reflect.DeepEqual(keys, want) {
		t.Fatalf("Keys() = %#v, want %#v", keys, want)
	}

	if err := ring.Remove(key); err != nil {
		t.Fatalf("Remove() failed: %v", err)
	}
	if _, err := ring.store.Read(key); !errors.Is(err, ErrKeyNotFound) {
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
	winHelloParentHWNDFunc = func() uintptr {
		return 1234
	}
	ring, err := New("svc")
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	wrapper := &fakeWinHelloBackendWrapper{}
	ensureCalls := 0
	openCalls := 0
	ensurePassportKeyFunc = func(logicalName string, hwnd uintptr) (winHelloKeyWrapper, error) {
		ensureCalls++
		if logicalName != ring.logicalName {
			t.Fatalf("logicalName = %q, want %q", logicalName, ring.logicalName)
		}
		if hwnd != 1234 {
			t.Fatalf("hwnd = %d, want 1234", hwnd)
		}
		return wrapper, nil
	}
	openPassportKeyFunc = func(_ string, _ uintptr) (winHelloKeyWrapper, error) {
		openCalls++
		return &fakeWinHelloBackendWrapper{}, nil
	}

	if err := ring.Set("item", []byte("lazy")); err != nil {
		t.Fatalf("first Set() failed: %v", err)
	}
	if err := ring.Set("item-2", []byte("lazy-two")); err != nil {
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
	ring, err := New("svc")
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	openCalls := 0
	openPassportKeyFunc = func(_ string, _ uintptr) (winHelloKeyWrapper, error) {
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
	winHelloParentHWNDFunc = func() uintptr {
		return 1234
	}

	encryptingRing, err := New("svc")
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}
	encryptingRing.wrapper = &fakeWinHelloBackendWrapper{}

	key := "item"
	data := []byte("open-lazily")
	if err := encryptingRing.Set(key, data); err != nil {
		t.Fatalf("Set() failed: %v", err)
	}

	readingRing, err := New("svc")
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	wrapper := &fakeWinHelloBackendWrapper{}
	ensureCalls := 0
	openCalls := 0
	ensurePassportKeyFunc = func(_ string, _ uintptr) (winHelloKeyWrapper, error) {
		ensureCalls++
		return &fakeWinHelloBackendWrapper{}, nil
	}
	openPassportKeyFunc = func(logicalName string, hwnd uintptr) (winHelloKeyWrapper, error) {
		openCalls++
		if logicalName != readingRing.logicalName {
			t.Fatalf("logicalName = %q, want %q", logicalName, readingRing.logicalName)
		}
		if hwnd != 1234 {
			t.Fatalf("hwnd = %d, want 1234", hwnd)
		}
		return wrapper, nil
	}

	got, err := readingRing.Get(key)
	if err != nil {
		t.Fatalf("Get() failed: %v", err)
	}
	if !bytes.Equal(got, data) {
		t.Fatalf("Get() data = %q, want %q", got, data)
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

func TestWinHelloKeyringGetMapsMissingPassportKeyForExistingItem(t *testing.T) {
	restore := stubWinHelloKeyringHooks(t)
	defer restore()

	_ = stubWinHelloKeyringStoreHooks(t)

	encryptingRing, err := New("svc")
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}
	encryptingRing.wrapper = &fakeWinHelloBackendWrapper{}

	key := "item"
	if err := encryptingRing.Set(key, []byte("passport-missing")); err != nil {
		t.Fatalf("Set() failed: %v", err)
	}

	readingRing, err := New("svc")
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}
	openPassportKeyFunc = func(_ string, _ uintptr) (winHelloKeyWrapper, error) {
		return nil, errWinHelloPassportKeyNotFound
	}

	_, err = readingRing.Get(key)
	if !errors.Is(err, errWinHelloPassportKeyNotFound) {
		t.Fatalf("Get() error = %v, want %v", err, errWinHelloPassportKeyNotFound)
	}
	if errors.Is(err, ErrKeyNotFound) {
		t.Fatalf("Get() error = %v, should not look like missing item", err)
	}
	if got, want := err.Error(), `open winhello Passport key for existing item "item": `+errWinHelloPassportKeyNotFound.Error(); got != want {
		t.Fatalf("Get() error text = %q, want %q", got, want)
	}
}

func TestWinHelloKeyringKeysAndRemoveDoNotTouchPassportKey(t *testing.T) {
	restore := stubWinHelloKeyringHooks(t)
	defer restore()

	directory := stubWinHelloKeyringStoreHooks(t)
	ring, err := New("svc")
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	directory.blobs[ring.store.credentialName("item")] = []byte("encrypted-envelope")
	ensureCalls := 0
	openCalls := 0
	ensurePassportKeyFunc = func(_ string, _ uintptr) (winHelloKeyWrapper, error) {
		ensureCalls++
		return &fakeWinHelloBackendWrapper{}, nil
	}
	openPassportKeyFunc = func(_ string, _ uintptr) (winHelloKeyWrapper, error) {
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

	logicalName := newWinHelloPassportTestLogicalName("backend")
	passportLogicalNameFunc = func() string {
		return logicalName
	}
	t.Cleanup(func() {
		cleanupWinHelloPassportKey(t, logicalName)
	})

	serviceName := newWinHelloWinCredTestServiceName("backend")
	ring, err := New(serviceName)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	key := fmt.Sprintf("item-%d", time.Now().UnixNano())
	plaintext := []byte("winhello-integration-secret")
	t.Cleanup(func() {
		_ = ring.Remove(key)
	})

	if err := ring.Set(key, plaintext); err != nil {
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
	if !bytes.Equal(item, plaintext) {
		t.Fatalf("Get() data = %q, want %q", item, plaintext)
	}

	keys, err := ring.Keys()
	if err != nil {
		t.Fatalf("Keys() failed: %v", err)
	}
	if want := []string{key}; !reflect.DeepEqual(keys, want) {
		t.Fatalf("Keys() = %#v, want %#v", keys, want)
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

	oldLogicalName := passportLogicalNameFunc
	oldEnsure := ensurePassportKeyFunc
	oldOpen := openPassportKeyFunc
	oldParentHWND := winHelloParentHWNDFunc

	return func() {
		passportLogicalNameFunc = oldLogicalName
		ensurePassportKeyFunc = oldEnsure
		openPassportKeyFunc = oldOpen
		winHelloParentHWNDFunc = oldParentHWND
	}
}

func stubWinHelloKeyringStoreHooks(t *testing.T) *fakeWinHelloKeyringCredentialDirectory {
	t.Helper()

	oldGet := winHelloGetGenericCredentialFunc
	oldNew := winHelloNewGenericCredentialFunc
	oldList := winHelloListCredentialsFunc

	directory := &fakeWinHelloKeyringCredentialDirectory{blobs: map[string][]byte{}}
	winHelloGetGenericCredentialFunc = func(target string) (winHelloWinCredCredential, error) {
		blob, ok := directory.blobs[target]
		if !ok {
			return nil, errElementNotFound
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

	t.Cleanup(func() {
		winHelloGetGenericCredentialFunc = oldGet
		winHelloNewGenericCredentialFunc = oldNew
		winHelloListCredentialsFunc = oldList
	})

	return directory
}
