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

type fakeWinHelloWinCredCredential struct {
	target    string
	blob      []byte
	writeErr  error
	deleteErr error
	deleted   bool
	writes    int
	deletes   int
}

func (c *fakeWinHelloWinCredCredential) Write() error {
	c.writes++
	return c.writeErr
}

func (c *fakeWinHelloWinCredCredential) Delete() error {
	c.deletes++
	c.deleted = true
	return c.deleteErr
}

func (c *fakeWinHelloWinCredCredential) Blob() []byte {
	return c.blob
}

func (c *fakeWinHelloWinCredCredential) SetBlob(data []byte) {
	c.blob = data
}

func (c *fakeWinHelloWinCredCredential) TargetName() string {
	return c.target
}

func TestWinHelloWinCredStoreCredentialName(t *testing.T) {
	store := newWinHelloWinCredStore("svc")
	if got, want := store.credentialName("item"), "keyring-winhello:svc:item"; got != want {
		t.Fatalf("credentialName() = %q, want %q", got, want)
	}
}

func TestWinHelloWinCredStoreDefaultsServiceName(t *testing.T) {
	store := newWinHelloWinCredStore("")
	if got, want := store.serviceName, "default"; got != want {
		t.Fatalf("serviceName = %q, want %q", got, want)
	}
}

func TestWinHelloWinCredStoreReadMissingReturnsKeyNotFound(t *testing.T) {
	restore := stubWinHelloWinCredHooks(t)
	defer restore()

	winHelloGetGenericCredentialFunc = func(_ string) (winHelloWinCredCredential, error) {
		return nil, elementNotFoundError
	}

	store := newWinHelloWinCredStore("read-missing")
	_, err := store.Read("no-such-key")
	if !errors.Is(err, ErrKeyNotFound) {
		t.Fatalf("Read() error = %v, want %v", err, ErrKeyNotFound)
	}
}

func TestWinHelloWinCredStoreDeleteMissingReturnsKeyNotFound(t *testing.T) {
	restore := stubWinHelloWinCredHooks(t)
	defer restore()

	winHelloGetGenericCredentialFunc = func(_ string) (winHelloWinCredCredential, error) {
		return nil, elementNotFoundError
	}

	store := newWinHelloWinCredStore("delete-missing")
	err := store.Delete("no-such-key")
	if !errors.Is(err, ErrKeyNotFound) {
		t.Fatalf("Delete() error = %v, want %v", err, ErrKeyNotFound)
	}
}

func TestWinHelloWinCredStoreDeleteMapsDeleteRaceToKeyNotFound(t *testing.T) {
	restore := stubWinHelloWinCredHooks(t)
	defer restore()

	winHelloGetGenericCredentialFunc = func(_ string) (winHelloWinCredCredential, error) {
		return &fakeWinHelloWinCredCredential{deleteErr: elementNotFoundError}, nil
	}

	store := newWinHelloWinCredStore("delete-race")
	err := store.Delete("key")
	if !errors.Is(err, ErrKeyNotFound) {
		t.Fatalf("Delete() error = %v, want %v", err, ErrKeyNotFound)
	}
}

func TestWinHelloWinCredStoreKeysReturnsListError(t *testing.T) {
	restore := stubWinHelloWinCredHooks(t)
	defer restore()

	wantErr := errors.New("list rejected")
	winHelloListCredentialsFunc = func() ([]winHelloWinCredListEntry, error) {
		return nil, wantErr
	}

	store := newWinHelloWinCredStore("list-error")
	_, err := store.Keys()
	if !errors.Is(err, wantErr) {
		t.Fatalf("Keys() error = %v, want %v", err, wantErr)
	}
}

func TestWinHelloWinCredStoreKeysFiltersAndSortsOwnPrefix(t *testing.T) {
	restore := stubWinHelloWinCredHooks(t)
	defer restore()

	winHelloListCredentialsFunc = func() ([]winHelloWinCredListEntry, error) {
		return []winHelloWinCredListEntry{
			&fakeWinHelloWinCredCredential{target: "keyring-winhello:svc:z-key"},
			&fakeWinHelloWinCredCredential{target: "keyring:svc:plaintext-wincred"},
			&fakeWinHelloWinCredCredential{target: "keyring-winhello:other:other-service"},
			&fakeWinHelloWinCredCredential{target: "keyring-winhello:svc:a-key"},
		}, nil
	}

	store := newWinHelloWinCredStore("svc")
	keys, err := store.Keys()
	if err != nil {
		t.Fatalf("Keys() failed: %v", err)
	}

	if want := []string{"a-key", "z-key"}; !reflect.DeepEqual(keys, want) {
		t.Fatalf("Keys() = %#v, want %#v", keys, want)
	}
}

func TestWinHelloWinCredStoreWriteUsesCredentialBlob(t *testing.T) {
	restore := stubWinHelloWinCredHooks(t)
	defer restore()

	fakeCred := &fakeWinHelloWinCredCredential{target: "keyring-winhello:svc:item"}
	winHelloNewGenericCredentialFunc = func(target string) winHelloWinCredCredential {
		if target != fakeCred.target {
			t.Fatalf("target = %q, want %q", target, fakeCred.target)
		}
		return fakeCred
	}

	store := newWinHelloWinCredStore("svc")
	data := []byte("ciphertext-envelope")
	if err := store.Write("item", data); err != nil {
		t.Fatalf("Write() failed: %v", err)
	}
	if fakeCred.writes != 1 {
		t.Fatalf("writes = %d, want %d", fakeCred.writes, 1)
	}
	if !bytes.Equal(fakeCred.blob, data) {
		t.Fatalf("blob = %q, want %q", fakeCred.blob, data)
	}

	data[0] = 'X'
	if bytes.Equal(fakeCred.blob, data) {
		t.Fatal("stored blob aliases caller data")
	}
}

func TestWinHelloWinCredStoreReadWriteDeleteRoundTrip(t *testing.T) {
	store := newWinHelloWinCredStore(newWinHelloWinCredTestServiceName("roundtrip"))
	key := fmt.Sprintf("item-%d", time.Now().UnixNano())
	data := []byte("{\"ciphertext\":\"step11-roundtrip\"}")

	t.Cleanup(func() {
		_ = store.Delete(key)
	})

	if err := store.Write(key, data); err != nil {
		t.Fatalf("Write() failed: %v", err)
	}

	readData, err := store.Read(key)
	if err != nil {
		t.Fatalf("Read() failed: %v", err)
	}
	if !bytes.Equal(readData, data) {
		t.Fatalf("Read() data = %q, want %q", readData, data)
	}

	keys, err := store.Keys()
	if err != nil {
		t.Fatalf("Keys() failed: %v", err)
	}
	if want := []string{key}; !reflect.DeepEqual(keys, want) {
		t.Fatalf("Keys() = %#v, want %#v", keys, want)
	}

	if err := store.Delete(key); err != nil {
		t.Fatalf("Delete() failed: %v", err)
	}
	if _, err := store.Read(key); !errors.Is(err, ErrKeyNotFound) {
		t.Fatalf("Read() after delete error = %v, want %v", err, ErrKeyNotFound)
	}
}

func stubWinHelloWinCredHooks(t *testing.T) func() {
	t.Helper()

	oldGet := winHelloGetGenericCredentialFunc
	oldNew := winHelloNewGenericCredentialFunc
	oldList := winHelloListCredentialsFunc

	return func() {
		winHelloGetGenericCredentialFunc = oldGet
		winHelloNewGenericCredentialFunc = oldNew
		winHelloListCredentialsFunc = oldList
	}
}

func newWinHelloWinCredTestServiceName(label string) string {
	return fmt.Sprintf("keyring-winhello-test-%s-%d", label, time.Now().UnixNano())
}
