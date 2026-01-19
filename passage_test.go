//go:build !windows

package keyring

import (
	"bytes"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

// we use runCmd defined in pass_test.go
func passageSetup(t *testing.T) (*passageKeyring, func(t *testing.T)) {
	t.Helper()

	tmpdir, err := os.MkdirTemp("/tmp", "keyring-passage-test-*")
	if err != nil {
		t.Fatal(err)
	}

	// Initialise a passage homedir; create a test identity
	passagehome := filepath.Join(tmpdir, ".passage")
	err = os.MkdirAll(filepath.Join(passagehome, "store"), os.FileMode(int(0700)))
	if err != nil {
		t.Fatal(err)
	}
	identityFile := filepath.Join(passagehome, "identities")
	runCmd(t, "age-keygen", "--output", identityFile)
	t.Setenv("PASSAGE_IDENTITIES_FILE", identityFile)

	passdir := filepath.Join(passagehome, "store")
	k := &passageKeyring{
		dir:     passdir,
		passcmd: "passage",
		prefix:  "keyring",
	}

	return k, func(t *testing.T) {
		t.Helper()
		os.RemoveAll(tmpdir)
	}
}

func TestPassageKeyringSetWhenEmpty(t *testing.T) {
	k, teardown := passageSetup(t)
	defer teardown(t)

	item := Item{Key: "llamas", Data: []byte("llamas are great")}

	if err := k.Set(item); err != nil {
		t.Fatal(err)
	}

	foundItem, err := k.Get("llamas")
	if err != nil {
		t.Fatal(err)
	}

	if string(foundItem.Data) != "llamas are great" {
		t.Fatalf("Value stored was not the value retrieved: %q", foundItem.Data)
	}

	if foundItem.Key != "llamas" {
		t.Fatalf("Key wasn't persisted: %q", foundItem.Key)
	}
}

func TestPassageKeyringKeysWhenEmpty(t *testing.T) {
	k, teardown := passageSetup(t)
	defer teardown(t)

	keys, err := k.Keys()
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 0 {
		t.Fatalf("Expected 0 keys, got %d", len(keys))
	}
}

func TestPassageKeyringKeysWhenNotEmpty(t *testing.T) {
	k, teardown := passageSetup(t)
	defer teardown(t)

	items := []Item{
		{Key: "llamas", Data: []byte("llamas are great")},
		{Key: "alpacas", Data: []byte("alpacas are better")},
		{Key: "africa/elephants", Data: []byte("who doesn't like elephants")},
	}

	for _, item := range items {
		if err := k.Set(item); err != nil {
			t.Fatal(err)
		}
	}

	keys, err := k.Keys()
	if err != nil {
		t.Fatal(err)
	}

	if len(keys) != len(items) {
		t.Fatalf("Expected %d keys, got %d", len(items), len(keys))
	}

	expectedKeys := []string{
		"africa/elephants",
		"alpacas",
		"llamas",
	}

	if !reflect.DeepEqual(keys, expectedKeys) {
		t.Fatalf("Expected keys %v, got %v", expectedKeys, keys)
	}
}

func TestPassageKeyringRemoveWhenEmpty(t *testing.T) {
	k, teardown := passageSetup(t)
	defer teardown(t)

	err := k.Remove("no-such-key")
	if err != ErrKeyNotFound {
		t.Fatalf("expected ErrKeyNotFound, got: %v", err)
	}
}

func TestPassageKeyringRemoveWhenNotEmpty(t *testing.T) {
	k, teardown := passageSetup(t)
	defer teardown(t)

	item := Item{Key: "llamas", Data: []byte("llamas are great")}

	if err := k.Set(item); err != nil {
		t.Fatal(err)
	}

	if err := k.Remove(item.Key); err != nil {
		t.Fatal(err)
	}

	keys, err := k.Keys()
	if err != nil {
		t.Fatal(err)
	}

	if len(keys) != 0 {
		t.Fatalf("Expected 0 keys, got %d", len(keys))
	}
}

func TestPassageKeyringGetWhenEmpty(t *testing.T) {
	k, teardown := passageSetup(t)
	defer teardown(t)

	_, err := k.Get("no-such-key")
	if err != ErrKeyNotFound {
		t.Fatalf("expected ErrKeyNotFound, got: %v", err)
	}
}

func TestPassageKeyringGetWhenNotEmpty(t *testing.T) {
	k, teardown := passageSetup(t)
	defer teardown(t)

	item := Item{Key: "llamas", Data: []byte("llamas are great")}

	if err := k.Set(item); err != nil {
		t.Fatal(err)
	}

	v1, err := k.Get(item.Key)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(v1.Data, item.Data) {
		t.Fatal("Expected item not returned")
	}
}

func TestPassageKeyringKeysWithSymlink(t *testing.T) {
	k, teardown := passageSetup(t)
	defer teardown(t)

	items := []Item{
		{Key: "llamas", Data: []byte("llamas are great")},
		{Key: "alpacas", Data: []byte("alpacas are better")},
		{Key: "africa/elephants", Data: []byte("who doesn't like elephants")},
	}

	for _, item := range items {
		if err := k.Set(item); err != nil {
			t.Fatal(err)
		}
	}

	s := filepath.Join(t.TempDir(), "newsymlink")
	err := os.Symlink(k.dir, s)
	if err != nil {
		t.Fatal(err)
	}
	k.dir = s

	keys, err := k.Keys()
	if err != nil {
		t.Fatal(err)
	}

	if len(keys) != len(items) {
		t.Fatalf("Expected %d keys, got %d", len(items), len(keys))
	}

	expectedKeys := []string{
		"africa/elephants",
		"alpacas",
		"llamas",
	}

	if !reflect.DeepEqual(keys, expectedKeys) {
		t.Fatalf("Expected keys %v, got %v", expectedKeys, keys)
	}
}
