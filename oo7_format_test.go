package keyring

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

// testdata/oo7/passphrase.keyring was written by oo7-cli 0.7.0:
//
//	oo7-cli -k passphrase.keyring -s keyring-test store llamas  service=keyring-test key=llamas  xdg:schema=cc.byteness.keyring
//	oo7-cli -k passphrase.keyring -s keyring-test store alpacas service=keyring-test key=alpacas xdg:schema=cc.byteness.keyring
const oo7FixtureSecret = "keyring-test"

func loadOO7Fixture(t *testing.T) (*oo7File, []byte) {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", "oo7", "passphrase.keyring"))
	if err != nil {
		t.Fatal(err)
	}
	f, err := parseOO7File(data)
	if err != nil {
		t.Fatal(err)
	}
	key, err := f.deriveKey([]byte(oo7FixtureSecret))
	if err != nil {
		t.Fatal(err)
	}
	return f, key
}

func TestOO7FixtureDecrypts(t *testing.T) {
	f, key := loadOO7Fixture(t)
	if f.iterationCount != 100000 || len(f.salt) != 32 || f.usageCount != 2 || len(f.items) != 2 {
		t.Fatalf("unexpected header: iterations=%d salt=%d usage=%d items=%d",
			f.iterationCount, len(f.salt), f.usageCount, len(f.items))
	}
	if err := f.validateItems(key); err != nil {
		t.Fatal(err)
	}

	search := map[string]string{"service": "keyring-test", "key": "llamas", oo7SchemaAttribute: "cc.byteness.keyring"}
	var found *oo7Item
	for i := range f.items {
		if f.items[i].matches(search, key) {
			item, err := f.items[i].decrypt(key)
			if err != nil {
				t.Fatal(err)
			}
			found = item
		}
	}
	if found == nil {
		t.Fatal("llamas not found")
	}
	if found.label != "llamas" || string(found.secret) != "llamas are great" {
		t.Fatalf("unexpected item %+v", found)
	}
	if found.attributes[oo7ContentTypeAttribute] != "text/plain" {
		t.Fatalf("unexpected content type %q", found.attributes[oo7ContentTypeAttribute])
	}
	if found.created == 0 || found.modified == 0 {
		t.Fatal("timestamps not decoded")
	}

	if f.items[0].matches(map[string]string{"key": "nope"}, key) {
		t.Fatal("matched an attribute that is not there")
	}
	if !f.items[0].matches(map[string]string{oo7SchemaAttribute: "cc.byteness.keyring"}, key) {
		t.Fatal("schema attribute did not match")
	}
}

func TestOO7FixtureWrongSecret(t *testing.T) {
	f, _ := loadOO7Fixture(t)
	key, err := f.deriveKey([]byte("not the secret"))
	if err != nil {
		t.Fatal(err)
	}
	if err := f.validateItems(key); !errors.Is(err, ErrOO7IncorrectSecret) {
		t.Fatalf("expected ErrOO7IncorrectSecret, got %v", err)
	}
}

func TestOO7FixtureTamperedItem(t *testing.T) {
	f, key := loadOO7Fixture(t)
	f.items[0].blob[len(f.items[0].blob)-1] ^= 0xff
	if _, err := f.items[0].decrypt(key); !errors.Is(err, errOO7MAC) {
		t.Fatalf("expected MAC error, got %v", err)
	}
	f.items[0].blob[len(f.items[0].blob)-1] ^= 0xff
	f.items[0].blob[0] ^= 0xff
	if _, err := f.items[0].decrypt(key); !errors.Is(err, errOO7MAC) {
		t.Fatalf("expected MAC error after tampering ciphertext, got %v", err)
	}
}

func TestOO7FixtureRoundTrip(t *testing.T) {
	f, key := loadOO7Fixture(t)
	item := newOO7Item("vicunas", map[string]string{"service": "keyring-test", "key": "vicunas"}, []byte(`{"a":1}`), "application/json")
	enc, err := item.encrypt(key)
	if err != nil {
		t.Fatal(err)
	}
	f.items = append(f.items, enc)

	again, err := parseOO7File(f.marshal())
	if err != nil {
		t.Fatal(err)
	}
	if err := again.validateItems(key); err != nil {
		t.Fatal(err)
	}
	if len(again.items) != 3 {
		t.Fatalf("got %d items", len(again.items))
	}
	got, err := again.items[2].decrypt(key)
	if err != nil {
		t.Fatal(err)
	}
	if got.label != "vicunas" || string(got.secret) != `{"a":1}` || got.attributes[oo7ContentTypeAttribute] != "application/json" {
		t.Fatalf("unexpected item %+v", got)
	}
	if !again.items[2].matches(map[string]string{"key": "vicunas"}, key) {
		t.Fatal("new item does not match its attributes")
	}
}

func TestOO7ValidateItemsCorruption(t *testing.T) {
	f, key := loadOO7Fixture(t)
	item := newOO7Item("vicunas", map[string]string{"key": "vicunas"}, []byte("x"), "text/plain")
	enc, err := item.encrypt(key)
	if err != nil {
		t.Fatal(err)
	}
	f.items = append(f.items, enc)
	// One broken item out of three is tolerated.
	f.items[0].blob[0] ^= 0xff
	if err := f.validateItems(key); err != nil {
		t.Fatalf("one broken item of three should be tolerated, got %v", err)
	}
	// Two broken out of three is reported as corruption, not a wrong secret.
	f.items[1].blob[0] ^= 0xff
	err = f.validateItems(key)
	if err == nil || errors.Is(err, ErrOO7IncorrectSecret) {
		t.Fatalf("expected a corruption error, got %v", err)
	}
}

func TestOO7UnencryptedKeyringIsRejected(t *testing.T) {
	f, err := newOO7File()
	if err != nil {
		t.Fatal(err)
	}
	item := newOO7Item("plain", map[string]string{"key": "plain"}, []byte("secret"), "text/plain")
	f.items = append(f.items, oo7EncryptedItem{
		hashedAttributes: map[string][]byte{"key": []byte("plain"), oo7ContentTypeAttribute: []byte("text/plain")},
		blob:             item.marshal(),
	})
	key, err := f.deriveKey([]byte("anything"))
	if err != nil {
		t.Fatal(err)
	}
	if err := f.validateItems(key); !errors.Is(err, ErrOO7Unencrypted) {
		t.Fatalf("expected ErrOO7Unencrypted, got %v", err)
	}
}

func TestOO7WeakKeyringRefusesWrite(t *testing.T) {
	f, err := newOO7File()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "weak.keyring")
	f.iterationCount = 1000
	if err := f.write(path, time.Time{}); err == nil {
		t.Fatal("expected a weak key error for a low iteration count")
	}
	f.iterationCount = oo7DefaultIterationCount
	f.salt = f.salt[:8]
	if err := f.write(path, time.Time{}); err == nil {
		t.Fatal("expected a weak key error for a short salt")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("a refused write must not create the file")
	}
}

func TestOO7WriteDetectsConcurrentChange(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "nested", "keyrings")
	path := filepath.Join(dir, "test.keyring")

	f, mtime, err := readOO7File(path)
	if err != nil {
		t.Fatal(err)
	}
	if !mtime.IsZero() || len(f.items) != 0 {
		t.Fatal("a missing file should load as an empty keyring")
	}
	if err := f.write(path, mtime); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" { // Windows has no Unix permission bits
		if info.Mode().Perm() != 0o600 {
			t.Fatalf("keyring mode is %o, want 600", info.Mode().Perm())
		}
		if dirInfo, err := os.Stat(dir); err != nil || dirInfo.Mode().Perm() != 0o700 {
			t.Fatalf("keyring dir mode is wrong: %v %v", dirInfo, err)
		}
	}

	// Writing again with the stale (zero) mtime must be refused.
	if err := f.write(path, time.Time{}); !errors.Is(err, errOO7TargetChanged) {
		t.Fatalf("expected errOO7TargetChanged, got %v", err)
	}

	// A fresh load carries the right mtime; a write between load and save is detected.
	f2, mtime2, err := readOO7File(path)
	if err != nil {
		t.Fatal(err)
	}
	future := time.Now().Add(2 * time.Second)
	if err := os.Chtimes(path, future, future); err != nil {
		t.Fatal(err)
	}
	if err := f2.write(path, mtime2); !errors.Is(err, errOO7TargetChanged) {
		t.Fatalf("expected errOO7TargetChanged after external modification, got %v", err)
	}
	f3, mtime3, err := readOO7File(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := f3.write(path, mtime3); err != nil {
		t.Fatal(err)
	}
	if f3.usageCount != 2 {
		t.Fatalf("usage count is %d, want 2", f3.usageCount)
	}
	leftovers, _ := filepath.Glob(filepath.Join(dir, ".tmpkeyring*"))
	if len(leftovers) != 0 {
		t.Fatalf("temporary files left behind: %v", leftovers)
	}
	data, _ := os.ReadFile(path)
	if !bytes.HasPrefix(data, []byte(oo7FileHeader)) {
		t.Fatal("written file lacks the oo7 header")
	}
}

func TestOO7RemoveDetectsConcurrentChange(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test.keyring")
	f, mtime, err := readOO7File(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.write(path, mtime); err != nil {
		t.Fatal(err)
	}
	if err := removeOO7File(path, time.Time{}); !errors.Is(err, errOO7TargetChanged) {
		t.Fatalf("expected errOO7TargetChanged for a stale mtime, got %v", err)
	}
	_, mtime, err = readOO7File(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := removeOO7File(path, mtime); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("file should be gone")
	}
	if err := removeOO7File(path, mtime); !errors.Is(err, errOO7TargetChanged) {
		t.Fatalf("a file that vanished under us is a concurrent change, got %v", err)
	}
	if err := removeOO7File(path, time.Time{}); err != nil {
		t.Fatalf("removing a file that never existed is fine, got %v", err)
	}
}

func TestOO7DefaultKeyringPath(t *testing.T) {
	dataDir := filepath.Join(t.TempDir(), "xdg") // absolute on every platform
	t.Setenv("XDG_DATA_HOME", dataDir)
	got, err := OO7DefaultKeyringPath("aws-vault")
	if err != nil {
		t.Fatal(err)
	}
	if want := filepath.Join(dataDir, "aws-vault", "keyrings", "default.keyring"); got != want {
		t.Fatalf("got %q want %q", got, want)
	}

	t.Setenv("XDG_DATA_HOME", "relative/ignored")
	home, err := os.UserHomeDir()
	if err != nil {
		t.Skip(err)
	}
	got, err = OO7DefaultKeyringPath("aws-vault")
	if err != nil {
		t.Fatal(err)
	}
	if want := filepath.Join(home, ".local", "share", "aws-vault", "keyrings", "default.keyring"); got != want {
		t.Fatalf("got %q want %q", got, want)
	}

	for _, name := range []string{"", ".", "..", "../escape", "a/b", "/abs", `a\b`} {
		if got, err := OO7DefaultKeyringPath(name); err == nil {
			t.Errorf("name %q: expected an error, got %q", name, got)
		}
	}
}
