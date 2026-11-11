//go:build linux && !keyring_nooo7

package keyring

import (
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
)

func oo7TestStore(t *testing.T, path string) *oo7Store {
	t.Helper()
	kr, err := newOO7Store(Config{
		ServiceName:     "keyring-test",
		OO7KeyringPath:  path,
		OO7KeySource:    OO7KeySourcePassphrase,
		OO7PasswordFunc: FixedStringPrompt("no more secrets"),
	})
	if err != nil {
		t.Fatal(err)
	}
	return kr
}

func TestOO7KeysWhenMissing(t *testing.T) {
	kr := oo7TestStore(t, filepath.Join(t.TempDir(), "missing.keyring"))
	keys, err := kr.Keys()
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 0 {
		t.Fatalf("expected no keys, got %v", keys)
	}
	if _, err := kr.Get("llamas"); !errors.Is(err, ErrKeyNotFound) {
		t.Fatalf("expected ErrKeyNotFound, got %v", err)
	}
	if err := kr.Remove("llamas"); !errors.Is(err, ErrKeyNotFound) {
		t.Fatalf("expected ErrKeyNotFound, got %v", err)
	}
	if _, err := kr.GetMetadata("llamas"); !errors.Is(err, ErrMetadataNeedsCredentials) {
		t.Fatalf("expected ErrMetadataNeedsCredentials, got %v", err)
	}
	if kr.secret != nil {
		t.Fatal("reads of a missing keyring must not resolve the secret")
	}
}

func TestOO7SetGetRemove(t *testing.T) {
	path := filepath.Join(t.TempDir(), "keyrings", "v1", "test.keyring")
	kr := oo7TestStore(t, path)

	item := Item{Key: "llamas", Data: []byte("llamas are great"), Label: "Llamas", Description: "camelid"}
	if err := kr.Set(item); err != nil {
		t.Fatal(err)
	}
	if err := kr.Set(Item{Key: "alpacas", Data: []byte("alpacas are better")}); err != nil {
		t.Fatal(err)
	}

	got, err := kr.Get("llamas")
	if err != nil {
		t.Fatal(err)
	}
	if got.Key != item.Key || string(got.Data) != string(item.Data) || got.Label != item.Label || got.Description != item.Description {
		t.Fatalf("got %+v want %+v", got, item)
	}

	keys, err := kr.Keys()
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(keys)
	if len(keys) != 2 || keys[0] != "alpacas" || keys[1] != "llamas" {
		t.Fatalf("unexpected keys %v", keys)
	}

	if _, err := kr.GetMetadata("llamas"); !errors.Is(err, ErrMetadataNeedsCredentials) {
		t.Fatalf("expected ErrMetadataNeedsCredentials, got %v", err)
	}

	// Replacing keeps a single item per key.
	if err := kr.Set(Item{Key: "llamas", Data: []byte("still great")}); err != nil {
		t.Fatal(err)
	}
	got, err = kr.Get("llamas")
	if err != nil {
		t.Fatal(err)
	}
	if string(got.Data) != "still great" {
		t.Fatalf("replace did not take: %q", got.Data)
	}
	f, _, err := readOO7File(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(f.items) != 2 {
		t.Fatalf("expected 2 items on disk, got %d", len(f.items))
	}

	if err := kr.Remove("llamas"); err != nil {
		t.Fatal(err)
	}
	if _, err := kr.Get("llamas"); !errors.Is(err, ErrKeyNotFound) {
		t.Fatalf("expected ErrKeyNotFound after remove, got %v", err)
	}
	if err := kr.Remove("llamas"); !errors.Is(err, ErrKeyNotFound) {
		t.Fatalf("expected ErrKeyNotFound on second remove, got %v", err)
	}
	keys, err = kr.Keys()
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 1 || keys[0] != "alpacas" {
		t.Fatalf("unexpected keys %v", keys)
	}

	// Removing the last item deletes the file, so a stale empty keyring
	// cannot adopt whatever passphrase the next writer happens to use.
	if err := kr.Remove("alpacas"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("expected the keyring file to be deleted, got %v", err)
	}
	keys, err = kr.Keys()
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 0 {
		t.Fatalf("unexpected keys %v", keys)
	}
}

func TestOO7KeysWithSlashesAndUnicode(t *testing.T) {
	kr := oo7TestStore(t, filepath.Join(t.TempDir(), "test.keyring"))
	key := "https://aws-sso-portal.awsapps.com/start/ünïcödé"
	if err := kr.Set(Item{Key: key, Data: []byte("x")}); err != nil {
		t.Fatal(err)
	}
	got, err := kr.Get(key)
	if err != nil {
		t.Fatal(err)
	}
	if got.Key != key {
		t.Fatalf("got %q", got.Key)
	}
	keys, err := kr.Keys()
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 1 || keys[0] != key {
		t.Fatalf("unexpected keys %v", keys)
	}
}

func TestOO7ItemsOfOtherServicesAreIgnored(t *testing.T) {
	path := filepath.Join(t.TempDir(), "shared.keyring")
	a := oo7TestStore(t, path)
	b, err := newOO7Store(Config{
		ServiceName:     "other-service",
		OO7KeyringPath:  path,
		OO7KeySource:    OO7KeySourcePassphrase,
		OO7PasswordFunc: FixedStringPrompt("no more secrets"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Set(Item{Key: "shared", Data: []byte("a")}); err != nil {
		t.Fatal(err)
	}
	if err := b.Set(Item{Key: "shared", Data: []byte("b")}); err != nil {
		t.Fatal(err)
	}
	got, err := a.Get("shared")
	if err != nil {
		t.Fatal(err)
	}
	if string(got.Data) != "a" {
		t.Fatalf("service a read %q", got.Data)
	}
	keys, err := b.Keys()
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 1 {
		t.Fatalf("service b sees %v", keys)
	}
	if err := b.Remove("shared"); err != nil {
		t.Fatal(err)
	}
	if _, err := a.Get("shared"); err != nil {
		t.Fatalf("service a's item was removed by b: %v", err)
	}
}

func TestOO7WrongPassphrase(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test.keyring")
	kr := oo7TestStore(t, path)
	if err := kr.Set(Item{Key: "llamas", Data: []byte("x")}); err != nil {
		t.Fatal(err)
	}
	other, err := newOO7Store(Config{
		ServiceName:     "keyring-test",
		OO7KeyringPath:  path,
		OO7KeySource:    OO7KeySourcePassphrase,
		OO7PasswordFunc: FixedStringPrompt("wrong"),
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = other.Get("llamas")
	if !errors.Is(err, ErrOO7IncorrectSecret) {
		t.Fatalf("expected ErrOO7IncorrectSecret, got %v", err)
	}
	if !strings.Contains(err.Error(), "wrong passphrase for "+path) || strings.Contains(err.Error(), "OO7KeySource") {
		t.Fatalf("passphrase mode should name the passphrase and not hint at key sources: %v", err)
	}
	if err := other.Set(Item{Key: "alpacas"}); !errors.Is(err, ErrOO7IncorrectSecret) {
		t.Fatalf("a wrong secret must not be able to write, got %v", err)
	}
}

func TestOO7WrongPassphraseIsNotCached(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test.keyring")
	kr := oo7TestStore(t, path)
	if err := kr.Set(Item{Key: "llamas", Data: []byte("x")}); err != nil {
		t.Fatal(err)
	}
	attempts := []string{"typo", "no more secrets"}
	other, err := newOO7Store(Config{
		ServiceName:    "keyring-test",
		OO7KeyringPath: path,
		OO7KeySource:   OO7KeySourcePassphrase,
		OO7PasswordFunc: func(string) (string, error) {
			pwd := attempts[0]
			attempts = attempts[1:]
			return pwd, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := other.Get("llamas"); !errors.Is(err, ErrOO7IncorrectSecret) {
		t.Fatalf("expected ErrOO7IncorrectSecret, got %v", err)
	}
	if _, err := other.Get("llamas"); err != nil {
		t.Fatalf("second attempt should prompt again and succeed, got %v", err)
	}
	if len(attempts) != 0 {
		t.Fatal("the prompt was not called again after a wrong passphrase")
	}
}

func TestOO7PromptsBeforeTakingTheLock(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test.keyring")
	kr, err := newOO7Store(Config{
		ServiceName:    "keyring-test",
		OO7KeyringPath: path,
		OO7KeySource:   OO7KeySourcePassphrase,
		OO7PasswordFunc: func(string) (string, error) {
			// While the prompt is up, another writer must still be able to
			// take the lock.
			lock, err := oo7LockFile(path + ".lock")
			if err != nil {
				return "", err
			}
			if err := lock.Unlock(); err != nil {
				return "", err
			}
			return "no more secrets", nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := kr.Set(Item{Key: "llamas", Data: []byte("x")}); err != nil {
		t.Fatal(err)
	}
}

func TestOO7EmptyPassphraseRejected(t *testing.T) {
	kr, err := newOO7Store(Config{
		ServiceName:     "keyring-test",
		OO7KeyringPath:  filepath.Join(t.TempDir(), "test.keyring"),
		OO7KeySource:    OO7KeySourcePassphrase,
		OO7PasswordFunc: FixedStringPrompt(""),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := kr.Set(Item{Key: "llamas"}); err == nil {
		t.Fatal("expected an error for an empty passphrase")
	}
}

func TestOO7ConcurrentWriters(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test.keyring")
	const writers = 8
	stores := make([]*oo7Store, writers)
	for i := range stores {
		stores[i] = oo7TestStore(t, path)
	}
	var wg sync.WaitGroup
	errs := make(chan error, writers)
	for i, kr := range stores {
		wg.Add(1)
		go func(i int, kr *oo7Store) {
			defer wg.Done()
			errs <- kr.Set(Item{Key: string(rune('a' + i)), Data: []byte("x")})
		}(i, kr)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("writer failed: %v", err)
		}
	}
	keys, err := oo7TestStore(t, path).Keys()
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != writers {
		t.Fatalf("%d keys survived, want %d", len(keys), writers)
	}
}

func TestOO7KeysSkipsUndecryptableItem(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test.keyring")
	kr := oo7TestStore(t, path)
	for _, k := range []string{"a", "b", "c"} {
		if err := kr.Set(Item{Key: k, Data: []byte("x")}); err != nil {
			t.Fatal(err)
		}
	}
	f, mtime, err := readOO7File(path)
	if err != nil {
		t.Fatal(err)
	}
	f.items[1].blob[0] ^= 0xff
	if err := f.write(path, mtime); err != nil {
		t.Fatal(err)
	}
	keys, err := kr.Keys()
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 2 {
		t.Fatalf("expected the broken item to be skipped, got %v", keys)
	}
}

func TestOO7Config(t *testing.T) {
	t.Setenv("XDG_DATA_HOME", "/xdg")
	kr, err := newOO7Store(Config{ServiceName: "svc"})
	if err != nil {
		t.Fatal(err)
	}
	if kr.path != "/xdg/svc/keyrings/default.keyring" || kr.keySource != OO7KeySourceAuto {
		t.Fatalf("unexpected defaults %+v", kr)
	}
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	kr, err = newOO7Store(Config{OO7KeyringPath: "~/custom.keyring", OO7KeySource: OO7KeySourcePortal})
	if err != nil {
		t.Fatal(err)
	}
	if kr.path != filepath.Join(home, "custom.keyring") || kr.service != "keyring" {
		t.Fatalf("unexpected config %+v", kr)
	}
	if _, err := newOO7Store(Config{OO7KeySource: "tpm"}); err == nil {
		t.Fatal("expected an error for an unknown key source")
	}
}

func TestOO7AutoKeySource(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "flatpak-info")
	cgroup := filepath.Join(t.TempDir(), "cgroup")
	orig, origCgroup := oo7SandboxMarker, oo7CgroupPath
	oo7SandboxMarker, oo7CgroupPath = marker, cgroup
	t.Cleanup(func() { oo7SandboxMarker, oo7CgroupPath = orig, origCgroup })

	if oo7IsSandboxed() {
		t.Fatal("not sandboxed yet")
	}
	kr, err := newOO7Store(Config{
		ServiceName:     "keyring-test",
		OO7KeyringPath:  filepath.Join(t.TempDir(), "auto.keyring"),
		OO7PasswordFunc: FixedStringPrompt("no more secrets"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := kr.Set(Item{Key: "llamas", Data: []byte("x")}); err != nil {
		t.Fatal(err)
	}
	if kr.secretSource != OO7KeySourcePassphrase {
		t.Fatalf("unsandboxed auto used %q", kr.secretSource)
	}

	if err := os.WriteFile(marker, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if !oo7IsSandboxed() {
		t.Fatal("marker not detected")
	}

	// Sandboxed, auto asks the portal; a wrong portal secret then names the
	// portal and, in auto mode, hints at the other key source.
	origPortal := oo7PortalSecret
	oo7PortalSecret = func() ([]byte, error) { return []byte("portal secret"), nil }
	t.Cleanup(func() { oo7PortalSecret = origPortal })
	sandboxed, err := newOO7Store(Config{
		ServiceName:    "keyring-test",
		OO7KeyringPath: kr.path,
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = sandboxed.Get("llamas")
	if !errors.Is(err, ErrOO7IncorrectSecret) {
		t.Fatalf("expected ErrOO7IncorrectSecret from the portal secret, got %v", err)
	}
	if sandboxed.secretSource != OO7KeySourcePortal || !strings.Contains(err.Error(), "Secret portal") || !strings.Contains(err.Error(), "OO7KeySource") {
		t.Fatalf("sandboxed auto should have used the portal and hinted at the other source: %v", err)
	}

	// An inherited $SNAP says nothing; the cgroup decides.
	t.Setenv("SNAP", "/snap/x")
	if err := os.Remove(marker); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cgroup, []byte("0::/user.slice/user-1000.slice/user@1000.service/app.slice/vte-spawn-1.scope\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if oo7IsSandboxed() {
		t.Fatal("SNAP alone should not count as sandboxed")
	}
	if err := os.WriteFile(cgroup, []byte("0::/user.slice/user-1000.slice/user@1000.service/app.slice/snap.x.x-1.scope\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if !oo7IsSandboxed() {
		t.Fatal("snap cgroup not detected")
	}
}

// The listings are the ones ashpd tests its own check with.
func TestOO7CgroupIsSnap(t *testing.T) {
	for name, tc := range map[string]struct {
		cgroups string
		want    bool
	}{
		"v2 snap scope": {
			cgroups: "0::/user.slice/user-1000.slice/user@1000.service/apps.slice/snap.something.scope\n",
			want:    true,
		},
		"v2 no scope": {
			cgroups: "0::/user.slice/user-1000.slice/user@1000.service/apps.slice\n",
		},
		"v1 freezer": {
			cgroups: `12:pids:/user.slice/user-1000.slice/user@1000.service
11:perf_event:/
10:net_cls,net_prio:/
9:cpuset:/
8:memory:/user.slice/user-1000.slice/user@1000.service/apps.slice/apps-org.gnome.Terminal.slice/vte-spawn-228ae109-a869-4533-8988-65ea4c10b492.scope
7:rdma:/
6:devices:/user.slice
5:blkio:/user.slice
4:hugetlb:/
3:freezer:/snap.portal-test
2:cpu,cpuacct:/user.slice
1:name=systemd:/user.slice/user-1000.slice/user@1000.service/apps.slice/apps-org.gnome.Terminal.slice/vte-spawn-228ae109-a869-4533-8988-65ea4c10b492.scope
0::/user.slice/user-1000.slice/user@1000.service/apps.slice/apps-org.gnome.Terminal.slice/vte-spawn-228ae109-a869-4533-8988-65ea4c10b492.scope
`,
			want: true,
		},
		"other controller": {
			cgroups: "8:memory:/snap.something.scope\n",
		},
		"snap in a parent only": {
			cgroups: "0::/snap.something.scope/vte-spawn-1.scope\n",
		},
		"not a listing": {
			cgroups: "snap.something.scope\nx::/snap.something.scope\n",
		},
		"empty": {},
	} {
		if got := oo7CgroupIsSnap(tc.cgroups); got != tc.want {
			t.Errorf("%s: got %v want %v", name, got, tc.want)
		}
	}
}

// TestOO7Portal needs a Secret portal that can identify this process, which
// means a sandbox or a systemd app scope with a matching .desktop file:
//
//	systemd-run --user --scope --unit app-test-cc.byteness.keyringtest-$$.scope \
//	  env KEYRING_OO7_PORTAL_TEST=1 go test -run TestOO7Portal .
func TestOO7Portal(t *testing.T) {
	if os.Getenv("KEYRING_OO7_PORTAL_TEST") == "" {
		t.Skip("set KEYRING_OO7_PORTAL_TEST=1 in a sandbox or app scope with a Secret portal to run")
	}
	secret, err := oo7RetrievePortalSecret()
	if err != nil {
		t.Fatal(err)
	}
	if len(secret) == 0 {
		t.Fatal("empty secret")
	}
	again, err := oo7RetrievePortalSecret()
	if err != nil {
		t.Fatal(err)
	}
	if string(again) != string(secret) {
		t.Fatal("the portal secret is not stable across calls")
	}

	kr, err := newOO7Store(Config{
		ServiceName:    "keyring-test",
		OO7KeyringPath: filepath.Join(t.TempDir(), "portal.keyring"),
		OO7KeySource:   OO7KeySourcePortal,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := kr.Set(Item{Key: "llamas", Data: []byte("llamas are great")}); err != nil {
		t.Fatal(err)
	}
	got, err := kr.Get("llamas")
	if err != nil {
		t.Fatal(err)
	}
	if string(got.Data) != "llamas are great" {
		t.Fatalf("got %q", got.Data)
	}
}
