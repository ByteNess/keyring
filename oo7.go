//go:build linux && !keyring_nooo7

package keyring

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const (
	oo7ItemSchema      = "cc.byteness.keyring"
	oo7ItemContentType = "application/json"
)

func init() {
	supportedBackends[OO7Backend] = opener(func(cfg Config) (Keyring, error) {
		return newOO7Store(cfg)
	})
}

// oo7Store stores items in an oo7 keyring file, the format used by oo7-daemon
// (the Secret Service implementation that replaces gnome-keyring on GNOME).
// Every operation reloads the file, so several processes can share it; writers
// hold a lock on a sibling .lock file and replace the file atomically. The lock
// is private to this library: oo7-daemon and oo7-cli do not take it, so the
// file should be one of our own rather than a keyring the daemon manages,
// which is why the default path stays out of the directory the daemon scans.
type oo7Store struct {
	path         string
	service      string
	keySource    string
	passwordFunc PromptFunc

	secret       []byte
	secretSource string

	key           []byte
	keySalt       []byte
	keyIterations uint32
}

func newOO7Store(cfg Config) (*oo7Store, error) {
	if cfg.ServiceName == "" {
		cfg.ServiceName = "keyring"
	}
	path := cfg.OO7KeyringPath
	var err error
	if path == "" {
		path, err = OO7DefaultKeyringPath(cfg.ServiceName)
	} else {
		path, err = ExpandTilde(path)
	}
	if err != nil {
		return nil, err
	}
	source := cfg.OO7KeySource
	switch source {
	case "":
		source = OO7KeySourceAuto
	case OO7KeySourceAuto, OO7KeySourcePortal, OO7KeySourcePassphrase:
	default:
		return nil, fmt.Errorf("oo7: unknown key source %q (expected %s, %s or %s)",
			source, OO7KeySourceAuto, OO7KeySourcePortal, OO7KeySourcePassphrase)
	}
	return &oo7Store{
		path:         path,
		service:      cfg.ServiceName,
		keySource:    source,
		passwordFunc: cfg.OO7PasswordFunc,
	}, nil
}

// resolveSecret obtains the keyring secret once per process.
func (s *oo7Store) resolveSecret() ([]byte, error) {
	if s.secret != nil {
		return s.secret, nil
	}
	var (
		secret []byte
		source string
		err    error
	)
	switch s.keySource {
	case OO7KeySourcePortal:
		secret, err = oo7PortalSecret()
		source = OO7KeySourcePortal
	case OO7KeySourcePassphrase:
		secret, source, err = s.passphrase()
	default:
		// The Secret portal only hands out secrets to applications it can
		// identify, which in practice means sandboxed ones; a host process
		// is identified by the desktop app that launched it, if any, which is
		// the wrong identity for a command line tool. Mirror oo7's own
		// Keyring::new(): portal when sandboxed, otherwise not.
		if oo7IsSandboxed() {
			secret, err = oo7PortalSecret()
			source = OO7KeySourcePortal
		} else {
			secret, source, err = s.passphrase()
		}
	}
	if err != nil {
		return nil, err
	}
	s.secret, s.secretSource = secret, source
	return secret, nil
}

// oo7SandboxMarker exists inside a Flatpak sandbox; a Snap is recognised by
// the cgroup listed in oo7CgroupPath instead.
var (
	oo7SandboxMarker = "/.flatpak-info"
	oo7CgroupPath    = "/proc/self/cgroup"
)

// oo7IsSandboxed follows ashpd::is_sandboxed(), which is what oo7 calls.
func oo7IsSandboxed() bool {
	if _, err := os.Stat(oo7SandboxMarker); err == nil {
		return true
	}
	cgroups, err := os.ReadFile(oo7CgroupPath)
	if err != nil {
		return false
	}
	return oo7CgroupIsSnap(string(cgroups))
}

// oo7CgroupIsSnap reports whether a /proc/<pid>/cgroup listing places the
// process in one of the snap.* scopes snapd starts applications in. $SNAP is
// not consulted: it is inherited by processes that have since left the scope.
func oo7CgroupIsSnap(cgroups string) bool {
	for _, line := range strings.Split(cgroups, "\n") {
		id, rest, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		if _, err := strconv.ParseUint(id, 10, 32); err != nil {
			continue
		}
		controller, unit, ok := strings.Cut(rest, ":")
		if !ok {
			continue
		}
		switch controller {
		case "", "freezer", "name=systemd":
		default:
			continue
		}
		if strings.HasPrefix(path.Base(unit), "snap.") {
			return true
		}
	}
	return false
}

func (s *oo7Store) passphrase() ([]byte, string, error) {
	if s.passwordFunc == nil {
		return nil, "", errors.New("oo7: no passphrase prompt is configured (set OO7PasswordFunc, or OO7KeySource to portal)")
	}
	pwd, err := s.passwordFunc(fmt.Sprintf("Enter passphrase to unlock %q", s.path))
	if err != nil {
		return nil, "", err
	}
	if pwd == "" {
		return nil, "", errors.New("oo7: the keyring passphrase must not be empty")
	}
	return []byte(pwd), OO7KeySourcePassphrase, nil
}

// keyFor derives (and caches) the encryption key for the file's KDF parameters.
func (s *oo7Store) keyFor(f *oo7File) ([]byte, error) {
	if s.key != nil && bytes.Equal(s.keySalt, f.salt) && s.keyIterations == f.iterationCount {
		return s.key, nil
	}
	secret, err := s.resolveSecret()
	if err != nil {
		return nil, err
	}
	key, err := f.deriveKey(secret)
	if err != nil {
		return nil, err
	}
	s.key, s.keySalt, s.keyIterations = key, append([]byte(nil), f.salt...), f.iterationCount
	return key, nil
}

// open loads and unlocks the keyring file. A missing file is returned as an
// empty keyring with a zero mtime and no key, so reads of a keyring that does
// not exist yet never prompt for a secret; create makes it resolve the key
// anyway so a write can follow.
func (s *oo7Store) open(create bool) (*oo7File, time.Time, []byte, error) {
	f, mtime, err := readOO7File(s.path)
	if err != nil {
		return nil, time.Time{}, nil, err
	}
	if mtime.IsZero() && !create {
		return f, mtime, nil, nil
	}
	key, err := s.keyFor(f)
	if err != nil {
		return nil, time.Time{}, nil, err
	}
	if err := f.validateItems(key); err != nil {
		if errors.Is(err, ErrOO7IncorrectSecret) {
			// Forget the secret so the next call asks again instead of
			// failing with a typo for the rest of the process.
			s.secret, s.key = nil, nil
			return nil, time.Time{}, nil, s.incorrectSecretError(err)
		}
		return nil, time.Time{}, nil, err
	}
	return f, mtime, key, nil
}

func (s *oo7Store) incorrectSecretError(err error) error {
	what := "wrong passphrase for"
	if s.secretSource == OO7KeySourcePortal {
		what = "the Secret portal's secret does not open"
	}
	if s.keySource == OO7KeySourceAuto {
		return fmt.Errorf("%w: %s %s; if it was created with the other key source, set OO7KeySource explicitly", err, what, s.path)
	}
	return fmt.Errorf("%w: %s %s", err, what, s.path)
}

// update applies fn to the keyring and writes it back while holding the
// keyring's lock, so concurrent writers queue up instead of overwriting each
// other. The secret is resolved first, so a writer waiting at the passphrase
// prompt does not hold the lock meanwhile. A keyring left without items is
// deleted rather than written, so an empty file cannot silently adopt
// whatever secret the next writer uses.
func (s *oo7Store) update(fn func(f *oo7File, key []byte) error) error {
	if _, err := s.resolveSecret(); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(s.path), 0o700); err != nil {
		return err
	}
	lock, err := oo7LockFile(s.path + ".lock")
	if err != nil {
		return err
	}
	defer func() { _ = lock.Unlock() }()

	f, mtime, key, err := s.open(true)
	if err != nil {
		return err
	}
	if err := fn(f, key); err != nil {
		return err
	}
	if len(f.items) == 0 {
		return removeOO7File(s.path, mtime)
	}
	return f.write(s.path, mtime)
}

func (s *oo7Store) searchAttributes(key string) map[string]string {
	return map[string]string{
		oo7SchemaAttribute: oo7ItemSchema,
		"service":          s.service,
		"key":              key,
	}
}

func (f *oo7File) removeMatching(attributes map[string]string, key []byte) int {
	kept := f.items[:0]
	removed := 0
	for _, it := range f.items {
		if it.matches(attributes, key) {
			removed++
			continue
		}
		kept = append(kept, it)
	}
	f.items = kept
	return removed
}

func (s *oo7Store) Get(key string) (Item, error) {
	f, mtime, k, err := s.open(false)
	if err != nil {
		return Item{}, err
	}
	if mtime.IsZero() {
		return Item{}, ErrKeyNotFound
	}
	attrs := s.searchAttributes(key)
	for i := range f.items {
		if !f.items[i].matches(attrs, k) {
			continue
		}
		item, err := f.items[i].decrypt(k)
		if err != nil {
			return Item{}, err
		}
		var ret Item
		if err := json.Unmarshal(item.secret, &ret); err != nil {
			return Item{}, err
		}
		return ret, nil
	}
	return Item{}, ErrKeyNotFound
}

// GetMetadata reports that metadata needs credentials: whether a key exists
// and when it changed are only known after decrypting the items.
func (s *oo7Store) GetMetadata(_ string) (Metadata, error) {
	return Metadata{}, ErrMetadataNeedsCredentials
}

func (s *oo7Store) Set(item Item) error {
	data, err := json.Marshal(item)
	if err != nil {
		return err
	}
	attrs := s.searchAttributes(item.Key)
	return s.update(func(f *oo7File, key []byte) error {
		f.removeMatching(attrs, key)
		enc, err := newOO7Item(item.Key, attrs, data, oo7ItemContentType).encrypt(key)
		if err != nil {
			return err
		}
		f.items = append(f.items, enc)
		return nil
	})
}

func (s *oo7Store) Remove(key string) error {
	if _, err := os.Stat(s.path); os.IsNotExist(err) {
		return ErrKeyNotFound
	}
	attrs := s.searchAttributes(key)
	return s.update(func(f *oo7File, k []byte) error {
		if f.removeMatching(attrs, k) == 0 {
			return ErrKeyNotFound
		}
		return nil
	})
}

func (s *oo7Store) Keys() ([]string, error) {
	f, mtime, k, err := s.open(false)
	if err != nil {
		return nil, err
	}
	keys := []string{}
	if mtime.IsZero() {
		return keys, nil
	}
	mine := map[string]string{oo7SchemaAttribute: oo7ItemSchema, "service": s.service}
	for i := range f.items {
		if !f.items[i].matches(mine, k) {
			continue
		}
		item, err := f.items[i].decrypt(k)
		if err != nil {
			debugf("oo7: skipping undecryptable item: %v", err)
			continue
		}
		keys = append(keys, item.attributes["key"])
	}
	return keys, nil
}
