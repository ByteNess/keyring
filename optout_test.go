//go:build keyring_no1password && keyring_nofile && keyring_nopass && keyring_nopassage

package keyring

import (
	"errors"
	"testing"
)

// TestOptOutTagsExcludeBackends verifies that each keyring_no<backend> build tag
// de-registers its backend: the backend is absent from AvailableBackends and
// requesting it explicitly returns ErrNoAvailImpl, exactly as an unavailable
// platform backend behaves today.
func TestOptOutTagsExcludeBackends(t *testing.T) {
	excluded := []BackendType{
		OPBackend,
		OPConnectBackend,
		OPDesktopBackend,
		FileBackend,
		PassBackend,
		PassageBackend,
	}

	available := AvailableBackends()
	for _, b := range excluded {
		for _, a := range available {
			if a == b {
				t.Errorf("backend %q still registered despite opt-out tag", b)
			}
		}

		_, err := Open(Config{AllowedBackends: []BackendType{b}})
		if !errors.Is(err, ErrNoAvailImpl) {
			t.Errorf("Open with backend %q: got %v, want ErrNoAvailImpl", b, err)
		}
	}
}
