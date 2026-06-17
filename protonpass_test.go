//go:build !keyring_noprotonpass

package keyring

import (
	"context"
	"errors"
	"slices"
	"testing"

	"github.com/byteness/keyring/internal/protonpass"
)

// mockProtonAPI is an injectable protonpass.API for backend tests.
type mockProtonAPI struct {
	auth   func(ctx context.Context, pat string) (*protonpass.Session, error)
	shares func(ctx context.Context, s *protonpass.Session) ([]protonpass.Share, error)
	items     func(ctx context.Context, s *protonpass.Session, shareID string) ([]protonpass.ItemRevision, error)
	shareKeys func(ctx context.Context, s *protonpass.Session, shareID string) ([]protonpass.ShareKey, error)
}

func (m mockProtonAPI) Authenticate(ctx context.Context, pat string) (*protonpass.Session, error) {
	return m.auth(ctx, pat)
}

func (m mockProtonAPI) ListShares(ctx context.Context, s *protonpass.Session) ([]protonpass.Share, error) {
	return m.shares(ctx, s)
}

func (m mockProtonAPI) ListItems(ctx context.Context, s *protonpass.Session, shareID string) ([]protonpass.ItemRevision, error) {
	return m.items(ctx, s, shareID)
}

func (m mockProtonAPI) GetShareKeys(ctx context.Context, s *protonpass.Session, shareID string) ([]protonpass.ShareKey, error) {
	if m.shareKeys != nil {
		return m.shareKeys(ctx, s, shareID)
	}
	return nil, nil
}

func TestNewProtonPassKeyring(t *testing.T) {
	t.Setenv(ProtonPassEnvShareID, "")

	if _, err := NewProtonPassKeyring(&Config{}); !errors.Is(err, ErrProtonPassNoShareID) {
		t.Fatalf("missing share id: got %v, want ErrProtonPassNoShareID", err)
	}

	k, err := NewProtonPassKeyring(&Config{ProtonPassShareID: "share1"})
	if err != nil {
		t.Fatalf("NewProtonPassKeyring: %v", err)
	}
	if k.ShareID != "share1" {
		t.Errorf("ShareID = %q, want share1", k.ShareID)
	}
	if k.ItemTitlePrefix != ProtonPassDefaultItemTitlePrefix {
		t.Errorf("ItemTitlePrefix = %q, want default %q", k.ItemTitlePrefix, ProtonPassDefaultItemTitlePrefix)
	}

	// Share ID falls back to the environment.
	t.Setenv(ProtonPassEnvShareID, "envshare")
	envK, err := NewProtonPassKeyring(&Config{})
	if err != nil {
		t.Fatalf("NewProtonPassKeyring (env): %v", err)
	}
	if envK.ShareID != "envshare" {
		t.Errorf("ShareID from env = %q, want envshare", envK.ShareID)
	}
}

func TestProtonPassRegistered(t *testing.T) {
	if !slices.Contains(AvailableBackends(), ProtonPassBackend) {
		t.Fatal("proton-pass backend not registered in AvailableBackends()")
	}
}

func TestOpenProtonPass(t *testing.T) {
	t.Setenv(ProtonPassEnvShareID, "")

	// Good config: the opener builds a *ProtonPassKeyring.
	kr, err := Open(Config{
		AllowedBackends:   []BackendType{ProtonPassBackend},
		ProtonPassShareID: "share1",
	})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if _, ok := kr.(*ProtonPassKeyring); !ok {
		t.Fatalf("Open returned %T, want *ProtonPassKeyring", kr)
	}

	// Missing required config: the opener errors, so Open finds no usable backend.
	if _, err := Open(Config{AllowedBackends: []BackendType{ProtonPassBackend}}); !errors.Is(err, ErrNoAvailImpl) {
		t.Fatalf("Open with bad config: got %v, want ErrNoAvailImpl", err)
	}
}

func TestProtonPassResolvePAT(t *testing.T) {
	t.Run("config wins over env", func(t *testing.T) {
		t.Setenv(ProtonPassEnvPAT, "pst_env::k")
		got, err := ProtonPassKeyring{pat: "pst_cfg::k"}.resolvePAT()
		if err != nil || got != "pst_cfg::k" {
			t.Fatalf("resolvePAT = %q, %v; want config value", got, err)
		}
	})
	t.Run("env fallback", func(t *testing.T) {
		t.Setenv(ProtonPassEnvPAT, "pst_env::k")
		got, err := ProtonPassKeyring{}.resolvePAT()
		if err != nil || got != "pst_env::k" {
			t.Fatalf("resolvePAT = %q, %v; want env value", got, err)
		}
	})
	t.Run("prompt fallback", func(t *testing.T) {
		t.Setenv(ProtonPassEnvPAT, "")
		k := ProtonPassKeyring{tokenFunc: func(string) (string, error) { return "pst_prompt::k", nil }}
		got, err := k.resolvePAT()
		if err != nil || got != "pst_prompt::k" {
			t.Fatalf("resolvePAT = %q, %v; want prompt value", got, err)
		}
	})
}

func TestProtonPassWriteNotImplemented(t *testing.T) {
	k := ProtonPassKeyring{ShareID: "target"}
	if err := k.Set(Item{Key: "k"}); !errors.Is(err, ErrProtonPassNotImplemented) {
		t.Errorf("Set err = %v, want ErrProtonPassNotImplemented", err)
	}
	if err := k.Remove("k"); !errors.Is(err, ErrProtonPassNotImplemented) {
		t.Errorf("Remove err = %v, want ErrProtonPassNotImplemented", err)
	}
}

func TestProtonPassKeyringKeysWiring(t *testing.T) {
	var calls []string
	k := ProtonPassKeyring{
		Client: mockProtonAPI{
			auth: func(_ context.Context, pat string) (*protonpass.Session, error) {
				calls = append(calls, "auth")
				if pat != "pst_tok::key" {
					t.Errorf("Authenticate got pat %q, want the full compound PAT", pat)
				}
				return &protonpass.Session{UID: "u", AccessToken: "a"}, nil
			},
			shares: func(_ context.Context, _ *protonpass.Session) ([]protonpass.Share, error) {
				calls = append(calls, "shares")
				return []protonpass.Share{{ShareID: "target"}}, nil
			},
			items: func(_ context.Context, _ *protonpass.Session, shareID string) ([]protonpass.ItemRevision, error) {
				calls = append(calls, "items")
				if shareID != "target" {
					t.Errorf("ListItems got shareID %q, want target", shareID)
				}
				return []protonpass.ItemRevision{{ItemID: "i"}}, nil
			},
		},
		ShareID: "target",
		pat:     "pst_tok::key",
	}

	_, err := k.Keys()
	if !errors.Is(err, ErrProtonPassNotImplemented) {
		t.Fatalf("Keys err = %v, want ErrProtonPassNotImplemented", err)
	}
	if got := len(calls); got != 3 || calls[0] != "auth" || calls[1] != "shares" || calls[2] != "items" {
		t.Fatalf("Keys did not auth->shares->items in order: %v", calls)
	}
}

func TestProtonPassKeyringShareNotAccessible(t *testing.T) {
	k := ProtonPassKeyring{
		Client: mockProtonAPI{
			auth: func(_ context.Context, _ string) (*protonpass.Session, error) {
				return &protonpass.Session{UID: "u"}, nil
			},
			shares: func(_ context.Context, _ *protonpass.Session) ([]protonpass.Share, error) {
				return []protonpass.Share{{ShareID: "someone-elses-vault"}}, nil
			},
			items: func(_ context.Context, _ *protonpass.Session, _ string) ([]protonpass.ItemRevision, error) {
				t.Error("ListItems must not be called when the share is inaccessible")
				return nil, nil
			},
		},
		ShareID: "target",
		pat:     "pst_x::y",
	}

	if _, err := k.Keys(); !errors.Is(err, ErrProtonPassShareNotAccessible) {
		t.Fatalf("Keys err = %v, want ErrProtonPassShareNotAccessible", err)
	}
}

func TestProtonPassKeyringNoPAT(t *testing.T) {
	t.Setenv(ProtonPassEnvPAT, "")
	k := ProtonPassKeyring{
		Client:  mockProtonAPI{auth: func(_ context.Context, _ string) (*protonpass.Session, error) { return nil, nil }},
		ShareID: "target",
	}
	if _, err := k.Keys(); !errors.Is(err, ErrProtonPassNoPAT) {
		t.Fatalf("Keys err = %v, want ErrProtonPassNoPAT", err)
	}
}

func TestProtonPassKeyringGetMetadata(t *testing.T) {
	k := ProtonPassKeyring{ShareID: "target"}
	if _, err := k.GetMetadata("x"); !errors.Is(err, ErrMetadataNeedsCredentials) {
		t.Fatalf("GetMetadata err = %v, want ErrMetadataNeedsCredentials", err)
	}
}
