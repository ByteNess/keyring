//go:build !keyring_noprotonpass

package keyring

import (
	"context"
	"slices"
	"testing"
	"time"

	"github.com/byteness/keyring/internal/protonpass"
)

func TestKeyringSessionStoreRoundTrip(t *testing.T) {
	store := &keyringSessionStore{kr: NewArrayKeyring(nil)}

	if _, ok := store.load("acct"); ok {
		t.Fatal("load on empty store returned ok")
	}

	cs := cachedSession{UID: "u", AccessToken: "tok", RefreshToken: "rt", AccessExpiry: 123, CachedAt: 456}
	store.save("acct", cs)

	got, ok := store.load("acct")
	if !ok || got != cs {
		t.Fatalf("round trip = %+v ok=%v, want %+v", got, ok, cs)
	}

	store.invalidate("acct")
	if _, ok := store.load("acct"); ok {
		t.Fatal("load after invalidate returned ok")
	}
}

func TestCachedSessionFresh(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	tests := []struct {
		name string
		cs   cachedSession
		want bool
	}{
		{"empty token is never fresh", cachedSession{AccessToken: "", CachedAt: now.Unix()}, false},
		{"future epoch beyond skew", cachedSession{AccessToken: "a", AccessExpiry: now.Unix() + 3600}, true},
		{"future epoch within skew", cachedSession{AccessToken: "a", AccessExpiry: now.Unix() + 30}, false},
		{"duration-like value falls back to TTL", cachedSession{AccessToken: "a", AccessExpiry: 3600, CachedAt: now.Unix()}, true},
		{"no expiry, fresh within TTL", cachedSession{AccessToken: "a", CachedAt: now.Unix() - 60}, true},
		{"no expiry, stale past TTL", cachedSession{AccessToken: "a", CachedAt: now.Add(-2 * time.Hour).Unix()}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.cs.fresh(now); got != tt.want {
				t.Errorf("fresh() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestProtonSessionAccount(t *testing.T) {
	a := protonSessionAccount("https://api", "pst_one::k")
	if a != protonSessionAccount("https://api", "pst_one::different-crypto-half") {
		t.Error("account must depend only on the pst_ token half, not the ::<key> crypto half")
	}
	if a == protonSessionAccount("https://api", "pst_two::k") {
		t.Error("a different PAT token must produce a different account")
	}
	if a == protonSessionAccount("https://other", "pst_one::k") {
		t.Error("a different API base must produce a different account")
	}
}

// TestProtonPassSessionCacheReuse proves the headline 429 fix: a second operation
// reuses the cached session instead of re-exchanging the PAT.
func TestProtonPassSessionCacheReuse(t *testing.T) {
	fx := buildVaultFixture(t, map[string]string{"aws-vault/dev": "blob"})
	m := readMock(fx)
	var authCalls int
	base := m.auth
	m.auth = func(ctx context.Context, pat string) (*protonpass.Session, error) {
		authCalls++
		return base(ctx, pat)
	}
	now := time.Unix(1_700_000_000, 0)
	k := ProtonPassKeyring{
		Client:          *m,
		ShareID:         "target",
		ItemTitlePrefix: "aws-vault",
		pat:             fx.pat,
		cache:           &keyringSessionStore{kr: NewArrayKeyring(nil)},
		nowFunc:         func() time.Time { return now },
	}

	if _, err := k.Keys(); err != nil {
		t.Fatalf("Keys: %v", err)
	}
	if _, err := k.Get("dev"); err != nil {
		t.Fatalf("Get: %v", err)
	}
	if authCalls != 1 {
		t.Fatalf("Authenticate called %d times across two operations, want 1 (session cached)", authCalls)
	}
}

// TestProtonPassSessionCacheNilNoReuse confirms that without a cache the backend
// behaves as before: it re-exchanges on every operation.
func TestProtonPassSessionCacheNilNoReuse(t *testing.T) {
	fx := buildVaultFixture(t, map[string]string{"aws-vault/dev": "blob"})
	m := readMock(fx)
	var authCalls int
	base := m.auth
	m.auth = func(ctx context.Context, pat string) (*protonpass.Session, error) {
		authCalls++
		return base(ctx, pat)
	}
	k := ProtonPassKeyring{Client: *m, ShareID: "target", ItemTitlePrefix: "aws-vault", pat: fx.pat}

	if _, err := k.Keys(); err != nil {
		t.Fatalf("Keys: %v", err)
	}
	if _, err := k.Get("dev"); err != nil {
		t.Fatalf("Get: %v", err)
	}
	if authCalls != 2 {
		t.Fatalf("Authenticate called %d times, want 2 (no cache configured)", authCalls)
	}
}

// TestProtonPassSessionCacheRetriesOn401 proves a cached-but-revoked session is
// recovered: the 401 invalidates the cache, the PAT is re-exchanged once, and the
// operation retries and succeeds.
func TestProtonPassSessionCacheRetriesOn401(t *testing.T) {
	fx := buildVaultFixture(t, map[string]string{"aws-vault/dev": "blob"})
	now := time.Unix(1_700_000_000, 0)
	store := &keyringSessionStore{kr: NewArrayKeyring(nil)}

	account := protonSessionAccount("", fx.pat)
	store.save(account, newCachedSession(&protonpass.Session{UID: "stale", AccessToken: "stale-token"}, now))

	var authCalls, shareCalls int
	m := readMock(fx)
	m.auth = func(_ context.Context, _ string) (*protonpass.Session, error) {
		authCalls++
		return &protonpass.Session{UID: "fresh", AccessToken: "fresh-token"}, nil
	}
	m.shares = func(_ context.Context, s *protonpass.Session) ([]protonpass.Share, error) {
		shareCalls++
		if s.AccessToken == "stale-token" {
			return nil, &protonpass.APIError{Status: 401, Code: 401, Message: "Invalid access token"}
		}
		return []protonpass.Share{{ShareID: "target", ContentKeyRotation: 1}}, nil
	}
	k := ProtonPassKeyring{
		Client:          *m,
		ShareID:         "target",
		ItemTitlePrefix: "aws-vault",
		pat:             fx.pat,
		cache:           store,
		nowFunc:         func() time.Time { return now },
	}

	keys, err := k.Keys()
	if err != nil {
		t.Fatalf("Keys after stale-session retry: %v", err)
	}
	if !slices.Equal(keys, []string{"dev"}) {
		t.Fatalf("Keys = %v, want [dev]", keys)
	}
	if authCalls != 1 {
		t.Fatalf("Authenticate called %d times, want 1 (single re-exchange after 401)", authCalls)
	}
	if shareCalls != 2 {
		t.Fatalf("ListShares called %d times, want 2 (stale 401, then fresh)", shareCalls)
	}
	if cs, ok := store.load(account); !ok || cs.AccessToken != "fresh-token" {
		t.Fatalf("cache not refreshed after retry: %+v ok=%v", cs, ok)
	}
}
