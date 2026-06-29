//go:build !keyring_noprotonpass

package keyring

import (
	"context"
	"errors"
	"fmt"
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

	cs := cachedSession{UID: "u", AccessToken: "tok", AccessExpiry: 123, CachedAt: 456}
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
		{"implausibly far epoch falls back to TTL", cachedSession{AccessToken: "a", AccessExpiry: now.Add(60 * 24 * time.Hour).Unix(), CachedAt: now.Unix()}, true},
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

func TestZeroBytes(t *testing.T) {
	b := []byte{1, 2, 3, 4}
	zeroBytes(b)
	for i, v := range b {
		if v != 0 {
			t.Fatalf("byte %d = %d, want 0", i, v)
		}
	}
	zeroBytes(nil) // must not panic

	m := map[int][]byte{1: {9, 9}, 2: {7}}
	zeroVaultKeys(m)
	for rot, k := range m {
		for i, v := range k {
			if v != 0 {
				t.Fatalf("rotation %d byte %d = %d, want 0", rot, i, v)
			}
		}
	}
}

func TestClassifyProtonErr(t *testing.T) {
	tests := []struct {
		name   string
		apiErr *protonpass.APIError
		want   error
	}{
		{"rate limit by HTTP 429", &protonpass.APIError{Status: 429}, ErrProtonPassRateLimited},
		{"rate limit by code 2028", &protonpass.APIError{Status: 200, Code: 2028}, ErrProtonPassRateLimited},
		{"human verification code 9001", &protonpass.APIError{Status: 422, Code: 9001}, ErrProtonPassHumanVerification},
		{"session expired HTTP 401", &protonpass.APIError{Status: 401}, ErrProtonPassSessionExpired},
		{"pat rejected by message", &protonpass.APIError{Status: 400, Message: "Invalid or expired personal access token"}, ErrProtonPassPATRejected},
		{"401 carrying a PAT message is pat-rejected", &protonpass.APIError{Status: 401, Message: "Invalid or expired personal access token"}, ErrProtonPassPATRejected},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := classifyProtonErr(fmt.Errorf("op: %w", tt.apiErr))
			if !errors.Is(got, tt.want) {
				t.Errorf("classifyProtonErr = %v, want it to wrap %v", got, tt.want)
			}
			var ae *protonpass.APIError
			if !errors.As(got, &ae) {
				t.Error("classified error must still unwrap to the original APIError")
			}
		})
	}

	if classifyProtonErr(nil) != nil {
		t.Error("classifyProtonErr(nil) must be nil")
	}
	plain := errors.New("not an api error")
	if !errors.Is(classifyProtonErr(plain), plain) {
		t.Error("non-API errors must pass through unchanged")
	}
}

func TestProtonPassRateLimitSurfaced(t *testing.T) {
	m := mockProtonAPI{
		auth: func(_ context.Context, _ string) (*protonpass.Session, error) {
			return nil, &protonpass.APIError{Status: 429, Code: 2028, Message: "Too many recent logins"}
		},
	}
	k := ProtonPassKeyring{Client: m, ShareID: "target", pat: "pst_x::AAAA"}
	if _, err := k.Keys(); !errors.Is(err, ErrProtonPassRateLimited) {
		t.Fatalf("Keys err = %v, want ErrProtonPassRateLimited", err)
	}
}

func TestProtonPassOpContextDeadline(t *testing.T) {
	k := ProtonPassKeyring{timeout: 5 * time.Second}
	ctx, cancel := k.opContext()
	defer cancel()
	dl, ok := ctx.Deadline()
	if !ok {
		t.Fatal("opContext returned a context with no deadline")
	}
	if d := time.Until(dl); d <= 0 || d > 6*time.Second {
		t.Fatalf("deadline in %v, want ~5s", d)
	}

	// A zero timeout falls back to the built-in default.
	dctx, dcancel := ProtonPassKeyring{}.opContext()
	defer dcancel()
	dl2, ok := dctx.Deadline()
	if !ok || time.Until(dl2) <= 5*time.Second {
		t.Fatalf("default timeout not applied; ok=%v remaining=%v", ok, time.Until(dl2))
	}
}

func TestProtonPassTimeoutCancels(t *testing.T) {
	m := mockProtonAPI{
		auth: func(ctx context.Context, _ string) (*protonpass.Session, error) {
			<-ctx.Done() // simulate a slow Proton call that outlives the deadline
			return nil, ctx.Err()
		},
	}
	k := ProtonPassKeyring{Client: m, ShareID: "target", pat: "pst_x::AAAA", timeout: time.Millisecond}

	if _, err := k.Keys(); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Keys err = %v, want context.DeadlineExceeded", err)
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

// TestProtonPassSetRetriesLoadIssuesWriteOnce proves a stale cached session is
// recovered during the load phase and the create is issued exactly once.
func TestProtonPassSetRetriesLoadIssuesWriteOnce(t *testing.T) {
	fx := buildVaultFixture(t, nil) // empty vault: Set must create
	now := time.Unix(1_700_000_000, 0)
	store := &keyringSessionStore{kr: NewArrayKeyring(nil)}
	account := protonSessionAccount("", fx.pat)
	store.save(account, newCachedSession(&protonpass.Session{UID: "stale", AccessToken: "stale-token"}, now))

	var authCalls, shareCalls, createCalls int
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
	m.create = func(_ context.Context, _ *protonpass.Session, _ string, _ protonpass.CreateItemRequest) (*protonpass.ItemRevision, error) {
		createCalls++
		return &protonpass.ItemRevision{ItemID: "new", Revision: 1}, nil
	}
	k := ProtonPassKeyring{Client: *m, ShareID: "target", ItemTitlePrefix: "aws-vault", pat: fx.pat, cache: store, nowFunc: func() time.Time { return now }}

	if err := k.Set(Item{Key: "dev", Data: []byte("blob")}); err != nil {
		t.Fatalf("Set after stale-session retry: %v", err)
	}
	if authCalls != 1 {
		t.Fatalf("Authenticate called %d times, want 1 (re-exchange during load)", authCalls)
	}
	if shareCalls != 2 {
		t.Fatalf("ListShares called %d times, want 2 (stale 401, then fresh)", shareCalls)
	}
	if createCalls != 1 {
		t.Fatalf("CreateItem called %d times, want exactly 1 (write must not be re-issued)", createCalls)
	}
}

// TestProtonPassWritePhase401NotRetried proves a 401 raised by the write itself is
// not retried (the create may already be applied); the cache is dropped so the next
// invocation re-exchanges, and the error is surfaced as session-expired.
func TestProtonPassWritePhase401NotRetried(t *testing.T) {
	fx := buildVaultFixture(t, nil)
	now := time.Unix(1_700_000_000, 0)
	store := &keyringSessionStore{kr: NewArrayKeyring(nil)}
	account := protonSessionAccount("", fx.pat)
	store.save(account, newCachedSession(&protonpass.Session{UID: "u", AccessToken: "good-token"}, now))

	var authCalls, createCalls int
	m := readMock(fx)
	m.auth = func(_ context.Context, _ string) (*protonpass.Session, error) {
		authCalls++
		return &protonpass.Session{UID: "u2", AccessToken: "good-token-2"}, nil
	}
	m.create = func(_ context.Context, _ *protonpass.Session, _ string, _ protonpass.CreateItemRequest) (*protonpass.ItemRevision, error) {
		createCalls++
		return nil, &protonpass.APIError{Status: 401, Code: 401, Message: "Invalid access token"}
	}
	k := ProtonPassKeyring{Client: *m, ShareID: "target", ItemTitlePrefix: "aws-vault", pat: fx.pat, cache: store, nowFunc: func() time.Time { return now }}

	err := k.Set(Item{Key: "dev", Data: []byte("blob")})
	if !errors.Is(err, ErrProtonPassSessionExpired) {
		t.Fatalf("Set err = %v, want ErrProtonPassSessionExpired", err)
	}
	if createCalls != 1 {
		t.Fatalf("CreateItem called %d times, want exactly 1 (write-phase 401 must not retry)", createCalls)
	}
	if authCalls != 0 {
		t.Fatalf("Authenticate called %d times, want 0 (load used the cached session)", authCalls)
	}
	if _, ok := store.load(account); ok {
		t.Fatal("cache must be invalidated after a write-phase 401")
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
