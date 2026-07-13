//go:build !keyring_noprotonpass

package keyring

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"time"

	"github.com/byteness/keyring/internal/protonpass"
)

const (
	// protonSessionServiceName is the fixed keychain service under which cached
	// Proton sessions live, kept separate from any aws-vault credential items. It is
	// intentionally not derived from Config.ServiceName: the cache entry is already
	// scoped per API base and PAT (see protonSessionAccount), so one shared store
	// lets every aws-vault config reuse a single login for the same token rather
	// than re-authenticating per service name.
	protonSessionServiceName = "aws-vault-proton-pass-session"

	// protonSessionFallbackTTL bounds reuse of a cached session when the server
	// expiry is absent or implausible. A stale-but-cached session is still caught
	// by the 401 re-exchange path, so this only caps proactive re-logins; it is
	// deliberately well below typical Proton token lifetimes.
	protonSessionFallbackTTL = time.Hour

	// protonSessionExpirySkew re-exchanges slightly before the reported expiry so a
	// token does not die mid-operation.
	protonSessionExpirySkew = 60 * time.Second

	// protonSessionMaxPlausibleLifetime bounds how far from now a server expiry may
	// sit, in either direction, to be treated as a real timestamp. A value far in the
	// future (a millisecond epoch mistaken for seconds) or far in the past (a duration
	// mistaken for an epoch) is implausible and falls back to the local TTL.
	protonSessionMaxPlausibleLifetime = 30 * 24 * time.Hour
)

// protonSecureSessionBackends are the OS-protected keyring backends eligible to
// hold the cached session, in platform-preference order. File/pass-style backends
// are intentionally excluded: the cached session is a live bearer credential.
var protonSecureSessionBackends = []BackendType{
	WinCredBackend,
	WinHelloBackend,
	KeychainBackend,
	SecretServiceBackend,
	KWalletBackend,
}

// protonSessionStore persists and retrieves a cached Proton session keyed by an
// opaque, non-secret account id. Every method is best-effort: a caching failure
// must never fail the underlying keyring operation.
type protonSessionStore interface {
	load(account string) (cachedSession, bool)
	save(account string, cs cachedSession)
	invalidate(account string)
}

// cachedSession is the persisted form of an authenticated session plus the
// bookkeeping the freshness check needs. The refresh token is deliberately not
// stored: recovery re-exchanges the PAT rather than using a refresh grant, so
// persisting a long-lived refresh token would widen exposure for no benefit.
type cachedSession struct {
	UID          string `json:"uid"`
	AccessToken  string `json:"access_token"`
	AccessExpiry int64  `json:"access_expiry,omitempty"` // server epoch seconds, if plausible
	CachedAt     int64  `json:"cached_at"`               // unix seconds at save time
}

func newCachedSession(s *protonpass.Session, now time.Time) cachedSession {
	return cachedSession{
		UID:          s.UID,
		AccessToken:  s.AccessToken,
		AccessExpiry: s.AccessExpiry,
		CachedAt:     now.Unix(),
	}
}

func (cs cachedSession) toSession() *protonpass.Session {
	return &protonpass.Session{
		UID:          cs.UID,
		AccessToken:  cs.AccessToken,
		AccessExpiry: cs.AccessExpiry,
	}
}

// fresh reports whether the cached session can still be reused. It trusts the
// server expiry whenever it is a plausible epoch (within the max lifetime of now in
// either direction, so a small duration-like value or a millisecond epoch falls
// through); a real past or imminent expiry then reads as not-fresh. Only an absent
// or implausible expiry falls back to the local TTL. Either way a wrongly-fresh
// session is caught by the 401 re-exchange path.
func (cs cachedSession) fresh(now time.Time) bool {
	if cs.AccessToken == "" {
		return false
	}
	nowUnix := now.Unix()
	minPlausible := now.Add(-protonSessionMaxPlausibleLifetime).Unix()
	maxPlausible := now.Add(protonSessionMaxPlausibleLifetime).Unix()
	if cs.AccessExpiry >= minPlausible && cs.AccessExpiry <= maxPlausible {
		return nowUnix+int64(protonSessionExpirySkew.Seconds()) < cs.AccessExpiry
	}
	return now.Before(time.Unix(cs.CachedAt, 0).Add(protonSessionFallbackTTL))
}

// keyringSessionStore stores the cached session as a JSON item in an underlying
// (OS-protected) keyring.
type keyringSessionStore struct {
	kr Keyring
}

func (s *keyringSessionStore) load(account string) (cachedSession, bool) {
	item, err := s.kr.Get(account)
	if err != nil {
		return cachedSession{}, false
	}
	var cs cachedSession
	if err := json.Unmarshal(item.Data, &cs); err != nil {
		debugf("proton-pass: discarding unreadable session cache entry: %v", err)
		return cachedSession{}, false
	}
	return cs, true
}

func (s *keyringSessionStore) save(account string, cs cachedSession) {
	data, err := json.Marshal(cs)
	if err != nil {
		return
	}
	_ = s.kr.Set(Item{
		Key:         account,
		Data:        data,
		Label:       protonSessionServiceName,
		Description: "aws-vault cached Proton Pass session",
	})
}

func (s *keyringSessionStore) invalidate(account string) {
	_ = s.kr.Remove(account)
}

// newKeychainSessionStore opens an OS-protected keyring for caching the Proton
// session. It returns nil when no secure backend is available (for example a
// headless host with no Secret Service): the backend then re-exchanges the PAT on
// every operation, so calls in quick succession may hit Proton's login rate limit.
func newKeychainSessionStore() protonSessionStore {
	kr, err := Open(Config{
		ServiceName:     protonSessionServiceName,
		AllowedBackends: protonSecureSessionBackends,
	})
	if err != nil {
		debugf("proton-pass: no secure backend for session cache (%v); each operation will re-exchange the PAT", err)
		return nil
	}
	return &keyringSessionStore{kr: kr}
}

// protonSessionAccount derives a stable, non-secret keychain account id from the
// API base and the PAT's token half, so rotating the PAT or pointing at a
// different API naturally invalidates the cache. Only the "pst_<token>" half feeds
// the hash; the "::<key>" crypto half never leaves the process.
func protonSessionAccount(apiBase, pat string) string {
	sum := sha256.Sum256([]byte(apiBase + "\x00" + protonpass.PATToken(pat)))
	return hex.EncodeToString(sum[:])
}
