//go:build !keyring_noprotonpass

package keyring

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/byteness/keyring/internal/protonpass"
)

// Environment variables and defaults for the Proton Pass backend.
const (
	// ProtonPassEnvPAT is the env var holding the "pst_<token>::<key>" PAT
	// (matches the Proton Pass CLI's own variable).
	ProtonPassEnvPAT = "PROTON_PASS_PERSONAL_ACCESS_TOKEN"
	// ProtonPassEnvShareID is the env var holding the target vault's Share ID.
	ProtonPassEnvShareID = "PROTON_PASS_SHARE_ID"
	// ProtonPassEnvAPIBase optionally overrides the Proton API base URL.
	ProtonPassEnvAPIBase = "PROTON_PASS_API_BASE"
	// ProtonPassDefaultItemTitlePrefix namespaces aws-vault's items in the vault.
	ProtonPassDefaultItemTitlePrefix = "aws-vault"

	// protonPassDefaultTimeout bounds a single backend operation (which may issue
	// several HTTP calls) when no timeout is configured.
	protonPassDefaultTimeout = 30 * time.Second

	// Proton API error codes the backend recognises.
	protonCodeTooManyLogins     = 2028 // accompanies HTTP 429 "Too many recent logins"
	protonCodeHumanVerification = 9001 // human-verification / CAPTCHA challenge required
)

// Errors returned by the Proton Pass backend.
var (
	errProtonPassKeyring = errors.New("unable to create a Proton Pass keyring")
	// errEnvUnsetOrEmpty is Proton-local so the backend does not depend on a
	// symbol another backend defines (keyring_no1password removes opcommon.go).
	errEnvUnsetOrEmpty     = errors.New("environment variable unset or empty")
	ErrProtonPassNoPAT     = fmt.Errorf("%w: %w: %#v or Config.ProtonPassPAT", errProtonPassKeyring, errEnvUnsetOrEmpty, ProtonPassEnvPAT)
	ErrProtonPassNoShareID = fmt.Errorf("%w: %w: %#v or Config.ProtonPassShareID", errProtonPassKeyring, errEnvUnsetOrEmpty, ProtonPassEnvShareID)

	// ErrProtonPassShareNotAccessible is returned when the configured Share ID is
	// not among the shares the PAT can access (usually a missing access grant).
	ErrProtonPassShareNotAccessible = errors.New("proton-pass backend: configured share id is not accessible to this PAT (grant it access)")

	// ErrProtonPassRateLimited wraps Proton's "too many recent logins" response.
	// Session caching should keep operations well under the limit; hitting this
	// usually means a burst of fresh logins, so wait a few minutes before retrying.
	ErrProtonPassRateLimited = errors.New("proton-pass backend: rate limited by Proton (too many recent logins); wait a few minutes and retry")

	// ErrProtonPassSessionExpired is returned when a session is rejected as expired
	// or revoked and re-exchanging the PAT did not recover it.
	ErrProtonPassSessionExpired = errors.New("proton-pass backend: Proton session expired or revoked")

	// ErrProtonPassPATRejected is returned when Proton rejects the PAT itself
	// (invalid, expired, or revoked); mint or re-grant a personal access token.
	ErrProtonPassPATRejected = errors.New("proton-pass backend: personal access token rejected (invalid, expired, or revoked)")

	// ErrProtonPassHumanVerification is returned when Proton demands human
	// verification (CAPTCHA / 2FA), which this headless client cannot satisfy;
	// re-authenticate with the Proton Pass app or CLI to clear it.
	ErrProtonPassHumanVerification = errors.New("proton-pass backend: Proton requires human verification, which this client cannot satisfy; re-authenticate with the Proton Pass app or CLI")
)

func init() {
	supportedBackends[ProtonPassBackend] = opener(func(cfg Config) (Keyring, error) {
		return NewProtonPassKeyring(&cfg)
	})
}

// ProtonPassKeyring implements the Keyring interface backed by Proton Pass over
// its native HTTP API. Client is exported so tests can inject a mock.
type ProtonPassKeyring struct {
	Client          protonpass.API
	ShareID         string
	ItemTitlePrefix string

	pat       string
	tokenFunc PromptFunc

	apiBase string
	cache   protonSessionStore
	timeout time.Duration
	nowFunc func() time.Time // overridable in tests; nil means time.Now
}

// NewProtonPassKeyring builds a Proton Pass keyring from config + environment.
// The Share ID is required up front; the PAT is resolved lazily at first use
// (config, then env, then prompt).
func NewProtonPassKeyring(cfg *Config) (*ProtonPassKeyring, error) {
	shareID := cfg.ProtonPassShareID
	if shareID == "" {
		shareID = os.Getenv(ProtonPassEnvShareID)
	}
	if shareID == "" {
		return nil, ErrProtonPassNoShareID
	}

	apiBase := cfg.ProtonPassAPIBase
	if apiBase == "" {
		apiBase = os.Getenv(ProtonPassEnvAPIBase)
	}
	apiBase = protonpass.NormalizeAPIBase(apiBase)

	itemTitlePrefix := cfg.ProtonPassItemTitlePrefix
	if itemTitlePrefix == "" {
		itemTitlePrefix = ProtonPassDefaultItemTitlePrefix
	}

	return &ProtonPassKeyring{
		Client:          protonpass.New(apiBase),
		ShareID:         shareID,
		ItemTitlePrefix: itemTitlePrefix,
		pat:             cfg.ProtonPassPAT,
		tokenFunc:       cfg.ProtonPassTokenFunc,
		apiBase:         apiBase,
		cache:           newKeychainSessionStore(),
		timeout:         cfg.ProtonPassTimeout,
	}, nil
}

// opContext derives a per-operation context carrying the configured timeout, so
// every Proton API call an operation makes shares one deadline.
func (k ProtonPassKeyring) opContext() (context.Context, context.CancelFunc) {
	timeout := k.timeout
	if timeout <= 0 {
		timeout = protonPassDefaultTimeout
	}
	return context.WithTimeout(context.Background(), timeout)
}

// now returns the current time, allowing tests to control session-cache aging.
func (k ProtonPassKeyring) now() time.Time {
	if k.nowFunc != nil {
		return k.nowFunc()
	}
	return time.Now()
}

// resolvePAT returns the PAT from config, then env, then a prompt.
func (k ProtonPassKeyring) resolvePAT() (string, error) {
	if k.pat != "" {
		return k.pat, nil
	}
	if v := os.Getenv(ProtonPassEnvPAT); v != "" {
		return v, nil
	}
	if k.tokenFunc != nil {
		return k.tokenFunc("Enter Proton Pass personal access token")
	}
	return "", ErrProtonPassNoPAT
}

// patAndKey resolves the PAT once and derives the AES enc-key from its "::<key>"
// half. Resolving once per operation means a prompt-sourced PAT is requested at
// most once, even when an operation retries after a session expiry.
func (k ProtonPassKeyring) patAndKey() (pat string, encKey []byte, err error) {
	pat, err = k.resolvePAT()
	if err != nil {
		return "", nil, err
	}
	encKey, err = protonpass.PATKey(pat)
	if err != nil {
		return "", nil, err
	}
	return pat, encKey, nil
}

// authSession returns a usable Proton session for pat, reusing a fresh cached one
// when available and otherwise exchanging the PAT and caching the result.
// forceFresh clears the cache and forces a new exchange, recovering from a cached
// session that the server has expired or revoked. Caching is best-effort: a store
// failure degrades to a per-operation exchange, never an operation failure.
func (k ProtonPassKeyring) authSession(ctx context.Context, pat string, forceFresh bool) (*protonpass.Session, error) {
	account := protonSessionAccount(k.apiBase, pat)
	if k.cache != nil {
		if forceFresh {
			k.cache.invalidate(account)
		} else if cs, ok := k.cache.load(account); ok && cs.fresh(k.now()) {
			return cs.toSession(), nil
		}
	}
	session, err := k.Client.Authenticate(ctx, pat)
	if err != nil {
		return nil, err
	}
	if k.cache != nil {
		k.cache.save(account, newCachedSession(session, k.now()))
	}
	return session, nil
}

// isUnauthorized reports whether the API error is a 401 (by HTTP status or Proton
// code) — a session the server treats as expired or revoked.
func isUnauthorized(apiErr *protonpass.APIError) bool {
	return apiErr.Status == http.StatusUnauthorized || apiErr.Code == http.StatusUnauthorized
}

// isSessionExpired reports whether err is an authentication failure that a fresh
// PAT exchange could recover from (a session token expired or revoked server-side).
func isSessionExpired(err error) bool {
	var apiErr *protonpass.APIError
	return errors.As(err, &apiErr) && isUnauthorized(apiErr)
}

// classifyProtonErr maps a raw Proton API error to an actionable backend sentinel,
// keeping the original error unwrappable for diagnostics. Non-API errors (e.g.
// ErrProtonPassShareNotAccessible, ErrKeyNotFound) pass through unchanged.
func classifyProtonErr(err error) error {
	if err == nil {
		return nil
	}
	var apiErr *protonpass.APIError
	if !errors.As(err, &apiErr) {
		return err
	}
	switch {
	case apiErr.Status == http.StatusTooManyRequests || apiErr.Code == protonCodeTooManyLogins:
		return fmt.Errorf("%w: %w", ErrProtonPassRateLimited, err)
	case apiErr.Code == protonCodeHumanVerification:
		return fmt.Errorf("%w: %w", ErrProtonPassHumanVerification, err)
	// A PAT-rejection message is more specific than the bare status, so check it
	// before the generic 401/unauthorized case.
	case strings.Contains(strings.ToLower(apiErr.Message), "personal access token"):
		return fmt.Errorf("%w: %w", ErrProtonPassPATRejected, err)
	case isUnauthorized(apiErr):
		return fmt.Errorf("%w: %w", ErrProtonPassSessionExpired, err)
	default:
		return err
	}
}

// decryptedItem is one aws-vault item recovered from the vault: its key (the title
// with the namespace prefix stripped), the stored blob (the item note), and the
// identifiers + keys the write path needs to update or delete it in place.
type decryptedItem struct {
	key         string
	note        string
	itemID      string
	revision    int
	keyRotation int
	contentKey  []byte // the AES key Content is sealed under (per-item key, or share key for old items)
}

// openVault verifies the configured Share is accessible and decrypts every
// share-key rotation (AES-GCM with the PAT enc-key) into a rotation -> 32-byte
// share key map.
func (k ProtonPassKeyring) openVault(ctx context.Context, session *protonpass.Session, encKey []byte) (map[int][]byte, error) {
	shares, err := k.Client.ListShares(ctx, session)
	if err != nil {
		return nil, err
	}
	if !slices.ContainsFunc(shares, func(s protonpass.Share) bool { return s.ShareID == k.ShareID }) {
		return nil, ErrProtonPassShareNotAccessible
	}

	shareKeys, err := k.Client.GetShareKeys(ctx, session, k.ShareID)
	if err != nil {
		return nil, err
	}
	vaultKeys := make(map[int][]byte, len(shareKeys))
	for _, sk := range shareKeys {
		raw, err := protonpass.OpenShareKey(sk, encKey)
		if err != nil {
			return nil, fmt.Errorf("open share key (rotation %d): %w", sk.KeyRotation, err)
		}
		vaultKeys[sk.KeyRotation] = raw
	}
	return vaultKeys, nil
}

// loadVaultOnce authenticates (cache-aware), decrypts the share keys, then lists
// and decrypts every aws-vault item into its key, note, and the identifiers +
// content key the write path needs. Items whose title lacks this keyring's
// namespace prefix are dropped. forceFresh forces a new PAT exchange.
func (k ProtonPassKeyring) loadVaultOnce(ctx context.Context, pat string, encKey []byte, forceFresh bool) (session *protonpass.Session, vaultKeys map[int][]byte, items []decryptedItem, err error) {
	session, err = k.authSession(ctx, pat, forceFresh)
	if err != nil {
		return nil, nil, nil, err
	}
	vaultKeys, err = k.openVault(ctx, session, encKey)
	if err != nil {
		return nil, nil, nil, err
	}
	// Past this point vaultKeys (and any per-item keys decrypted below) hold key
	// material. If we return an error instead of handing them to the caller, zero
	// them rather than leaving them for the GC.
	defer func() {
		if err != nil {
			zeroVaultKeys(vaultKeys)
			zeroItems(items)
			session, vaultKeys, items = nil, nil, nil
		}
	}()

	revisions, err := k.Client.ListItems(ctx, session, k.ShareID)
	if err != nil {
		return session, vaultKeys, items, err
	}

	for _, rev := range revisions {
		shareKey, ok := vaultKeys[rev.KeyRotation]
		if !ok {
			continue // item encrypted under a rotation we did not fetch
		}
		content, contentKey, cerr := k.openContent(shareKey, rev)
		if cerr != nil {
			err = fmt.Errorf("item %s: %w", rev.ItemID, cerr)
			return session, vaultKeys, items, err
		}
		meta, perr := protonpass.ParseItemMetadata(content)
		if perr != nil {
			zeroBytes(contentKey) // this revision's key is not yet recorded in items
			err = fmt.Errorf("item %s: parse: %w", rev.ItemID, perr)
			return session, vaultKeys, items, err
		}
		key, ok := k.keyFromTitle(meta.Name)
		if !ok {
			continue // not an aws-vault item
		}
		items = append(items, decryptedItem{
			key:         key,
			note:        meta.Note,
			itemID:      rev.ItemID,
			revision:    rev.Revision,
			keyRotation: rev.KeyRotation,
			contentKey:  contentKey,
		})
	}
	return session, vaultKeys, items, nil
}

// withVault loads the vault, then runs fn against it exactly once. The 401 retry
// is scoped to the load phase: if loading fails because a cached session was
// expired or revoked server-side, the cache is invalidated, the PAT re-exchanged,
// and the load retried — all before any mutation runs, so a write (fn) is never
// re-issued. If fn itself fails with a session-expired error (the token died after
// the load), the cache is dropped so the next invocation re-exchanges, but fn is
// not retried, since a create may already have been applied.
func (k ProtonPassKeyring) withVault(ctx context.Context, pat string, encKey []byte, fn func(session *protonpass.Session, vaultKeys map[int][]byte, items []decryptedItem) error) error {
	session, vaultKeys, items, err := k.loadVaultOnce(ctx, pat, encKey, false)
	if err != nil && k.cache != nil && isSessionExpired(err) {
		session, vaultKeys, items, err = k.loadVaultOnce(ctx, pat, encKey, true)
	}
	if err != nil {
		return err
	}
	defer zeroVaultKeys(vaultKeys)
	defer zeroItems(items)

	err = fn(session, vaultKeys, items)
	if err != nil && k.cache != nil && isSessionExpired(err) {
		k.cache.invalidate(protonSessionAccount(k.apiBase, pat))
	}
	return err
}

// openContent decrypts one item revision's Content and returns the plaintext plus
// the key it was sealed under. Newer items wrap a per-item key (ItemKey) with the
// share key; older items have no ItemKey and their Content is opened with the share
// key directly. The returned key is what an update must re-encrypt under.
func (k ProtonPassKeyring) openContent(shareKey []byte, rev protonpass.ItemRevision) (content, contentKey []byte, err error) {
	if rev.ItemKey == "" {
		content, err = protonpass.OpenItemContent(shareKey, rev.Content)
		if err != nil {
			return nil, nil, fmt.Errorf("open content: %w", err)
		}
		return content, shareKey, nil
	}
	itemKey, err := protonpass.OpenItemKey(shareKey, rev.ItemKey)
	if err != nil {
		return nil, nil, fmt.Errorf("open item key: %w", err)
	}
	content, err = protonpass.OpenItemContent(itemKey, rev.Content)
	if err != nil {
		return nil, nil, fmt.Errorf("open content: %w", err)
	}
	return content, itemKey, nil
}

// itemTitle maps an aws-vault key to a Proton Pass item title. An empty prefix
// means the title is the key verbatim.
func (k ProtonPassKeyring) itemTitle(key string) string {
	if k.ItemTitlePrefix == "" {
		return key
	}
	return k.ItemTitlePrefix + "/" + key
}

// keyFromTitle is the inverse of itemTitle: it strips the namespace prefix,
// reporting false for titles that do not belong to this keyring.
func (k ProtonPassKeyring) keyFromTitle(title string) (string, bool) {
	if k.ItemTitlePrefix == "" {
		return title, true
	}
	return strings.CutPrefix(title, k.ItemTitlePrefix+"/")
}

// Keys lists the aws-vault item keys in the configured vault. Titles live inside
// the encrypted item content, so this fetches and decrypts every item.
func (k ProtonPassKeyring) Keys() ([]string, error) {
	pat, encKey, err := k.patAndKey()
	if err != nil {
		return nil, err
	}
	defer zeroBytes(encKey)

	ctx, cancel := k.opContext()
	defer cancel()

	var keys []string
	err = k.withVault(ctx, pat, encKey, func(_ *protonpass.Session, _ map[int][]byte, items []decryptedItem) error {
		keys = make([]string, 0, len(items))
		for _, it := range items {
			keys = append(keys, it.key)
		}
		slices.Sort(keys)
		return nil
	})
	if err != nil {
		return nil, classifyProtonErr(err)
	}
	return keys, nil
}

// Get returns the Item for key, decrypting its stored blob, or ErrKeyNotFound.
func (k ProtonPassKeyring) Get(key string) (Item, error) {
	pat, encKey, err := k.patAndKey()
	if err != nil {
		return Item{}, err
	}
	defer zeroBytes(encKey)

	ctx, cancel := k.opContext()
	defer cancel()

	var found bool
	var out Item
	err = k.withVault(ctx, pat, encKey, func(_ *protonpass.Session, _ map[int][]byte, items []decryptedItem) error {
		for _, it := range items {
			if it.key == key {
				out, found = Item{Key: key, Data: []byte(it.note)}, true
				return nil
			}
		}
		return nil
	})
	if err != nil {
		return Item{}, classifyProtonErr(err)
	}
	if !found {
		return Item{}, ErrKeyNotFound
	}
	return out, nil
}

// GetMetadata reports that Proton requires credentials even for metadata.
func (k ProtonPassKeyring) GetMetadata(_ string) (Metadata, error) {
	return Metadata{}, ErrMetadataNeedsCredentials
}

// Set creates or updates the aws-vault item for item.Key. The blob (item.Data) is
// stored as the item note inside an encrypted item-v1 protobuf. An existing item
// with the same key is updated in place (re-encrypted under its current per-item
// key); otherwise a new item is created under the current share-key rotation.
func (k ProtonPassKeyring) Set(item Item) error {
	pat, encKey, err := k.patAndKey()
	if err != nil {
		return err
	}
	defer zeroBytes(encKey)

	ctx, cancel := k.opContext()
	defer cancel()
	return classifyProtonErr(k.withVault(ctx, pat, encKey, func(session *protonpass.Session, vaultKeys map[int][]byte, items []decryptedItem) error {
		return k.setItem(ctx, session, vaultKeys, items, item)
	}))
}

// setItem performs the create-or-update against an already-loaded vault.
func (k ProtonPassKeyring) setItem(ctx context.Context, session *protonpass.Session, vaultKeys map[int][]byte, items []decryptedItem, item Item) error {
	uuid, err := protonpass.NewItemUUID()
	if err != nil {
		return err
	}
	plaintext := protonpass.EncodeItem(
		protonpass.ItemMetadata{Name: k.itemTitle(item.Key), Note: string(item.Data)}, uuid)

	if existing, ok := findItem(items, item.Key); ok {
		content, err := protonpass.SealItemContent(existing.contentKey, plaintext)
		if err != nil {
			return err
		}
		_, err = k.Client.UpdateItem(ctx, session, k.ShareID, existing.itemID, protonpass.UpdateItemRequest{
			KeyRotation:  existing.keyRotation,
			LastRevision: existing.revision,
			Content:      content,
		})
		return err
	}

	rotation, shareKey, ok := currentRotation(vaultKeys)
	if !ok {
		return fmt.Errorf("proton-pass backend: no share key available to encrypt %q", item.Key)
	}
	itemKey, err := protonpass.NewItemKey()
	if err != nil {
		return err
	}
	defer zeroBytes(itemKey)
	content, err := protonpass.SealItemContent(itemKey, plaintext)
	if err != nil {
		return err
	}
	wrappedKey, err := protonpass.SealItemKey(shareKey, itemKey)
	if err != nil {
		return err
	}
	_, err = k.Client.CreateItem(ctx, session, k.ShareID, protonpass.CreateItemRequest{
		KeyRotation: rotation,
		Content:     content,
		ItemKey:     wrappedKey,
	})
	return err
}

// Remove permanently deletes the item with the matching key, or returns
// ErrKeyNotFound if no aws-vault item carries that key.
func (k ProtonPassKeyring) Remove(key string) error {
	pat, encKey, err := k.patAndKey()
	if err != nil {
		return err
	}
	defer zeroBytes(encKey)

	ctx, cancel := k.opContext()
	defer cancel()
	return classifyProtonErr(k.withVault(ctx, pat, encKey, func(session *protonpass.Session, _ map[int][]byte, items []decryptedItem) error {
		existing, ok := findItem(items, key)
		if !ok {
			return ErrKeyNotFound
		}
		return k.Client.DeleteItem(ctx, session, k.ShareID, existing.itemID, existing.revision)
	}))
}

// zeroBytes overwrites b with zeros. Best-effort: Go's GC may already have copied
// the bytes elsewhere, but clearing the live copy shrinks the window in which
// derived key material sits in process memory.
func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// zeroVaultKeys clears every decrypted share key in m.
func zeroVaultKeys(m map[int][]byte) {
	for _, k := range m {
		zeroBytes(k)
	}
}

// zeroItems clears the per-item content key held by each decrypted item. For
// legacy items this aliases a share key (already cleared by zeroVaultKeys); a
// second zeroing is harmless. Call after fn has run, since the update path reads
// the content key.
func zeroItems(items []decryptedItem) {
	for _, it := range items {
		zeroBytes(it.contentKey)
	}
}

// findItem returns the decrypted item with the given key.
func findItem(items []decryptedItem, key string) (decryptedItem, bool) {
	for _, it := range items {
		if it.key == key {
			return it, true
		}
	}
	return decryptedItem{}, false
}

// currentRotation returns the highest share-key rotation and its key, the rotation
// a new item is encrypted under. ok is false when no share key is available.
func currentRotation(vaultKeys map[int][]byte) (rotation int, shareKey []byte, ok bool) {
	best := -1
	for rot := range vaultKeys {
		if rot > best {
			best = rot
		}
	}
	if best < 0 {
		return 0, nil, false
	}
	return best, vaultKeys[best], true
}
