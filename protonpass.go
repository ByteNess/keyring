//go:build !keyring_noprotonpass

package keyring

import (
	"context"
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"

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
)

// Errors returned by the Proton Pass backend.
var (
	// ErrProtonPassNotImplemented marks the unimplemented write path (Set/Remove).
	ErrProtonPassNotImplemented = errors.New("proton-pass backend: operation not yet implemented")

	errProtonPassKeyring   = errors.New("unable to create a Proton Pass keyring")
	ErrProtonPassNoPAT     = fmt.Errorf("%w: %w: %#v or Config.ProtonPassPAT", errProtonPassKeyring, ErrEnvUnsetOrEmpty, ProtonPassEnvPAT)
	ErrProtonPassNoShareID = fmt.Errorf("%w: %w: %#v or Config.ProtonPassShareID", errProtonPassKeyring, ErrEnvUnsetOrEmpty, ProtonPassEnvShareID)

	// ErrProtonPassShareNotAccessible is returned when the configured Share ID is
	// not among the shares the PAT can access (usually a missing access grant).
	ErrProtonPassShareNotAccessible = errors.New("proton-pass backend: configured share id is not accessible to this PAT (grant it access)")
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
	}, nil
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

// session resolves the PAT, exchanges it for a Proton session, and derives the AES
// enc-key from the PAT's "::<key>" half. Every operation authenticates afresh; there
// is no session caching yet.
func (k ProtonPassKeyring) session(ctx context.Context) (*protonpass.Session, []byte, error) {
	pat, err := k.resolvePAT()
	if err != nil {
		return nil, nil, err
	}
	encKey, err := protonpass.PATKey(pat)
	if err != nil {
		return nil, nil, err
	}
	session, err := k.Client.Authenticate(ctx, pat)
	if err != nil {
		return nil, nil, err
	}
	return session, encKey, nil
}

// decryptedItem is one aws-vault item recovered from the vault: its key (the title
// with the namespace prefix stripped) and the stored blob (the item note).
type decryptedItem struct {
	key  string
	note string
}

// openVault authenticates, verifies the configured Share is accessible, and
// decrypts every share-key rotation (AES-GCM with the PAT enc-key) into a
// rotation -> 32-byte share key map.
func (k ProtonPassKeyring) openVault(ctx context.Context) (*protonpass.Session, map[int][]byte, error) {
	session, encKey, err := k.session(ctx)
	if err != nil {
		return nil, nil, err
	}
	shares, err := k.Client.ListShares(ctx, session)
	if err != nil {
		return nil, nil, err
	}
	if !slices.ContainsFunc(shares, func(s protonpass.Share) bool { return s.ShareID == k.ShareID }) {
		return nil, nil, ErrProtonPassShareNotAccessible
	}

	shareKeys, err := k.Client.GetShareKeys(ctx, session, k.ShareID)
	if err != nil {
		return nil, nil, err
	}
	vaultKeys := make(map[int][]byte, len(shareKeys))
	for _, sk := range shareKeys {
		raw, err := protonpass.OpenShareKey(sk, encKey)
		if err != nil {
			return nil, nil, fmt.Errorf("open share key (rotation %d): %w", sk.KeyRotation, err)
		}
		vaultKeys[sk.KeyRotation] = raw
	}
	return session, vaultKeys, nil
}

// readItems lists the vault's items and decrypts each into its key + note,
// dropping items whose title does not carry this keyring's namespace prefix.
func (k ProtonPassKeyring) readItems(ctx context.Context) ([]decryptedItem, error) {
	session, vaultKeys, err := k.openVault(ctx)
	if err != nil {
		return nil, err
	}
	revisions, err := k.Client.ListItems(ctx, session, k.ShareID)
	if err != nil {
		return nil, err
	}

	var items []decryptedItem
	for _, rev := range revisions {
		shareKey, ok := vaultKeys[rev.KeyRotation]
		if !ok {
			continue // item encrypted under a rotation we did not fetch
		}
		content, err := k.openContent(shareKey, rev)
		if err != nil {
			return nil, fmt.Errorf("item %s: %w", rev.ItemID, err)
		}
		meta, err := protonpass.ParseItemMetadata(content)
		if err != nil {
			return nil, fmt.Errorf("item %s: parse: %w", rev.ItemID, err)
		}
		key, ok := k.keyFromTitle(meta.Name)
		if !ok {
			continue // not an aws-vault item
		}
		items = append(items, decryptedItem{key: key, note: meta.Note})
	}
	return items, nil
}

// openContent decrypts one item revision's Content. Newer items wrap a per-item
// key (ItemKey) with the share key; older items have no ItemKey and their Content
// is opened with the share key directly.
func (k ProtonPassKeyring) openContent(shareKey []byte, rev protonpass.ItemRevision) ([]byte, error) {
	if rev.ItemKey == "" {
		content, err := protonpass.OpenItemContent(shareKey, rev.Content)
		if err != nil {
			return nil, fmt.Errorf("open content: %w", err)
		}
		return content, nil
	}
	itemKey, err := protonpass.OpenItemKey(shareKey, rev.ItemKey)
	if err != nil {
		return nil, fmt.Errorf("open item key: %w", err)
	}
	content, err := protonpass.OpenItemContent(itemKey, rev.Content)
	if err != nil {
		return nil, fmt.Errorf("open content: %w", err)
	}
	return content, nil
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
	items, err := k.readItems(context.Background())
	if err != nil {
		return nil, err
	}
	keys := make([]string, 0, len(items))
	for _, it := range items {
		keys = append(keys, it.key)
	}
	slices.Sort(keys)
	return keys, nil
}

// Get returns the Item for key, decrypting its stored blob, or ErrKeyNotFound.
func (k ProtonPassKeyring) Get(key string) (Item, error) {
	items, err := k.readItems(context.Background())
	if err != nil {
		return Item{}, err
	}
	for _, it := range items {
		if it.key == key {
			return Item{Key: key, Data: []byte(it.note)}, nil
		}
	}
	return Item{}, ErrKeyNotFound
}

// GetMetadata reports that Proton requires credentials even for metadata.
func (k ProtonPassKeyring) GetMetadata(_ string) (Metadata, error) {
	return Metadata{}, ErrMetadataNeedsCredentials
}

// Set creates or updates an item; not yet implemented.
func (k ProtonPassKeyring) Set(_ Item) error {
	return ErrProtonPassNotImplemented
}

// Remove deletes the item with the matching key; not yet implemented.
func (k ProtonPassKeyring) Remove(_ string) error {
	return ErrProtonPassNotImplemented
}
