//go:build !keyring_noprotonpass

package keyring

import (
	"context"
	"errors"
	"fmt"
	"os"
	"slices"

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
	// ErrProtonPassNotImplemented marks the read-decrypt and write paths that
	// land in later phases (Phase 2/3); the auth + listing transport is wired.
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

// authenticate resolves the PAT and exchanges it for a session.
// Session caching/refresh is Phase 5; for now every operation authenticates.
func (k ProtonPassKeyring) authenticate(ctx context.Context) (*protonpass.Session, error) {
	pat, err := k.resolvePAT()
	if err != nil {
		return nil, err
	}
	return k.Client.Authenticate(ctx, pat)
}

// requireShare authenticates and confirms the configured Share ID is accessible.
func (k ProtonPassKeyring) requireShare(ctx context.Context) (*protonpass.Session, error) {
	session, err := k.authenticate(ctx)
	if err != nil {
		return nil, err
	}
	shares, err := k.Client.ListShares(ctx, session)
	if err != nil {
		return nil, err
	}
	accessible := slices.ContainsFunc(shares, func(s protonpass.Share) bool {
		return s.ShareID == k.ShareID
	})
	if !accessible {
		return nil, ErrProtonPassShareNotAccessible
	}
	return session, nil
}

// Keys lists the keyring items in the configured vault.
//
// The transport (authenticate, verify share access, list items) is wired; turning
// item titles into keys requires the OpenPGP/AES-GCM unwrap chain, which lands in
// Phase 2. Until then this validates connectivity and returns
// ErrProtonPassNotImplemented.
func (k ProtonPassKeyring) Keys() ([]string, error) {
	ctx := context.Background()
	session, err := k.requireShare(ctx)
	if err != nil {
		return nil, err
	}
	if _, err := k.Client.ListItems(ctx, session, k.ShareID); err != nil {
		return nil, err
	}
	return nil, ErrProtonPassNotImplemented
}

// Get returns the Item for key. Decryption of item content is Phase 2.
func (k ProtonPassKeyring) Get(_ string) (Item, error) {
	if _, err := k.requireShare(context.Background()); err != nil {
		return Item{}, err
	}
	return Item{}, ErrProtonPassNotImplemented
}

// GetMetadata reports that Proton requires credentials even for metadata.
func (k ProtonPassKeyring) GetMetadata(_ string) (Metadata, error) {
	return Metadata{}, ErrMetadataNeedsCredentials
}

// Set creates or updates an item. The write path is Phase 3.
func (k ProtonPassKeyring) Set(_ Item) error {
	return ErrProtonPassNotImplemented
}

// Remove deletes the item with the matching key. The write path is Phase 3.
func (k ProtonPassKeyring) Remove(_ string) error {
	return ErrProtonPassNotImplemented
}
