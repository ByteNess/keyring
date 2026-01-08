package keyring

import (
	"context"
	"errors"
	"fmt"
	"os"

	onepassword "github.com/1password/onepassword-sdk-go"
)

const (
	OPDesktopEnvAccountID = "OP_DESKTOP_ACCOUNT_ID"
)

var (
	OPDesktopErrAccountID = fmt.Errorf(
		"%w: %w: %#v",
		OPDesktopErrKeyring,
		ErrEnvUnsetOrEmpty,
		OPDesktopEnvAccountID,
	)

	OPDesktopErrClient    = errors.New("Unable to create a 1Password Desktop client")
	OPDesktopErrKeyring   = errors.New("Unable to create a 1Password Desktop keyring")
	OPDesktopErrNewClient = fmt.Errorf(
		"%w: onepassword.NewClient returned an error",
		OPDesktopErrClient,
	)
	OPDesktopErrTimeout = fmt.Errorf(
		"%w: Timeout must be a non-zero duration",
		OPDesktopErrKeyring,
	)
)

func init() {
	supportedBackends[OPDesktopBackend] = opener(func(cfg Config) (Keyring, error) {
		keyring, err := NewOPDesktopKeyring(&cfg)
		if err != nil {
			return nil, err
		}
		return keyring, nil
	})
}

// OPDesktopKeyring implements Keyring interface for 1Password Desktop Integration
type OPDesktopKeyring struct {
	OPStandardKeyring
	DesktopAccountID string
	// fullClient stores the complete client to prevent premature garbage collection
	// which would trigger the finalizer and release the client ID
	fullClient *onepassword.Client
}

func NewOPDesktopKeyring(cfg *Config) (*OPDesktopKeyring, error) {
	errs := []error{}

	timeout := cfg.OPTimeout
	if timeout == 0 {
		errs = append(errs, OPDesktopErrTimeout)
	}

	vaultID := cfg.OPVaultID
	if vaultID == "" {
		vaultID = os.Getenv(OPEnvVaultID)
		if vaultID == "" {
			errs = append(errs, OPErrVaultID)
		}
	}

	accountID := cfg.OPDesktopAccountID
	if accountID == "" {
		accountID = os.Getenv(OPDesktopEnvAccountID)
		if accountID == "" {
			errs = append(errs, OPDesktopErrAccountID)
		}
	}

	itemTitlePrefix := cfg.OPItemTitlePrefix
	if itemTitlePrefix == "" {
		itemTitlePrefix = OPItemTitlePrefix
	}

	itemTag := cfg.OPItemTag
	if itemTag == "" {
		itemTag = OPItemTag
	}

	itemFieldTitle := cfg.OPItemFieldTitle
	if itemFieldTitle == "" {
		itemFieldTitle = OPItemFieldTitle
	}

	if len(errs) > 0 {
		return nil, errors.Join(errs...)
	}

	keyring := &OPDesktopKeyring{
		OPStandardKeyring: OPStandardKeyring{
			OPBaseKeyring: OPBaseKeyring{
				VaultID:         vaultID,
				ItemTitlePrefix: itemTitlePrefix,
				ItemTag:         itemTag,
				ItemFieldTitle:  itemFieldTitle,
				TokenEnvs:       []string{},
				TokenFunc:       cfg.OPTokenFunc,
			},
			Timeout: timeout,
		},
		DesktopAccountID: accountID,
	}

	return keyring, nil
}

// InitializeClient initializes the Desktop Integration client
func (k *OPDesktopKeyring) InitializeClient() error {
	if k.Client != nil {
		return nil
	}

	client, err := onepassword.NewClient(
		context.Background(),
		// account name or account UUID for Desktop Integration
		onepassword.WithDesktopAppIntegration(k.DesktopAccountID),
		onepassword.WithIntegrationInfo(OPStandardIntegrationName, OPStandardIntegrationVersion),
	)
	if err != nil {
		return fmt.Errorf("%w: %w", OPDesktopErrNewClient, err)
	}

	// The full client must be retained to prevent garbage collection
	// which would trigger the finalizer and invalidate the client ID
	k.fullClient = client
	k.Client = client.Items()

	return nil
}

// Get retrieves an item by key
func (k *OPDesktopKeyring) Get(key string) (Item, error) {
	if err := k.InitializeClient(); err != nil {
		return Item{}, err
	}
	return k.OPStandardKeyring.Get(key)
}

// GetMetadata returns metadata for a key
func (k *OPDesktopKeyring) GetMetadata(key string) (Metadata, error) {
	return k.OPStandardKeyring.GetMetadata(key)
}

// Set creates or updates an item
func (k *OPDesktopKeyring) Set(item Item) error {
	if err := k.InitializeClient(); err != nil {
		return err
	}
	return k.OPStandardKeyring.Set(item)
}

// Remove deletes an item by key
func (k *OPDesktopKeyring) Remove(key string) error {
	if err := k.InitializeClient(); err != nil {
		return err
	}
	return k.OPStandardKeyring.Remove(key)
}

// Keys returns all keys in the keyring
func (k *OPDesktopKeyring) Keys() ([]string, error) {
	if err := k.InitializeClient(); err != nil {
		return nil, err
	}

	return k.OPStandardKeyring.Keys()
}
