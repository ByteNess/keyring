package keyring

import (
	"context"
	"errors"
	"fmt"
	"os"

	onepassword "github.com/1password/onepassword-sdk-go"
)

const (
	OPSrvAccountEnvToken = "OP_SERVICE_ACCOUNT_TOKEN"
)

var (
	OPSrvAccountErrClient    = errors.New("Unable to create a 1Password Service Accounts client")
	OPSrvAccountErrKeyring   = errors.New("Unable to create a 1Password Service Accounts keyring")
	OPSrvAccountErrNewClient = fmt.Errorf(
		"%w: onepassword.NewClient returned an error",
		OPSrvAccountErrClient,
	)
	OPSrvAccountErrTimeout = fmt.Errorf(
		"%w: Timeout must be a non-zero duration",
		OPSrvAccountErrKeyring,
	)
)

func init() {
	supportedBackends[OPBackend] = opener(func(cfg Config) (Keyring, error) {
		keyring, err := NewOPSrvAccountKeyring(&cfg)
		if err != nil {
			return nil, err
		}
		return keyring, nil
	})
}

// OPSrvAccountKeyring implements Keyring interface for 1Password Service Accounts
type OPSrvAccountKeyring struct {
	OPStandardKeyring
	// fullClient stores the complete client to prevent premature garbage collection
	// which would trigger the finalizer and release the client ID
	fullClient *onepassword.Client
}

// NewOPSrvAccountKeyring creates a new Service Account keyring
func NewOPSrvAccountKeyring(cfg *Config) (*OPSrvAccountKeyring, error) {
	errs := []error{}

	timeout := cfg.OPTimeout
	if timeout == 0 {
		errs = append(errs, OPSrvAccountErrTimeout)
	}

	vaultID := cfg.OPVaultID
	if vaultID == "" {
		vaultID = os.Getenv(OPEnvVaultID)
		if vaultID == "" {
			errs = append(errs, OPErrVaultID)
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

	keyring := &OPSrvAccountKeyring{
		OPStandardKeyring: OPStandardKeyring{
			OPBaseKeyring: OPBaseKeyring{
				VaultID:         vaultID,
				ItemTitlePrefix: itemTitlePrefix,
				ItemTag:         itemTag,
				ItemFieldTitle:  itemFieldTitle,
				TokenEnvs:       []string{cfg.OPTokenEnv, OPSrvAccountEnvToken},
				TokenFunc:       cfg.OPTokenFunc,
			},
			Timeout: timeout,
		},
	}

	return keyring, nil
}

// InitializeClient initializes the Service Account client
func (k *OPSrvAccountKeyring) InitializeClient() error {
	if k.Client != nil {
		return nil
	}

	token, err := k.GetOPToken("Enter 1Password service account token")
	if err != nil {
		return err
	}

	client, err := onepassword.NewClient(
		context.Background(),
		onepassword.WithIntegrationInfo(OPStandardIntegrationName, OPStandardIntegrationVersion),
		onepassword.WithServiceAccountToken(token),
	)
	if err != nil {
		return fmt.Errorf("%w: %w", OPSrvAccountErrNewClient, err)
	}

	// The full client must be retained to prevent garbage collection
	// which would trigger the finalizer and invalidate the client ID
	k.fullClient = client
	k.Client = client.Items()

	return nil
}

// Get retrieves an item by key
func (k *OPSrvAccountKeyring) Get(key string) (Item, error) {
	if err := k.InitializeClient(); err != nil {
		return Item{}, err
	}
	return k.OPStandardKeyring.Get(key)
}

// GetMetadata returns metadata for a key
func (k *OPSrvAccountKeyring) GetMetadata(key string) (Metadata, error) {
	return k.OPStandardKeyring.GetMetadata(key)
}

// Set creates or updates an item
func (k *OPSrvAccountKeyring) Set(item Item) error {
	if err := k.InitializeClient(); err != nil {
		return err
	}
	return k.OPStandardKeyring.Set(item)
}

// Remove deletes an item by key
func (k *OPSrvAccountKeyring) Remove(key string) error {
	if err := k.InitializeClient(); err != nil {
		return err
	}
	return k.OPStandardKeyring.Remove(key)
}

// Keys returns all keys in the keyring
func (k *OPSrvAccountKeyring) Keys() ([]string, error) {
	if err := k.InitializeClient(); err != nil {
		return nil, err
	}
	return k.OPStandardKeyring.Keys()
}
