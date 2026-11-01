//go:build !freebsd && !keyring_no1password

package keyring

import (
	"errors"
	"fmt"
	"os"
	"slices"
	"time"

	"github.com/1Password/connect-sdk-go/connect"
	connectop "github.com/1Password/connect-sdk-go/onepassword"
	onepassword "github.com/1password/onepassword-sdk-go"
)

// Environment variable names and item conventions for the 1Password Connect backend.
const (
	OPConnectEnvHost       = "OP_CONNECT_HOST"
	OPConnectEnvToken      = "OP_CONNECT_TOKEN"
	OPConnectItemCategory  = connectop.ApiCredential
	OPConnectItemFieldType = connectop.FieldTypeConcealed
)

// Errors returned by the 1Password Connect backend.
var (
	OPConnectErrHost = fmt.Errorf(
		"%w: %w: %#v",
		OPConnectErrKeyring,
		ErrEnvUnsetOrEmpty,
		OPConnectEnvHost,
	)
	OPConnectErrKeyring = errors.New("unable to create a 1Password Connect keyring")
)

func init() {
	supportedBackends[OPConnectBackend] = opener(func(cfg Config) (Keyring, error) {
		keyring, err := NewOPConnectKeyring(&cfg)
		if err != nil {
			return nil, err
		}
		return *keyring, nil
	})
}

// OPConnectKeyring implements the Keyring interface for 1Password Connect.
type OPConnectKeyring struct {
	OPBaseKeyring
	Host   string
	Client OPConnectClientAPI
}

// NewOPConnectKeyring creates a new 1Password Connect keyring.
func NewOPConnectKeyring(cfg *Config) (*OPConnectKeyring, error) {
	errs := []error{}

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

	host := cfg.OPConnectHost
	if host == "" {
		host = os.Getenv(OPConnectEnvHost)
		if host == "" {
			errs = append(errs, OPConnectErrHost)
		}
	}

	if len(errs) > 0 {
		return nil, errors.Join(errs...)
	}

	keyring := &OPConnectKeyring{
		OPBaseKeyring: OPBaseKeyring{
			VaultID:         vaultID,
			ItemTitlePrefix: itemTitlePrefix,
			ItemTag:         itemTag,
			ItemFieldTitle:  itemFieldTitle,
			TokenEnvs:       []string{cfg.OPConnectTokenEnv, OPConnectEnvToken},
			TokenFunc:       cfg.OPTokenFunc,
		},
		Host: host,
	}

	return keyring, nil
}

// InitializeOPConnectClient initializes the 1Password Connect client if needed.
func (k *OPConnectKeyring) InitializeOPConnectClient() error {
	if k.Client != nil {
		return nil
	}

	token, err := k.GetOPToken("Enter 1Password Connect token")
	if err != nil {
		return err
	}

	k.Client = connect.NewClient(k.Host, token)

	return nil
}

// GetOPItem returns the 1Password item matching the given key, with only its
// keyring field.
func (k *OPConnectKeyring) GetOPItem(key string) (*onepassword.Item, error) {
	opConnectItemOverview, err := k.getOPConnectItemOverview(key)
	if err != nil {
		return nil, err
	}

	opConnectItem, err := k.Client.GetItemByUUID(opConnectItemOverview.ID, k.VaultID)
	if err != nil {
		return nil, fmt.Errorf(
			"unable to get item with ID %#v from vault with ID %#v: %w",
			opConnectItemOverview.ID,
			k.VaultID,
			err,
		)
	}

	opItem, ok := k.getOPItemFromOPConnectItem(opConnectItem)
	if !ok {
		return nil, fmt.Errorf(
			"%w: item with title %#v in vault with ID %#v",
			OPErrItemMalformed,
			opConnectItem.Title,
			k.VaultID,
		)
	}
	return &opItem, nil
}

// getOPConnectItemOverview returns the overview of the keyring item matching
// the given key.
func (k *OPConnectKeyring) getOPConnectItemOverview(key string) (*connectop.Item, error) {
	opItemTitle := k.GetOPItemTitleFromKey(key)

	opConnectItemOverviewsAll, err := k.Client.GetItemsByTitle(opItemTitle, k.VaultID)
	if err != nil {
		return nil, fmt.Errorf(
			"unable to get item overviews with title %#v from vault with ID %#v: %w",
			opItemTitle,
			k.VaultID,
			err,
		)
	}

	opConnectItemOverviews := k.pruneOPConnectItemOverviews(opConnectItemOverviewsAll)

	if len(opConnectItemOverviews) == 0 {
		return nil, ErrKeyNotFound
	}
	if len(opConnectItemOverviews) > 1 {
		return nil, fmt.Errorf(
			"%w: matched %v items with title %#v in vault with ID %#v",
			OPErrItemMultiple,
			len(opConnectItemOverviews),
			opItemTitle,
			k.VaultID,
		)
	}

	return &opConnectItemOverviews[0], nil
}

// pruneOPConnectItemOverviews filters item overviews down to keyring items.
// Keys, Get, Set and Remove all match items by this rule, so a key that Keys
// returns can always be read or removed.
func (k *OPConnectKeyring) pruneOPConnectItemOverviews(
	opConnectItemOverviews []connectop.Item,
) []connectop.Item {
	pruned := []connectop.Item{}
	for _, opConnectItemOverview := range opConnectItemOverviews {
		if k.hasOPItemTitlePrefix(opConnectItemOverview.Title) &&
			slices.Contains(opConnectItemOverview.Tags, k.ItemTag) &&
			opConnectItemOverview.Category == OPConnectItemCategory {
			pruned = append(pruned, opConnectItemOverview)
		}
	}
	return pruned
}

// PruneAndHydrateOPItemOverviews filters item overviews down to keyring items
// and fetches their full contents, skipping items without a valid keyring field.
func (k *OPConnectKeyring) PruneAndHydrateOPItemOverviews(
	opConnectItemOverviews []connectop.Item,
) ([]onepassword.Item, error) {
	opItems := []onepassword.Item{}
	for _, opConnectItemOverview := range k.pruneOPConnectItemOverviews(opConnectItemOverviews) {
		opConnectItem, err := k.Client.GetItemByUUID(opConnectItemOverview.ID, k.VaultID)
		if err != nil {
			return nil, fmt.Errorf(
				"unable to get item with ID %#v from vault with ID %#v: %w",
				opConnectItemOverview.ID,
				k.VaultID,
				err,
			)
		}

		opItem, ok := k.getOPItemFromOPConnectItem(opConnectItem)
		if !ok {
			continue
		}
		opItems = append(opItems, opItem)
	}

	return opItems, nil
}

// getOPItemFromOPConnectItem converts a Connect item to a 1Password item with
// only its keyring field, provided it has exactly one concealed field and that
// field has the keyring field title.
func (k *OPConnectKeyring) getOPItemFromOPConnectItem(
	opConnectItem *connectop.Item,
) (onepassword.Item, bool) {
	opItemFields := []onepassword.ItemField{}
	for _, opConnectItemField := range opConnectItem.Fields {
		if opConnectItemField.Type == OPConnectItemFieldType {
			opItemFields = append(opItemFields, onepassword.ItemField{
				ID:        opConnectItemField.ID,
				Title:     opConnectItemField.Label,
				FieldType: OPStandardItemFieldType,
				Value:     opConnectItemField.Value,
			})
		}
	}

	if len(opItemFields) != 1 || opItemFields[0].Title != k.ItemFieldTitle {
		return onepassword.Item{}, false
	}

	return onepassword.Item{
		ID:        opConnectItem.ID,
		Title:     opConnectItem.Title,
		Category:  OPStandardItemCategory,
		VaultID:   opConnectItem.Vault.ID,
		Fields:    opItemFields,
		Tags:      opConnectItem.Tags,
		UpdatedAt: opConnectItem.UpdatedAt,
	}, true
}

// Get returns the Item matching the given key, or ErrKeyNotFound.
func (k OPConnectKeyring) Get(key string) (Item, error) {
	if err := k.InitializeOPConnectClient(); err != nil {
		return Item{}, err
	}

	opItem, err := k.GetOPItem(key)
	if err != nil {
		return Item{}, err
	}
	item, err := k.GetItemFromOPItemFieldValue(opItem.Fields[0].Value)
	if err != nil {
		return Item{}, err
	}
	return *item, nil
}

// GetMetadata returns the non-secret parts of an Item.
func (k OPConnectKeyring) GetMetadata(_ string) (Metadata, error) {
	return Metadata{}, nil
}

// Set creates or updates an Item.
func (k OPConnectKeyring) Set(item Item) error {
	if err := k.InitializeOPConnectClient(); err != nil {
		return err
	}

	opItem, err := k.GetOPItem(item.Key)
	if err != nil && !errors.Is(err, ErrKeyNotFound) {
		return err
	}

	opItemTitle := k.GetOPItemTitleFromKey(item.Key)
	opItemFieldValue, err := k.GetOPItemFieldValueFromItem(&item)
	if err != nil {
		return err
	}

	opConnectItem := &connectop.Item{
		Title:    opItemTitle,
		Tags:     []string{k.ItemTag},
		Vault:    connectop.ItemVault{ID: k.VaultID},
		Category: OPConnectItemCategory,
		Fields: []*connectop.ItemField{{
			Type:  OPConnectItemFieldType,
			Label: k.ItemFieldTitle,
			Value: opItemFieldValue,
		}},
	}

	if opItem == nil {
		_, err := k.Client.CreateItem(opConnectItem, k.VaultID)
		if err != nil {
			return fmt.Errorf(
				"unable to create item with title %#v in vault with ID %#v: %w",
				opItemTitle,
				k.VaultID,
				err,
			)
		}
		return nil
	}

	opConnectItem.ID = opItem.ID
	opConnectItem.Fields[0].ID = opItem.Fields[0].ID
	opConnectItem.UpdatedAt = time.Now()

	_, err = k.Client.UpdateItem(opConnectItem, k.VaultID)
	if err != nil {
		return fmt.Errorf(
			"unable to update item with title %#v in vault with ID %#v: %w",
			opItemTitle,
			k.VaultID,
			err,
		)
	}
	return nil
}

// Remove deletes the item with the matching key.
func (k OPConnectKeyring) Remove(key string) error {
	if err := k.InitializeOPConnectClient(); err != nil {
		return err
	}

	opConnectItemOverview, err := k.getOPConnectItemOverview(key)
	if err != nil {
		return err
	}

	if err := k.Client.DeleteItemByID(opConnectItemOverview.ID, k.VaultID); err != nil {
		return fmt.Errorf(
			"unable to delete item with ID %#v in vault with ID %#v: %w",
			opConnectItemOverview.ID,
			k.VaultID,
			err,
		)
	}
	return nil
}

// GetOPItems returns all keyring items from the configured vault.
func (k *OPConnectKeyring) GetOPItems() ([]onepassword.Item, error) {
	opItemOverviews, err := k.Client.GetItems(k.VaultID)
	if err != nil {
		return nil, fmt.Errorf(
			"unable to get item overviews from vault with ID %#v: %w",
			k.VaultID,
			err,
		)
	}

	opItems, err := k.PruneAndHydrateOPItemOverviews(opItemOverviews)
	if err != nil {
		return nil, err
	}

	return opItems, nil
}

// Keys returns a slice of all keys stored on the keyring.
func (k OPConnectKeyring) Keys() ([]string, error) {
	if err := k.InitializeOPConnectClient(); err != nil {
		return nil, err
	}

	opConnectItemOverviewsAll, err := k.Client.GetItems(k.VaultID)
	if err != nil {
		return nil, fmt.Errorf(
			"unable to get item overviews from vault with ID %#v: %w",
			k.VaultID,
			err,
		)
	}
	opConnectItemOverviews := k.pruneOPConnectItemOverviews(opConnectItemOverviewsAll)

	opItemTitles := []string{}
	keys := []string{}
	for _, opConnectItemOverview := range opConnectItemOverviews {
		if !slices.Contains(opItemTitles, opConnectItemOverview.Title) {
			opItemTitles = append(opItemTitles, opConnectItemOverview.Title)
			keys = append(keys, k.GetKeyFromOPItemTitle(opConnectItemOverview.Title))
		}
	}

	if len(opItemTitles) != len(opConnectItemOverviews) {
		return nil, fmt.Errorf(
			"%w in vault with ID %#v: %#v",
			OPErrItemTitleDuplicate,
			k.VaultID,
			opItemTitles,
		)
	}

	return keys, nil
}

// OPConnectClientAPI is the subset of the 1Password Connect client used by this backend.
type OPConnectClientAPI interface {
	CreateItem(item *connectop.Item, vaultQuery string) (*connectop.Item, error)
	DeleteItemByID(itemUUID string, vaultQuery string) error
	GetItemByUUID(uuid string, vaultQuery string) (*connectop.Item, error)
	GetItems(vaultQuery string) ([]connectop.Item, error)
	GetItemsByTitle(title string, vaultQuery string) ([]connectop.Item, error)
	UpdateItem(item *connectop.Item, vaultQuery string) (*connectop.Item, error)
}
