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

const (
	OPConnectEnvHost       = "OP_CONNECT_HOST"
	OPConnectEnvToken      = "OP_CONNECT_TOKEN"
	OPConnectItemCategory  = connectop.ApiCredential
	OPConnectItemFieldType = connectop.FieldTypeConcealed
)

var (
	OPConnectErrKeyring = errors.New(
		"Unable to create a 1Password Connect keyring",
	)
	OPConnectErrKeyringEnvHostUnsetOrEmpty = fmt.Errorf(
		"%w: %w: %#v",
		OPConnectErrKeyring,
		ErrEnvUnsetOrEmpty,
		OPConnectEnvHost,
	)
	OPConnectErrKeyringEnvTokenUnsetOrEmpty = fmt.Errorf(
		"%w: %w: %#v",
		OPConnectErrKeyring,
		ErrEnvUnsetOrEmpty,
		OPConnectEnvToken,
	)
)

func init() {
	supportedBackends[OPConnectBackend] = opener(func(cfg Config) (Keyring, error) {
		vaultID := cfg.OPVaultID
		if vaultID == "" {
			vaultID = os.Getenv(OPEnvVaultID)
			if vaultID == "" {
				return nil, OPErrKeyringEnvVaultIDUnsetOrEmpty
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

		keyring, err := NewOPConnectKeyring(vaultID, itemTitlePrefix, itemTag, itemFieldTitle)
		if err != nil {
			return nil, err
		}

		return *keyring, nil
	})
}

type OPConnectKeyring struct {
	OPBaseKeyring
	Client OPConnectClientAPI
}

func NewOPConnectKeyring(
	vaultID string,
	itemTitlePrefix string,
	itemTag string,
	itemFieldTitle string,
) (*OPConnectKeyring, error) {
	keyring := &OPConnectKeyring{
		OPBaseKeyring: OPBaseKeyring{
			VaultID:         vaultID,
			ItemTitlePrefix: itemTitlePrefix,
			ItemTag:         itemTag,
			ItemFieldTitle:  itemFieldTitle,
		},
	}

	errs := []error{}

	host := os.Getenv(OPConnectEnvHost)
	if host == "" {
		errs = append(errs, OPConnectErrKeyringEnvHostUnsetOrEmpty)
	}

	token := os.Getenv(OPConnectEnvToken)
	if token == "" {
		errs = append(errs, OPConnectErrKeyringEnvTokenUnsetOrEmpty)
	}

	if len(errs) > 0 {
		return nil, errors.Join(errs...)
	}

	keyring.Client = connect.NewClient(host, token)

	return keyring, nil
}

func (k *OPConnectKeyring) GetOPItem(key string) (*onepassword.Item, error) {
	opItemTitle := k.GetOPItemTitleFromKey(key)

	opConnectItemOverviews, err := k.Client.GetItemsByTitle(opItemTitle, k.VaultID)
	if err != nil {
		return nil, fmt.Errorf(
			"Unable to get item overviews with title %#v from vault with ID %#v: %w",
			opItemTitle,
			k.VaultID,
			err,
		)
	}

	opItems, err := k.PruneAndHydrateOPItemOverviews(opConnectItemOverviews)
	if err != nil {
		return nil, err
	}

	if len(opItems) == 0 {
		return nil, ErrKeyNotFound
	}
	if len(opItems) > 1 {
		return nil, fmt.Errorf(
			"%w: matched %v items with title %#v in vault with ID %#v",
			OPErrItemMultiple,
			len(opItems),
			opItemTitle,
			k.VaultID,
		)
	}

	return &opItems[0], nil
}

func (k *OPConnectKeyring) PruneAndHydrateOPItemOverviews(
	opConnectItemOverviews []connectop.Item,
) ([]onepassword.Item, error) {
	opItems := []onepassword.Item{}
	for _, opConnectItemOverview := range opConnectItemOverviews {
		if !slices.Contains(opConnectItemOverview.Tags, k.ItemTag) ||
			opConnectItemOverview.Category != OPConnectItemCategory {
			continue
		}

		opConnectItem, err := k.Client.GetItemByUUID(opConnectItemOverview.ID, k.VaultID)
		if err != nil {
			return nil, fmt.Errorf(
				"Unable to get item with ID %#v from vault with ID %#v: %w",
				opConnectItemOverview.ID,
				k.VaultID,
				err,
			)
		}

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
			continue
		}

		opItems = append(opItems, onepassword.Item{
			ID:        opConnectItem.ID,
			Title:     opConnectItem.Title,
			Category:  OPStandardItemCategory,
			VaultID:   opConnectItem.Vault.ID,
			Fields:    opItemFields,
			Tags:      opConnectItem.Tags,
			UpdatedAt: opConnectItem.UpdatedAt,
		})
	}

	return opItems, nil
}

func (k OPConnectKeyring) Get(key string) (Item, error) {
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

func (k OPConnectKeyring) GetMetadata(key string) (Metadata, error) {
	opItem, err := k.GetOPItem(key)
	if err != nil {
		return Metadata{}, err
	}
	return Metadata{ModificationTime: opItem.UpdatedAt}, nil
}

func (k OPConnectKeyring) Set(item Item) error {
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
				"Unable to create item with title %#v in vault with ID %#v: %w",
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
			"Unable to update item with title %#v in vault with ID %#v: %w",
			opItemTitle,
			k.VaultID,
			err,
		)
	}
	return nil
}

func (k OPConnectKeyring) Remove(key string) error {
	opItem, err := k.GetOPItem(key)
	if err != nil {
		return err
	}

	if err := k.Client.DeleteItemByID(opItem.ID, k.VaultID); err != nil {
		return fmt.Errorf(
			"Unable to delete item with ID %#v in vault with ID %#v: %w",
			opItem.ID,
			k.VaultID,
			err,
		)
	}
	return nil
}

func (k *OPConnectKeyring) GetOPItems() ([]onepassword.Item, error) {
	opItemOverviews, err := k.Client.GetItems(k.VaultID)
	if err != nil {
		return nil, fmt.Errorf(
			"Unable to get item overviews from vault with ID %#v: %w",
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

func (k OPConnectKeyring) Keys() ([]string, error) {
	opItems, err := k.GetOPItems()
	if err != nil {
		return nil, err
	}

	opItemTitles := []string{}
	keys := []string{}
	for _, opItem := range opItems {
		if !slices.Contains(opItemTitles, opItem.Title) {
			opItemTitles = append(opItemTitles, opItem.Title)
			keys = append(keys, k.GetKeyFromOPItemTitle(opItem.Title))
		}
	}

	if len(opItemTitles) != len(opItems) {
		return nil, fmt.Errorf(
			"%w in vault with ID %#v: %#v",
			OPErrItemTitleDuplicate,
			k.VaultID,
			opItemTitles,
		)
	}

	return keys, nil
}

type OPConnectClientAPI interface {
	CreateItem(item *connectop.Item, vaultQuery string) (*connectop.Item, error)
	DeleteItemByID(itemUUID string, vaultQuery string) error
	GetItemByUUID(uuid string, vaultQuery string) (*connectop.Item, error)
	GetItems(vaultQuery string) ([]connectop.Item, error)
	GetItemsByTitle(title string, vaultQuery string) ([]connectop.Item, error)
	UpdateItem(item *connectop.Item, vaultQuery string) (*connectop.Item, error)
}
