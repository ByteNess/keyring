package keyring

import (
	"context"
	"errors"
	"fmt"
	"os"
	"slices"
	"time"

	onepassword "github.com/1password/onepassword-sdk-go"
)

const (
	OPStandardEnvToken           = "OP_SERVICE_ACCOUNT_TOKEN"
	OPStandardIntegrationName    = "keyring"
	OPStandardIntegrationVersion = "v1.0.0"
	OPStandardItemCategory       = onepassword.ItemCategoryAPICredentials
	OPStandardItemFieldType      = onepassword.ItemFieldTypeConcealed
)

var (
	OPStandardErrKeyring = errors.New(
		"Unable to create a 1Password Service Accounts keyring",
	)
	OPStandardErrKeyringEnvTokenUnsetOrEmpty = fmt.Errorf(
		"%w: %w: %#v",
		OPStandardErrKeyring,
		ErrEnvUnsetOrEmpty,
		OPStandardEnvToken,
	)
	OPStandardErrKeyringNewClientErr = fmt.Errorf(
		"%w: onepassword.NewClient returned an error",
		OPStandardErrKeyring,
	)
)

func init() {
	supportedBackends[OPBackend] = opener(func(cfg Config) (Keyring, error) {
		var err error

		timeout := cfg.OPTimeout
		if timeout == 0 {
			return nil, errors.New("1Password timeout must be a non-zero duration")
		}

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

		keyring, err := NewOPStandardKeyring(
			timeout,
			vaultID,
			itemTitlePrefix,
			itemTag,
			itemFieldTitle,
		)
		if err != nil {
			return nil, err
		}

		return *keyring, nil
	})
}

type OPStandardKeyring struct {
	OPBaseKeyring
	Timeout time.Duration
	Client  OPStandardClientAPI
}

func NewOPStandardKeyring(
	timeout time.Duration,
	vaultID string,
	itemTitlePrefix string,
	itemTag string,
	itemFieldTitle string,
) (*OPStandardKeyring, error) {
	keyring := &OPStandardKeyring{
		OPBaseKeyring: OPBaseKeyring{
			VaultID:         vaultID,
			ItemTitlePrefix: itemTitlePrefix,
			ItemTag:         itemTag,
			ItemFieldTitle:  itemFieldTitle,
		},
		Timeout: timeout,
	}

	token := os.Getenv(OPStandardEnvToken)
	if token == "" {
		return nil, OPStandardErrKeyringEnvTokenUnsetOrEmpty
	}

	client, err := onepassword.NewClient(
		context.Background(),
		onepassword.WithIntegrationInfo(OPStandardIntegrationName, OPStandardIntegrationVersion),
		onepassword.WithServiceAccountToken(token),
	)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", OPStandardErrKeyringNewClientErr, err)
	}

	keyring.Client = client.Items()

	return keyring, nil
}

func (k *OPStandardKeyring) GetOPItem(key string) (*onepassword.Item, error) {
	opItemsAll, err := k.GetOPItems()
	if err != nil {
		return nil, err
	}

	opItemTitle := k.GetOPItemTitleFromKey(key)

	opItems := []onepassword.Item{}
	for _, opItem := range opItemsAll {
		if opItem.Title == opItemTitle {
			opItems = append(opItems, opItem)
		}
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

func (k *OPStandardKeyring) GetOPItems() ([]onepassword.Item, error) {
	ctxOuter, cancelOuter := context.WithTimeout(context.Background(), k.Timeout)
	defer cancelOuter()

	itemOverviews, err := k.Client.List(
		ctxOuter,
		k.VaultID,
		onepassword.NewItemListFilterTypeVariantByState(
			&onepassword.ItemListFilterByStateInner{Active: true},
		),
	)
	if err != nil {
		return nil, fmt.Errorf("Unable to list items from vault with ID %#v: %w", k.VaultID, err)
	}

	opItems := []onepassword.Item{}
	for _, itemOverview := range itemOverviews {
		if !slices.Contains(itemOverview.Tags, k.ItemTag) ||
			itemOverview.State != onepassword.ItemStateActive ||
			itemOverview.Category != OPStandardItemCategory {
			continue
		}

		ctxInner, cancelInner := context.WithTimeout(context.Background(), k.Timeout)
		defer cancelInner()

		opItem, err := k.Client.Get(ctxInner, k.VaultID, itemOverview.ID)
		if err != nil {
			return nil, fmt.Errorf(
				"Unable to get item with ID %#v from vault with ID %#v: %w",
				itemOverview.ID,
				k.VaultID,
				err,
			)
		}

		opItemFields := []onepassword.ItemField{}
		for _, opItemField := range opItem.Fields {
			if opItemField.FieldType == OPStandardItemFieldType {
				opItemFields = append(opItemFields, opItemField)
			}
		}

		if len(opItemFields) != 1 || opItemFields[0].Title != k.ItemFieldTitle {
			continue
		}

		opItem.Fields = opItemFields
		opItems = append(opItems, opItem)
	}

	return opItems, nil
}

func (k OPStandardKeyring) Get(key string) (Item, error) {
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

func (k OPStandardKeyring) GetMetadata(key string) (Metadata, error) {
	opItem, err := k.GetOPItem(key)
	if err != nil {
		return Metadata{}, nil
	}
	return Metadata{ModificationTime: opItem.UpdatedAt}, nil
}

func (k OPStandardKeyring) Set(item Item) error {
	opItem, err := k.GetOPItem(item.Key)
	if err != nil && !errors.Is(err, ErrKeyNotFound) {
		return err
	}

	opItemTitle := k.GetOPItemTitleFromKey(item.Key)
	opItemFieldValue, err := k.GetOPItemFieldValueFromItem(&item)
	if err != nil {
		return err
	}

	if opItem == nil {
		params := onepassword.ItemCreateParams{
			Category: OPStandardItemCategory,
			VaultID:  k.VaultID,
			Title:    opItemTitle,
			Fields: []onepassword.ItemField{{
				Title:     k.ItemFieldTitle,
				FieldType: OPStandardItemFieldType,
				Value:     opItemFieldValue,
			}},
			Tags: []string{k.ItemTag},
		}

		ctx, cancel := context.WithTimeout(context.Background(), k.Timeout)
		defer cancel()

		_, err := k.Client.Create(ctx, params)
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

	opItem.Fields[0].Value = opItemFieldValue
	opItem.UpdatedAt = time.Now()

	ctx, cancel := context.WithTimeout(context.Background(), k.Timeout)
	defer cancel()

	_, err = k.Client.Put(ctx, *opItem)
	if err != nil {
		return fmt.Errorf(
			"Unable to put item with title %#v in vault with ID %#v: %w",
			opItemTitle,
			k.VaultID,
			err,
		)
	}
	return nil
}

func (k OPStandardKeyring) Remove(key string) error {
	opItem, err := k.GetOPItem(key)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), k.Timeout)
	defer cancel()

	if err := k.Client.Delete(ctx, k.VaultID, opItem.ID); err != nil {
		return fmt.Errorf(
			"Unable to delete item with ID %#v in vault with ID %#v: %w",
			opItem.ID,
			k.VaultID,
			err,
		)
	}
	return nil
}

func (k OPStandardKeyring) Keys() ([]string, error) {
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

type OPStandardClientAPI interface {
	Create(ctx context.Context, params onepassword.ItemCreateParams) (onepassword.Item, error)
	Delete(ctx context.Context, vaultID string, itemID string) error
	Get(ctx context.Context, vaultID string, itemID string) (onepassword.Item, error)
	List(
		ctx context.Context,
		vaultID string,
		filters ...onepassword.ItemListFilter,
	) ([]onepassword.ItemOverview, error)
	Put(ctx context.Context, item onepassword.Item) (onepassword.Item, error)
}
