//go:build !freebsd && !keyring_no1password

package keyring

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	onepassword "github.com/1password/onepassword-sdk-go"
)

// Integration metadata and item conventions for onepassword-sdk-go based backends.
const (
	OPStandardIntegrationName    = "keyring"
	OPStandardIntegrationVersion = "v1.0.0"
	OPStandardItemCategory       = onepassword.ItemCategoryAPICredentials
	OPStandardItemFieldType      = onepassword.ItemFieldTypeConcealed
)

// OPStandardKeyring contains shared logic for all onepassword-sdk-go based backends
type OPStandardKeyring struct {
	OPBaseKeyring
	Timeout time.Duration
	Client  OPStandardClientAPI
}

// GetOPItem returns the 1Password item matching the given key, with only its
// keyring field.
func (k *OPStandardKeyring) GetOPItem(key string) (*onepassword.Item, error) {
	opItemOverview, err := k.getOPItemOverview(key)
	if err != nil {
		return nil, err
	}

	opItem, err := k.fetchOPItem(opItemOverview.ID)
	if err != nil {
		return nil, err
	}

	opItemField, ok := k.getOPItemKeyringField(opItem)
	if !ok {
		return nil, fmt.Errorf(
			"%w: item with title %#v in vault with ID %#v",
			OPErrItemMalformed,
			opItem.Title,
			k.VaultID,
		)
	}
	opItem.Fields = []onepassword.ItemField{opItemField}
	return &opItem, nil
}

// GetOPItems returns all keyring items from the configured vault.
func (k *OPStandardKeyring) GetOPItems() ([]onepassword.Item, error) {
	opItemOverviews, err := k.listOPItemOverviews()
	if err != nil {
		return nil, err
	}

	opItems := []onepassword.Item{}
	for _, opItemOverview := range opItemOverviews {
		opItem, err := k.fetchOPItem(opItemOverview.ID)
		if err != nil {
			return nil, err
		}

		opItemField, ok := k.getOPItemKeyringField(opItem)
		if !ok {
			continue
		}

		opItem.Fields = []onepassword.ItemField{opItemField}
		opItems = append(opItems, opItem)
	}

	return opItems, nil
}

// listOPItemOverviews returns the overviews of all keyring items in the
// configured vault. Keys, Get, Set and Remove all match items by this rule, so
// a key that Keys returns can always be read or removed.
func (k *OPStandardKeyring) listOPItemOverviews() ([]onepassword.ItemOverview, error) {
	ctx, cancel := context.WithTimeout(context.Background(), k.Timeout)
	defer cancel()

	itemOverviews, err := k.Client.List(
		ctx,
		k.VaultID,
		onepassword.NewItemListFilterTypeVariantByState(
			&onepassword.ItemListFilterByStateInner{Active: true},
		),
	)
	if err != nil {
		return nil, fmt.Errorf("unable to list items from vault with ID %#v: %w", k.VaultID, err)
	}

	opItemOverviews := []onepassword.ItemOverview{}
	for _, itemOverview := range itemOverviews {
		if k.hasOPItemTitlePrefix(itemOverview.Title) &&
			slices.Contains(itemOverview.Tags, k.ItemTag) &&
			itemOverview.State == onepassword.ItemStateActive &&
			itemOverview.Category == OPStandardItemCategory {
			opItemOverviews = append(opItemOverviews, itemOverview)
		}
	}
	return opItemOverviews, nil
}

// getOPItemOverview returns the overview of the keyring item matching the given key.
func (k *OPStandardKeyring) getOPItemOverview(key string) (*onepassword.ItemOverview, error) {
	opItemOverviewsAll, err := k.listOPItemOverviews()
	if err != nil {
		return nil, err
	}

	opItemTitle := k.GetOPItemTitleFromKey(key)

	opItemOverviews := []onepassword.ItemOverview{}
	for _, opItemOverview := range opItemOverviewsAll {
		if opItemOverview.Title == opItemTitle {
			opItemOverviews = append(opItemOverviews, opItemOverview)
		}
	}

	if len(opItemOverviews) == 0 {
		return nil, ErrKeyNotFound
	}
	if len(opItemOverviews) > 1 {
		return nil, fmt.Errorf(
			"%w: matched %v items with title %#v in vault with ID %#v",
			OPErrItemMultiple,
			len(opItemOverviews),
			opItemTitle,
			k.VaultID,
		)
	}
	return &opItemOverviews[0], nil
}

func (k *OPStandardKeyring) fetchOPItem(opItemID string) (onepassword.Item, error) {
	ctx, cancel := context.WithTimeout(context.Background(), k.Timeout)
	defer cancel()

	opItem, err := k.Client.Get(ctx, k.VaultID, opItemID)
	if err != nil {
		return onepassword.Item{}, fmt.Errorf(
			"unable to get item with ID %#v from vault with ID %#v: %w",
			opItemID,
			k.VaultID,
			err,
		)
	}
	return opItem, nil
}

// getOPItemKeyringField returns the item's only concealed field, provided it
// has the keyring field title.
func (k *OPStandardKeyring) getOPItemKeyringField(
	opItem onepassword.Item,
) (onepassword.ItemField, bool) {
	var opItemField onepassword.ItemField
	concealed := 0
	for _, field := range opItem.Fields {
		if field.FieldType == OPStandardItemFieldType {
			opItemField = field
			concealed++
		}
	}
	return opItemField, concealed == 1 && opItemField.Title == k.ItemFieldTitle
}

// Get returns the Item matching the given key, or ErrKeyNotFound.
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

// GetMetadata returns the non-secret parts of an Item.
func (k OPStandardKeyring) GetMetadata(_ string) (Metadata, error) {
	return Metadata{}, nil
}

// Set creates or updates an Item.
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
				"unable to create item with title %#v in vault with ID %#v: %w",
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
			"unable to put item with title %#v in vault with ID %#v: %w",
			opItemTitle,
			k.VaultID,
			err,
		)
	}
	return nil
}

// Remove deletes the item with the matching key.
func (k OPStandardKeyring) Remove(key string) error {
	opItemOverview, err := k.getOPItemOverview(key)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), k.Timeout)
	defer cancel()

	if err := k.Client.Delete(ctx, k.VaultID, opItemOverview.ID); err != nil {
		return fmt.Errorf(
			"unable to delete item with ID %#v in vault with ID %#v: %w",
			opItemOverview.ID,
			k.VaultID,
			err,
		)
	}
	return nil
}

// Keys returns a slice of all keys stored on the keyring.
func (k OPStandardKeyring) Keys() ([]string, error) {
	opItemOverviews, err := k.listOPItemOverviews()
	if err != nil {
		return nil, err
	}

	opItemTitles := []string{}
	keys := []string{}
	for _, opItemOverview := range opItemOverviews {
		if !slices.Contains(opItemTitles, opItemOverview.Title) {
			opItemTitles = append(opItemTitles, opItemOverview.Title)
			keys = append(keys, k.GetKeyFromOPItemTitle(opItemOverview.Title))
		}
	}

	if len(opItemTitles) != len(opItemOverviews) {
		return nil, fmt.Errorf(
			"%w in vault with ID %#v: %#v",
			OPErrItemTitleDuplicate,
			k.VaultID,
			opItemTitles,
		)
	}

	return keys, nil
}

// OPStandardClientAPI is the subset of the onepassword-sdk-go items client
// used by these backends.
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
