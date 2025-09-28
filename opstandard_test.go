package keyring

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	onepassword "github.com/1password/onepassword-sdk-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestOPStandardKeyring_Get(t *testing.T) {
	testCases := []struct {
		name            string
		key             string
		data            []byte
		opItemsExisting []onepassword.Item
		err             error
	}{
		{
			"ok",
			"key",
			[]byte(`data`),
			[]onepassword.Item{{
				ID:       "itemID",
				Title:    "itemTitlePrefix: key",
				Category: onepassword.ItemCategoryAPICredentials,
				VaultID:  "vaultID",
				Fields: []onepassword.ItemField{{
					ID:        "itemFieldID",
					Title:     "itemFieldTitle",
					FieldType: onepassword.ItemFieldTypeConcealed,
					Value:     NewOPItemFieldValue(t, "key", []byte(`data`)),
				}},
				Tags:      []string{"itemTag"},
				UpdatedAt: time.Date(1955, 11, 5, 11, 0, 0, 0, time.UTC),
			}},
			nil,
		},
		{
			"opItemTitleMismatch",
			"key",
			[]byte(`data`),
			[]onepassword.Item{{
				ID:       "itemID",
				Title:    "itemTitleMismatch",
				Category: onepassword.ItemCategoryAPICredentials,
				VaultID:  "vaultID",
				Fields: []onepassword.ItemField{{
					ID:        "itemFieldID",
					Title:     "itemFieldTitle",
					FieldType: onepassword.ItemFieldTypeConcealed,
					Value:     NewOPItemFieldValue(t, "key", []byte(`data`)),
				}},
				Tags:      []string{"itemTag"},
				UpdatedAt: time.Date(1955, 11, 5, 11, 0, 0, 0, time.UTC),
			}},
			ErrKeyNotFound,
		},
		{
			"opItemTagMismatch",
			"key",
			[]byte(`data`),
			[]onepassword.Item{{
				ID:       "itemID",
				Title:    "itemTitlePrefix: key",
				Category: onepassword.ItemCategoryAPICredentials,
				VaultID:  "vaultID",
				Fields: []onepassword.ItemField{{
					ID:        "itemFieldID",
					Title:     "itemFieldTitle",
					FieldType: onepassword.ItemFieldTypeConcealed,
					Value:     NewOPItemFieldValue(t, "key", []byte(`data`)),
				}},
				Tags:      []string{"itemTagMismatch"},
				UpdatedAt: time.Date(1955, 11, 5, 11, 0, 0, 0, time.UTC),
			}},
			ErrKeyNotFound,
		},
		{
			"opItemCategoryMismatch",
			"key",
			[]byte(`data`),
			[]onepassword.Item{{
				ID:       "itemID",
				Title:    "itemTitlePrefix: key",
				Category: onepassword.ItemCategoryUnsupported,
				VaultID:  "vaultID",
				Fields: []onepassword.ItemField{{
					ID:        "itemFieldID",
					Title:     "itemFieldTitle",
					FieldType: onepassword.ItemFieldTypeConcealed,
					Value:     NewOPItemFieldValue(t, "key", []byte(`data`)),
				}},
				Tags:      []string{"itemTag"},
				UpdatedAt: time.Date(1955, 11, 5, 11, 0, 0, 0, time.UTC),
			}},
			ErrKeyNotFound,
		},
		{
			"opItemFieldTitleMismatch",
			"key",
			[]byte(`data`),
			[]onepassword.Item{{
				ID:       "itemID",
				Title:    "itemTitlePrefix: key",
				Category: onepassword.ItemCategoryAPICredentials,
				VaultID:  "vaultID",
				Fields: []onepassword.ItemField{{
					ID:        "itemFieldID",
					Title:     "itemFieldTitleMismatch",
					FieldType: onepassword.ItemFieldTypeConcealed,
					Value:     NewOPItemFieldValue(t, "key", []byte(`data`)),
				}},
				Tags:      []string{"itemTag"},
				UpdatedAt: time.Date(1955, 11, 5, 11, 0, 0, 0, time.UTC),
			}},
			ErrKeyNotFound,
		},
		{
			"opItemFieldTitleDuplicate",
			"key",
			[]byte(`data`),
			[]onepassword.Item{{
				ID:       "itemID",
				Title:    "itemTitlePrefix: key",
				Category: onepassword.ItemCategoryAPICredentials,
				VaultID:  "vaultID",
				Fields: []onepassword.ItemField{
					{
						ID:        "itemFieldID0",
						Title:     "itemFieldTitle",
						FieldType: onepassword.ItemFieldTypeConcealed,
						Value:     NewOPItemFieldValue(t, "key", []byte(`data`)),
					},
					{
						ID:        "itemFieldID1",
						Title:     "itemFieldTitle",
						FieldType: onepassword.ItemFieldTypeConcealed,
						Value:     NewOPItemFieldValue(t, "key", []byte(`data`)),
					},
				},
				Tags:      []string{"itemTag"},
				UpdatedAt: time.Date(1955, 11, 5, 11, 0, 0, 0, time.UTC),
			}},
			ErrKeyNotFound,
		},
		{
			"opItemFieldTypeMismatch",
			"key",
			[]byte(`data`),
			[]onepassword.Item{{
				ID:       "itemID",
				Title:    "itemTitlePrefix: key",
				Category: onepassword.ItemCategoryAPICredentials,
				VaultID:  "vaultID",
				Fields: []onepassword.ItemField{{
					ID:        "itemFieldID",
					Title:     "itemFieldTitle",
					FieldType: onepassword.ItemFieldTypeUnsupported,
					Value:     NewOPItemFieldValue(t, "key", []byte(`data`)),
				}},
				Tags:      []string{"itemTag"},
				UpdatedAt: time.Date(1955, 11, 5, 11, 0, 0, 0, time.UTC),
			}},
			ErrKeyNotFound,
		},
		{
			"opItemDuplicate",
			"key",
			[]byte(`data`),
			[]onepassword.Item{
				{
					ID:       "itemID1",
					Title:    "itemTitlePrefix: key",
					Category: onepassword.ItemCategoryAPICredentials,
					VaultID:  "vaultID",
					Fields: []onepassword.ItemField{{
						ID:        "itemFieldID",
						Title:     "itemFieldTitle",
						FieldType: onepassword.ItemFieldTypeConcealed,
						Value:     NewOPItemFieldValue(t, "key", []byte(`data`)),
					}},
					Tags:      []string{"itemTag"},
					UpdatedAt: time.Date(1955, 11, 5, 11, 0, 0, 0, time.UTC),
				},
				{
					ID:       "itemID1",
					Title:    "itemTitlePrefix: key",
					Category: onepassword.ItemCategoryAPICredentials,
					VaultID:  "vaultID",
					Fields: []onepassword.ItemField{{
						ID:        "itemFieldID",
						Title:     "itemFieldTitle",
						FieldType: onepassword.ItemFieldTypeConcealed,
						Value:     NewOPItemFieldValue(t, "key", []byte(`data`)),
					}},
					Tags:      []string{"itemTag"},
					UpdatedAt: time.Date(1955, 11, 5, 11, 0, 0, 0, time.UTC),
				},
			},
			OPErrItemMultiple,
		},
	}

	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			keyring := &OPStandardKeyring{
				OPBaseKeyring: OPBaseKeyring{
					VaultID:         "vaultID",
					ItemTitlePrefix: "itemTitlePrefix",
					ItemTag:         "itemTag",
					ItemFieldTitle:  "itemFieldTitle",
				},
			}
			NewOPStandardKeyringMock_GetItem(t, keyring, tt.opItemsExisting)

			expectedItem := Item{
				Key:  tt.key,
				Data: tt.data,
			}

			actualItem, err := keyring.Get(tt.key)
			if (tt.err == ErrKeyNotFound && err != tt.err) || !errors.Is(err, tt.err) {
				t.Fatal(err)
			}
			if err != nil {
				return
			}

			if !reflect.DeepEqual(actualItem, expectedItem) {
				t.Fatalf(
					"Item generated is not item retrieved: %#v vs %#v",
					expectedItem,
					actualItem,
				)
			}
		})
	}
}

func TestOPStandardKeyring_Set(t *testing.T) {
	testCases := []struct {
		name             string
		key              string
		data             []byte
		opNewItemID      string
		opNewItemFieldID string
		opItemUpdatedAt  time.Time
		opItemExisting   *onepassword.Item
	}{
		{
			"create",
			"key",
			[]byte(`data`),
			"newItemID",
			"newItemFieldID",
			time.Date(1985, 11, 5, 11, 0, 0, 0, time.UTC),
			nil,
		},
		{
			"update",
			"key",
			[]byte(`dataNew`),
			"newItemID",
			"newItemFieldID",
			time.Date(1985, 11, 5, 11, 0, 0, 0, time.UTC),
			&onepassword.Item{
				ID:       "itemID",
				Title:    "itemTitlePrefix: key",
				Category: OPStandardItemCategory,
				VaultID:  "vaultID",
				Fields: []onepassword.ItemField{{
					ID:        "itemFieldID",
					Title:     "itemFieldTitle",
					FieldType: OPStandardItemFieldType,
					Value:     NewOPItemFieldValue(t, "key", []byte(`dataOld`)),
				}},
				Tags:      []string{"itemTag"},
				UpdatedAt: time.Date(1955, 11, 5, 11, 0, 0, 0, time.UTC),
			},
		},
	}

	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			keyring := &OPStandardKeyring{
				OPBaseKeyring: OPBaseKeyring{
					VaultID:         "vaultID",
					ItemTitlePrefix: "itemTitlePrefix",
					ItemTag:         "itemTag",
					ItemFieldTitle:  "itemFieldTitle",
				},
			}

			opItemsExisting := []onepassword.Item{}
			if tt.opItemExisting != nil {
				opItemsExisting = append(opItemsExisting, *tt.opItemExisting)
			}

			var opItemSetActual onepassword.Item
			NewOPStandardKeyringMock_SetItem(
				t,
				keyring,
				tt.opNewItemID,
				tt.opNewItemFieldID,
				tt.opItemUpdatedAt,
				opItemsExisting,
				&opItemSetActual,
			)

			item := Item{
				Key:  tt.key,
				Data: tt.data,
			}

			if err := keyring.Set(item); err != nil {
				t.Fatal(err)
			}

			var opItemSetExpected onepassword.Item
			if tt.opItemExisting == nil {
				opItemSetExpected = onepassword.Item{
					ID:       tt.opNewItemID,
					Title:    keyring.GetOPItemTitleFromKey(tt.key),
					Category: OPStandardItemCategory,
					VaultID:  keyring.VaultID,
					Fields: []onepassword.ItemField{{
						ID:        tt.opNewItemFieldID,
						Title:     keyring.ItemFieldTitle,
						FieldType: OPStandardItemFieldType,
						Value:     NewOPItemFieldValue(t, tt.key, tt.data),
					}},
					Tags:      []string{keyring.ItemTag},
					UpdatedAt: tt.opItemUpdatedAt,
				}
			} else {
				opItemSetExpected = *tt.opItemExisting
				opItemSetExpected.Fields[0].Value = NewOPItemFieldValue(t, tt.key, tt.data)
				opItemSetExpected.UpdatedAt = tt.opItemUpdatedAt
			}

			if !reflect.DeepEqual(opItemSetActual, opItemSetExpected) {
				t.Fatalf(
					"Expected item %#v does not match the set item %#v",
					opItemSetExpected,
					opItemSetActual,
				)
			}
		})
	}
}

func TestOPStandardKeyring_Remove(t *testing.T) {
	testCases := []struct {
		name           string
		key            string
		opItemExisting *onepassword.Item
		err            error
	}{
		{
			"ok",
			"key",
			&onepassword.Item{
				ID:       "itemID",
				Title:    "itemTitlePrefix: key",
				Category: OPStandardItemCategory,
				VaultID:  "vaultID",
				Fields: []onepassword.ItemField{{
					ID:        "itemFieldID",
					Title:     "itemFieldTitle",
					FieldType: OPStandardItemFieldType,
					Value:     NewOPItemFieldValue(t, "key", []byte(`data`)),
				}},
				Tags:      []string{"itemTag"},
				UpdatedAt: time.Date(1955, 11, 5, 11, 0, 0, 0, time.UTC),
			},
			nil,
		},
		{
			"opItemNotExists",
			"key",
			nil,
			ErrKeyNotFound,
		},
	}

	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			keyring := &OPStandardKeyring{
				OPBaseKeyring: OPBaseKeyring{
					VaultID:         "vaultID",
					ItemTitlePrefix: "itemTitlePrefix",
					ItemTag:         "itemTag",
					ItemFieldTitle:  "itemFieldTitle",
				},
			}

			opItemsExisting := []onepassword.Item{}
			if tt.opItemExisting != nil {
				opItemsExisting = append(opItemsExisting, *tt.opItemExisting)
			}

			var opRemovedItemID string
			NewOPStandardKeyringMock_RemoveItem(
				t,
				keyring,
				opItemsExisting,
				&opRemovedItemID,
			)

			err := keyring.Remove(tt.key)
			if (tt.err == ErrKeyNotFound && err != tt.err) || !errors.Is(err, tt.err) {
				t.Fatal(err)
			}
			if err != nil {
				return
			}

			if opRemovedItemID != tt.opItemExisting.ID {
				t.Fatalf(
					"Expected item ID %#v does not match the removed item ID %#v",
					tt.opItemExisting.ID,
					opRemovedItemID,
				)
			}
		})
	}
}

func TestOPStandardKeyring_GetKeys(t *testing.T) {
	testCases := []struct {
		name            string
		opItemsExisting []onepassword.Item
		err             error
		keysExpected    []string
	}{
		{
			"empty",
			nil,
			nil,
			nil,
		},
		{
			"opItemMultipleOK",
			[]onepassword.Item{
				{
					ID:       "itemID0",
					Title:    "itemTitlePrefix: key0",
					Category: OPStandardItemCategory,
					Fields: []onepassword.ItemField{{
						ID:        "itemFieldID",
						Title:     "itemFieldTitle",
						FieldType: OPStandardItemFieldType,
						Value:     NewOPItemFieldValue(t, "key0", []byte(`data`)),
					}},
					Tags:      []string{"itemTag"},
					UpdatedAt: time.Date(1955, 11, 5, 11, 0, 0, 0, time.UTC),
				},
				{
					ID:       "itemID1",
					Title:    "itemTitlePrefix: key1",
					Category: OPStandardItemCategory,
					Fields: []onepassword.ItemField{{
						ID:        "itemFieldID",
						Title:     "itemFieldTitle",
						FieldType: OPStandardItemFieldType,
						Value:     NewOPItemFieldValue(t, "key1", []byte(`data`)),
					}},
					Tags:      []string{"itemTag"},
					UpdatedAt: time.Date(1955, 11, 5, 11, 0, 0, 0, time.UTC),
				},
			},
			nil,
			[]string{"key0", "key1"},
		},
		{
			"opItemTitleDuplicate",
			[]onepassword.Item{
				{
					ID:       "itemID0",
					Title:    "itemTitlePrefix: key",
					Category: OPStandardItemCategory,
					Fields: []onepassword.ItemField{{
						ID:        "itemFieldID",
						Title:     "itemFieldTitle",
						FieldType: OPStandardItemFieldType,
						Value:     NewOPItemFieldValue(t, "key", []byte(`data`)),
					}},
					Tags:      []string{"itemTag"},
					UpdatedAt: time.Date(1955, 11, 5, 11, 0, 0, 0, time.UTC),
				},
				{
					ID:       "itemID1",
					Title:    "itemTitlePrefix: key",
					Category: OPStandardItemCategory,
					Fields: []onepassword.ItemField{{
						ID:        "itemFieldID",
						Title:     "itemFieldTitle",
						FieldType: OPStandardItemFieldType,
						Value:     NewOPItemFieldValue(t, "key", []byte(`data`)),
					}},
					Tags:      []string{"itemTag"},
					UpdatedAt: time.Date(1955, 11, 5, 11, 0, 0, 0, time.UTC),
				},
			},
			OPErrItemTitleDuplicate,
			nil,
		},
	}

	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			keyring := &OPStandardKeyring{
				OPBaseKeyring: OPBaseKeyring{
					VaultID:         "vaultID",
					ItemTitlePrefix: "itemTitlePrefix",
					ItemTag:         "itemTag",
					ItemFieldTitle:  "itemFieldTitle",
				},
			}
			NewOPStandardKeyringMock_GetItem(t, keyring, tt.opItemsExisting)

			keysActual, err := keyring.Keys()
			if !errors.Is(err, tt.err) {
				t.Fatal(err)
			}
			if err != nil {
				return
			}

			assert.ElementsMatch(t, keysActual, tt.keysExpected)
		})
	}
}

func NewOPStandardKeyringMock_GetItem(
	t *testing.T,
	keyring *OPStandardKeyring,
	opItemsExisting []onepassword.Item,
) *MockOPStandardClientAPI {
	opClientMock := NewMockOPStandardClientAPI(t)
	keyring.Client = opClientMock

	matchedByContext := mock.MatchedBy(func(ctx context.Context) bool {
		_, ok := ctx.Deadline()
		return ok
	})

	matchedByOpItemListFilter := mock.MatchedBy(
		func(opItemListFilters []onepassword.ItemListFilter) bool {
			if len(opItemListFilters) != 1 {
				return false
			}
			if opItemListFilters[0].ByState().Active == true &&
				opItemListFilters[0].ByState().Archived == false {
				return true
			}
			return false
		},
	)
	opClientMock.On("List", matchedByContext, keyring.VaultID, matchedByOpItemListFilter).
		Return(
			func(_ context.Context, _ string, _ ...onepassword.ItemListFilter) ([]onepassword.ItemOverview, error) {
				opItemOverviews := []onepassword.ItemOverview{}
				for _, opItem := range opItemsExisting {
					opItemOverviews = append(opItemOverviews, onepassword.ItemOverview{
						ID:        opItem.ID,
						Title:     opItem.Title,
						Category:  opItem.Category,
						VaultID:   opItem.VaultID,
						Tags:      opItem.Tags,
						UpdatedAt: opItem.UpdatedAt,
						State:     onepassword.ItemStateActive,
					})
				}
				return opItemOverviews, nil
			},
		).
		Once()

	matchedByString := mock.MatchedBy(func(string) bool { return true })
	opClientMock.On("Get", matchedByContext, keyring.VaultID, matchedByString).Return(
		func(_ context.Context, _ string, opItemID string) (onepassword.Item, error) {
			for _, opItem := range opItemsExisting {
				if opItem.ID == opItemID {
					var opItemCopy onepassword.Item
					DeepCopy(t, &opItem, &opItemCopy)
					return opItemCopy, nil
				}
			}
			return onepassword.Item{}, nil
		},
	).Maybe()

	return opClientMock
}

func NewOPStandardKeyringMock_SetItem(
	t *testing.T,
	keyring *OPStandardKeyring,
	opNewItemID string,
	opNewItemFieldID string,
	opItemUpdatedAt time.Time,
	opItemsExisting []onepassword.Item,
	opItemSet *onepassword.Item,
) *MockOPStandardClientAPI {
	opClientMock := NewOPStandardKeyringMock_GetItem(t, keyring, opItemsExisting)

	matchedByContext := mock.MatchedBy(func(ctx context.Context) bool {
		_, ok := ctx.Deadline()
		return ok
	})

	matchedByOpItemCreateParams := mock.MatchedBy(func(onepassword.ItemCreateParams) bool {
		return true
	})
	opClientMock.On("Create", matchedByContext, matchedByOpItemCreateParams).Return(
		func(_ context.Context, opItemCreateParams onepassword.ItemCreateParams) (onepassword.Item, error) {
			opItem := onepassword.Item{
				ID:       opNewItemID,
				Title:    opItemCreateParams.Title,
				Category: opItemCreateParams.Category,
				VaultID:  opItemCreateParams.VaultID,
				Fields: []onepassword.ItemField{{
					ID:        opNewItemFieldID,
					Title:     opItemCreateParams.Fields[0].Title,
					FieldType: opItemCreateParams.Fields[0].FieldType,
					Value:     opItemCreateParams.Fields[0].Value,
				}},
				Tags:      opItemCreateParams.Tags,
				UpdatedAt: opItemUpdatedAt,
			}
			*opItemSet = opItem
			return opItem, nil
		},
	).
		Maybe()

	matchedByOpItem := mock.MatchedBy(func(onepassword.Item) bool { return true })
	opClientMock.On("Put", matchedByContext, matchedByOpItem).Return(
		func(_ context.Context, opItem onepassword.Item) (onepassword.Item, error) {
			opItem.UpdatedAt = opItemUpdatedAt
			*opItemSet = opItem
			return opItem, nil
		},
	).Maybe()

	return opClientMock
}

func NewOPStandardKeyringMock_RemoveItem(
	t *testing.T,
	keyring *OPStandardKeyring,
	opItemsExisting []onepassword.Item,
	opItemIDRemoved *string,
) *MockOPStandardClientAPI {
	opClientMock := NewOPStandardKeyringMock_GetItem(t, keyring, opItemsExisting)

	matchedByContext := mock.MatchedBy(func(ctx context.Context) bool {
		_, ok := ctx.Deadline()
		return ok
	})
	matchedByString := mock.MatchedBy(func(string) bool { return true })
	opClientMock.On("Delete", matchedByContext, keyring.VaultID, matchedByString).Return(
		func(_ context.Context, _ string, opItemID string) error {
			for _, opItem := range opItemsExisting {
				if opItem.ID == opItemID {
					*opItemIDRemoved = opItemID
					return nil
				}
			}
			return nil
		},
	).Maybe()

	return opClientMock
}
