//go:build !freebsd && !keyring_no1password

package keyring

import (
	"errors"
	"reflect"
	"testing"
	"time"

	connectop "github.com/1Password/connect-sdk-go/onepassword"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestOPConnectKeyring_Get(t *testing.T) {
	testCases := []struct {
		name            string
		key             string
		data            []byte
		opItemsExisting []connectop.Item
		err             error
	}{
		{
			"ok",
			"key",
			[]byte(`data`),
			[]connectop.Item{{
				ID:       "itemID",
				Title:    "itemTitlePrefix: key",
				Tags:     []string{"itemTag"},
				Vault:    connectop.ItemVault{ID: "vaultID"},
				Category: connectop.ApiCredential,
				Fields: []*connectop.ItemField{{
					ID:    "itemFieldID",
					Type:  connectop.FieldTypeConcealed,
					Label: "itemFieldTitle",
					Value: NewOPItemFieldValue(t, "key", []byte(`data`)),
				}},
				UpdatedAt: time.Date(1955, 11, 5, 11, 0, 0, 0, time.UTC),
			}},
			nil,
		},
		{
			"opItemTitleMismatch",
			"key",
			[]byte(`data`),
			[]connectop.Item{{
				ID:       "itemID",
				Title:    "itemTitleMismatch",
				Tags:     []string{"itemTag"},
				Vault:    connectop.ItemVault{ID: "vaultID"},
				Category: connectop.ApiCredential,
				Fields: []*connectop.ItemField{{
					ID:    "itemFieldID",
					Type:  connectop.FieldTypeConcealed,
					Label: "itemFieldTitle",
					Value: NewOPItemFieldValue(t, "key", []byte(`data`)),
				}},
				UpdatedAt: time.Date(1955, 11, 5, 11, 0, 0, 0, time.UTC),
			}},
			ErrKeyNotFound,
		},
		{
			"opItemTagMismatch",
			"key",
			[]byte(`data`),
			[]connectop.Item{{
				ID:       "itemID",
				Title:    "itemTitlePrefix: key",
				Tags:     []string{"itemTagMismatch"},
				Vault:    connectop.ItemVault{ID: "vaultID"},
				Category: connectop.ApiCredential,
				Fields: []*connectop.ItemField{{
					ID:    "itemFieldID",
					Type:  connectop.FieldTypeConcealed,
					Label: "itemFieldTitle",
					Value: NewOPItemFieldValue(t, "key", []byte(`data`)),
				}},
				UpdatedAt: time.Date(1955, 11, 5, 11, 0, 0, 0, time.UTC),
			}},
			ErrKeyNotFound,
		},
		{
			"opItemCategoryMismatch",
			"key",
			[]byte(`data`),
			[]connectop.Item{{
				ID:       "itemID",
				Title:    "itemTitlePrefix: key",
				Tags:     []string{"itemTag"},
				Vault:    connectop.ItemVault{ID: "vaultID"},
				Category: connectop.Custom,
				Fields: []*connectop.ItemField{{
					ID:    "itemFieldID",
					Type:  connectop.FieldTypeConcealed,
					Label: "itemFieldTitle",
					Value: NewOPItemFieldValue(t, "key", []byte(`data`)),
				}},
				UpdatedAt: time.Date(1955, 11, 5, 11, 0, 0, 0, time.UTC),
			}},
			ErrKeyNotFound,
		},
		{
			"opItemFieldTitleMismatch",
			"key",
			[]byte(`data`),
			[]connectop.Item{{
				ID:       "itemID",
				Title:    "itemTitlePrefix: key",
				Tags:     []string{"itemTag"},
				Vault:    connectop.ItemVault{ID: "vaultID"},
				Category: connectop.ApiCredential,
				Fields: []*connectop.ItemField{{
					ID:    "itemFieldID",
					Type:  connectop.FieldTypeConcealed,
					Label: "itemFieldTitleMismatch",
					Value: NewOPItemFieldValue(t, "key", []byte(`data`)),
				}},
				UpdatedAt: time.Date(1955, 11, 5, 11, 0, 0, 0, time.UTC),
			}},
			OPErrItemMalformed,
		},
		{
			"opItemFieldTitleDuplicate",
			"key",
			[]byte(`data`),
			[]connectop.Item{{
				ID:       "itemID",
				Title:    "itemTitlePrefix: key",
				Tags:     []string{"itemTag"},
				Vault:    connectop.ItemVault{ID: "vaultID"},
				Category: connectop.ApiCredential,
				Fields: []*connectop.ItemField{
					{
						ID:    "itemFieldID0",
						Type:  connectop.FieldTypeConcealed,
						Label: "itemFieldTitle",
						Value: NewOPItemFieldValue(t, "key", []byte(`data`)),
					},
					{
						ID:    "itemFieldID1",
						Type:  connectop.FieldTypeConcealed,
						Label: "itemFieldTitle",
						Value: NewOPItemFieldValue(t, "key", []byte(`data`)),
					},
				},
				UpdatedAt: time.Date(1955, 11, 5, 11, 0, 0, 0, time.UTC),
			}},
			OPErrItemMalformed,
		},
		{
			"opItemFieldTypeMismatch",
			"key",
			[]byte(`data`),
			[]connectop.Item{{
				ID:       "itemID",
				Title:    "itemTitlePrefix: key",
				Tags:     []string{"itemTag"},
				Vault:    connectop.ItemVault{ID: "vaultID"},
				Category: connectop.ApiCredential,
				Fields: []*connectop.ItemField{{
					ID:    "itemFieldID",
					Type:  connectop.FieldTypeUnknown,
					Label: "itemFieldTitle",
					Value: NewOPItemFieldValue(t, "key", []byte(`data`)),
				}},
				UpdatedAt: time.Date(1955, 11, 5, 11, 0, 0, 0, time.UTC),
			}},
			OPErrItemMalformed,
		},
		{
			"opItemDuplicate",
			"key",
			[]byte(`data`),
			[]connectop.Item{
				{
					ID:       "itemID0",
					Title:    "itemTitlePrefix: key",
					Tags:     []string{"itemTag"},
					Vault:    connectop.ItemVault{ID: "vaultID"},
					Category: connectop.ApiCredential,
					Fields: []*connectop.ItemField{{
						ID:    "itemID",
						Type:  connectop.FieldTypeConcealed,
						Label: "itemFieldTitle",
						Value: NewOPItemFieldValue(t, "key", []byte(`data`)),
					}},
					UpdatedAt: time.Date(1955, 11, 5, 11, 0, 0, 0, time.UTC),
				},
				{
					ID:       "itemID1",
					Title:    "itemTitlePrefix: key",
					Tags:     []string{"itemTag"},
					Vault:    connectop.ItemVault{ID: "vaultID"},
					Category: connectop.ApiCredential,
					Fields: []*connectop.ItemField{{
						ID:    "itemID",
						Type:  connectop.FieldTypeConcealed,
						Label: "itemFieldTitle",
						Value: NewOPItemFieldValue(t, "key", []byte(`data`)),
					}},
					UpdatedAt: time.Date(1955, 11, 5, 11, 0, 0, 0, time.UTC),
				},
			},
			OPErrItemMultiple,
		},
	}

	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			keyring := &OPConnectKeyring{
				OPBaseKeyring: OPBaseKeyring{
					VaultID:         "vaultID",
					ItemTitlePrefix: "itemTitlePrefix",
					ItemTag:         "itemTag",
					ItemFieldTitle:  "itemFieldTitle",
				},
			}
			NewOPConnectKeyringMock_GetItem(t, keyring, tt.key, tt.opItemsExisting)

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

func TestOPConnectKeyring_Set(t *testing.T) {
	testCases := []struct {
		name             string
		key              string
		data             []byte
		opNewItemID      string
		opNewItemFieldID string
		opItemUpdatedAt  time.Time
		opItemExisting   *connectop.Item
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
			&connectop.Item{
				ID:       "itemID",
				Title:    "itemTitlePrefix: key",
				Tags:     []string{"itemTag"},
				Vault:    connectop.ItemVault{ID: "vaultID"},
				Category: OPConnectItemCategory,
				Fields: []*connectop.ItemField{{
					ID:    "itemFieldID",
					Type:  OPConnectItemFieldType,
					Label: "itemFieldTitle",
					Value: NewOPItemFieldValue(t, "key", []byte(`dataOld`)),
				}},
				UpdatedAt: time.Date(1955, 11, 5, 11, 0, 0, 0, time.UTC),
			},
		},
	}

	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			keyring := &OPConnectKeyring{
				OPBaseKeyring: OPBaseKeyring{
					VaultID:         "vaultID",
					ItemTitlePrefix: "itemTitlePrefix",
					ItemTag:         "itemTag",
					ItemFieldTitle:  "itemFieldTitle",
				},
			}

			opItemsExisting := []connectop.Item{}
			if tt.opItemExisting != nil {
				opItemsExisting = append(opItemsExisting, *tt.opItemExisting)
			}

			var opItemSetActual connectop.Item
			NewOPConnectKeyringMock_SetItem(
				t,
				keyring,
				tt.key,
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

			var opItemSetExpected connectop.Item
			if tt.opItemExisting == nil {
				opItemSetExpected = connectop.Item{
					ID:       tt.opNewItemID,
					Title:    keyring.GetOPItemTitleFromKey(tt.key),
					Tags:     []string{keyring.ItemTag},
					Vault:    connectop.ItemVault{ID: keyring.VaultID},
					Category: OPConnectItemCategory,
					Fields: []*connectop.ItemField{{
						ID:    tt.opNewItemFieldID,
						Type:  OPConnectItemFieldType,
						Label: keyring.ItemFieldTitle,
						Value: NewOPItemFieldValue(t, tt.key, tt.data),
					}},
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

func TestOPConnectKeyring_Remove(t *testing.T) {
	testCases := []struct {
		name           string
		key            string
		opItemExisting *connectop.Item
		err            error
	}{
		{
			"ok",
			"key",
			&connectop.Item{
				ID:       "itemID",
				Title:    "itemTitlePrefix: key",
				Tags:     []string{"itemTag"},
				Category: OPConnectItemCategory,
				Fields: []*connectop.ItemField{{
					ID:    "itemFieldID",
					Type:  OPConnectItemFieldType,
					Label: "itemFieldTitle",
					Value: NewOPItemFieldValue(t, "key", []byte(`data`)),
				}},
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
			keyring := &OPConnectKeyring{
				OPBaseKeyring: OPBaseKeyring{
					VaultID:         "vaultID",
					ItemTitlePrefix: "itemTitlePrefix",
					ItemTag:         "itemTag",
					ItemFieldTitle:  "itemFieldTitle",
				},
			}

			opItemsExisting := []connectop.Item{}
			if tt.opItemExisting != nil {
				opItemsExisting = append(opItemsExisting, *tt.opItemExisting)
			}

			var opItemIDRemoved string
			NewOPConnectKeyringMock_RemoveItem(
				t,
				keyring,
				tt.key,
				opItemsExisting,
				&opItemIDRemoved,
			)

			err := keyring.Remove(tt.key)
			if (tt.err == ErrKeyNotFound && err != tt.err) || !errors.Is(err, tt.err) {
				t.Fatal(err)
			}
			if err != nil {
				return
			}

			if opItemIDRemoved != tt.opItemExisting.ID {
				t.Fatalf(
					"Expected item ID %#v does not match the removed item ID %#v",
					tt.opItemExisting.ID,
					opItemIDRemoved,
				)
			}
		})
	}
}

func TestOPConnectKeyring_GetKeys(t *testing.T) {
	testCases := []struct {
		name            string
		opItemsExisting []connectop.Item
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
			[]connectop.Item{
				{
					ID:       "itemID0",
					Title:    "itemTitlePrefix: key0",
					Tags:     []string{"itemTag"},
					Category: OPConnectItemCategory,
					Fields: []*connectop.ItemField{{
						ID:    "itemID",
						Type:  OPConnectItemFieldType,
						Label: "itemFieldTitle",
						Value: NewOPItemFieldValue(t, "key0", []byte(`data`)),
					}},
				},
				{
					ID:       "itemID1",
					Title:    "itemTitlePrefix: key1",
					Tags:     []string{"itemTag"},
					Category: OPConnectItemCategory,
					Fields: []*connectop.ItemField{{
						ID:    "itemID",
						Type:  OPConnectItemFieldType,
						Label: "itemFieldTitle",
						Value: NewOPItemFieldValue(t, "key1", []byte(`data`)),
					}},
				},
			},
			nil,
			[]string{"key0", "key1"},
		},
		{
			"opItemTitleDuplicate",
			[]connectop.Item{
				{
					ID:       "itemID0",
					Title:    "itemTitlePrefix: key",
					Tags:     []string{"itemTag"},
					Category: OPConnectItemCategory,
					Fields: []*connectop.ItemField{{
						ID:    "itemID",
						Type:  OPConnectItemFieldType,
						Label: "itemFieldTitle",
						Value: NewOPItemFieldValue(t, "key", []byte(`data`)),
					}},
				},
				{
					ID:       "itemID1",
					Title:    "itemTitlePrefix: key",
					Tags:     []string{"itemTag"},
					Category: OPConnectItemCategory,
					Fields: []*connectop.ItemField{{
						ID:    "itemID",
						Type:  OPConnectItemFieldType,
						Label: "itemFieldTitle",
						Value: NewOPItemFieldValue(t, "key", []byte(`data`)),
					}},
				},
			},
			OPErrItemTitleDuplicate,
			nil,
		},
	}

	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			keyring := &OPConnectKeyring{
				OPBaseKeyring: OPBaseKeyring{
					VaultID:         "vaultID",
					ItemTitlePrefix: "itemTitlePrefix",
					ItemTag:         "itemTag",
					ItemFieldTitle:  "itemFieldTitle",
				},
			}

			newOPConnectKeyringMock_GetKeys(t, keyring, tt.opItemsExisting)

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

func NewOPConnectKeyringMock_GetItem(
	t *testing.T,
	keyring *OPConnectKeyring,
	key string,
	opItemsExisting []connectop.Item,
) *MockOPConnectClientAPI {
	t.Helper()
	opClientMock := NewMockOPConnectClientAPI(t)
	keyring.Client = opClientMock

	opItemTitle := keyring.GetOPItemTitleFromKey(key)

	opClientMock.On("GetItemsByTitle", opItemTitle, keyring.VaultID).Return(
		func(opItemTitle string, _ string) ([]connectop.Item, error) {
			opItemOverviews := make([]connectop.Item, 0, len(opItemsExisting))
			for _, opItem := range opItemsExisting {
				if opItem.Title == opItemTitle {
					var opItemOverview connectop.Item
					DeepCopy(t, &opItem, &opItemOverview)
					opItemOverview.Fields = nil
					opItemOverviews = append(opItemOverviews, opItemOverview)
				}
			}
			return opItemOverviews, nil
		},
	).Once()

	matchedBy := mock.MatchedBy(func(string) bool { return true })
	opClientMock.On("GetItemByUUID", matchedBy, keyring.VaultID).Return(
		func(opItemID string, _ string) (*connectop.Item, error) {
			for _, opItem := range opItemsExisting {
				if opItem.ID == opItemID {
					var opItemCopy connectop.Item
					DeepCopy(t, &opItem, &opItemCopy)
					return &opItemCopy, nil
				}
			}
			return nil, nil
		},
	).Maybe()

	return opClientMock
}

func NewOPConnectKeyringMock_SetItem(
	t *testing.T,
	keyring *OPConnectKeyring,
	key string,
	opNewItemID string,
	opNewItemFieldID string,
	opItemUpdatedAt time.Time,
	opItemsExisting []connectop.Item,
	opItemSet *connectop.Item,
) *MockOPConnectClientAPI {
	t.Helper()
	opClientMock := NewOPConnectKeyringMock_GetItem(t, keyring, key, opItemsExisting)

	matchedByOpItem := mock.MatchedBy(func(*connectop.Item) bool { return true })

	opClientMock.On("CreateItem", matchedByOpItem, keyring.VaultID).Return(
		func(opItem *connectop.Item, _ string) (*connectop.Item, error) {
			opItem.ID = opNewItemID
			opItem.Fields[0].ID = opNewItemFieldID
			opItem.UpdatedAt = opItemUpdatedAt
			*opItemSet = *opItem
			return opItem, nil
		},
	).Maybe()

	opClientMock.On("UpdateItem", matchedByOpItem, keyring.VaultID).Return(
		func(opItem *connectop.Item, _ string) (*connectop.Item, error) {
			opItem.UpdatedAt = opItemUpdatedAt
			*opItemSet = *opItem
			return opItem, nil
		},
	).Maybe()

	return opClientMock
}

func NewOPConnectKeyringMock_RemoveItem(
	t *testing.T,
	keyring *OPConnectKeyring,
	key string,
	opItemsExisting []connectop.Item,
	opItemIDRemoved *string,
) *MockOPConnectClientAPI {
	t.Helper()
	opClientMock := NewOPConnectKeyringMock_GetItem(t, keyring, key, opItemsExisting)

	matchedByString := mock.MatchedBy(func(string) bool { return true })
	opClientMock.On("DeleteItemByID", matchedByString, keyring.VaultID).Return(
		func(opItemID string, _ string) error {
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

func newOPConnectKeyringMock_GetKeys(
	t *testing.T,
	keyring *OPConnectKeyring,
	opItemsExisting []connectop.Item,
) *MockOPConnectClientAPI {
	t.Helper()
	opClientMock := NewMockOPConnectClientAPI(t)
	keyring.Client = opClientMock

	opClientMock.On("GetItems", keyring.VaultID).Return(
		func(_ string) ([]connectop.Item, error) {
			opItemOverviews := make([]connectop.Item, 0, len(opItemsExisting))
			for _, opItem := range opItemsExisting {
				var opItemOverview connectop.Item
				DeepCopy(t, &opItem, &opItemOverview)
				opItemOverview.Fields = nil
				opItemOverviews = append(opItemOverviews, opItemOverview)
			}
			return opItemOverviews, nil
		},
	).Once()

	matchedByString := mock.MatchedBy(func(string) bool { return true })
	opClientMock.On("GetItemByUUID", matchedByString, keyring.VaultID).Return(
		func(opItemID string, _ string) (*connectop.Item, error) {
			for _, opItem := range opItemsExisting {
				if opItem.ID == opItemID {
					var opItemCopy connectop.Item
					DeepCopy(t, &opItem, &opItemCopy)
					return &opItemCopy, nil
				}
			}
			return nil, nil
		},
	).Maybe()

	return opClientMock
}

func newOPConnectTestKeyring() *OPConnectKeyring {
	return &OPConnectKeyring{
		OPBaseKeyring: OPBaseKeyring{
			VaultID:         "vaultID",
			ItemTitlePrefix: "itemTitlePrefix",
			ItemTag:         "itemTag",
			ItemFieldTitle:  "itemFieldTitle",
		},
	}
}

func newOPConnectTestItem(t *testing.T, id, key string) connectop.Item {
	t.Helper()
	return connectop.Item{
		ID:       id,
		Title:    "itemTitlePrefix: " + key,
		Tags:     []string{"itemTag"},
		Vault:    connectop.ItemVault{ID: "vaultID"},
		Category: connectop.ApiCredential,
		Fields: []*connectop.ItemField{{
			ID:    "itemFieldID",
			Type:  connectop.FieldTypeConcealed,
			Label: "itemFieldTitle",
			Value: NewOPItemFieldValue(t, key, []byte(`data`)),
		}},
		UpdatedAt: time.Date(1955, 11, 5, 11, 0, 0, 0, time.UTC),
	}
}

func newOPConnectTestItemMalformed(t *testing.T, id, key string) connectop.Item {
	t.Helper()
	opItem := newOPConnectTestItem(t, id, key)
	opItem.Fields[0].Label = "itemFieldTitleMismatch"
	return opItem
}

func TestOPConnectKeyring_SDKCalls(t *testing.T) {
	opItemsExisting := []connectop.Item{
		newOPConnectTestItem(t, "itemID0", "key0"),
		newOPConnectTestItem(t, "itemID1", "key1"),
		newOPConnectTestItem(t, "itemID2", "key2"),
	}

	t.Run("Keys", func(t *testing.T) {
		keyring := newOPConnectTestKeyring()
		opClientMock := newOPConnectKeyringMock_GetKeys(t, keyring, opItemsExisting)

		if _, err := keyring.Keys(); err != nil {
			t.Fatal(err)
		}
		opClientMock.AssertNumberOfCalls(t, "GetItems", 1)
		opClientMock.AssertNumberOfCalls(t, "GetItemByUUID", 0)
	})

	t.Run("Get", func(t *testing.T) {
		keyring := newOPConnectTestKeyring()
		opClientMock := NewOPConnectKeyringMock_GetItem(t, keyring, "key1", opItemsExisting)

		if _, err := keyring.Get("key1"); err != nil {
			t.Fatal(err)
		}
		opClientMock.AssertNumberOfCalls(t, "GetItemsByTitle", 1)
		opClientMock.AssertNumberOfCalls(t, "GetItemByUUID", 1)
	})

	t.Run("SetCreate", func(t *testing.T) {
		keyring := newOPConnectTestKeyring()
		var opItemSet connectop.Item
		opClientMock := NewOPConnectKeyringMock_SetItem(
			t, keyring, "new", "newItemID", "newItemFieldID", time.Time{}, opItemsExisting, &opItemSet,
		)

		if err := keyring.Set(Item{Key: "new", Data: []byte(`data`)}); err != nil {
			t.Fatal(err)
		}
		opClientMock.AssertNumberOfCalls(t, "GetItemsByTitle", 1)
		opClientMock.AssertNumberOfCalls(t, "GetItemByUUID", 0)
		opClientMock.AssertNumberOfCalls(t, "CreateItem", 1)
	})

	t.Run("SetUpdate", func(t *testing.T) {
		keyring := newOPConnectTestKeyring()
		var opItemSet connectop.Item
		opClientMock := NewOPConnectKeyringMock_SetItem(
			t, keyring, "key1", "newItemID", "newItemFieldID", time.Time{}, opItemsExisting, &opItemSet,
		)

		if err := keyring.Set(Item{Key: "key1", Data: []byte(`data`)}); err != nil {
			t.Fatal(err)
		}
		opClientMock.AssertNumberOfCalls(t, "GetItemsByTitle", 1)
		opClientMock.AssertNumberOfCalls(t, "GetItemByUUID", 1)
		opClientMock.AssertNumberOfCalls(t, "UpdateItem", 1)
	})

	t.Run("Remove", func(t *testing.T) {
		keyring := newOPConnectTestKeyring()
		var opItemIDRemoved string
		opClientMock := NewOPConnectKeyringMock_RemoveItem(
			t, keyring, "key1", opItemsExisting, &opItemIDRemoved,
		)

		if err := keyring.Remove("key1"); err != nil {
			t.Fatal(err)
		}
		opClientMock.AssertNumberOfCalls(t, "GetItemsByTitle", 1)
		opClientMock.AssertNumberOfCalls(t, "GetItemByUUID", 0)
		opClientMock.AssertNumberOfCalls(t, "DeleteItemByID", 1)
		assert.Equal(t, "itemID1", opItemIDRemoved)
	})
}

func TestOPConnectKeyring_Malformed(t *testing.T) {
	opItemsExisting := []connectop.Item{
		newOPConnectTestItem(t, "itemID0", "key0"),
		newOPConnectTestItemMalformed(t, "itemID1", "key1"),
	}

	t.Run("KeysListsIt", func(t *testing.T) {
		keyring := newOPConnectTestKeyring()
		newOPConnectKeyringMock_GetKeys(t, keyring, opItemsExisting)

		keys, err := keyring.Keys()
		if err != nil {
			t.Fatal(err)
		}
		assert.ElementsMatch(t, []string{"key0", "key1"}, keys)
	})

	t.Run("GetReportsIt", func(t *testing.T) {
		keyring := newOPConnectTestKeyring()
		NewOPConnectKeyringMock_GetItem(t, keyring, "key1", opItemsExisting)

		_, err := keyring.Get("key1")
		assert.ErrorIs(t, err, OPErrItemMalformed)
	})

	t.Run("SetRefusesIt", func(t *testing.T) {
		keyring := newOPConnectTestKeyring()
		var opItemSet connectop.Item
		opClientMock := NewOPConnectKeyringMock_SetItem(
			t, keyring, "key1", "newItemID", "newItemFieldID", time.Time{}, opItemsExisting, &opItemSet,
		)

		err := keyring.Set(Item{Key: "key1", Data: []byte(`data`)})
		assert.ErrorIs(t, err, OPErrItemMalformed)
		opClientMock.AssertNotCalled(t, "CreateItem", mock.Anything, mock.Anything)
		opClientMock.AssertNotCalled(t, "UpdateItem", mock.Anything, mock.Anything)
	})

	t.Run("RemoveDeletesIt", func(t *testing.T) {
		keyring := newOPConnectTestKeyring()
		var opItemIDRemoved string
		NewOPConnectKeyringMock_RemoveItem(t, keyring, "key1", opItemsExisting, &opItemIDRemoved)

		if err := keyring.Remove("key1"); err != nil {
			t.Fatal(err)
		}
		assert.Equal(t, "itemID1", opItemIDRemoved)
	})
}

func TestOPConnectKeyring_KeysSkipsUnprefixedTitles(t *testing.T) {
	noPrefix := newOPConnectTestItem(t, "itemID1", "key1")
	noPrefix.Title = "key1"
	noSeparator := newOPConnectTestItem(t, "itemID2", "key2")
	noSeparator.Title = "itemTitlePrefixkey2"

	keyring := newOPConnectTestKeyring()
	newOPConnectKeyringMock_GetKeys(t, keyring, []connectop.Item{
		newOPConnectTestItem(t, "itemID0", "key0"),
		noPrefix,
		noSeparator,
	})

	keys, err := keyring.Keys()
	if err != nil {
		t.Fatal(err)
	}
	assert.ElementsMatch(t, []string{"key0"}, keys)
}
