//go:build ios && cgo

package keyring

import (
	"errors"
	"fmt"

	gokeychain "github.com/byteness/go-keychain"
)

type keychain struct {
	service string

	passwordFunc PromptFunc

	isSynchronizable         bool
	isAccessibleWhenUnlocked bool
}

func init() {
	supportedBackends[KeychainBackend] = opener(func(cfg Config) (Keyring, error) {
		kc := &keychain{
			service:      cfg.ServiceName,
			passwordFunc: cfg.KeychainPasswordFunc,

			// Set the isAccessibleWhenUnlocked to the boolean value of
			// KeychainAccessibleWhenUnlocked is a shorthand for setting the accessibility value.
			// See: https://developer.apple.com/documentation/security/ksecattraccessiblewhenunlocked
			isAccessibleWhenUnlocked: cfg.KeychainAccessibleWhenUnlocked,
		}
		return kc, nil
	})
}

func (k *keychain) Get(key string) (Item, error) {
	query := gokeychain.NewItem()
	query.SetSecClass(gokeychain.SecClassGenericPassword)
	query.SetService(k.service)
	query.SetAccount(key)
	query.SetMatchLimit(gokeychain.MatchLimitOne)
	query.SetReturnAttributes(true)
	query.SetReturnData(true)

	debugf("Querying keychain for service=%q, account=%q", k.service, key)
	results, err := gokeychain.QueryItem(query)
	if err == gokeychain.ErrorItemNotFound || len(results) == 0 {
		debugf("No results found")
		return Item{}, ErrKeyNotFound
	}

	if err != nil {
		debugf("Error: %#v", err)
		return Item{}, err
	}

	item := Item{
		Key:         key,
		Data:        results[0].Data,
		Label:       results[0].Label,
		Description: results[0].Description,
	}

	debugf("Found item %q", results[0].Label)
	return item, nil
}

func (k *keychain) GetMetadata(key string) (Metadata, error) {
	query := gokeychain.NewItem()
	query.SetSecClass(gokeychain.SecClassGenericPassword)
	query.SetService(k.service)
	query.SetAccount(key)
	query.SetMatchLimit(gokeychain.MatchLimitOne)
	query.SetReturnAttributes(true)
	query.SetReturnData(false)
	query.SetReturnRef(true)

	debugf("Querying keychain for metadata of service=%q, account=%q", k.service, key)
	results, err := gokeychain.QueryItem(query)
	if err == gokeychain.ErrorItemNotFound || len(results) == 0 {
		debugf("No results found")
		return Metadata{}, ErrKeyNotFound
	} else if err != nil {
		debugf("Error: %#v", err)
		return Metadata{}, err
	}

	md := Metadata{
		Item: &Item{
			Key:         key,
			Label:       results[0].Label,
			Description: results[0].Description,
		},
		ModificationTime: results[0].ModificationDate,
	}

	debugf("Found metadata for %q", md.Item.Label)

	return md, nil
}

func (k *keychain) updateItem(kcItem gokeychain.Item, account string) error {
	queryItem := gokeychain.NewItem()
	queryItem.SetSecClass(gokeychain.SecClassGenericPassword)
	queryItem.SetService(k.service)
	queryItem.SetAccount(account)
	queryItem.SetMatchLimit(gokeychain.MatchLimitOne)
	queryItem.SetReturnAttributes(true)

	results, err := gokeychain.QueryItem(queryItem)
	if err != nil {
		return fmt.Errorf("Failed to query keychain: %v", err)
	}
	if len(results) == 0 {
		return errors.New("no results")
	}

	if err := gokeychain.UpdateItem(queryItem, kcItem); err != nil {
		return fmt.Errorf("Failed to update item in keychain: %v", err)
	}

	return nil
}

func (k *keychain) Set(item Item) error {
	kcItem := gokeychain.NewItem()
	kcItem.SetSecClass(gokeychain.SecClassGenericPassword)
	kcItem.SetService(k.service)
	kcItem.SetAccount(item.Key)
	kcItem.SetLabel(item.Label)
	kcItem.SetDescription(item.Description)
	kcItem.SetData(item.Data)

	if k.isSynchronizable && !item.KeychainNotSynchronizable {
		kcItem.SetSynchronizable(gokeychain.SynchronizableYes)
	}

	if k.isAccessibleWhenUnlocked {
		kcItem.SetAccessible(gokeychain.AccessibleWhenUnlocked)
	}

	err := gokeychain.AddItem(kcItem)

	if err == gokeychain.ErrorDuplicateItem {
		debugf("Item already exists, updating")
		err = k.updateItem(kcItem, item.Key)
	}

	if err != nil {
		return err
	}

	return nil
}

func (k *keychain) Remove(key string) error {
	item := gokeychain.NewItem()
	item.SetSecClass(gokeychain.SecClassGenericPassword)
	item.SetService(k.service)
	item.SetAccount(key)

	debugf("Removing keychain item service=%q, account=%q", k.service, key)
	err := gokeychain.DeleteItem(item)
	if err == gokeychain.ErrorItemNotFound {
		return ErrKeyNotFound
	}

	return err
}

func (k *keychain) Keys() ([]string, error) {
	query := gokeychain.NewItem()
	query.SetSecClass(gokeychain.SecClassGenericPassword)
	query.SetService(k.service)
	query.SetMatchLimit(gokeychain.MatchLimitAll)
	query.SetReturnAttributes(true)

	debugf("Querying keychain for service=%q", k.service)
	results, err := gokeychain.QueryItem(query)
	if err != nil {
		return nil, err
	}

	debugf("Found %d results", len(results))
	accountNames := make([]string, len(results))
	for idx, r := range results {
		accountNames[idx] = r.Account
	}

	return accountNames, nil
}
