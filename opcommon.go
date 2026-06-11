//go:build !freebsd && !keyring_no1password

package keyring

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"

	onepassword "github.com/1password/onepassword-sdk-go"
)

// Environment variable names and item naming conventions shared by the
// 1Password backends.
const (
	OPEnvVaultID            = "OP_VAULT_ID"
	OPItemFieldTitle        = "keyring"
	OPItemTag               = "keyring"
	OPItemTitlePrefix       = "keyring"
	OPItemTitlePrefixKeySep = ": "
)

// Errors shared by the 1Password backends.
var (
	ErrEnvUnsetOrEmpty = errors.New("environment variable unset or empty")
	OPErrClient        = errors.New(
		"unable to create a 1Password Connect / Service Accounts / Desktop Integration client",
	)
	OPErrItemMultiple       = errors.New("found multiple matching 1Password items")
	OPErrItemTitleDuplicate = errors.New("found duplicate 1Password item title")
	OPErrKeyring            = errors.New(
		"unable to create a 1Password Connect / Service Accounts / Desktop Integration keyring",
	)
	OPErrTokenFuncNil = fmt.Errorf("%w: Token function is nil", OPErrClient)
	OPErrVaultID      = fmt.Errorf("%w: %w: %#v", OPErrKeyring, ErrEnvUnsetOrEmpty, OPEnvVaultID)
)

// OPKeyringAPI is the interface implemented by the 1Password backends.
type OPKeyringAPI interface {
	Keyring
	GetItemFromOPItemFieldValue(opItemFieldValue string) (*Item, error)
	GetKeyFromOPItemTitle(opItemTitle string) string
	GetOPItem(key string) (*onepassword.Item, error)
	GetOPItemFieldValueFromItem(item *Item) (string, error)
	GetOPItems() ([]onepassword.Item, error)
	GetOPItemTitleFromKey(key string) string
	GetOPToken(prompt string) (string, error)
}

// OPBaseKeyring holds the configuration common to all 1Password backends.
type OPBaseKeyring struct {
	VaultID         string
	ItemTitlePrefix string
	ItemTag         string
	ItemFieldTitle  string
	TokenEnvs       []string
	TokenFunc       PromptFunc
}

// GetItemFromOPItemFieldValue unmarshals a 1Password item field value into an Item.
func (k *OPBaseKeyring) GetItemFromOPItemFieldValue(opItemFieldValue string) (*Item, error) {
	var item Item
	err := json.Unmarshal([]byte(opItemFieldValue), &item)
	return &item, err
}

// GetKeyFromOPItemTitle derives the keyring key from a 1Password item title.
func (k *OPBaseKeyring) GetKeyFromOPItemTitle(opItemTitle string) string {
	return strings.TrimPrefix(opItemTitle, k.ItemTitlePrefix+OPItemTitlePrefixKeySep)
}

// GetOPItemFieldValueFromItem marshals an Item into a 1Password item field value.
func (k *OPBaseKeyring) GetOPItemFieldValueFromItem(item *Item) (string, error) {
	opItemFieldValueBytes, err := json.Marshal(item)
	if err != nil {
		return "", err
	}
	return string(opItemFieldValueBytes), nil
}

// GetOPItemTitleFromKey derives the 1Password item title from a keyring key.
func (k *OPBaseKeyring) GetOPItemTitleFromKey(key string) string {
	return k.ItemTitlePrefix + OPItemTitlePrefixKeySep + key
}

// GetOPToken returns the 1Password token from the configured environment
// variables, falling back to prompting via TokenFunc.
func (k *OPBaseKeyring) GetOPToken(prompt string) (string, error) {
	for _, tokenEnv := range k.TokenEnvs {
		token := os.Getenv(tokenEnv)
		if token != "" {
			return token, nil
		}
	}
	if k.TokenFunc != nil {
		return k.TokenFunc(prompt)
	}
	return "", OPErrTokenFuncNil
}
