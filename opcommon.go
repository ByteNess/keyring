package keyring

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"

	onepassword "github.com/1password/onepassword-sdk-go"
)

const (
	OPEnvVaultID            = "OP_VAULT_ID"
	OPItemFieldTitle        = "keyring"
	OPItemTag               = "keyring"
	OPItemTitlePrefix       = "keyring"
	OPItemTitlePrefixKeySep = ": "
)

var (
	ErrEnvUnsetOrEmpty = errors.New("Environment variable unset or empty")
	OPErrClient        = errors.New(
		"Unable to create a 1Password Connect / Service Accounts / Desktop Integration client",
	)
	OPErrItemMultiple       = errors.New("Found multiple matching 1Password items")
	OPErrItemTitleDuplicate = errors.New("Found duplicate 1Password item title")
	OPErrKeyring            = errors.New(
		"Unable to create a 1Password Connect / Service Accounts / Desktop Integration keyring",
	)
	OPErrTokenFuncNil = fmt.Errorf("%w: Token function is nil", OPErrClient)
	OPErrVaultID      = fmt.Errorf("%w: %w: %#v", OPErrKeyring, ErrEnvUnsetOrEmpty, OPEnvVaultID)
)

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

type OPBaseKeyring struct {
	VaultID         string
	ItemTitlePrefix string
	ItemTag         string
	ItemFieldTitle  string
	TokenEnvs       []string
	TokenFunc       PromptFunc
}

func (k *OPBaseKeyring) GetItemFromOPItemFieldValue(opItemFieldValue string) (*Item, error) {
	var item Item
	err := json.Unmarshal([]byte(opItemFieldValue), &item)
	return &item, err
}

func (k *OPBaseKeyring) GetKeyFromOPItemTitle(opItemTitle string) string {
	return strings.TrimPrefix(opItemTitle, k.ItemTitlePrefix+OPItemTitlePrefixKeySep)
}

func (k *OPBaseKeyring) GetOPItemFieldValueFromItem(item *Item) (string, error) {
	opItemFieldValueBytes, err := json.Marshal(item)
	if err != nil {
		return "", err
	}
	return string(opItemFieldValueBytes), nil
}

func (k *OPBaseKeyring) GetOPItemTitleFromKey(key string) string {
	return k.ItemTitlePrefix + OPItemTitlePrefixKeySep + key
}

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
