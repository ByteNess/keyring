//go:build windows
// +build windows

package keyring

import (
	"errors"

	winhelloimpl "github.com/byteness/keyring/winhello" //nolint:depguard
)

type winHelloKeyring struct {
	backend *winhelloimpl.Backend
}

func newWinHelloKeyring(serviceName string) (*winHelloKeyring, error) {
	backend, err := winhelloimpl.New(serviceName)
	if err != nil {
		return nil, err
	}

	return &winHelloKeyring{
		backend: backend,
	}, nil
}

func init() {
	supportedBackends[WinHelloBackend] = opener(func(cfg Config) (Keyring, error) {
		return newWinHelloKeyring(cfg.ServiceName)
	})
}

func (k *winHelloKeyring) Get(key string) (Item, error) {
	data, err := k.backend.Get(key)
	if err != nil {
		if errors.Is(err, winhelloimpl.ErrKeyNotFound) {
			return Item{}, ErrKeyNotFound
		}
		return Item{}, err
	}

	return Item{Key: key, Data: data}, nil
}

func (k *winHelloKeyring) GetMetadata(_ string) (Metadata, error) {
	return Metadata{}, ErrMetadataNotSupported
}

func (k *winHelloKeyring) Set(item Item) error {
	return k.backend.Set(item.Key, item.Data)
}

func (k *winHelloKeyring) Remove(key string) error {
	if err := k.backend.Remove(key); err != nil {
		if errors.Is(err, winhelloimpl.ErrKeyNotFound) {
			return ErrKeyNotFound
		}
		return err
	}

	return nil
}

func (k *winHelloKeyring) Keys() ([]string, error) {
	return k.backend.Keys()
}
