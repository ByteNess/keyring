//go:build windows
// +build windows

package keyring

import (
	"errors"
	"fmt"
)

const winHelloPassportDefaultLogicalName = "keyring-winhello-v1"

var (
	winHelloPassportLogicalNameFunc = func() string {
		return winHelloPassportDefaultLogicalName
	}
	winHelloEnsurePassportKeyFunc = func(logicalName string, hwnd uintptr) (winHelloKeyWrapper, error) {
		return ensureWinHelloPassportKey(logicalName, hwnd)
	}
	winHelloOpenPassportKeyFunc = func(logicalName string, hwnd uintptr) (winHelloKeyWrapper, error) {
		return openWinHelloPassportKey(logicalName, hwnd)
	}
)

type winHelloKeyring struct {
	serviceName string
	store       *winHelloWinCredStore
	wrapper     winHelloKeyWrapper
	logicalName string
	keyName     string
}

func newWinHelloKeyring(serviceName string) (*winHelloKeyring, error) {
	logicalName := winHelloPassportLogicalNameFunc()
	keyName, err := winHelloPassportKeyName(logicalName)
	if err != nil {
		return nil, err
	}

	store := newWinHelloWinCredStore(serviceName)

	return &winHelloKeyring{
		serviceName: store.serviceName,
		store:       store,
		logicalName: logicalName,
		keyName:     keyName,
	}, nil
}

func (k *winHelloKeyring) Get(key string) (Item, error) {
	encoded, err := k.store.Read(key)
	if err != nil {
		return Item{}, fmt.Errorf("read winhello item %q: %w", key, err)
	}

	wrapper, err := k.openWrapper()
	if err != nil {
		return Item{}, winHelloWrapExistingItemPassportKeyError(key, err)
	}

	plaintext, err := decryptWinHelloEnvelope(
		encoded,
		winHelloAAD(k.serviceName, key),
		k.keyName,
		wrapper,
		winHelloUseContext(k.serviceName, key),
	)
	if err != nil {
		return Item{}, fmt.Errorf("decrypt winhello item %q: %w", key, err)
	}

	return Item{Key: key, Data: plaintext}, nil
}

func (k *winHelloKeyring) GetMetadata(_ string) (Metadata, error) {
	return Metadata{}, ErrMetadataNotSupported
}

func (k *winHelloKeyring) Set(item Item) error {
	wrapper, err := k.ensureWrapper()
	if err != nil {
		return fmt.Errorf("prepare winhello Passport key for %q: %w", item.Key, err)
	}

	encoded, err := encryptWinHelloEnvelope(item.Data, winHelloAAD(k.serviceName, item.Key), k.keyName, wrapper)
	if err != nil {
		return fmt.Errorf("encrypt winhello item %q: %w", item.Key, err)
	}

	if err := k.store.Write(item.Key, encoded); err != nil {
		return fmt.Errorf("write winhello item %q: %w", item.Key, err)
	}

	return nil
}

func (k *winHelloKeyring) Remove(key string) error {
	if err := k.store.Delete(key); err != nil {
		return fmt.Errorf("remove winhello item %q: %w", key, err)
	}

	return nil
}

func (k *winHelloKeyring) Keys() ([]string, error) {
	keys, err := k.store.Keys()
	if err != nil {
		return nil, fmt.Errorf("list winhello items: %w", err)
	}

	return keys, nil
}

func (k *winHelloKeyring) ensureWrapper() (winHelloKeyWrapper, error) {
	if k.wrapper != nil {
		return k.wrapper, nil
	}

	// Keep Windows Hello activity out of Keys/Remove/GetMetadata and only touch
	// the shared Passport key when an operation actually needs crypto.
	wrapper, err := winHelloEnsurePassportKeyFunc(k.logicalName, winHelloParentHWNDFunc())
	if err != nil {
		return nil, err
	}

	k.wrapper = wrapper
	return wrapper, nil
}

func (k *winHelloKeyring) openWrapper() (winHelloKeyWrapper, error) {
	if k.wrapper != nil {
		return k.wrapper, nil
	}

	wrapper, err := winHelloOpenPassportKeyFunc(k.logicalName, winHelloParentHWNDFunc())
	if err != nil {
		return nil, err
	}

	k.wrapper = wrapper
	return wrapper, nil
}

func winHelloUseContext(serviceName, key string) string {
	if serviceName == "" {
		serviceName = "default"
	}
	if key == "" {
		return "Unlock keyring secret for " + serviceName
	}

	return "Unlock keyring secret for " + key + " at " + serviceName
}

func winHelloWrapExistingItemPassportKeyError(key string, err error) error {
	if errors.Is(err, ErrKeyNotFound) || errors.Is(err, errWinHelloPassportKeyNotFound) {
		return fmt.Errorf(
			"open winhello Passport key for existing item %q: %w",
			key,
			errWinHelloPassportKeyNotFound,
		)
	}

	return fmt.Errorf("open winhello Passport key for existing item %q: %w", key, err)
}
