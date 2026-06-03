//go:build windows
// +build windows

package winhello

import (
	"errors"
	"fmt"
)

var ErrKeyNotFound = errors.New("The specified item could not be found in the keyring")

const passportDefaultLogicalName = "keyring-winhello-v1"

var (
	passportLogicalNameFunc = func() string {
		return passportDefaultLogicalName
	}
	ensurePassportKeyFunc = func(logicalName string, hwnd uintptr) (winHelloKeyWrapper, error) {
		return ensureWinHelloPassportKey(logicalName, hwnd)
	}
	openPassportKeyFunc = func(logicalName string, hwnd uintptr) (winHelloKeyWrapper, error) {
		return openWinHelloPassportKey(logicalName, hwnd)
	}
)

type Backend struct {
	serviceName string
	store       *winHelloWinCredStore
	wrapper     winHelloKeyWrapper
	logicalName string
	keyName     string
}

func New(serviceName string) (*Backend, error) {
	logicalName := passportLogicalNameFunc()
	keyName, err := winHelloPassportKeyName(logicalName)
	if err != nil {
		return nil, err
	}

	store := newWinHelloWinCredStore(serviceName)

	return &Backend{
		serviceName: store.serviceName,
		store:       store,
		logicalName: logicalName,
		keyName:     keyName,
	}, nil
}

func (b *Backend) Get(key string) ([]byte, error) {
	encoded, err := b.store.Read(key)
	if err != nil {
		return nil, fmt.Errorf("read winhello item %q: %w", key, err)
	}

	wrapper, err := b.openWrapper()
	if err != nil {
		return nil, wrapExistingItemPassportKeyError(key, err)
	}

	plaintext, err := decryptWinHelloEnvelope(
		encoded,
		winHelloAAD(b.serviceName, key),
		b.keyName,
		wrapper,
		winHelloUseContext(b.serviceName, key),
	)
	if err != nil {
		return nil, fmt.Errorf("decrypt winhello item %q: %w", key, err)
	}

	return plaintext, nil
}

func (b *Backend) Set(key string, data []byte) error {
	wrapper, err := b.ensureWrapper()
	if err != nil {
		return fmt.Errorf("prepare winhello Passport key for %q: %w", key, err)
	}

	encoded, err := encryptWinHelloEnvelope(data, winHelloAAD(b.serviceName, key), b.keyName, wrapper)
	if err != nil {
		return fmt.Errorf("encrypt winhello item %q: %w", key, err)
	}

	if err := b.store.Write(key, encoded); err != nil {
		return fmt.Errorf("write winhello item %q: %w", key, err)
	}

	return nil
}

func (b *Backend) Remove(key string) error {
	if err := b.store.Delete(key); err != nil {
		return fmt.Errorf("remove winhello item %q: %w", key, err)
	}

	return nil
}

func (b *Backend) Keys() ([]string, error) {
	keys, err := b.store.Keys()
	if err != nil {
		return nil, fmt.Errorf("list winhello items: %w", err)
	}

	return keys, nil
}

func (b *Backend) ensureWrapper() (winHelloKeyWrapper, error) {
	if b.wrapper != nil {
		return b.wrapper, nil
	}

	wrapper, err := ensurePassportKeyFunc(b.logicalName, winHelloParentHWNDFunc())
	if err != nil {
		return nil, err
	}

	b.wrapper = wrapper
	return wrapper, nil
}

func (b *Backend) openWrapper() (winHelloKeyWrapper, error) {
	if b.wrapper != nil {
		return b.wrapper, nil
	}

	wrapper, err := openPassportKeyFunc(b.logicalName, winHelloParentHWNDFunc())
	if err != nil {
		return nil, err
	}

	b.wrapper = wrapper
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

func wrapExistingItemPassportKeyError(key string, err error) error {
	if errors.Is(err, ErrKeyNotFound) || errors.Is(err, errWinHelloPassportKeyNotFound) {
		return fmt.Errorf(
			"open winhello Passport key for existing item %q: %w",
			key,
			errWinHelloPassportKeyNotFound,
		)
	}

	return fmt.Errorf("open winhello Passport key for existing item %q: %w", key, err)
}
