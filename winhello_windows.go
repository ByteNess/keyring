//go:build windows
// +build windows

package keyring

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
		return Item{}, err
	}

	wrapper, err := k.openWrapper()
	if err != nil {
		return Item{}, err
	}

	plaintext, err := decryptWinHelloEnvelope(encoded, winHelloAAD(k.serviceName, key), k.keyName, wrapper, "")
	if err != nil {
		return Item{}, err
	}

	return Item{Key: key, Data: plaintext}, nil
}

func (k *winHelloKeyring) GetMetadata(_ string) (Metadata, error) {
	return Metadata{}, ErrMetadataNotSupported
}

func (k *winHelloKeyring) Set(item Item) error {
	wrapper, err := k.ensureWrapper()
	if err != nil {
		return err
	}

	encoded, err := encryptWinHelloEnvelope(item.Data, winHelloAAD(k.serviceName, item.Key), k.keyName, wrapper)
	if err != nil {
		return err
	}

	return k.store.Write(item.Key, encoded)
}

func (k *winHelloKeyring) Remove(key string) error {
	return k.store.Delete(key)
}

func (k *winHelloKeyring) Keys() ([]string, error) {
	return k.store.Keys()
}

func (k *winHelloKeyring) ensureWrapper() (winHelloKeyWrapper, error) {
	if k.wrapper != nil {
		return k.wrapper, nil
	}

	// Keep Windows Hello activity out of Keys/Remove/GetMetadata and only touch
	// the shared Passport key when an operation actually needs crypto.
	wrapper, err := winHelloEnsurePassportKeyFunc(k.logicalName, 0)
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

	wrapper, err := winHelloOpenPassportKeyFunc(k.logicalName, 0)
	if err != nil {
		return nil, err
	}

	k.wrapper = wrapper
	return wrapper, nil
}
