//go:build windows
// +build windows

package keyring

func init() {
	supportedBackends[WinHelloBackend] = opener(func(cfg Config) (Keyring, error) {
		return newWinHelloKeyring(cfg.ServiceName)
	})
}
