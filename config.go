package keyring

import (
	"time"
)

// Config contains configuration for keyring.
type Config struct {
	// AllowedBackends is a whitelist of backend providers that can be used. Nil means all available.
	AllowedBackends []BackendType

	// ServiceName is a generic service name that is used by backends that support the concept
	ServiceName string

	// MacOSKeychainNameKeychainName is the name of the macOS keychain that is used
	KeychainName string

	// KeychainTrustApplication is whether the calling application should be trusted by default by items
	KeychainTrustApplication bool

	// KeychainSynchronizable is whether the item can be synchronized to iCloud
	KeychainSynchronizable bool

	// KeychainAccessibleWhenUnlocked is whether the item is accessible when the device is locked
	KeychainAccessibleWhenUnlocked bool

	// KeychainPasswordFunc is an optional function used to prompt the user for a password
	KeychainPasswordFunc PromptFunc

	// FilePasswordFunc is a required function used to prompt the user for a password
	FilePasswordFunc PromptFunc

	// FileDir is the directory that keyring files are stored in, ~/ is resolved to the users' home dir
	FileDir string

	// KeyCtlScope is the scope of the kernel keyring (either "user", "session", "process" or "thread")
	KeyCtlScope string

	// KeyCtlPerm is the permission mask to use for new keys
	KeyCtlPerm uint32

	// KWalletAppID is the application id for KWallet
	KWalletAppID string

	// KWalletFolder is the folder for KWallet
	KWalletFolder string

	// LibSecretCollectionName is the name collection in secret-service
	LibSecretCollectionName string

	// PassDir is the pass password-store directory, ~/ is resolved to the users' home dir
	PassDir string

	// PassCmd is the name of the pass executable
	PassCmd string

	// PassPrefix is a string prefix to prepend to the item path stored in pass
	PassPrefix string

	// WinCredPrefix is a string prefix to prepend to the key name
	WinCredPrefix string

	// UseBiometrics is whether to use biometrics (where available) to unlock the keychain
	UseBiometrics bool

	// TouchIDAccount is the name of the account that we store the unlock password in keychain
	TouchIDAccount string

	// TouchIDService is the name of the service that we store the unlock password in keychain
	TouchIDService string

	// OPTimeout is the timeout for 1Password API operations (1Password Service Accounts only)
	OPTimeout time.Duration

	// OPVaultID is the UUID of the 1Password vault
	OPVaultID string

	// OPItemTitlePrefix is the prefix to prepend to 1Password item titles
	OPItemTitlePrefix string

	// OPItemTag is the tag to apply to 1Password items
	OPItemTag string

	// OPItemFieldTitle is the title of the 1Password item field
	OPItemFieldTitle string

	// OPConnectHost is the 1Password Connect server HTTP(S) URI
	OPConnectHost string

	// OPConnectTokenEnv is the primary environment variable from which to look up the 1Password Connect token
	OPConnectTokenEnv string

	// OPTokenEnv is the primary environment variable from which to look up the 1Password service account token
	OPTokenEnv string

	// OPTokenFunc is the function used to prompt the user for the 1Password Connect / service account token
	OPTokenFunc PromptFunc
}
