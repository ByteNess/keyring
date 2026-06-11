Keyring
=======
[![Build Status](https://github.com/byteness/keyring/workflows/Continuous%20Integration/badge.svg)](https://github.com/byteness/keyring/actions)
[![Documentation](https://godoc.org/github.com/byteness/keyring?status.svg)](https://godoc.org/github.com/byteness/keyring)

> [!NOTE]
> This is a maintained fork of https://github.com/99designs/keyring which seems to be an abandoned project.
> Contributions are welcome, but keep in mind this is a side project and maintained on best effort basis!

Keyring provides a common interface to a range of secure credential storage services. Originally developed as part of [AWS Vault](https://github.com/byteness/aws-vault), a command line tool for securely managing AWS access from developer workstations.

Currently Keyring supports the following backends
 * [macOS Keychain](https://support.apple.com/en-au/guide/keychain-access/welcome/mac) (with TouchID support 🎉)
 * [Windows Credential Manager](https://support.microsoft.com/en-au/help/4026814/windows-accessing-credential-manager)
 * [Windows Hello](https://support.microsoft.com/en-us/windows/configure-windows-hello-dae28983-8242-bb2a-d3d1-87c9d265a5f0)-gated encrypted Credential Manager backend
 * Secret Service ([Gnome Keyring](https://wiki.gnome.org/Projects/GnomeKeyring), [KWallet](https://kde.org/applications/system/org.kde.kwalletmanager5))
 * [KWallet](https://kde.org/applications/system/org.kde.kwalletmanager5)
 * [Pass](https://www.passwordstore.org/)
 * [Passage](https://github.com/FiloSottile/passage)
 * [Encrypted file (JWT)](https://datatracker.ietf.org/doc/html/rfc7519)
 * [KeyCtl](https://linux.die.net/man/1/keyctl)
 * [1Password Connect](https://developer.1password.com/docs/connect/)
 * [1Password Service Accounts](https://developer.1password.com/docs/service-accounts)
 * [1Password Desktop Application Integration](https://developer.1password.com/docs/sdks/desktop-app-integrations/)

## Usage

The short version of how to use keyring is shown below.

```go
ring, _ := keyring.Open(keyring.Config{
  ServiceName: "example",
})

_ = ring.Set(keyring.Item{
	Key: "foo",
	Data: []byte("secret-bar"),
})

i, _ := ring.Get("foo")

fmt.Printf("%s", i.Data)
```

To configure TouchId biometrics:

```go
keyring.Config.UseBiometrics = true
keyring.Config.TouchIDAccount = "cc.byteness.aws-vault.biometrics"
keyring.Config.TouchIDService = "aws-vault"
```

### Windows Hello backend

The `winhello` backend stores encrypted envelopes in Windows Credential Manager.
This may sound similar to the `wincred` backend, but the difference is encryption.
Here, we don't store plaintext item data in Credential Manager. It is encrypted
with AES-256-GCM, and the content encryption key is wrapped by a Windows Hello /
Passport KSP key and unwrapped through an interactive private-key operation.

Upon the first use, a new Passport KSP key is created and stored in the user's
protected key store. This operation requires user interaction and Windows Hello
authentication. Later, whenever an item is accessed, the content encryption key
is unwrapped by the Passport KSP key, which requires Windows Hello authentication
again. This means that every access to the stored secrets requires user presence
and authentication through Windows Hello (using PIN, fingerprint, face ID, etc.).

This protects against silent reads of the stored Credential Manager blob. It
does not protect against malware that can read process memory after a successful
unlock, inject into an approved process, or steal credentials after they are
handed to a caller.

To use the Windows Hello backend on Windows:

```go
ring, err := keyring.Open(keyring.Config{
  ServiceName: "example",
  AllowedBackends: []keyring.BackendType{
    keyring.WinHelloBackend,
  },
})
if err != nil {
  return err
}
```

For more detail on the API please check [the keyring godocs](https://godoc.org/github.com/byteness/keyring)

## Testing

[Vagrant](https://www.vagrantup.com/) is used to create linux and windows test environments.

```bash
# Start vagrant
vagrant up

# Run go tests on all platforms
./bin/go-test
```

## Contributing

### Before you start

Please read the following first:

- **[AI_POLICY.md](../AI_POLICY.md)** — if you intend to use any AI assistance (Claude, Copilot, Cursor, etc.) for your contribution. The short version: AI is welcome, but its use must be disclosed, code must be human-tested, and AI-generated PRs require an accepted issue first. Drive-by AI PRs will be closed.

Please only submit changes to backends you can actually test on the relevant platform. Untested code for platforms you don't have access to is one of the failure modes called out in `AI_POLICY.md` and applies to manual contributions too.

### How to contribute

Contributions to the keyring package are most welcome from engineers of all backgrounds and skill levels. In particular the addition of extra backends across popular operating systems would be appreciated.

This project will adhere to the [Go Community Code of Conduct](https://golang.org/conduct) in the github provided discussion spaces, with the moderators being the part of ByteNess engineering team.

To make a contribution:

  * Fork the repository
  * Make your changes on the fork
  * Submit a pull request back to this repo with a clear description of the problem you're solving
  * Ensure your PR passes all current (and new) tests
  * Ideally verify that [aws-vault](https://github.com/byteness/aws-vault) works with your changes (optional)

...and we'll do our best to get your work merged in!
