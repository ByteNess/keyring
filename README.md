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
 * Secret Service ([Gnome Keyring](https://wiki.gnome.org/Projects/GnomeKeyring), [KWallet](https://kde.org/applications/system/org.kde.kwalletmanager5))
 * [KWallet](https://kde.org/applications/system/org.kde.kwalletmanager5)
 * [Pass](https://www.passwordstore.org/)
 * [Encrypted file (JWT)](https://datatracker.ietf.org/doc/html/rfc7519)
 * [KeyCtl](https://linux.die.net/man/1/keyctl)
 * [1Password Connect](https://developer.1password.com/docs/connect/)
 * [1Password Service Accounts](https://developer.1password.com/docs/service-accounts)


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

Contributions to the keyring package are most welcome from engineers of all backgrounds and skill levels. In particular the addition of extra backends across popular operating systems would be appreciated.

This project will adhere to the [Go Community Code of Conduct](https://golang.org/conduct) in the github provided discussion spaces, with the moderators being the part of ByteNess engineering team.

To make a contribution:

  * Fork the repository
  * Make your changes on the fork
  * Submit a pull request back to this repo with a clear description of the problem you're solving
  * Ensure your PR passes all current (and new) tests
  * Ideally verify that [aws-vault](https://github.com/bteness/aws-vault) works with your changes (optional)

...and we'll do our best to get your work merged in!
