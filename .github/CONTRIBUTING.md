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
