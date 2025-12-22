# Contributing

Hello, and thank you for taking the time to read the contributing guidelines for Sandhole! Please read through our [Code of Conduct](./CODE_OF_CONDUCT.md) as well.

Here are some ways to contribute to the project:

## Creating issues

Please search the [existing issues](https://github.com/EpicEric/sandhole/issues), as well as [the Sandhole book](https://sandhole.com.br/), for any answers or existing discussions before creating your own issue.

## Submitting changes

In the case that you'd like to make contributions to Sandhole, create an issue first if one does not exist.

If you wish to contribute changes to Sandhole, please [fork the repository](https://github.com/EpicEric/sandhole/fork), push your modifications to a branch other than main, and create a [pull request](https://github.com/EpicEric/sandhole/compare). Make sure to [link to the original issue](https://docs.github.com/en/issues/tracking-your-work-with-issues/using-issues/linking-a-pull-request-to-an-issue#linking-a-pull-request-to-an-issue-using-a-keyword) in your PR's body.

If possible, make sure that your changes pass all tests and linting/formatting checks before creating a pull request by running `just test` and `just clippy`, respectively. This should ensure that your PR will pass the CI pipeline.

Please add a short description of any user-facing changes to the top of [CHANGELOG.md](./CHANGELOG.md), under the "Unreleased" section (or create one if it does not exist). The changelog should adhere to [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and it must emphasize any breaking changes. Also, update the [features.md page](./book/src/features.md) of the book accordingly.

If you're adding or modifying a command line option, run `just cli`, manually format the contents output to `cli.html` (i.e. by wrapping long lines and removing trailing whitespace), and update the [cli.md page](./book/src/cli.md) of the book accordingly.
