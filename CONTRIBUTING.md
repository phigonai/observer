# Contributing to the Phigon Observer

Thank you for helping. Bug reports, fixes, new agent adapters and documentation
improvements are all welcome.

## How this repository works

This repository is published automatically from Phigon's main repository, where
the observer is developed alongside the Phigon control plane. Changes made
there appear here within a few minutes, and released versions are tagged here
and published to npm.

Pull requests are reviewed here as usual. When a pull request is accepted, a
maintainer applies it in the main repository with you as the commit author, and
closes it here with a link to the published commit. Please do not be surprised
that the merge button stays disabled: the main branch here only changes through
that sync.

## Before you start

- For anything larger than a small fix, open an issue first so we can agree on
  the approach.
- Security problems must not be reported in issues or pull requests. See
  [SECURITY.md](SECURITY.md).
- By taking part you agree to follow the [Code of Conduct](CODE_OF_CONDUCT.md).

## Sign your commits (DCO)

Every commit must carry a `Signed-off-by` line. It certifies that you wrote the
change or otherwise have the right to submit it under the Apache License 2.0,
as described in the [Developer Certificate of Origin](https://developercertificate.org/).
Add it with `-s`:

```sh
git commit -s -m "Detect Cursor background agents"
```

To sign off commits you already made: `git rebase --signoff main`.
A check on every pull request fails if a commit is not signed off.

## Development

You need Node.js 24+ and Go 1.26+.

```sh
npm ci
npm run check            # lint, type check and tests
cd go && go test ./...   # Go tests for the Guardian runner and its packages
```

`npm run build` compiles the CLI and the Guardian runner for your platform.

### Changing the protocol

The wire protocol in `proto/` is shared with every Phigon control plane, so
changes must stay backward compatible: add new fields and messages, and never
rename, renumber or remove existing ones. After editing a `.proto` file,
regenerate the code with [Buf](https://buf.build), update the checksums, and
include both in your pull request:

```sh
buf lint
buf generate
sha256sum go/gen/phigon/v1/*.go src/generated/phigon/v1/*.ts | sed 's/ \*/  /' | LC_ALL=C sort > proto/generated.sha256
sh scripts/check-generated.sh
```

Never edit generated files by hand.

### Adding an agent

Agent detection lives in `src/discovery/adapters` and activity parsing in
`src/activity/adapters`. New adapters need tests with realistic, anonymized
sample records, and must keep the privacy rules: content is collected only
under the Full activity profile, and every value passes through local
redaction before it is queued.

## Pull requests

- Keep each pull request focused on one change, with tests.
- Write commit messages in the imperative mood ("Add", "Fix"), and explain why
  in the body when it is not obvious.
- Run `npm run check` and the Go tests before pushing; CI runs them on Linux,
  macOS and Windows.

## License

By contributing, you agree that your contributions are licensed under the
[Apache License 2.0](LICENSE).
