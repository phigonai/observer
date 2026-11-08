# Changelog

All notable changes to `@phigon/observer` are listed here. Versions follow
[Semantic Versioning](https://semver.org/). Each release is published to npm
from the matching `vX.Y.Z` tag in this repository.

## Unreleased

- `pair --remote-actions <all|stop-agents|none>` sets what the company's
  administrators may do on the computer: stop agents and run the commands
  they approve, only stop agents, or nothing. The consent prompt says its
  default, all. `--no-remote-commands` and `--no-remote-actions` still work.
- `pair --accept-consent` skips the prompt, so it now allows no remote
  actions unless `--remote-actions` says otherwise.
- Commands refuse options they do not take, a switch given twice and
  unknown `--remote-actions` values. Usage errors exit with code 2.
- The person at the computer is told before an administrator's command
  starts.
- Everything after `--` goes to the program that `guardian` runs.
- Redaction fixes.
- Safer consent defaults.
- Lower CPU use while the observer is idle.
- Trust fixes.
- Background service and agent discovery fixes.
- Guardian runner sandbox hardening.
- CI and release hardening:
  - The release publishes only after the full test suite passes on Linux,
    macOS and Windows for the tagged commit, from a job that runs none of
    the repository's code.
  - Each GitHub release carries a `SHA256SUMS` file for the npm tarball and
    the Guardian runner binaries.
  - CI installs the packed package globally on all three systems and runs
    `phigon-observer --version` and `phigon-observer doctor --json`.
  - Go tests run on all three systems; CI checks the protocol against the
    last release with `buf breaking`, enforces the coverage floor, runs
    govulncheck and CodeQL, and type-checks the scripts in `scripts/`.
  - The mirror sync keeps its push key away from the mirrored code.

## 8.11.2 (2026-11-05)

- The README opens with Phigon's banner.

## 8.11.1 (2026-11-05)

- Every observer command is explained in the README, along with how this
  repository mirrors Phigon's main repository.

## 8.11.0 (2026-11-05)

- The relay is safe to rely on: it falls back both ways, pins the server it
  trusts, and limits floods and memory.

## 8.10.0 (2026-11-05)

- Computers can reach their Phigon server from any network through Phigon's
  relay.

## 8.9.0 (2026-11-04)

- Detects Gemini CLI, Copilot CLI, Amp and Claude Code when they are
  installed with npm.
- Finds npm-installed agents on Linux, where Node.js is listed by its main
  thread.

## 8.8.1 (2026-11-04)

- Keeps consent exact, and corrects the observer's own advice.

## 8.8.0 (2026-11-04)

- Pairing asks whether administrators may stop agents and run commands on
  the computer.

## 8.7.2 (2026-11-04)

- Recognises a running observer when the clock was corrected while it
  started.

## 8.7.1 (2026-11-04)

- The background service keeps running when Node.js is upgraded.

## 8.7.0 (2026-11-04)

- Follows the server to its new address when the administrator's computer
  changes address.

## 8.6.1 (2026-11-03)

- The observer keeps running on its own after the terminal that started it
  closes.

## 8.6.0 (2026-11-03)

- The observer keeps running after pairing.

## 8.5.0 (2026-11-03)

- Computers follow their server to a new address, and narrowed consent takes
  effect at once.
- Quieter retries, and a removed computer no longer restarts in a loop.

## 8.4.0 (2026-11-03)

- Fixes four problems found by testing the installed app.

## 8.3.0 (2026-11-02)

- Fleet enrollment with the company's code: the person at the computer is
  told, and the observer reports its version.
- Ready for a whole fleet: more reliable through damaged queues, stale locks
  and bad records.
- Content stays off without full consent, and more secret formats are
  redacted.
- Removing a computer keeps its history; re-pairing, a 5x faster spool, the
  server's clock, a quieter Guardian and pruning.
- Reliability: bounded memory, a full spool, a single instance per data
  directory, skipped bad sources, Windows renames and redaction.
- Service install fixes on Linux and macOS.

## 8.2.0 (2026-11-01)

- Other computers on the network can connect to a company's own server.
- Tells the person at the computer when Phigon acts on it.
- Stop works for terminal agents on Windows, with exact process-tree stops
  and honest receipts.
- Reads Cline, Roo Code, Kilo Code, Factory Droid, Zed, Cursor, VS Code
  Copilot and Kiro records; finds Antigravity, Trae, Zed, Droid and Roo.
- Captures OpenCode 1 and OpenCode 2 conversations, and live activity for
  Gemini CLI, Goose and Cline.
- History imports are paced to about half a core, never spin forever, and
  scan documents 16x more cheaply.
- Idle databases are skipped, Windows process listing is 10x faster, and
  discovery survives errors.
- Hardened token redaction, update caching, flag parsing, replay boundaries
  and spool retries; the Windows data directory is restricted to its owner.
- The Guardian runner tolerates one unreachable lease renewal.

## 8.1.0 (2026-10-25)

- First open-source release under the Apache License 2.0, published to npm
  as `@phigon/observer` through npm trusted publishing with provenance.
