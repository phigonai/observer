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
- Lower CPU use while the observer is idle, and less while agents work:
  - Agent session folders are kept between scans instead of listed and
    checked every second. Recently changed folders and files are still
    checked every second; the rest by a full pass every 10 s on Windows
    and 3 s elsewhere, or once a minute while `fs.watch` (Windows and
    macOS, used only as a hint) reports changes. Roots that do not exist
    are looked for every 5 s.
  - After two minutes without activity, scans run every 5 s, and every
    second again as soon as anything changes.
  - `activity-cursors.json` is written at most every 5 s while an agent
    is active, and on shutdown.
  - Discovery reads an npm-installed CLI's version from its package.json
    instead of running it (through PowerShell for `.cmd` shims), and lists
    each PATH folder once instead of checking every name and extension.
    A CLI that has to be run gets 15 s to print its version.
  - When the native process helper fails on Windows, it and the
    PowerShell fallback back off up to five minutes.
  - The agent inventory is sent when it changes and every 30 s otherwise,
    instead of every 10 s.
  - The event spool is not rewritten on every start and connection, keeps
    stored records when it compacts, and each event is encoded once for
    its size check and the spool.
- A log that is emptied and written again in place gets new record IDs,
  so its new records are no longer dropped as copies of the old ones.
- `doctor` shows the running observer's CPU, memory, event-loop delay,
  last scan and delivery backlog.
- Trust and network fixes:
  - A server paired with `--server-ca-sha256` is trusted under that
    authority only. `PHIGON_TLS_CA_FILE` no longer replaces it for the
    stream; a network that inspects HTTPS must exempt the server or
    `*.relay.phigon.online`, and the observer says so.
  - Addresses on Phigon's relay are never trusted without a pinned
    authority, and pairing there needs `--server-ca-sha256`.
  - The machine key is stored with the authority it was issued under. If
    `server-ca.pem` goes missing or changes, the observer refuses to
    connect until the Connect machine command is run again.
  - Pairing again at the same address with another fingerprint never sends
    the stored key there: the computer pairs as a new machine, and the
    earlier key and its undelivered activity are kept in
    `retired-pairings`. A lost answer can be retried with the same code,
    and a new code pairs with a new installation ID.
  - Activity queued before a computer was paired again with the metadata
    profile is sent without its content.
  - Reconnect waits are spread over the whole backoff window, and the
    backoff starts over only after the stream stayed up for 30 seconds.
  - The Guardian runner is checked against the SHA-256 recorded at build
    time (`dist/bin/guardian-runner.sha256.json`) before it first runs.
  - Windows tools (icacls, whoami, PowerShell) start from
    `%SystemRoot%\System32`, never from the current folder.
  - A proxy password is masked in the output of administrators' commands.
  - On Linux and macOS the machine key is made owner-only when it is read,
    and refused if others can still read it or write to its folder.
  - An unreadable stream cursor is copied aside once, and only three copies
    are kept.
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
