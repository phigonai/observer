<p align="center">
  <a href="https://phigon.online">
    <picture>
      <source media="(prefers-color-scheme: dark)" srcset="https://phigon.online/brand/phigon-white.svg" />
      <img src="https://phigon.online/brand/phigon-black.svg" alt="Phigon" width="64" />
    </picture>
  </a>
</p>

<h1 align="center">Phigon Observer</h1>

<p align="center">
  See what AI coding agents do on a computer, with the owner's consent.
</p>

<p align="center">
  <a href="https://www.npmjs.com/package/@phigon/observer"><img alt="npm" src="https://img.shields.io/npm/v/@phigon/observer?color=000000&label=npm"></a>
  <a href="LICENSE"><img alt="License: Apache 2.0" src="https://img.shields.io/badge/license-Apache%202.0-000000"></a>
  <a href="https://github.com/phigonai/observer/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/phigonai/observer/actions/workflows/ci.yml/badge.svg"></a>
</p>

The Phigon Observer runs on a computer where people use AI coding agents such as
Claude Code, Codex, Cursor and GitHub Copilot. It finds the agents, records what
they do within the scope the computer's owner approves, removes secrets on the
machine, and streams the activity to a [Phigon](https://phigon.online)
workspace. It can also check your company's Guardian rules before an agent runs
a risky action.

It is open source under the [Apache License 2.0](LICENSE), so you can read
exactly what runs on your computers and what leaves them.

- **Consent first.** Nothing is collected until the computer's owner approves
  the exact scope on that machine.
- **Metadata by default.** The default profile shares which agents run and the
  kind of work they do, not prompts, replies, code or terminal output.
- **Secrets stay on the machine.** Passwords, tokens and API keys are redacted
  before anything is sent. Local settings can only narrow what is shared.
- **Survives disconnects.** Activity waits in an encrypted local queue and is
  delivered, in order and without duplicates, when the connection returns.

## Supported agents

| | Agent | Detected | Activity and history |
| --- | --- | --- | --- |
| <img src="https://phigon.online/agents/claude-code.svg" width="20" alt=""> | Claude Code | Yes | Built in |
| <img src="https://phigon.online/agents/codex.svg" width="20" alt=""> | OpenAI Codex | Yes | Built in |
| <img src="https://phigon.online/agents/github-copilot.svg" width="20" alt=""> | GitHub Copilot CLI | Yes | Built in |
| <img src="https://phigon.online/agents/github-copilot.svg" width="20" alt=""> | GitHub Copilot in VS Code (chat and agent mode) | Yes | Built in |
| <img src="https://phigon.online/agents/opencode.svg" width="20" alt=""> | OpenCode | Yes | Built in |
| <img src="https://phigon.online/agents/openclaw.svg" width="20" alt=""> | OpenClaw | Yes | Built in |
| <img src="https://phigon.online/agents/hermes.svg" width="20" alt=""> | Hermes Agent | Yes | Built in |
| <img src="https://phigon.online/agents/cursor.svg" width="20" alt=""> | Cursor (editor agent and `cursor-agent` CLI) | Yes | Built in |
| <img src="https://phigon.online/agents/gemini-cli.svg" width="20" alt=""> | Gemini CLI | Yes | Built in |
| <img src="https://phigon.online/agents/amp.svg" width="20" alt=""> | Amp | Yes | Bridge |
| <img src="https://phigon.online/agents/goose.svg" width="20" alt=""> | Goose | Yes | Built in |
| <img src="https://phigon.online/agents/cline.svg" width="20" alt=""> | Cline (CLI) | Yes | Built in |
| <img src="https://phigon.online/agents/openhands.svg" width="20" alt=""> | OpenHands | Yes | Bridge |
| | Kiro | Yes | Built in (chat; agent actions not yet) |
| | Antigravity | Yes | Not yet (no documented conversation format) |
| | Trae | Yes | Not yet (its history database is encrypted) |
| | Zed (its own agent) | Yes | Built in |
| | Factory Droid | Yes | Not yet |
| | Roo Code | Yes | Not yet |
| | Aider, Amazon Q Developer CLI, Continue | Yes | Bridge |
| | Any other agent | [Register it](#custom-agents) | Bridge |

*Built in* means the observer reads the agent's own records. *Bridge* means the
agent (or a small wrapper) pipes NDJSON to `phigon-observer ingest`.

## How it works

```
 Your computer                                      Phigon workspace
┌──────────────────────────────────────────┐       ┌─────────────────────────┐
│  AI agents  (Claude Code, Codex, ...)     │       │  Control plane          │
│      │  their own records and processes   │       │   history and search    │
│      ▼                                    │  TLS  │   Guardian rules        │
│  phigon-observer                          │ ────► │   the Phigon app        │
│   discover → collect → redact             │ gRPC  └─────────────────────────┘
│   → encrypted queue → stream              │
│                                           │
│  Guardian runner  (managed launches)      │
└──────────────────────────────────────────┘
```

The observer never needs inbound connections. It talks to the control plane
over HTTPS for pairing and over a single authenticated gRPC stream for
telemetry. The wire protocol is in [`proto/`](proto).

## Quick start

You need **Node.js 24 or newer** and a Phigon workspace. Installed releases
include the Guardian runner for Windows, macOS and Linux on x64 and Arm64; Go is
only needed to build from source.

```sh
npm install --global @phigon/observer
```

1. In the Phigon app, choose **Connect machine**.
2. Choose **Metadata** or **Full activity**, then generate a one-time code.
3. On the computer, run the two commands the dialog shows. The computer's owner
   reviews and accepts the scope.

Metadata only:

```sh
phigon-observer pair --code YOUR-CODE --consent-profile metadata
phigon-observer run --profile metadata
```

Full activity (supported conversations, commands, outputs and past history):

```sh
phigon-observer pair --code YOUR-CODE --consent-profile full
phigon-observer run --profile full
```

Keep `phigon-observer run` running for live collection; closing the Phigon app
does not stop it. Check the installation and connection at any time:

```sh
phigon-observer doctor --json
```

## What is collected

What the observer sends is always the overlap of your workspace's policy and
the profile the computer's owner accepted.

| | Metadata (default) | Full activity |
| --- | --- | --- |
| Which agents are installed and running | Yes | Yes |
| Agent state, health and kind of activity | Yes | Yes |
| Prompts and replies | No | Supported agents |
| Commands, tool calls and their output | No | Supported agents, redacted |
| Past conversations | No | Imported once, then live |
| Passwords, tokens and API keys | Never | Never (redacted on the machine) |
| Provider-encrypted model reasoning | Never | Never decoded |

Individual categories can be narrowed further with `PHIGON_COLLECT_*`
settings. A full description is in
[privacy and security](https://phigon.online/docs/privacy-and-security/).

## Commands

| Command | What it does |
| --- | --- |
| `pair --code <code> --consent-profile <metadata\|full>` | Connects this computer to a workspace after local consent. |
| `run [--profile <metadata\|full>]` | Discovers agents and streams permitted activity. |
| `doctor [--profile <...>] [--json]` | Checks the setup without sending any data. |
| `discover [--json]` | Prints a one-time, sanitized inventory of local agents. |
| `agent add \| list \| remove` | Manages custom agent definitions. |
| `ingest --agent <id\|custom> [--name <name>]` | Reads NDJSON activity from stdin (bridges). |
| `guardian status \| exec \| launch` | Guardian checks and managed execution. |
| `authorize-action --action <a> --resource <r>` | Asks Guardian whether one action may run. |
| `update [--check] [--yes]` | Checks for or installs a new release. |
| `remove-machine` | Unregisters this computer and revokes its credential. |

Run `phigon-observer help` for every flag.

## Configuration

Settings are environment variables. The most common ones:

| Variable | Purpose |
| --- | --- |
| `PHIGON_DATA_DIR` | Where the credential, checkpoints and encrypted queue live. Use a separate directory per workspace. |
| `PHIGON_CONTROL_PLANE_URL`, `PHIGON_GRPC_URL` | Endpoints for a self-hosted workspace. Pairing saves them; the stream refuses to send credentials anywhere else. |
| `PHIGON_TLS_CA_FILE` | A private certificate authority for gRPC. Use `NODE_EXTRA_CA_CERTS` for HTTPS. |
| `PHIGON_TLS_CLIENT_CERT_FILE`, `PHIGON_TLS_CLIENT_KEY_FILE` | Client certificate, when the workspace requires mutual TLS. |
| `PHIGON_COLLECT_*` | Turns individual content categories off (or on, within the workspace policy). |
| `PHIGON_REDACT_PATH_PATTERNS` | Extra file path patterns to redact. |
| `PHIGON_<AGENT>_ACTIVITY_DIRS` | Extra record folders for an agent, e.g. `PHIGON_CLAUDE_ACTIVITY_DIRS`. |
| `PHIGON_REMOTE_ACTIONS_ENABLED` | Opt in to administrator-approved agent stop and force stop. Off by default. |
| `PHIGON_REMOTE_COMMANDS_ENABLED` | Opt in to administrator-reviewed system operations. Off by default. |
| `PHIGON_UPDATE_CHECK` | Set to `false` to turn off the once-a-day update check. |
| `PHIGON_LOG_LEVEL` | Logging detail. |

Never disable certificate verification. Interactive `pair` and `run` sessions
check npm for a new release at most once a day and ask before updating;
background services and `--json` commands never prompt or update on their own.

## Custom agents

To monitor an agent without a built-in adapter, register its local signals once:

```sh
phigon-observer agent add \
  --id release-bot \
  --name "Release Bot" \
  --executable release-bot \
  --process release-bot-worker \
  --config-path ~/.release-bot \
  --activity-dir ~/.release-bot/sessions
```

Definitions are reloaded on every scan. `agent list` shows them and
`agent remove --id release-bot` stops using one. Activity directories accept
bounded JSONL; paths must be absolute or start with `~/`, roots must be narrow,
and overlapping signals are rejected instead of guessed. Custom activity stays
labeled by its source unless independent process evidence proves an exact
match.

## Optional agent actions

Remote actions are off on every computer by default.

- `PHIGON_REMOTE_ACTIONS_ENABLED=true` lets administrators stop or force-stop
  one exact running agent process. Each stop needs an operator proposal and a
  separate administrator confirmation, expires quickly, and leaves a receipt.
  A stop acts on one exact process lifetime (process ID plus start time, checked
  again just before anything is sent) and the child processes it started.
  Graceful stop sends `SIGTERM` on Linux and macOS; on Windows it asks the
  agent's windows to close, and for a console agent, which Windows can only
  end by force, it sends nothing and reports `graceful_stop_unsupported`.
  Force stop is approved separately. Receipts say when the process had already
  exited, access was denied, or the agent or a child is still running. It does
  not enable shell access, file access, screen capture or general remote
  control.
- `PHIGON_REMOTE_COMMANDS_ENABLED=true` additionally allows
  administrator-reviewed commands (executable and arguments, no shell), system
  inspection, and scheduled shutdown or restart. Commands run as the observer's
  account, are limited to 1–120 seconds and return at most 32 KB of redacted
  output. A durable journal prevents a command from running twice after a crash.
  System inspection reports the operating system, memory, uptime, CPU load,
  space on the main drive, the observer version, and each running agent's
  name, process ID, CPU share, memory and run time, measured once over half a
  second. It never includes file contents, environment values or command lines.

## Guardian: checks before an agent acts

Guardian rules are set centrally by your administrators; the observer has no
local on/off switch. Three integration points are available.

**Ask before one action.** Returns exit code `0` only when the action is
allowed; a denial, a required approval or an unavailable decision returns `77`
with a message for the agent:

```sh
phigon-observer authorize-action \
  --agent codex:worker-1 \
  --action command.execute \
  --resource "git status" \
  --context-file ./phigon-action-context.json \
  --json
```

The optional context file holds bounded `task_id`, `proposal_id`,
`plan_step_id`, `user_prompt`, `agent_plan`, `justification`,
`expected_effect` and `recent_activity` fields. Pass `--process-id` and
`--process-started-at` for a running agent so the decision is bound to that
exact process.

**Run a command through Guardian.** The check is mandatory, and the input,
output and exit code are recorded:

```sh
phigon-observer guardian exec --agent codex:worker-1 -- npm test
```

**Launch an agent through Guardian.** One short-lived grant covers starting the
agent, using the declared model and running the command. The Guardian runner
contains the process tree, renews its lease directly with the control plane and
stops the agent if the lease is revoked:

```sh
phigon-observer guardian launch \
  --agent claude-code:worker-1 \
  --model anthropic:claude-sonnet-4-5 \
  -- claude
```

Assigned OS profiles are enforced at launch: on Linux, filesystem and network
rules through Landlock and seccomp, plus memory, CPU and process limits and
separate workload users when a cgroup is provisioned; on Windows, memory, CPU
and process limits; on macOS, runtime deadlines. Compatible agents receive a
temporary loopback model gateway, so company provider keys stay on the server.

While `run` is active, running agents are also reviewed periodically, including
ones started outside `guardian launch`. Discovery happens after launch, so it
cannot undo earlier activity. A company that must prevent bypass also needs
operating-system application control and a controlled model provider proxy.

## Troubleshooting

- **Command not found:** put npm's global bin directory on `PATH` and reopen
  the terminal.
- **Expired pairing code:** generate a new one in **Connect machine**.
- **No conversations:** the metadata profile excludes content. Check with
  `phigon-observer doctor --profile full --json`.
- **Disconnected:** keep `run` running and allow its HTTPS and gRPC endpoints.
  Queued activity is delivered when the connection returns.
- **Older self-hosted pairing without a saved stream endpoint:** pass
  `run --grpc-url https://stream.your-company.example` or set `PHIGON_GRPC_URL`.
- **Unreadable pairing data:** keep the data directory and encrypted queue, and
  restore the credential file from a trusted backup. Never paste it into a
  support message.

More help: [setup guide](https://phigon.online/docs/get-started/),
[documentation](https://phigon.online/docs/) and
[troubleshooting](https://phigon.online/docs/troubleshooting/).

## Building from source

You need Node.js 24+ and Go 1.26+.

```sh
npm ci
npm run build              # TypeScript and the Guardian runner for this platform
npm run check              # lint, type check and tests
npm run build:platforms    # Guardian runners for every platform, for releases
cd go && go test ./...     # Go tests
```

After changing the protocol in `proto/`, regenerate the code with
[Buf](https://buf.build) and record the new checksums:

```sh
buf generate
sh scripts/check-generated.sh
```

### Repository layout

| Path | Contents |
| --- | --- |
| `src/` | The observer CLI (TypeScript): discovery, activity adapters, redaction, pairing, the stream client and Guardian integration. |
| `test/` | Tests for the CLI. |
| `go/` | Go module `github.com/phigonai/observer/go`: the Guardian runner, the Linux supervisor, OS sandbox profiles, and the generated protocol code. |
| `proto/` | The wire protocol between the observer and a Phigon control plane. |
| `scripts/` | Build, install and release helpers. |

## Contributing

Contributions are welcome. Read [CONTRIBUTING.md](CONTRIBUTING.md) first. This
repository is published from Phigon's main repository; a maintainer applies
accepted pull requests there, keeping you as the author, and they appear here
automatically.

## Security

Please report vulnerabilities privately. See [SECURITY.md](SECURITY.md).

## License

Licensed under the [Apache License, Version 2.0](LICENSE). See [NOTICE](NOTICE)
and [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md). The Phigon name and logo
are trademarks and are not covered by the license; see
[TRADEMARKS.md](TRADEMARKS.md).
