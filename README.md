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
| <img src="https://phigon.online/agents/cline.svg" width="20" alt=""> | Cline (CLI and VS Code extension) | Yes | Built in |
| <img src="https://phigon.online/agents/openhands.svg" width="20" alt=""> | OpenHands | Yes | Bridge |
| | Kiro | Yes | Built in (chat; agent actions not yet) |
| | Antigravity | Yes | Not yet (no documented conversation format) |
| | Trae | Yes | Not yet (its history database is encrypted) |
| | Zed (its own agent) | Yes | Built in |
| | Factory Droid | Yes | Built in |
| | Roo Code | Yes | Built in |
| | Kilo Code | Yes | Built in |
| | Aider, Amazon Q Developer CLI, Continue | Yes | Bridge |
| | Any other agent | [Register it](#custom-agents) | Bridge |

*Built in* means the observer reads the agent's own records. *Bridge* means the
agent (or a small wrapper) pipes NDJSON to `phigon-observer ingest`. The
observer deletes each bridge file once the workspace has received it, and any
bridge file after seven days.

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

You need **Node.js 24.5 or newer** and a Phigon workspace. Installed releases
include the Guardian runner for Windows, macOS and Linux on x64 and Arm64; Go is
only needed to build from source.

```sh
npm install --global @phigon/observer
```

1. In the Phigon app, choose **Connect machine**.
2. Choose **Metadata** or **Full activity**, then generate a one-time code.
3. On the computer, run the command the dialog shows. The computer's owner
   reviews and accepts the scope.

Metadata only:

```sh
phigon-observer pair --code YOUR-CODE --consent-profile metadata
```

Full activity (supported conversations, commands, outputs and past history):

```sh
phigon-observer pair --code YOUR-CODE --consent-profile full
```

That is all: pairing also installs the observer as a background service for
the signed-in user, with the profile the owner agreed to (see
[Background service](#background-service)). It keeps collecting after the
terminal closes and starts again after every restart. The consent prompt says
so before the owner agrees. If the computer cannot have a background service
(for example Linux without systemd user services), pairing still succeeds and
says to run `phigon-observer run --profile metadata` (or `full`) instead. Add
`--no-service` to pair without installing one.

Consent always wins. Pairing again while the observer runs takes effect at
once: within a second the running observer stops collecting and exits (with
code 75), and its background service starts it again with the new pairing.
If the owner paired again with `--consent-profile metadata`, an observer
started with `--profile full` (for example a background service) then
collects metadata only and says so, rather than failing to start.

To install the background service yourself, for a computer paired with
`--no-service` or an older observer, or to change its profile:

```sh
phigon-observer service install --profile metadata   # or --profile full
```

Closing the Phigon app does not stop it. Check the installation and connection
at any time:

```sh
phigon-observer service status
phigon-observer doctor --check
```

### Background service

`service install` runs `phigon-observer run` in the background as the
signed-in user, not as SYSTEM or root, because it reads that user's agent
records. It starts when the user signs in and again if it stops:

| System | What is installed | Restart |
| --- | --- | --- |
| Windows | A Task Scheduler task, "Phigon Observer", that runs at sign-in without a window | Started again within a minute |
| macOS | A LaunchAgent, `~/Library/LaunchAgents/com.phigon.observer.plist` | launchd keeps it running (`KeepAlive`) |
| Linux | A systemd user unit, `~/.config/systemd/user/phigon-observer.service` | `Restart=on-failure` |

- The service runs the same Node.js and observer that ran `service install`,
  with the same data directory. The settings it needs (`PHIGON_*`, `PATH`,
  the proxy variables, `NODE_EXTRA_CA_CERTS` and the agents' folder settings)
  are saved to `service-settings.json` in the data directory, which only this
  user can read. Settings whose names suggest a secret (token, password and
  similar) are never saved, and the service definition holds no settings at
  all, only the paths of Node.js, the observer and that file. A proxy address
  that includes a user name and password is saved there as it is, so prefer a
  proxy that does not need one in the address.
- `service install` refuses until the computer is paired and its owner (or,
  with an enrollment code, its company) has consented, and `--profile full`
  needs full-activity consent. Running it
  again replaces the earlier definition, so run it again after moving
  Node.js or changing settings.
- `service status` says whether the service is installed and whether an
  observer is running with its data directory. `service uninstall` stops it
  and removes it.
- A data directory other than the default gets its own service, named with a
  short code made from its path.
- On Linux the service runs while the user is signed in (a desktop or SSH
  session). To keep it running after sign-out, an administrator can run
  `loginctl enable-linger <user>`.
- What the service prints goes to `logs/observer.log` in the data directory.

### Rolling out to many computers with an enrollment code

A company that installs the observer with device management (Intune, Jamf or
a Linux configuration tool) uses a reusable **enrollment code** (`phe_…`)
from its administrator instead of one pairing code per computer. With an
enrollment code **the company gives consent for its computers, and nobody at
the computer is asked**. The administrator chose the profile, metadata or
full activity, when creating the code; the server answers with it, and the
observer stores it with the key and keeps collection within it exactly as it
does for a profile an owner chose.

Enroll as the signed-in user, with the code in the environment so it does
not show in process lists, then install the background service:

```sh
PHIGON_ENROLLMENT_CODE="$(cat /path/to/code)" phigon-observer pair \
  --control-plane-url https://phigon.corp.example:8443 \
  --grpc-url https://phigon.corp.example:9443 --json
phigon-observer service install
```

- `--enrollment-code <code>` works too, but anyone on the computer can see a
  command line. `--server-ca-sha256 <fingerprint>` and `--name <name>` work
  as with pairing; `--consent-profile` and `--accept-consent` are refused.
- The code is never printed, logged or saved, and `service install` never
  copies `PHIGON_ENROLLMENT_CODE` into its settings.
- A computer already paired with the same server keeps its machine and key,
  and its consent becomes the company's.
- A busy server (HTTP 429 or 503) is asked again up to three times, after
  the wait it asks for, within five minutes in all.
- `doctor` shows who consented, the owner or the company and the code's
  label, as a `Consent:` line and as `consent` in `--json` (`doctor --check`
  too).
- When it starts collecting, the observer tells the person at the computer
  once with a system notification: "Phigon is recording AI agent activity",
  what the profile records, the code's label and "Ask your IT team for
  details". It tells them again when the profile changes. A computer whose
  owner paired it gets no such notice, because the owner accepted the
  profile at the keyboard. `PHIGON_USER_NOTICES=false` turns it off, and it
  cannot show without the user's desktop session; it is remembered only once
  shown, so it is tried again at the next start.

A failed enrollment prints the server's sentence and exits with a code a
script can act on (with `--json`, also an `{"enrolled": false, "error": …}`
object):

| Exit code | Meaning |
| --- | --- |
| `20` | The server was busy, unavailable or unreachable. Try again later. |
| `21` | The code expired, was revoked, is used up or was made under an earlier policy. Ask for a new code. |
| `22` | Not an enrollment code, or cut short. |
| `23` | This computer enrolled with this code before and was removed since. Ask for a new code. |
| `24` | This computer is already connected to the workspace. Check it with `doctor`. |
| `1` | Anything else, such as a bad setting. |

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
| `pair --code <code> --consent-profile <metadata\|full>` | Connects this computer to a workspace after local consent, and keeps the observer running in the background from then on. `--no-service` pairs only. |
| `pair` with `PHIGON_ENROLLMENT_CODE` (or `--enrollment-code <code>`) | Enrolls this computer with a company's enrollment code, under the company's consent, without asking; see [above](#rolling-out-to-many-computers-with-an-enrollment-code). |
| `run [--profile <metadata\|full>]` | Discovers agents and streams permitted activity. |
| `service install [--profile <metadata\|full>]`, `service uninstall`, `service status` | Runs the observer in the background for the signed-in user, from sign-in on. |
| `doctor [--profile <...>] [--json]` | Checks the setup without sending any data. |
| `doctor --check [--max-delivery-age <minutes>] [--json]` | Checks that collection is working, with an exit code for scripts. |
| `discover [--json]` | Prints a one-time, sanitized inventory of local agents. |
| `agent add \| list \| remove` | Manages custom agent definitions. |
| `ingest --agent <id\|custom> [--name <name>]` | Reads NDJSON activity from stdin (bridges). |
| `guardian status \| exec \| launch` | Guardian checks and managed execution. |
| `authorize-action --action <a> --resource <r>` | Asks Guardian whether one action may run. |
| `update [--check] [--yes]` | Checks for or installs a new release. |
| `remove-machine [--purge]` | Stops collection and revokes this computer's key. Activity already collected stays with the company until an administrator deletes the computer or it expires. `--purge` also removes the background service and the observer's local files; see [Uninstall](#uninstall). |

Run `phigon-observer help` for every flag.

### Checking a computer from scripts

`doctor --check` is meant for device management scripts. It sends no
activity: it reads the local state and asks the control plane's `/healthz`
(through the configured proxy and pinned authority, with a five-second
limit). It exits with the code of the first problem it finds:

| Exit code | Meaning |
| --- | --- |
| `0` | Everything checked out. |
| `1` | The check itself could not run, for example because of a bad setting. |
| `3` | This computer is not paired, or its pairing data cannot be read. |
| `4` | The owner's consent is missing or out of date. Pair again. |
| `5` | No observer is running with this data directory. |
| `6` | The workspace has not confirmed delivery for longer than `--max-delivery-age` minutes (default 15). A connected observer confirms at least once a minute, even when no agent is active. |
| `7` | The control plane did not answer. |

`--json` prints every check with its result. Plain `doctor` keeps exiting
`0`.

### A company's own Phigon server

The Phigon app can run a company's own server, and other computers on the
company network can connect to it. That server signs its HTTPS certificate
with an authority of its own, so the **Connect machine** command adds
`--server-ca-sha256 <fingerprint>`.

On first contact, pairing finds the authority in the server's certificate
chain whose SHA-256 matches the fingerprint. It saves that authority as
`server-ca.pem` in the data directory, and every later HTTPS and gRPC
connection trusts it. A server that presents another certificate is refused
before anything is sent. `remove-machine` deletes the file. This needs
Node.js 24.5 or newer.

When that server's address changes (a new IP address from the network, or
the company moves the Phigon app to another network), run the new **Connect
machine** command on each computer with the same data directory. The
computer keeps its machine and the activity it has not delivered yet, and
sends them to the new address; a running observer and its background service
restart with it, and service settings that named the old address are
updated. Its stored key goes there only after the new
address proves it holds a certificate from the authority pinned at pairing.
A server on the computer itself may also move between its own addresses,
for example when the Phigon app turns sharing with the network on or off.
Pairing with a server that is neither is refused, and the authority already
saved is kept.

## Configuration

Settings are environment variables. The most common ones:

| Variable | Purpose |
| --- | --- |
| `PHIGON_DATA_DIR` | Where the credential, checkpoints and encrypted queue live. Use a separate directory per workspace. |
| `PHIGON_CONTROL_PLANE_URL`, `PHIGON_GRPC_URL` | Endpoints for a self-hosted workspace. Pairing saves them; the stream refuses to send credentials anywhere else. |
| `PHIGON_TLS_CA_FILE` | A private certificate authority for gRPC. Use `NODE_EXTRA_CA_CERTS` for HTTPS. Pairing with `--server-ca-sha256` sets up both for you. |
| `PHIGON_TLS_CLIENT_CERT_FILE`, `PHIGON_TLS_CLIENT_KEY_FILE` | Client certificate, when the workspace requires mutual TLS. |
| `PHIGON_COLLECT_*` | Turns individual content categories off. Content can be turned on only under `--profile full` on a computer whose owner consented to full activity. Under `--profile metadata`, `run` refuses to start with one turned on; when the consent alone covers metadata only, they stay off. |
| `PHIGON_REDACT_PATH_PATTERNS` | Extra file path patterns to redact. |
| `PHIGON_<AGENT>_ACTIVITY_DIRS` | Extra record folders for an agent, e.g. `PHIGON_CLAUDE_ACTIVITY_DIRS`. |
| `PHIGON_REMOTE_ACTIONS_ENABLED` | Opt in to administrator-approved agent stop and force stop. Off by default. |
| `PHIGON_REMOTE_COMMANDS_ENABLED` | Opt in to administrator-reviewed system operations. Off by default. |
| `PHIGON_USER_NOTICES` | Set to `false` to stop telling the person at the computer when Phigon stops an agent, runs a command or restarts it, and, on a computer enrolled with a company's code, that collection started. On by default. |
| `PHIGON_UPDATE_CHECK` | Set to `false` to turn off the once-a-day update check. |
| `PHIGON_LOG_LEVEL` | What `run` prints and writes to its log: `debug`, `info` (default), `warn` or `error`. |

`run` also writes what it prints to `logs/observer.log` in the data directory,
so a background service leaves a record. The log is rotated at about 5 MB and
keeps three files. Like the terminal output, it never contains activity
content, credentials or secrets.

Never disable certificate verification. Interactive `pair` and `run` sessions
check npm for a new release at most once a day and ask before updating;
background services and `--json` commands never prompt or update on their own.

### Corporate proxies

The observer sends every HTTPS call (pairing, `remove-machine`, update checks,
Guardian, `doctor --check`) and the telemetry stream through the proxy that
`HTTPS_PROXY` names, or `HTTP_PROXY` when only that is set. `NO_PROXY` lists
hosts it reaches directly. Either case works; when both are set, the lowercase
name wins. A user name and password in the proxy address are supported and
never printed.

- `NO_PROXY` is a comma-separated list of host names. `example.com`,
  `.example.com` and `*.example.com` each cover `example.com` and every host
  under it, `*` turns the proxy off, and `host:port` applies to that port only.
- HTTPS passes through the proxy as a CONNECT tunnel, and TLS is negotiated
  with the Phigon server inside it, so certificate checks, including the
  authority pinned for a company's own server, still apply. A proxy that
  inspects TLS must leave the Phigon endpoints alone; the observer never turns
  certificate checks off.
- The telemetry stream uses the same settings, but it can use only an
  `http://` proxy address, and it cannot check ports or address ranges in
  `NO_PROXY`. Set `grpc_proxy` (and `no_grpc_proxy`) to give the stream
  different ones.
- Node.js 24.14 or newer applies these settings by itself. On Node.js 24.5 to
  24.13, also set `NODE_USE_ENV_PROXY=1` in the environment that starts the
  observer.

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
  agent's windows to close, and for a console agent it presses Ctrl+C in its
  terminal, but only when nothing else shares that terminal; otherwise it
  sends nothing and reports `terminal_shared`.
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

Whenever Phigon stops an agent on a computer, whether someone asked, Phigon AI
decided or the agent is blocked, the person at that computer sees a system
notification such as "Claude Code was stopped by Phigon", with the reason. The
same goes for commands Phigon runs and a scheduled restart or shutdown. It uses
the system's own notifications (a Windows toast, macOS Notification Center, or
`notify-send` on Linux) and shows nothing when the observer runs without a
desktop session, for example as a Windows service. `PHIGON_USER_NOTICES=false`
turns it off.

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

## Uninstall

To remove this computer from the workspace and delete everything the observer
keeps on it, then the program itself:

```sh
phigon-observer remove-machine --purge
npm uninstall --global @phigon/observer
```

`remove-machine --purge` does what `remove-machine` does (collection stops and
this computer's key is revoked), then stops and removes the background
service and deletes every file the observer keeps in its data directory,
including activity that was not delivered yet. It removes only files the
observer created, and the data directory itself once it is empty. It also
works on a computer that is no longer paired. If the workspace cannot be
reached, nothing is deleted and the service is started again.

Without `--purge`, `remove-machine` keeps the observer's local progress files
so the computer can be paired again where it left off. Use a separate
`service uninstall` to remove only the background service.

Either way, the activity the company already collected stays in the workspace
until an administrator deletes the computer or it expires under the retention
policy; removing the observer from a computer never erases it.

## Troubleshooting

- **Command not found:** put npm's global bin directory on `PATH` and reopen
  the terminal.
- **Expired pairing code:** generate a new one in **Connect machine**.
- **No conversations:** the metadata profile excludes content. Check with
  `phigon-observer doctor --profile full --json`.
- **Collection stops after a restart:** install the background service with
  `phigon-observer service install`, and read `logs/observer.log` in the data
  directory.
- **Disconnected:** keep the observer running and allow its HTTPS and gRPC endpoints.
  Queued activity is delivered when the connection returns. While the server
  cannot be reached, the observer tries again up to once a minute and logs
  each new reason once.
- **"This computer was removed from Phigon":** an administrator removed the
  computer or revoked its key, and the server confirmed it, so the observer
  stopped. Pair it again with a new code from **Connect machine**, or run
  `phigon-observer service uninstall`. Until then the background service
  stops as soon as it starts and asks the server again once an hour. On
  Linux it stays stopped; after pairing again, start it with
  `systemctl --user restart phigon-observer` or sign in again.
- **Older self-hosted pairing without a saved stream endpoint:** pass
  `run --grpc-url https://stream.your-company.example` or set `PHIGON_GRPC_URL`.
- **Unreadable pairing data:** keep the data directory and encrypted queue, and
  restore the credential file from a trusted backup. Never paste it into a
  support message.

More help: [setup guide](https://phigon.online/docs/get-started/),
[documentation](https://phigon.online/docs/) and
[troubleshooting](https://phigon.online/docs/troubleshooting/).

## Building from source

You need Node.js 24.5+ and Go 1.26+.

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
