# Phigon Observer command reference

Every `phigon-observer` command, what it does, and the options it takes. For an
overview of the observer, see the [README](../README.md).

```sh
npm install --global @phigon/observer   # needs Node.js 24.5 or newer
phigon-observer --version
phigon-observer help                    # the short form of this page
```

## Contents

| Command | What it is for |
| --- | --- |
| [`pair`](#pair) | Connect this computer to a Phigon workspace, with its owner's consent. |
| [`pair` with an enrollment code](#pair-with-an-enrollment-code) | Connect many computers at once with a company's code. |
| [`run`](#run) | Find agents and stream the activity the owner allowed. |
| [`service`](#service) | Keep the observer running in the background. |
| [`doctor`](#doctor) | Check the setup, and whether collection works. |
| [`update`](#update) | Install a new release. |
| [`discover`](#discover) | List the AI agents on this computer once. |
| [`agent`](#agent) | Teach the observer about an agent it doesn't know. |
| [`ingest`](#ingest) | Send activity from a bridge or script. |
| [`guardian`](#guardian) | Run agents and commands under your company's Guardian rules. |
| [`authorize-action`](#authorize-action) | Ask Guardian whether one action may run. |
| [`remove-machine`](#remove-machine) | Disconnect this computer. |

Commands that take `--json` print one JSON object and never ask anything,
which suits scripts and device management tools.

## Getting started

1. In the Phigon app, choose **Connect machine**, pick what to share, and copy
   the command it shows.
2. Run it on the computer. The owner reads the scope and accepts it:

   ```sh
   phigon-observer pair --code ABCD-EFGH --consent-profile metadata \
     --control-plane-url https://<label>.relay.phigon.online \
     --grpc-url https://<label>-grpc.relay.phigon.online \
     --server-ca-sha256 <fingerprint>
   ```

3. Check it:

   ```sh
   phigon-observer doctor --check
   ```

Pairing also installs the background service, so nothing else is needed. The
computer keeps reporting after the terminal closes and after restarts.

## pair

```text
phigon-observer pair --code <one-time-code> --consent-profile <metadata|full>
  [--control-plane-url <url> --grpc-url <url> [--server-ca-sha256 <fingerprint>]]
  [--name <machine-name>] [--accept-consent] [--no-service]
  [--no-remote-commands | --no-remote-actions] [--json]
```

Connects this computer to a workspace. It shows the computer's owner exactly
what will be collected and asks them to accept. The acceptance is stored with
the computer's key, which is saved with owner-only file permissions. Then it
installs the [background service](#service) with the same profile.

| Option | Meaning |
| --- | --- |
| `--code` | The one-time code from **Connect machine**. Codes expire after a few minutes and work once. |
| `--consent-profile metadata` | Share which agents run and the kind of work they do. No prompts, replies, code or terminal output. |
| `--consent-profile full` | Also share supported conversations, commands, outputs and past history. Secrets are still removed on the computer first. |
| `--control-plane-url`, `--grpc-url` | Your company's own Phigon server, as **Connect machine** gives them. Leave both out for Phigon's hosted service. |
| `--server-ca-sha256` | The fingerprint of your server's own certificate authority. The observer pins it and trusts nothing else for that server. See [Networks and the relay](#networks-and-the-relay). |
| `--name` | The name this computer has in the workspace. Defaults to the computer's name. |
| `--accept-consent` | The owner accepts the scope without the prompt. Only for an owner pairing their own computer from a script. |
| `--no-service` | Pair only; don't install the background service. Run [`run`](#run) yourself. |
| `--no-remote-commands` | Administrators may stop this computer's agents, but not run commands on it, inspect it or restart it. |
| `--no-remote-actions` | Administrators may do neither on this computer, even if the workspace allows it. |
| `--json` | Print the result as JSON. |

Pairing again replaces the previous pairing at once. A running observer stops
within a second and its background service starts it again under the new
consent. If the new pairing shares less, collection narrows immediately.

## pair with an enrollment code

```sh
PHIGON_ENROLLMENT_CODE=phe_... phigon-observer pair [--control-plane-url <url> --grpc-url <url> [--server-ca-sha256 <fingerprint>]] [--name <machine-name>] [--json]
phigon-observer pair --enrollment-code <code> [same options]
phigon-observer service install
```

For rolling Phigon out to many computers from Intune, Jamf or another device
management tool. The company gives consent and chooses the profile when it
creates the code in the Phigon app, so this asks nothing. The observer stores
the company's choice and never collects more than it allows.

Prefer `PHIGON_ENROLLMENT_CODE` over `--enrollment-code`: command-line options
show in process lists. The code is never printed or saved. A busy server is
retried a few times.

| Exit code | Meaning |
| --- | --- |
| `0` | Enrolled. |
| `20` | The server is busy or unreachable. Try again later. |
| `21` | The code expired, was revoked, is used up, or is outdated. Ask for a new one. |
| `22` | This is not a valid enrollment code. |
| `23` | This computer already used this code. |
| `24` | This computer is already connected to this workspace. |

## run

```sh
phigon-observer run [--profile <metadata|full>]
```

Finds the AI agents on this computer, reads their activity within the
profile, removes secrets, and streams it to the workspace. Activity waits in
an encrypted local queue while the connection is down and is delivered in
order, without duplicates, when it returns.

`--profile` can only narrow what the owner agreed to. Under `--profile
metadata`, `run` refuses to start if a setting turns content on. If the owner
consented to metadata only, `--profile full` collects metadata only and says
so.

You rarely run this by hand: the [background service](#service) runs it. It
prints a short status and writes the same lines to `logs/observer.log` in the
data directory.

## service

```sh
phigon-observer service install [--profile <metadata|full>] [--json]
phigon-observer service status [--json]
phigon-observer service uninstall [--json]
```

Runs the observer in the background for the signed-in user. It starts at
sign-in and again if it stops.

| System | How |
| --- | --- |
| Windows | A Task Scheduler task |
| macOS | A LaunchAgent, `~/Library/LaunchAgents/com.phigon.observer.plist` |
| Linux | A systemd user unit |

`install` needs a paired computer whose owner consented. It saves the current
settings (the `PHIGON_*` ones, never a key or password, plus proxy and
certificate settings and `PATH`) in `service-settings.json` in the data
directory, so the service runs with them. Use it after pairing
with `--no-service`, or to change the profile. `status` says whether the
service is installed and running. `uninstall` removes it; the pairing stays.

## doctor

```sh
phigon-observer doctor [--profile <metadata|full>] [--json]
phigon-observer doctor --check [--max-delivery-age <minutes>] [--json]
```

Plain `doctor` checks the local setup without sending anything, and always
exits `0`.

`doctor --check` also asks the server whether it answers, through the same
proxy and pinned certificate authority the observer uses. It sends no
activity. It exits with the code of the first problem it finds, so device
management scripts can act on it:

| Exit code | Meaning |
| --- | --- |
| `0` | Everything checked out. |
| `1` | The check could not run, for example because of a bad setting. |
| `3` | This computer is not paired, or its pairing data can't be read. |
| `4` | The owner's consent is missing or out of date. Pair again. |
| `5` | No observer is running with this data directory. |
| `6` | The workspace has not confirmed delivery for longer than `--max-delivery-age` minutes (default 15). A connected observer confirms at least once a minute, even when no agent is active. |
| `7` | The server did not answer. |

When a company's server is reached through Phigon's relay and doesn't answer,
`doctor` says whether the server isn't connected to the relay right now (for
example because the administrator's computer is off) or whether a proxy on the
network is inspecting HTTPS.

## update

```sh
phigon-observer update [--check] [--yes] [--json]
```

Checks npm for a newer release and installs it. Then it starts the background
service again so it runs the new version. The pairing and any activity not yet
delivered are kept.

| Option | Meaning |
| --- | --- |
| `--check` | Only say whether an update is available. Changes nothing. |
| `--yes` | Update without asking. Needed when nobody is at the keyboard. |
| `--json` | Report as JSON. With `--json`, `update` only checks, even with `--yes`. |

Interactive `pair` and `run` sessions also check for a release at most once a
day and ask before updating. Background services and `--json` commands never
update on their own. `PHIGON_UPDATE_CHECK=false` turns the daily check off.

## discover

```sh
phigon-observer discover [--json]
```

Prints which AI agents are installed and running on this computer, once. It
reads only local, sanitized information and sends nothing.

## agent

```sh
phigon-observer agent add --id <id> --name <name> [--executable <name>] [--process <name>]
  [--config-path <path>] [--activity-dir <path>] [--capability <name>] [--json]
phigon-observer agent list [--json]
phigon-observer agent remove --id <id> [--yes] [--json]
```

Teaches the observer about an AI agent it has no built-in support for, without
changing its code. Each option can be given more than once.

| Option | Meaning |
| --- | --- |
| `--id` | A short, lowercase identifier, such as `acme-agent`. |
| `--name` | The name shown in Phigon. |
| `--executable` | A program name that means the agent is installed. |
| `--process` | A process name that means the agent is running. |
| `--config-path` | A file or folder that means the agent is set up. |
| `--activity-dir` | A folder where the agent writes its activity records. |
| `--capability` | What the agent offers, such as `activity` (the default). |

`remove` asks first unless you add `--yes`.

## ingest

```sh
phigon-observer ingest --agent <agent-id|custom> [--name <agent-name>] [--quiet] [--json]
```

Reads activity as NDJSON (one JSON object per line) from standard input and
queues it like any other activity: within the consent profile, with secrets
removed. Bridges and scripts use it. For an agent the observer doesn't know,
use `--agent custom --name <agent-name>`. `--quiet` prints nothing on success.

## guardian

```sh
phigon-observer guardian status [--json]
phigon-observer guardian exec [--agent <agent-id>] [--context-file <path>] -- <program> [arguments...]
phigon-observer guardian launch --agent <agent-id> --model <provider:model> [--context-file <path>] -- <program> [arguments...]
```

Guardian applies your company's rules to what agents do. Only administrators
set the rules; nothing on the computer can loosen them. Guardian fails
closed: when it can't get an answer, the action does not run.

- **`status`** reports whether Guardian on this computer is centrally
  managed. Only administrator policies can block or contain an agent; there
  are no local overrides.
- **`exec`** asks Guardian whether the agent may start and run the command,
  then runs it directly (no shell). It records the command, its output and its
  exit code for the workspace.
- **`launch`** starts an agent under a single-use grant that covers starting
  the agent, using the model named with `--model` (for example
  `anthropic:claude-opus-5-5`) and running commands. The native supervisor
  stops the whole process tree if the grant is revoked or can't be renewed.

`--context-file` gives Guardian more to judge by: a JSON file with any of
`task_id`, `user_prompt`, `agent_plan`, `justification` and `recent_activity`.
Each is cut to a bounded length.

## authorize-action

```sh
phigon-observer authorize-action --action <action> --resource <normalized-resource>
  [--agent <agent-id>] [--process-id <pid> --process-started-at <RFC3339>]
  [--context-file <path>] [--json]
```

Asks Guardian whether one action may run, for gateways and tools that manage
agents. It only decides; it can't stop anything that happens outside the tool
that asks it.

| Option | Meaning |
| --- | --- |
| `--action` | One of `file.read`, `file.write`, `file.delete`, `command.execute`, `process.launch`, `network.connect`, `browser.navigate`, `credential.access`, `agent.start` or `model.use`. |
| `--resource` | What the action is about, such as a file path, a command line or a host. |
| `--agent` | Which agent asks. |
| `--process-id`, `--process-started-at` | The exact process, so an administrator's stop applies to it and nothing else. |
| `--context-file` | As for [`guardian`](#guardian). |

It exits `0` when the action is allowed and `77` when it is not.

## remove-machine

```sh
phigon-observer remove-machine [--purge] [--yes] [--json]
```

Disconnects this computer: collection stops and its key is revoked. Activity
already collected stays with the company until an administrator deletes the
computer or it expires.

It asks first unless you add `--yes` (and with `--json`, `--yes` is
required). `--purge` also removes the background service and every file the
observer keeps in the data directory. To remove the observer itself
afterwards, run `npm uninstall --global @phigon/observer`.

## Networks and the relay

A company's own Phigon server signs its HTTPS certificate with a certificate
authority of its own. When the computer pairs, the observer pins that
authority (`--server-ca-sha256`). From then on it trusts only that authority
for the server. A proxy or anyone else in between can't read or change what
the observer sends, Phigon's relay included.

The server is reachable in two ways:

- **Its network address**, such as `https://192.168.1.20:17080`, when the
  administrator shares it on the company network.
- **Phigon's relay**, `https://<label>.relay.phigon.online`, from any network.
  The label comes from the server's authority.

The background service moves between them by itself. It uses the network
address whenever that answers, and the relay when it doesn't, for example at
home. Each move happens only once the new address proves it holds a
certificate from the pinned authority. If computers are on a network that
inspects HTTPS (Zscaler, Netskope, some antivirus software), ask IT to exempt
`*.relay.phigon.online` and the server's address.

## Settings

Settings are environment variables. The background service saves the ones in
effect when it was installed.

### Where and how it connects

| Variable | Meaning |
| --- | --- |
| `PHIGON_DATA_DIR` | Where the observer keeps its key, settings, queue and logs. Default `~/.phigon/observer`. Use a separate folder for each workspace. |
| `PHIGON_CONTROL_PLANE_URL`, `PHIGON_GRPC_URL` | The server's addresses. Pairing saves them; you rarely set them. |
| `PHIGON_TLS_CA_FILE` | A private certificate authority for the stream. Pairing with `--server-ca-sha256` sets this up. |
| `PHIGON_TLS_CLIENT_CERT_FILE`, `PHIGON_TLS_CLIENT_KEY_FILE` | A client certificate, when the server requires mutual TLS. |
| `HTTPS_PROXY`, `HTTP_PROXY`, `NO_PROXY` | The company proxy. HTTPS goes through it as a tunnel, so certificate checks still apply. |
| `grpc_proxy`, `no_grpc_proxy` | A different proxy for the stream only (an `http://` address). |
| `NODE_USE_ENV_PROXY=1` | Needed on Node.js 24.5 to 24.13 for the proxy settings to apply. |

### What it collects

| Variable | Meaning |
| --- | --- |
| `PHIGON_COLLECT_*` | Turn individual content categories off. Content can be on only under `--profile full` with the owner's full consent. |
| `PHIGON_REDACT_PATH_PATTERNS` | More file path patterns to redact. |
| `PHIGON_<AGENT>_ACTIVITY_DIRS` | More folders where an agent writes its records, such as `PHIGON_CLAUDE_ACTIVITY_DIRS`. |
| `PHIGON_ACTIVITY_REPLAY_ON_FIRST_START` | `true` reads agents' past history on the first start (full profile only). Off by default. |

### What administrators may do

| Variable | Meaning |
| --- | --- |
| `PHIGON_REMOTE_ACTIONS_ENABLED` | `true` or `false` overrides whether administrators may stop and force-stop agents. Unset, the consent given at pairing decides. |
| `PHIGON_REMOTE_COMMANDS_ENABLED` | `true` or `false` overrides whether administrators may run reviewed commands, inspect the system and restart it. |
| `PHIGON_USER_NOTICES` | `false` stops the notices that tell the person at the computer when Phigon stops an agent, runs a command or restarts it. On by default. |

### Other

| Variable | Meaning |
| --- | --- |
| `PHIGON_UPDATE_CHECK` | `false` turns off the once-a-day update check. |
| `PHIGON_LOG_LEVEL` | `debug`, `info` (default), `warn` or `error`. |
| `PHIGON_DISCOVERY_INTERVAL_MS`, `PHIGON_HEARTBEAT_INTERVAL_MS` | How often agents are looked for and the server is told the computer is alive. |
| `PHIGON_ENROLLMENT_CODE` | A company's enrollment code, for [pairing without questions](#pair-with-an-enrollment-code). |

Logs and terminal output never contain activity content, keys or secrets.

## Files it keeps

All in the data directory, readable by the owner only.

| File | What it holds |
| --- | --- |
| `machine-credential.json` | This computer's key, its server's addresses and the owner's consent. |
| `server-ca.pem` | The certificate authority pinned at pairing, for a company's own server. |
| `server-endpoints.json` | The server's network address, learned from the server, so the observer can move between it and the relay. |
| `service-settings.json` | The settings the background service runs with. |
| `logs/observer.log` | What `run` prints. Rotated at about 5 MB; three files are kept. |
| `observer.lock` | Makes sure only one observer runs with this data directory. |
| The queue and checkpoints | Activity not yet delivered, encrypted, and how far each agent's records were read. |

`remove-machine --purge` deletes all of them.

## Getting help

- Run `phigon-observer doctor --check` and look at `logs/observer.log`.
- Read the [documentation](https://phigon.online/docs/) on phigon.online.
- [Book a demo or a support call](https://phigon.online/book/), or email
  [nikku@phigon.online](mailto:nikku@phigon.online).
- Report a bug in [GitHub issues](https://github.com/phigonai/observer/issues).
  Report security problems privately: see [SECURITY.md](../SECURITY.md).
