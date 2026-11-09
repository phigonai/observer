/**
 * The options each observer command takes, and the check that holds a
 * command line to them before the command does anything.
 *
 * An option a command does not list is refused, with the option it was
 * probably meant to be. A misspelling used to be ignored, so
 * `pair --no-remote-command` (one letter short) allowed what it was meant
 * to refuse. To give a command a new option, add it to `commandOptions`.
 */

/** One option of a command. */
export type OptionSpec = Readonly<{
  /** The option takes a value, shown in messages like this, such as "<url>". */
  value?: string;
  /** The option may be given more than once, each time with its own value. */
  repeatable?: boolean;
  /** What to say when the value is missing, in place of the usual sentence. */
  missingValue?: string;
  /**
   * Accepted but not shown in the usage lines of the help: an option only
   * the background service passes, or one a newer option replaced that
   * scripts may still use.
   */
  unlisted?: boolean;
}>;

/** What one command takes. */
export type CommandSpec = Readonly<{
  options: Readonly<Record<string, OptionSpec>>;
  /** It runs a program given after "--": `-- <program> [arguments...]`. */
  program?: boolean;
}>;

const json = { "--json": {} } satisfies Record<string, OptionSpec>;
const profile = { "--profile": { value: "<metadata|full>" } } satisfies Record<string, OptionSpec>;
// The server's addresses, for the commands that talk to it before pairing
// saves them.
const endpoints = {
  "--control-plane-url": { value: "<url>" },
  "--grpc-url": { value: "<url>" },
} satisfies Record<string, OptionSpec>;
// A computer the company enrolled is removed only with an administrator's code.
const uninstall = { "--uninstall-code": { value: "<code>" } } satisfies Record<string, OptionSpec>;
const removal = { "--purge": {}, "--yes": {}, ...uninstall, ...json } satisfies Record<string, OptionSpec>;

/**
 * Every command and the options it takes. A command with subcommands has
 * one entry for each, as "service install". Background services run
 * `run --service-settings <file>`, and device management scripts run
 * `pair` with the endpoint options, `--server-ca-sha256` and `--json`,
 * `service install`, `doctor --check --max-delivery-age <minutes>` and
 * `remove-machine --purge --yes --json`; keep them working.
 */
export const commandOptions: Readonly<Record<string, CommandSpec>> = {
  "authorize-action": {
    options: {
      "--action": { value: "<action>" },
      "--resource": { value: "<normalized-resource>" },
      "--agent": { value: "<agent-id>" },
      "--process-id": { value: "<pid>" },
      "--process-started-at": { value: "<RFC3339>" },
      "--context-file": { value: "<path>" },
      ...json,
    },
  },
  "guardian status": { options: json },
  // Their output is the program's own, as it comes, so they take no --json.
  "guardian exec": {
    options: { "--agent": { value: "<agent-id>" }, "--context-file": { value: "<path>" } },
    program: true,
  },
  "guardian launch": {
    options: {
      "--agent": { value: "<agent-id>" },
      "--model": { value: "<provider:model>" },
      "--context-file": { value: "<path>" },
    },
    program: true,
  },
  "agent add": {
    options: {
      "--id": { value: "<id>" },
      "--name": { value: "<name>" },
      "--executable": { value: "<name>", repeatable: true },
      "--process": { value: "<name>", repeatable: true },
      "--config-path": { value: "<path>", repeatable: true },
      "--activity-dir": { value: "<path>", repeatable: true },
      "--capability": { value: "<name>", repeatable: true },
      ...json,
    },
  },
  "agent list": { options: json },
  "agent remove": { options: { "--id": { value: "<id>" }, "--yes": {}, ...json } },
  doctor: {
    options: {
      ...profile,
      "--check": {},
      "--max-delivery-age": { value: "<minutes>" },
      ...endpoints,
      ...json,
    },
  },
  update: { options: { "--check": {}, "--yes": {}, ...json } },
  discover: { options: { "--explain": {}, ...json } },
  ingest: {
    options: {
      "--agent": { value: "<agent-id|custom>" },
      "--name": { value: "<agent-name>" },
      "--quiet": {},
      ...json,
    },
  },
  pair: {
    options: {
      "--code": { value: "<one-time-code>" },
      "--consent-profile": { value: "<metadata|full>" },
      "--enrollment-code": {
        value: "<code>",
        missingValue: "--enrollment-code needs the code. Device management scripts should set PHIGON_ENROLLMENT_CODE instead, which keeps it out of process lists.",
      },
      ...endpoints,
      "--server-ca-sha256": { value: "<fingerprint>" },
      "--name": { value: "<machine-name>" },
      "--accept-consent": {},
      "--no-service": {},
      "--remote-actions": { value: "<all|stop-agents|none>" },
      // From before --remote-actions: stop-agents and none.
      "--no-remote-commands": { unlisted: true },
      "--no-remote-actions": { unlisted: true },
      ...json,
    },
  },
  "remove-machine": { options: removal },
  unpair: { options: removal },
  run: {
    options: {
      ...profile,
      // Only the background service passes it.
      "--service-settings": { value: "<file>", unlisted: true },
      ...endpoints,
    },
  },
  "service install": { options: { ...profile, ...json } },
  "service uninstall": { options: { ...uninstall, ...json } },
  "service status": { options: json },
  // Without --tail it prints the last 50 lines.
  logs: { options: { "--tail": { value: "<lines>" }, "--follow": {} } },
};

/** The subcommand a command runs when none is named. */
const defaultSubcommands: Readonly<Record<string, string>> = { guardian: "status" };

/** The exit code for a command line that is wrong, as for an unknown command. */
export const usageExitCode = 2;

/** A command line the command does not take. The observer exits with 2. */
export class UsageError extends Error {
  readonly exitCode = usageExitCode;
}

/** Whether `command` is one of the observer's commands. */
export function isCommand(command: string): boolean {
  return Object.keys(commandOptions).some((name) => name === command || name.startsWith(`${command} `));
}

/**
 * Checks what came between the command and the first "--", and what came
 * after it, against what the command takes. Throws a UsageError for an
 * option it does not take, a value that is missing or given twice, a
 * value without an option, and anything after "--" for a command that runs
 * no program. Values are never repeated in a message. A subcommand the
 * command does not have is left to the command, which names the ones it
 * has. `--help` is read before this, so it is allowed anywhere.
 */
export function checkCommandLine(
  command: string,
  options: readonly string[],
  operands: readonly string[] | undefined = undefined,
): void {
  const found = commandSpec(command, options);
  if (found === undefined) return;
  const { label, spec, start } = found;
  const given = new Set<string>();
  for (let index = start; index < options.length; index++) {
    const token = options[index] as string;
    if (token === "--help") continue;
    if (!token.startsWith("-")) {
      throw new UsageError(spec.program === true
        ? `Put the program to run after --: phigon-observer ${label} [options] -- <program> [arguments...].`
        : `${label} got a value without an option. Put each value right after its option, in quotes if it has spaces.`);
    }
    const equals = token.startsWith("--") ? token.indexOf("=") : -1;
    const name = equals < 0 ? token : token.slice(0, equals);
    const option = spec.options[name];
    if (option === undefined) throw new UsageError(unknownOption(label, name, spec));
    if (option.value === undefined) {
      if (equals >= 0) throw new UsageError(`${name} takes no value. Remove the = and what follows it.`);
      if (given.has(name)) throw new UsageError(`${name} was given more than once. Give it once.`);
      given.add(name);
      continue;
    }
    let value: string | undefined;
    if (equals >= 0) {
      value = token.slice(equals + 1);
    } else {
      // A value never starts with "--": `--code --json` is a missing code.
      const next = options[index + 1];
      if (next !== undefined && !next.startsWith("--")) {
        value = next;
        index++;
      }
    }
    if (value === undefined || value.trim() === "") {
      throw new UsageError(option.missingValue ?? `${name} needs a value: ${name} ${option.value}.`);
    }
    if (given.has(name) && option.repeatable !== true) {
      throw new UsageError(`${name} was given more than once. Give it once.`);
    }
    given.add(name);
  }
  if (operands !== undefined && operands.length > 0 && spec.program !== true) {
    throw new UsageError(`${label} takes nothing after --. Remove the -- and what follows it.`);
  }
}

function commandSpec(
  command: string,
  options: readonly string[],
): { label: string; spec: CommandSpec; start: number } | undefined {
  const direct = commandOptions[command];
  if (direct !== undefined) return { label: command, spec: direct, start: 0 };
  const first = options[0];
  const named = first !== undefined && !first.startsWith("-");
  const subcommand = named ? first : defaultSubcommands[command];
  if (subcommand === undefined) return undefined;
  const label = `${command} ${subcommand}`;
  const spec = commandOptions[label];
  return spec === undefined ? undefined : { label, spec, start: named ? 1 : 0 };
}

function unknownOption(label: string, name: string, spec: CommandSpec): string {
  const shown = name.replace(/[^\x21-\x7e]/gu, "?").slice(0, 40);
  const suggestion = closestOption(name, Object.keys(spec.options));
  if (suggestion !== undefined) return `${label} has no option ${shown}. Did you mean ${suggestion}?`;
  const elsewhere = Object.keys(commandOptions).filter((other) => commandOptions[other]?.options[name] !== undefined);
  if (elsewhere.length > 0 && elsewhere.length <= 3) {
    return `${shown} is supported only by ${spokenList(elsewhere)}.`;
  }
  return `${label} has no option ${shown}. Run phigon-observer help to see the options it takes.`;
}

/**
 * The option `name` was most likely meant to be: one a typo or two away,
 * or the only one that contains it (--profile for --consent-profile).
 */
export function closestOption(name: string, options: readonly string[]): string | undefined {
  const bare = name.replace(/^-+/u, "").toLowerCase();
  if (bare === "") return undefined;
  const allowed = bare.length <= 4 ? 1 : 2;
  let best: string | undefined;
  let bestDistance = Infinity;
  for (const option of options) {
    const distance = editDistance(bare, option.replace(/^-+/u, ""));
    if (distance <= allowed && distance < bestDistance) {
      best = option;
      bestDistance = distance;
    }
  }
  if (best !== undefined) return best;
  const containing = bare.length >= 4 ? options.filter((option) => option.includes(bare)) : [];
  return containing.length === 1 ? containing[0] : undefined;
}

/** Edits between two words, a swap of two neighbouring letters counting as one. */
export function editDistance(left: string, right: string): number {
  const rows: number[][] = [];
  for (let i = 0; i <= left.length; i++) {
    const row = [i];
    for (let j = 1; j <= right.length; j++) {
      if (i === 0) {
        row.push(j);
        continue;
      }
      const cost = left[i - 1] === right[j - 1] ? 0 : 1;
      let value = Math.min((rows[i - 1]?.[j] ?? 0) + 1, (row[j - 1] ?? 0) + 1, (rows[i - 1]?.[j - 1] ?? 0) + cost);
      if (i > 1 && j > 1 && left[i - 1] === right[j - 2] && left[i - 2] === right[j - 1]) {
        value = Math.min(value, (rows[i - 2]?.[j - 2] ?? 0) + 1);
      }
      row.push(value);
    }
    rows.push(row);
  }
  return rows[left.length]?.[right.length] ?? Math.max(left.length, right.length);
}

function spokenList(items: readonly string[]): string {
  return items.length < 2 ? items.join("") : `${items.slice(0, -1).join(", ")} and ${items.at(-1) ?? ""}`;
}
