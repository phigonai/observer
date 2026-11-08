import { UsageError } from "./command-options.js";
import type { RemoteActionConsent, StoredMachineCredential } from "./credential-store.js";

/** What the observer lets the company's administrators do on this computer. */
export type RemoteActionsAllowed = Readonly<{ stopAgents: boolean; commands: boolean }>;

/**
 * How the computer is being connected, which decides what administrators
 * may do when the `pair` command does not say:
 * - "prompt": the owner reads the consent prompt, which says administrators
 *   may stop agents and run the commands they approve, and how to allow
 *   less, before typing yes. Both are allowed.
 * - "accepted": the owner accepted with --accept-consent and never saw that
 *   sentence, so neither is allowed.
 * - "enrollment": the company's enrollment code; its policy is the consent,
 *   and both are allowed.
 */
export type PairingConsent = "prompt" | "accepted" | "enrollment";

const remoteActionChoices: Readonly<Record<string, RemoteActionConsent>> = {
  all: "all",
  "stop-agents": "stop_agents",
  none: "none",
};

/**
 * What a `pair` command's options let administrators do here.
 * `--remote-actions all|stop-agents|none` says it outright;
 * `--no-remote-commands` (only stopping agents) and `--no-remote-actions`
 * (neither) still work. Options that contradict each other are refused.
 * When none of them is given, `consent` decides.
 */
export function remoteActionConsent(flags: readonly string[], consent: PairingConsent): RemoteActionConsent {
  return statedRemoteActions(flags) ?? (consent === "accepted" ? "none" : "all");
}

/** What the options say administrators may do, or undefined when they say nothing. */
export function statedRemoteActions(flags: readonly string[]): RemoteActionConsent | undefined {
  const noCommands = flags.includes("--no-remote-commands");
  const noActions = flags.includes("--no-remote-actions");
  const value = optionValue(flags, "--remote-actions");
  if (value === undefined) return noActions ? "none" : noCommands ? "stop_agents" : undefined;
  // Only the table's own names: "constructor" or "toString" are not choices.
  const chosen = Object.hasOwn(remoteActionChoices, value) ? remoteActionChoices[value] : undefined;
  if (chosen === undefined) throw new UsageError("--remote-actions must be all, stop-agents or none.");
  if (chosen === "all" && (noCommands || noActions)) {
    throw new UsageError(`--remote-actions all contradicts ${noActions ? "--no-remote-actions" : "--no-remote-commands"}. Use --remote-actions alone.`);
  }
  if (chosen === "stop_agents" && noActions) {
    throw new UsageError("--remote-actions stop-agents contradicts --no-remote-actions. Use --remote-actions alone.");
  }
  return chosen;
}

function optionValue(flags: readonly string[], name: string): string | undefined {
  for (let index = 0; index < flags.length; index++) {
    const flag = flags[index] as string;
    if (flag === name) {
      const value = flags[index + 1];
      return value === undefined || value.startsWith("--") ? undefined : value;
    }
    if (flag.startsWith(`${name}=`)) return flag.slice(name.length + 1);
  }
  return undefined;
}

/**
 * What this computer allows. A computer paired with this question allows
 * what was consented to; PHIGON_REMOTE_ACTIONS_ENABLED or
 * PHIGON_REMOTE_COMMANDS_ENABLED set to false can narrow that, never widen
 * it (`configured` holds their values). A computer paired before it was
 * asked follows the two settings alone, off unless set, as it always did.
 */
export function remoteActionsAllowed(
  credential: StoredMachineCredential,
  environment: NodeJS.ProcessEnv,
  configured: Readonly<{ remoteActionsEnabled: boolean; remoteCommandsEnabled: boolean }>,
): RemoteActionsAllowed {
  const consent = credential.remoteActions;
  if (consent === undefined) {
    return { stopAgents: configured.remoteActionsEnabled, commands: configured.remoteCommandsEnabled };
  }
  const refused = (name: string, enabled: boolean) => (environment[name]?.trim() ?? "") !== "" && !enabled;
  return {
    stopAgents: consent !== "none" && !refused("PHIGON_REMOTE_ACTIONS_ENABLED", configured.remoteActionsEnabled),
    commands: consent === "all" && !refused("PHIGON_REMOTE_COMMANDS_ENABLED", configured.remoteCommandsEnabled),
  };
}

/**
 * Whether Guardian may stop or force-stop an agent here when the
 * administrator's rules or blocks say so. An owner who refused stopping
 * agents is never overruled; a computer paired before the question keeps
 * the containment it always had.
 */
export function containmentAllowed(
  credential: StoredMachineCredential,
  environment: NodeJS.ProcessEnv,
  configured: Readonly<{ remoteActionsEnabled: boolean; remoteCommandsEnabled: boolean }>,
): boolean {
  return credential.remoteActions === undefined || remoteActionsAllowed(credential, environment, configured).stopAgents;
}

/** One sentence for the person at the computer about what administrators may do. */
export function remoteActionSentence(consent: RemoteActionConsent): string {
  switch (consent) {
    case "all":
      return "Your company's Phigon administrators can stop AI agents on this computer and run the commands they approve. You see a notification each time.";
    case "stop_agents":
      return "Your company's Phigon administrators can stop AI agents on this computer. You see a notification each time.";
    case "none":
      return "Your company's Phigon administrators cannot stop agents or run commands on this computer.";
  }
}
