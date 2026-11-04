import type { RemoteActionConsent, StoredMachineCredential } from "./credential-store.js";

/** What the observer lets the company's administrators do on this computer. */
export type RemoteActionsAllowed = Readonly<{ stopAgents: boolean; commands: boolean }>;

/**
 * What a `pair` command's flags let administrators do: stop agents and run
 * the commands they approve, unless the owner (or the company's device
 * management script) leaves out commands or both.
 */
export function remoteActionConsent(flags: readonly string[]): RemoteActionConsent {
  if (flags.includes("--no-remote-actions")) return "none";
  if (flags.includes("--no-remote-commands")) return "stop_agents";
  return "all";
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
