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
 * What this computer allows: what was consented to when it paired, unless
 * PHIGON_REMOTE_ACTIONS_ENABLED or PHIGON_REMOTE_COMMANDS_ENABLED says
 * otherwise (`configured` holds their values). A computer paired before
 * this was asked allows neither until it pairs again or one is set.
 */
export function remoteActionsAllowed(
  credential: StoredMachineCredential,
  environment: NodeJS.ProcessEnv,
  configured: Readonly<{ remoteActionsEnabled: boolean; remoteCommandsEnabled: boolean }>,
): RemoteActionsAllowed {
  const consent = credential.remoteActions ?? "none";
  const set = (name: string) => (environment[name]?.trim() ?? "") !== "";
  return {
    stopAgents: set("PHIGON_REMOTE_ACTIONS_ENABLED") ? configured.remoteActionsEnabled : consent !== "none",
    commands: set("PHIGON_REMOTE_COMMANDS_ENABLED") ? configured.remoteCommandsEnabled : consent === "all",
  };
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
