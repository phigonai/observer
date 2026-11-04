import { stat } from "node:fs/promises";
import { join } from "node:path";
import {
  FileCredentialStore,
  credentialFileName,
  type StoredMachineCredential,
} from "./credential-store.js";

/**
 * `run` exits with this code when the pairing changed under it, so a
 * background service starts it again with the new pairing (systemd restarts
 * only a failed unit; Task Scheduler and launchd start it again anyway).
 */
export const pairingChangedExitCode = 75;

export type PairingChange = Readonly<{
  /** The owner's consent no longer covers full activity. */
  narrowedConsent: boolean;
  /** One line for the person at the computer. */
  message: string;
}>;

export type PairingWatch = Readonly<{
  /** Reads the stored pairing now, as one pass of the watch does. */
  check: () => Promise<PairingChange | undefined>;
  stop: () => void;
}>;

// The fields that decide where activity goes, under whose key and consent.
const watchedFields = [
  "machineId",
  "tenantId",
  "credential",
  "controlPlaneOrigin",
  "grpcOrigin",
  "consentProfile",
  "consentPolicyVersion",
  "consentSource",
  "enrollmentCodeId",
] as const satisfies readonly (keyof StoredMachineCredential)[];

// Where the server answers; the same machine and consent at a new address.
const endpointFields: readonly (keyof StoredMachineCredential)[] = ["controlPlaneOrigin", "grpcOrigin"];

/**
 * Watches the pairing a running observer started with. Pairing again while
 * it runs rewrites the stored credential, for example to lower the owner's
 * consent from full activity to metadata; the observer must not go on with
 * what it read at start. Only a change to what activity is sent, where and
 * under whose consent counts, not a renewed date.
 */
export function watchPairing(options: Readonly<{
  dataDirectory: string;
  current: StoredMachineCredential;
  onChange: (change: PairingChange) => void;
  intervalMs?: number;
}>): PairingWatch {
  const store = new FileCredentialStore(options.dataDirectory);
  const file = join(options.dataDirectory, credentialFileName);
  let seen: string | undefined;
  let busy = false;
  let stopped = false;

  const check = async (): Promise<PairingChange | undefined> => {
    const stamp = await stat(file, { bigint: true }).then(
      (info) => `${info.ino}:${info.mtimeNs}:${info.size}`,
      () => "missing",
    );
    if (stamp === seen) return undefined;
    let stored: StoredMachineCredential | null;
    try {
      stored = await store.load();
    } catch {
      stored = null;
    }
    const change = describeChange(options.current, stored);
    if (change === undefined) seen = stamp;
    return change;
  };

  const stop = () => {
    stopped = true;
    clearInterval(timer);
  };
  const timer = setInterval(() => {
    if (busy || stopped) return;
    busy = true;
    void check().then((change) => {
      if (change === undefined || stopped) return;
      stop();
      options.onChange(change);
    }, () => undefined).finally(() => {
      busy = false;
    });
  }, options.intervalMs ?? 1_000);
  timer.unref();
  return { check, stop };
}

/** Whether a running observer paired as `before` stops for the pairing `after`. */
export function pairingChanged(
  before: StoredMachineCredential,
  after: StoredMachineCredential | null,
): boolean {
  return describeChange(before, after) !== undefined;
}

function describeChange(
  current: StoredMachineCredential,
  stored: StoredMachineCredential | null,
): PairingChange | undefined {
  if (stored === null) {
    return {
      narrowedConsent: true,
      message: "This computer's pairing was removed or cannot be read, so the observer stops collecting and exits.",
    };
  }
  if (watchedFields.every((field) => stored[field] === current[field])) return undefined;
  if (watchedFields.every((field) => endpointFields.includes(field) || stored[field] === current[field])) {
    return {
      narrowedConsent: false,
      message: `Phigon's server is now at ${stored.controlPlaneOrigin}, so the observer stops and starts again there. Its background service starts it again; if you started it yourself, run it again.`,
    };
  }
  const narrowedConsent = current.consentProfile === "full" && stored.consentProfile !== "full";
  return {
    narrowedConsent,
    message: narrowedConsent
      ? "This computer's consent changed to agent metadata only, so the observer stops collecting now and exits. Its background service starts it again with the new consent; if you started it yourself, run it again."
      : "This computer's pairing changed, so the observer stops and exits. Its background service starts it again with the new pairing; if you started it yourself, run it again.",
  };
}
