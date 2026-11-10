import { createHash, randomUUID } from "node:crypto";
import { chmod, readFile, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { atomicReplace } from "./atomic-replace.js";
import type { StoredMachineCredential } from "./credential-store.js";
import { serverFetch } from "./server-fetch.js";

/**
 * Remembers that the workspace no longer accepts this computer's key, so a
 * background service that starts the observer again (within seconds on
 * Windows, and at the next sign-in everywhere) stops at once instead of
 * scanning for agents and failing again. The service then exits cleanly,
 * which systemd (Restart=on-failure) and launchd (KeepAlive with
 * SuccessfulExit false) do not restart. A LaunchAgent written by an older
 * observer, with KeepAlive true, still starts it every 30 seconds until the
 * service is installed again, which `update` does.
 * Pairing again gives the computer a new key, which this file does not
 * match, so the observer starts normally.
 */
export const machineRemovedFileName = "machine-removed.json";

export const machineRemovedMessage =
  "This computer was removed from Phigon. Pair it again with a new code from Connect machine, or run phigon-observer service uninstall.";

/** The workspace refused this computer's key: it was removed, or its key revoked. */
export class MachineRemovedError extends Error {
  constructor() {
    super(machineRemovedMessage);
    this.name = "MachineRemovedError";
  }
}

/** The pairing the refusal was for. */
type MachineKey = Pick<StoredMachineCredential, "machineId" | "credential" | "createdAt" | "controlPlaneOrigin" | "grpcOrigin">;

type RemovedMachine = Readonly<{
  machineId: string;
  /**
   * A digest of the refused key and of when and where it was paired, so
   * any pairing since, even one that keeps the key, is told apart.
   */
  key: string;
  removedAt: string;
  /** When the server last said, when asked directly, that it refuses the key. */
  confirmedAt?: string;
}>;

export type RemovedAtStart =
  /** Not removed, or the server could not say: start as usual. */
  | "start"
  /** The server still refuses the key; it was asked now. */
  | "removed"
  /** Removed, and the server confirmed it recently: stop without asking again. */
  | "still_removed";

/**
 * Remembers that the telemetry stream refused this computer's key. That
 * alone never stops a later start quietly: the next start asks the server
 * directly, and only its answer that the key is invalid confirms it.
 */
export async function rememberMachineRemoved(
  dataDirectory: string,
  machine: MachineKey,
  now: Date = new Date(),
): Promise<void> {
  await writeRemoved(join(dataDirectory, machineRemovedFileName), {
    machineId: machine.machineId,
    key: pairingDigest(machine),
    removedAt: now.toISOString(),
  });
}

/**
 * Whether `run` should stop before it starts because the workspace removed
 * this computer. Until the server has confirmed the removal, and again
 * `recheckAfterMs` after it did, the server is asked, cheaply: a key it
 * accepts, or a server that cannot be reached or does not say plainly that
 * the key is invalid, starts the observer as usual, which finds out for
 * itself. So a healthy computer is never kept stopped.
 */
export async function removedAtStart(options: Readonly<{
  dataDirectory: string;
  machine: MachineKey;
  controlPlaneUrl: URL;
  recheckAfterMs: number;
  now?: () => Date;
  fetcher?: typeof fetch;
}>): Promise<RemovedAtStart> {
  const path = join(options.dataDirectory, machineRemovedFileName);
  const removed = await readRemoved(path);
  if (removed === undefined) return "start";
  if (removed.machineId !== options.machine.machineId || removed.key !== pairingDigest(options.machine)) {
    // Paired again since.
    await rm(path, { force: true });
    return "start";
  }
  const now = (options.now ?? (() => new Date()))();
  const confirmedAt = removed.confirmedAt === undefined ? Number.NaN : Date.parse(removed.confirmedAt);
  const sinceConfirmed = now.getTime() - confirmedAt;
  if (Number.isFinite(confirmedAt) && sinceConfirmed >= 0 && sinceConfirmed < options.recheckAfterMs) {
    return "still_removed";
  }
  const accepted = await keyAccepted(options.fetcher ?? serverFetch, options.controlPlaneUrl, options.machine.credential);
  if (accepted === false) {
    await writeRemoved(path, { ...removed, confirmedAt: now.toISOString() });
    return "removed";
  }
  await rm(path, { force: true });
  return "start";
}

/**
 * How long until `removedAtStart` asks the server again, counted from the
 * confirmation it keeps, so a restart in between does not put the question
 * off. Zero when it would ask now; never more than `recheckAfterMs`.
 */
export async function removedRecheckIn(dataDirectory: string, recheckAfterMs: number, now: Date = new Date()): Promise<number> {
  const removed = await readRemoved(join(dataDirectory, machineRemovedFileName)).catch(() => undefined);
  const confirmedAt = removed?.confirmedAt === undefined ? Number.NaN : Date.parse(removed.confirmedAt);
  if (!Number.isFinite(confirmedAt)) return 0;
  return Math.min(recheckAfterMs, Math.max(0, confirmedAt + recheckAfterMs - now.getTime()));
}

/** True or false when the server says so; undefined when it cannot be asked. */
/**
 * Whether the server confirmed that the workspace removed this pairing,
 * from the file `run` keeps; nothing is asked. `doctor --check` uses it to
 * say why no observer runs instead of suggesting to start it again.
 */
export async function removalConfirmed(dataDirectory: string, machine: MachineKey): Promise<boolean> {
  const removed = await readRemoved(join(dataDirectory, machineRemovedFileName)).catch(() => undefined);
  return removed !== undefined && removed.machineId === machine.machineId &&
    removed.key === pairingDigest(machine) && removed.confirmedAt !== undefined;
}

async function keyAccepted(fetcher: typeof fetch, controlPlaneUrl: URL, credential: string): Promise<boolean | undefined> {
  let response: Response;
  try {
    response = await fetcher(new URL("/v1/machine/heartbeat", controlPlaneUrl), {
      method: "POST",
      headers: { Authorization: `Bearer ${credential}`, Accept: "application/json" },
      redirect: "error",
      signal: AbortSignal.timeout(10_000),
    });
  } catch {
    return undefined;
  }
  try {
    if (response.ok) return true;
    if (response.status !== 401) return undefined;
    const value: unknown = await response.json();
    const code = typeof value === "object" && value !== null && "error" in value &&
        typeof value.error === "object" && value.error !== null && "code" in value.error
      ? value.error.code
      : undefined;
    return code === "invalid_credential" ? false : undefined;
  } catch {
    return undefined;
  } finally {
    await response.body?.cancel().catch(() => undefined);
  }
}

function pairingDigest(machine: MachineKey): string {
  const pairing = [machine.credential, machine.createdAt, machine.controlPlaneOrigin, machine.grpcOrigin ?? ""];
  return createHash("sha256").update(JSON.stringify(pairing), "utf8").digest("hex").slice(0, 32);
}

async function readRemoved(path: string): Promise<RemovedMachine | undefined> {
  let value: unknown;
  try {
    value = JSON.parse(await readFile(path, "utf8"));
  } catch {
    // Missing or unreadable: the observer starts and finds out again.
    return undefined;
  }
  if (
    typeof value === "object" && value !== null &&
    "machineId" in value && typeof value.machineId === "string" &&
    "key" in value && typeof value.key === "string" &&
    "removedAt" in value && typeof value.removedAt === "string"
  ) {
    const confirmedAt = "confirmedAt" in value && typeof value.confirmedAt === "string" ? value.confirmedAt : undefined;
    return {
      machineId: value.machineId, key: value.key, removedAt: value.removedAt,
      ...(confirmedAt === undefined ? {} : { confirmedAt }),
    };
  }
  return undefined;
}

async function writeRemoved(path: string, value: RemovedMachine): Promise<void> {
  const temporary = `${path}.${process.pid}.${randomUUID()}.tmp`;
  try {
    await writeFile(temporary, `${JSON.stringify(value)}\n`, { encoding: "utf8", flag: "wx", mode: 0o600 });
    await atomicReplace(temporary, path);
    await chmod(path, 0o600);
  } catch (error) {
    await rm(temporary, { force: true });
    throw error;
  }
}
