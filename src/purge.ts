import { readdir, rm, rmdir } from "node:fs/promises";
import { join } from "node:path";

/**
 * Everything the observer itself writes in its data directory. A purge
 * removes only these, so a data directory set to a folder that also holds
 * other files (a home folder, say) loses nothing else.
 */
const observerFiles = new Set([
  "action-policy.json",
  "activity-cursors.json",
  "agent-action-receipts.json",
  "collection-notice.json",
  "custom-agents.json",
  "historical-agent-identities.json",
  "installation-id",
  "machine-credential.json",
  "machine-removed.json",
  "observer.lock",
  "server-ca.pem",
  "service-settings.json",
  "stream-state.json",
  "telemetry-spool.jsonl",
  "update-check.json",
]);

const observerDirectories = new Set([
  "bridges",
  "damaged-spools",
  "history-sync",
  "logs",
  "machine-operation-receipts",
  "process-operation-claims",
  "retired-pairings",
]);

/** Temporary, corrupt and per-run files named after the ones above. */
function observerFile(name: string): boolean {
  if (observerFiles.has(name)) return true;
  for (const file of observerFiles) {
    if (name.startsWith(`${file}.`) && /\.(tmp|corrupt)$/u.test(name)) return true;
  }
  return /^guardian-lease-[0-9a-f-]{36}\.json$/u.test(name) ||
    /^service-task-[0-9a-f-]{36}\.xml$/u.test(name);
}

export type PurgeResult = Readonly<{
  /** Files and folders removed. */
  removed: number;
  /** Names left because the observer did not create them. */
  leftBehind: readonly string[];
  /** Whether the data directory itself was removed, being empty. */
  directoryRemoved: boolean;
}>;

/**
 * Removes every file the observer keeps in `dataDirectory`, then the
 * directory when nothing else is in it. `keep` names files to leave for
 * the caller to remove last, such as the lock it still holds.
 */
export async function purgeDataDirectory(
  dataDirectory: string,
  keep: readonly string[] = [],
): Promise<PurgeResult> {
  let entries: string[];
  try {
    entries = await readdir(dataDirectory);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") {
      return Object.freeze({ removed: 0, leftBehind: Object.freeze([]), directoryRemoved: true });
    }
    throw error;
  }
  let removed = 0;
  const leftBehind: string[] = [];
  for (const name of entries) {
    if (keep.includes(name)) continue;
    if (!observerFile(name) && !observerDirectories.has(name)) {
      leftBehind.push(name);
      continue;
    }
    await rm(join(dataDirectory, name), { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
    removed++;
  }
  return Object.freeze({ removed, leftBehind: Object.freeze(leftBehind.sort()), directoryRemoved: false });
}

/** Removes the data directory when it is empty. */
export async function removeEmptyDataDirectory(dataDirectory: string): Promise<boolean> {
  try {
    await rmdir(dataDirectory);
    return true;
  } catch (error) {
    return (error as NodeJS.ErrnoException).code === "ENOENT";
  }
}
