import { readFileSync, unlinkSync } from "node:fs";
import { mkdir, readFile, stat, unlink, writeFile } from "node:fs/promises";
import { uptime } from "node:os";
import { join } from "node:path";
import { makeDirectoryPrivate } from "./private-directory.js";
import { defaultProcessSampler } from "./system-inspection.js";

const lockFileName = "observer.lock";
// A lock file that is still empty or partly written may belong to an
// observer that is creating it right now.
const unreadableLockGraceMs = 10_000;
// Clock and uptime rounding between the lock's time and the boot time.
const bootToleranceMs = 60_000;
// Between the operating system's start time for a process and the time the
// observer wrote to its lock: start-up before Node's clock begins, the
// one-second resolution of ps, and small clock corrections.
const processStartToleranceMs = 10_000;
const processStartReadTimeoutMs = 15_000;

type LockRecord = Readonly<{ pid: number; started_at: string }>;

export type InstanceLockOptions = Readonly<{
  pid?: number;
  /** When this process started; written to the lock for diagnosis. */
  startedAt?: Date;
  isAlive?: (pid: number) => boolean;
  /**
   * When the running process with this ID started, in epoch milliseconds,
   * or null when the operating system does not say.
   */
  processStartedAt?: (pid: number) => Promise<number | null>;
  /** When the computer last started, in epoch milliseconds. */
  bootedAt?: () => number;
  now?: () => number;
}>;

export class ObserverAlreadyRunningError extends Error {}

/** Who holds a data directory, from `InstanceLock.inspect`. */
export type InstanceLockHolder = Readonly<{
  running: boolean;
  pid?: number;
  startedAt?: string;
}>;

/**
 * Holds a data directory for one running observer. Two `run` processes on
 * one directory would reuse sequence numbers and overwrite each other's
 * spool, cursors and saved state.
 *
 * The lock is a file created with the exclusive `wx` flag that names the
 * holder's process ID and start time. A lock whose process is gone, that was
 * taken before the computer last started, or whose process ID now belongs to
 * a process that started at another time, is stale and is taken over.
 */
export class InstanceLock {
  readonly #path: string;
  readonly #content: string;
  readonly #releaseOnExit: () => void;
  #released = false;

  private constructor(path: string, content: string) {
    this.#path = path;
    this.#content = content;
    // Last resort for an exit that skips `release`, such as process.exit.
    this.#releaseOnExit = () => this.#releaseSync();
    process.once("exit", this.#releaseOnExit);
  }

  static async acquire(
    dataDirectory: string,
    options: InstanceLockOptions = {},
  ): Promise<InstanceLock> {
    const pid = options.pid ?? process.pid;
    const startedAt = options.startedAt ??
      new Date(Date.now() - Math.round(process.uptime() * 1_000));
    const isAlive = options.isAlive ?? processIsAlive;
    const processStartedAt = options.processStartedAt ?? readProcessStartedAt;
    const bootedAt = options.bootedAt ?? (() => Date.now() - uptime() * 1_000);
    const now = options.now ?? Date.now;
    const path = join(dataDirectory, lockFileName);
    const content = `${JSON.stringify({ pid, started_at: startedAt.toISOString() })}\n`;
    await mkdir(dataDirectory, { recursive: true, mode: 0o700 });
    await makeDirectoryPrivate(dataDirectory);
    for (let attempt = 0; attempt < 3; attempt++) {
      try {
        await writeFile(path, content, { encoding: "utf8", flag: "wx", mode: 0o600 });
        return new InstanceLock(path, content);
      } catch (error) {
        if (!isNodeError(error) || error.code !== "EEXIST") throw error;
      }
      let existing: string;
      try {
        existing = await readFile(path, "utf8");
      } catch (error) {
        // Released between our attempt and this read: try again.
        if (isNodeError(error) && error.code === "ENOENT") continue;
        throw error;
      }
      const holder = parseLock(existing);
      if (holder === undefined) {
        let modifiedMs: number;
        try {
          modifiedMs = (await stat(path)).mtimeMs;
        } catch (error) {
          if (isNodeError(error) && error.code === "ENOENT") continue;
          throw error;
        }
        if (now() - modifiedMs < unreadableLockGraceMs) {
          throw alreadyRunning(path, undefined);
        }
      } else if (await holderIsLive(holder, isAlive, processStartedAt, bootedAt)) {
        throw alreadyRunning(path, holder);
      }
      // Stale. Remove it only while it is still the lock that was judged
      // stale, so an observer that took it over meanwhile keeps it.
      try {
        if (await readFile(path, "utf8") === existing) await unlink(path);
      } catch (error) {
        if (!isNodeError(error) || error.code !== "ENOENT") throw error;
      }
    }
    throw alreadyRunning(path, undefined);
  }

  /**
   * Whether an observer holds this data directory now, judged the way
   * `acquire` judges it, without taking or removing the lock.
   */
  static async inspect(
    dataDirectory: string,
    options: InstanceLockOptions = {},
  ): Promise<InstanceLockHolder> {
    const isAlive = options.isAlive ?? processIsAlive;
    const processStartedAt = options.processStartedAt ?? readProcessStartedAt;
    const bootedAt = options.bootedAt ?? (() => Date.now() - uptime() * 1_000);
    const now = options.now ?? Date.now;
    const path = join(dataDirectory, lockFileName);
    let existing: string;
    try {
      existing = await readFile(path, "utf8");
    } catch (error) {
      if (isNodeError(error) && error.code === "ENOENT") return { running: false };
      throw error;
    }
    const holder = parseLock(existing);
    if (holder === undefined) {
      try {
        // Still being written by an observer that is starting.
        return { running: now() - (await stat(path)).mtimeMs < unreadableLockGraceMs };
      } catch (error) {
        if (isNodeError(error) && error.code === "ENOENT") return { running: false };
        throw error;
      }
    }
    const running = await holderIsLive(holder, isAlive, processStartedAt, bootedAt);
    return running
      ? { running, pid: holder.pid, startedAt: holder.started_at }
      : { running };
  }

  async release(): Promise<void> {
    if (this.#released) return;
    this.#released = true;
    process.removeListener("exit", this.#releaseOnExit);
    try {
      if (await readFile(this.#path, "utf8") === this.#content) {
        await unlink(this.#path);
      }
    } catch (error) {
      if (!isNodeError(error) || error.code !== "ENOENT") throw error;
    }
  }

  #releaseSync(): void {
    if (this.#released) return;
    this.#released = true;
    try {
      if (readFileSync(this.#path, "utf8") === this.#content) unlinkSync(this.#path);
    } catch {
      // Exiting anyway; the next start treats a dead holder as stale.
    }
  }
}

function alreadyRunning(
  path: string,
  holder: LockRecord | undefined,
): ObserverAlreadyRunningError {
  const who = holder === undefined
    ? "Another Phigon observer"
    : `Another Phigon observer (process ${holder.pid}, started ${holder.started_at})`;
  return new ObserverAlreadyRunningError(
    `${who} is already running with this data directory. Two observers on ` +
      "one data directory would overwrite each other's queued activity and " +
      "progress. Stop the other observer, or give this one its own data " +
      `directory. If no observer is running, delete ${path}.`,
  );
}

function parseLock(raw: string): LockRecord | undefined {
  let value: unknown;
  try {
    value = JSON.parse(raw);
  } catch {
    return undefined;
  }
  if (
    typeof value !== "object" || value === null ||
    !("pid" in value) || typeof value.pid !== "number" ||
    !Number.isSafeInteger(value.pid) || value.pid < 1 ||
    !("started_at" in value) || typeof value.started_at !== "string" ||
    !Number.isFinite(Date.parse(value.started_at))
  ) {
    return undefined;
  }
  return { pid: value.pid, started_at: value.started_at };
}

/** A holder that started since the computer last started and still runs. */
async function holderIsLive(
  holder: LockRecord,
  isAlive: (pid: number) => boolean,
  processStartedAt: (pid: number) => Promise<number | null>,
  bootedAt: () => number,
): Promise<boolean> {
  return Date.parse(holder.started_at) >= bootedAt() - bootToleranceMs &&
    isAlive(holder.pid) &&
    !(await processIDReused(holder, processStartedAt));
}

/**
 * After a hard kill the operating system can give the holder's process ID to
 * an unrelated program. When its start time cannot be read, the holder is
 * taken to be still running.
 */
async function processIDReused(
  holder: LockRecord,
  processStartedAt: (pid: number) => Promise<number | null>,
): Promise<boolean> {
  let startedAt: number | null;
  try {
    startedAt = await processStartedAt(holder.pid);
  } catch {
    return false;
  }
  return startedAt !== null && Number.isFinite(startedAt) &&
    Math.abs(startedAt - Date.parse(holder.started_at)) > processStartToleranceMs;
}

async function readProcessStartedAt(pid: number): Promise<number | null> {
  let timer: NodeJS.Timeout | undefined;
  const timeout = new Promise<null>((resolve) => {
    timer = setTimeout(() => resolve(null), processStartReadTimeoutMs);
  });
  try {
    const sample = await Promise.race([defaultProcessSampler()([pid], 0), timeout]);
    return sample?.before.get(pid)?.startedAt ?? null;
  } finally {
    clearTimeout(timer);
  }
}

export function processIsAlive(pid: number): boolean {
  try {
    // Signal 0 checks that the process exists without touching it.
    process.kill(pid, 0);
    return true;
  } catch (error) {
    // EPERM: it exists but belongs to another user.
    return isNodeError(error) && error.code === "EPERM";
  }
}

function isNodeError(error: unknown): error is NodeJS.ErrnoException {
  return error instanceof Error && "code" in error;
}
