import { createHash, randomUUID } from "node:crypto";
import { readFileSync, unlinkSync } from "node:fs";
import { mkdir, readdir, readFile, rm, stat, unlink, writeFile } from "node:fs/promises";
import { uptime } from "node:os";
import { basename, dirname, join } from "node:path";
import { atomicReplace } from "./atomic-replace.js";
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

type LockRecord = Readonly<{
  pid: number;
  started_at: string;
  /**
   * The start time the operating system gave for the holder when it took
   * the lock, read the way later checks read it (absent in older locks).
   */
  process_started_at?: string;
}>;

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
 * a process that started at another time, is stale and is taken over. Of
 * several observers taking over one stale lock at once, exactly one gets it
 * (see takeOver).
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
    // Windows and macOS keep a process's start time as it was when it
    // started, so a later clock correction does not change it.
    const systemStartedAt = await readStart(pid, processStartedAt);
    const content = `${JSON.stringify({
      pid,
      started_at: startedAt.toISOString(),
      ...(systemStartedAt === null ? {} : { process_started_at: new Date(systemStartedAt).toISOString() }),
    })}\n`;
    await mkdir(dataDirectory, { recursive: true, mode: 0o700 });
    await makeDirectoryPrivate(dataDirectory);
    for (let attempt = 0; attempt < 4; attempt++) {
      try {
        await writeFile(path, content, { encoding: "utf8", flag: "wx", mode: 0o600 });
        await removeTakeoverMarkers(path);
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
      // Stale. Reading it again and removing it would race: another
      // observer could take it over between the two, and this one would
      // then remove that observer's lock. A takeover marker that only one
      // observer can create decides who replaces this stale lock.
      const takenOver = await takeOver(path, existing, content, now, (record) =>
        holderIsLive(record, isAlive, processStartedAt, bootedAt));
      if (takenOver === "taken") {
        await removeTakeoverMarkers(path);
        return new InstanceLock(path, content);
      }
      if (takenOver === "busy") throw alreadyRunning(path, undefined);
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

/**
 * Replaces the stale lock `stale` with `content`, so that of several
 * observers taking over the same stale lock at once exactly one succeeds.
 *
 * Each observer first creates a takeover marker for that stale lock with
 * the exclusive `wx` flag; the one that creates it checks that the lock
 * still is the stale one and then replaces it in a single rename, so the
 * lock never goes missing and nobody else can create one meanwhile.
 *
 * Markers are numbered. An observer creates the number after the highest
 * one there, and only when the observer that wrote that one is gone, so
 * only the highest marker can belong to a live observer, and two observers
 * that both find the same dead marker race for one name that only one gets.
 * A dead marker is never removed and its name reused, which would race the
 * same way; numbers have no limit, so dead markers never block a takeover.
 * Every marker is removed once an observer holds the lock (see
 * removeTakeoverMarkers). The markers end in `.tmp`, so a purge removes them.
 *
 * "taken": this observer holds the lock. "busy": another live observer is
 * taking it over. "changed": the lock or the markers changed; look again.
 */
async function takeOver(
  path: string,
  stale: string,
  content: string,
  now: () => number,
  isLive: (record: LockRecord) => Promise<boolean>,
): Promise<"taken" | "busy" | "changed"> {
  const digest = createHash("sha256").update(stale).digest("hex").slice(0, 16);
  const prefix = `${basename(path)}.takeover-${digest}-`;
  const markerPath = (generation: number) => join(dirname(path), `${prefix}${generation}.tmp`);
  const highest = (await readdir(dirname(path)))
    .filter((name) => name.startsWith(prefix) && name.endsWith(".tmp"))
    .map((name) => name.slice(prefix.length, -".tmp".length))
    .filter((generation) => /^\d{1,15}$/u.test(generation))
    .reduce((top, generation) => Math.max(top, Number(generation)), -1);
  if (highest >= 0) {
    // The latest marker is taking the lock over unless its observer died.
    let other: string;
    let modifiedMs: number;
    try {
      [other, modifiedMs] = await Promise.all([
        readFile(markerPath(highest), "utf8"),
        stat(markerPath(highest)).then((metadata) => metadata.mtimeMs),
      ]);
    } catch (error) {
      if (isNodeError(error) && error.code === "ENOENT") return "changed";
      throw error;
    }
    const record = parseLock(other);
    if (record === undefined ? now() - modifiedMs < unreadableLockGraceMs : await isLive(record)) {
      return "busy";
    }
  }
  const marker = markerPath(highest + 1);
  try {
    await writeFile(marker, content, { encoding: "utf8", flag: "wx", mode: 0o600 });
  } catch (error) {
    // Another observer took this number first: look again.
    if (isNodeError(error) && error.code === "EEXIST") return "changed";
    throw error;
  }
  const temporary = `${path}.${process.pid}.${randomUUID()}.tmp`;
  try {
    let current: string;
    try {
      current = await readFile(path, "utf8");
    } catch (error) {
      if (isNodeError(error) && error.code === "ENOENT") return "changed";
      throw error;
    }
    if (current !== stale) return "changed";
    await writeFile(temporary, content, { encoding: "utf8", flag: "wx", mode: 0o600 });
    await atomicReplace(temporary, path);
    return "taken";
  } finally {
    await rm(temporary, { force: true }).catch(() => undefined);
    // Only this observer's marker; once one holds the lock, all go.
    await rm(marker, { force: true }).catch(() => undefined);
  }
}

/**
 * Removes every takeover marker, once this observer holds the lock. Each
 * names a lock that is gone now, so an observer that creates one again, or
 * still holds one, finds the lock changed and looks again.
 */
async function removeTakeoverMarkers(path: string): Promise<void> {
  const prefix = `${basename(path)}.takeover-`;
  try {
    const names = (await readdir(dirname(path))).filter((name) => name.startsWith(prefix) && name.endsWith(".tmp"));
    await Promise.all(names.map((name) => rm(join(dirname(path), name), { force: true }).catch(() => undefined)));
  } catch {
    // Left for the next observer that holds the lock.
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
  const systemStartedAt = "process_started_at" in value && typeof value.process_started_at === "string" &&
    Number.isFinite(Date.parse(value.process_started_at))
    ? value.process_started_at
    : undefined;
  return {
    pid: value.pid,
    started_at: value.started_at,
    ...(systemStartedAt === undefined ? {} : { process_started_at: systemStartedAt }),
  };
}

/**
 * Whether the holder still runs. After a hard kill the operating system can
 * give its process ID to an unrelated program, so a live process counts only
 * when the start time the system recorded for it matches the lock: the one
 * the system gave when the lock was taken, or the time the observer wrote.
 * That holds even when the clock changed since: a computer whose clock is
 * wrong when it starts, and is corrected a few minutes later, would
 * otherwise make its own background service look like one from before the
 * restart. The observer may also take the lock just after the correction,
 * when its own clock no longer matches the time the system recorded, which
 * the system's start time in the lock still matches. Only when the start
 * time cannot be read does the holder have to have started since the
 * computer did.
 */
async function holderIsLive(
  holder: LockRecord,
  isAlive: (pid: number) => boolean,
  processStartedAt: (pid: number) => Promise<number | null>,
  bootedAt: () => number,
): Promise<boolean> {
  if (!isAlive(holder.pid)) return false;
  const started = await readStart(holder.pid, processStartedAt);
  if (started !== null) {
    const recorded = [holder.started_at, holder.process_started_at].filter((value) => value !== undefined);
    return recorded.some((value) => Math.abs(started - Date.parse(value)) <= processStartToleranceMs);
  }
  return Date.parse(holder.started_at) >= bootedAt() - bootToleranceMs;
}

async function readStart(pid: number, processStartedAt: (pid: number) => Promise<number | null>): Promise<number | null> {
  try {
    const started = await processStartedAt(pid);
    return started !== null && Number.isFinite(started) ? started : null;
  } catch {
    return null;
  }
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
