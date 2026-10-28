import type { Stats } from "node:fs";
import { stat } from "node:fs/promises";
import type { DatabaseSync } from "node:sqlite";

/**
 * Sizes and times of a database and its write-ahead log. A commit changes at
 * least the log's time, so an unchanged signature means nothing new landed.
 */
export async function databaseSignature(path: string, main: Pick<Stats, "size" | "mtimeMs">): Promise<string> {
  let log = "-";
  try {
    const wal = await stat(`${path}-wal`);
    log = `${wal.size}:${wal.mtimeMs}`;
  } catch {
    // No write-ahead log: the main file's size and time cover every commit.
  }
  return `${main.size}:${main.mtimeMs}:${log}`;
}

/**
 * Databases a history import already read to the end, by signature. A batch
 * that completes with nothing new marks its database; later batches skip it
 * until a commit changes the signature. New work after that point is the
 * live reader's, so this only spares re-reading finished history.
 */
export type CompletedHistory = Map<string, string>;

/**
 * The cursors an idle scan read, in order, with the values it found (or
 * undefined). An idle scan selected no row, so it changed no cursor.
 */
export type IdleCursors = ReadonlyArray<readonly [string, number | undefined]>;

/** What a live reader does with a database on this tick. */
export type SQLiteScan =
  | Readonly<{ unchanged: true }>
  | Readonly<{
    unchanged: false;
    database: DatabaseSync;
    /**
     * Record a successful scan; `idle` when it selected no row. `recheckAt`
     * is when a scan of the same data would find something new (a row it
     * waits for has settled), so the idle state expires then.
     */
    finish(idle: IdleCursors | undefined, recheckAt?: number): void;
    /** Drop the connection after a failed scan. */
    fail(): void;
  }>;

type DatabaseState = {
  /** The database path and file identity the state belongs to. */
  readonly identity: string;
  connection: DatabaseSync | undefined;
  /** The data_version last read on `connection`. */
  version: number | undefined;
  /** When a commit or a file change was last seen. */
  changedAt: number;
  /** Main and -wal file sizes and times, read at the start of a tick. */
  signature: string;
  /** When a closed database was last confirmed unchanged by a scan. */
  checkedAt: number;
  /** The last full scan selected no row: its data version and cursors. */
  idle: Readonly<{
    version: number;
    cursors: IdleCursors;
    /** When the idle state expires, if it does. */
    until: number | undefined;
  }> | undefined;
};

const unchanged = Object.freeze({ unchanged: true as const });

/**
 * Decides, for a live reader, when a database has to be scanned, keyed by
 * source root.
 *
 * While the database is active a read-only connection stays open, and
 * `PRAGMA data_version` proves it unchanged: SQLite changes that value on
 * the same connection whenever any other connection commits, even a WAL
 * commit that leaves every file size and timestamp as they were.
 *
 * After `idleCloseMs` without a change the connection is closed, because
 * an open SQLite file on Windows cannot be deleted or replaced by the user or
 * the agent. While closed, each tick compares the main and -wal file sizes
 * and modification times. A difference reopens the database for a full scan.
 * Because a commit can leave them unchanged (after a WAL restart within one
 * timestamp tick), a full scan also runs at least every `recheckMs`.
 *
 * A scan is skipped only when the last full scan selected no row and every
 * cursor it read still holds the same value, so a full scan would again find
 * nothing. A scan that waits for a row to settle sets when that happens, and
 * its idle state expires then. Statements finish within a scan (node:sqlite resets each one), so
 * no read transaction stays open between ticks to hold back checkpoints.
 */
export class SQLiteConnections {
  readonly #states = new Map<string, DatabaseState>();
  readonly #clock: () => number;
  readonly #idleCloseMs: number;
  readonly #recheckMs: number;

  constructor(
    options: Readonly<{
      clock?: () => number;
      idleCloseMs?: number;
      recheckMs?: number;
    }> = {},
  ) {
    this.#clock = options.clock ?? Date.now;
    this.#idleCloseMs = options.idleCloseMs ?? 60_000;
    this.#recheckMs = options.recheckMs ?? 60_000;
  }

  /**
   * Whether the database at `path` (resolved from `root`, with `metadata`
   * from the same tick) must be scanned, and the connection to scan it with.
   */
  async check(
    root: string,
    path: string,
    metadata: Stats,
    cursors: ReadonlyMap<string, number>,
    open: (path: string) => DatabaseSync,
  ): Promise<SQLiteScan> {
    const identity = databaseIdentity(path, metadata);
    // Read before data_version or any scan query, so whatever this tick
    // cannot see changes the signature or version the next tick reads.
    const signature = await fileSignature(path, metadata);
    let state = this.#states.get(root);
    if (state !== undefined && state.identity !== identity) {
      this.release(root);
      state = undefined;
    }
    const now = this.#clock();
    if (state === undefined) {
      state = {
        identity,
        connection: undefined,
        version: undefined,
        changedAt: now,
        signature,
        checkedAt: now,
        idle: undefined,
      };
      this.#states.set(root, state);
    }
    if (state.connection === undefined) {
      if (
        state.idle !== undefined &&
        state.signature === signature &&
        now - state.checkedAt < this.#recheckMs &&
        unexpired(state.idle, now) &&
        sameCursors(state.idle.cursors, cursors)
      ) {
        return unchanged;
      }
      // The files changed, the periodic full scan is due, or there is no
      // idle scan to compare with. A new connection has its own versions.
      if (state.signature !== signature) state.changedAt = now;
      state.idle = undefined;
      state.version = undefined;
      state.connection = open(path);
    }
    state.signature = signature;
    const current = state;
    const database = state.connection;
    let version: number;
    try {
      version = dataVersion(database);
    } catch (error) {
      this.release(root);
      throw error;
    }
    if (current.version !== undefined && current.version !== version) {
      current.changedAt = now;
    }
    current.version = version;
    if (
      current.idle !== undefined &&
      current.idle.version === version &&
      unexpired(current.idle, now) &&
      sameCursors(current.idle.cursors, cursors)
    ) {
      if (now - current.changedAt >= this.#idleCloseMs) this.#close(current, now);
      return unchanged;
    }
    current.idle = undefined;
    return {
      unchanged: false,
      database,
      finish: (idle, recheckAt) => {
        if (this.#states.get(root) !== current) return;
        if (idle !== undefined) current.idle = { version, cursors: idle, until: recheckAt };
        if (now - current.changedAt >= this.#idleCloseMs) this.#close(current, now);
      },
      fail: () => {
        if (this.#states.get(root) === current) this.release(root);
      },
    };
  }

  release(root: string): void {
    const state = this.#states.get(root);
    if (state === undefined) return;
    this.#states.delete(root);
    if (state.connection !== undefined) closeQuietly(state.connection);
  }

  /** Forget the databases of roots that are no longer configured. */
  retain(roots: ReadonlySet<string>): void {
    for (const root of [...this.#states.keys()]) {
      if (!roots.has(root)) this.release(root);
    }
  }

  closeAll(): void {
    for (const root of [...this.#states.keys()]) this.release(root);
  }

  /** How many connections are open now. */
  get openConnections(): number {
    let open = 0;
    for (const state of this.#states.values()) {
      if (state.connection !== undefined) open++;
    }
    return open;
  }

  #close(state: DatabaseState, now: number): void {
    if (state.connection !== undefined) closeQuietly(state.connection);
    state.connection = undefined;
    state.version = undefined;
    state.checkedAt = now;
  }
}

export function dataVersion(database: DatabaseSync): number {
  const value = database.prepare("PRAGMA data_version").get()?.["data_version"];
  if (typeof value !== "number" || !Number.isSafeInteger(value)) {
    throw new Error("SQLite data version is unavailable.");
  }
  return value;
}

function databaseIdentity(path: string, metadata: Stats): string {
  return [path, metadata.dev, metadata.ino, metadata.birthtimeMs].join("\u0000");
}

let unreadableWal = 0;

async function fileSignature(path: string, main: Stats): Promise<string> {
  let wal: string;
  try {
    const metadata = await stat(`${path}-wal`);
    wal = [metadata.size, metadata.mtimeMs, metadata.ino].join(":");
  } catch (error) {
    // No -wal file: a rollback-journal database, or WAL after the last
    // writer closed. Any other failure counts as a change.
    wal = error instanceof Error && "code" in error && error.code === "ENOENT"
      ? "none"
      : `unreadable:${++unreadableWal}`;
  }
  return `${main.size}:${main.mtimeMs}\u0000${wal}`;
}

/** True until the idle state's expiry, if it has one. */
function unexpired(idle: Readonly<{ until: number | undefined }>, now: number): boolean {
  return idle.until === undefined || now < idle.until;
}

/**
 * True when every cursor still holds the value the idle scan saw. They are
 * read in the scan's order, so least-recently-used bookkeeping matches the
 * scan this replaces.
 */
function sameCursors(
  idle: IdleCursors,
  cursors: ReadonlyMap<string, number>,
): boolean {
  for (const [key, value] of idle) {
    if (cursors.get(key) !== value) return false;
  }
  return true;
}

function closeQuietly(database: DatabaseSync): void {
  try {
    database.close();
  } catch {
    // Already closed.
  }
}
