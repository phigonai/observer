import { makeDirectoryPrivate } from "../private-directory.js";
import { createHash, randomUUID } from "node:crypto";
import {
  chmod,
  mkdir,
  open,
  readFile,
  readdir,
  realpath,
  stat,
  unlink,
  writeFile,
} from "node:fs/promises";
import { homedir } from "node:os";
import { basename, join, relative, resolve, sep } from "node:path";
import { atomicReplace } from "../atomic-replace.js";
import {
  DirectoryListingCache,
  type JSONDocumentOptions,
  scanJSONDocumentSource,
  startedAfter,
} from "./json-document-source.js";
import { type CompletedHistory, SQLiteConnections } from "./sqlite-connections.js";

const maxSourceFiles = 256;
const historicalFilesPerScan = 16;
const historicalRecordsPerScan = 4;
const maxDirectoryDepth = 8;
const maxReadBytesPerFile = 8 << 20;
const defaultInitialReplayBytes = 256 << 10;
// Normal read window. A longer complete record widens the read up to the line
// limit; the line limit stays below the per-file read limit.
const readWindowBytes = 1 << 20;
const maxLineBytes = 6 << 20;
const maxCursorEntries = 16_384;
// A source or file that fails is skipped for a while, twice as long after
// each further failure, so one broken agent folder or database cannot stop
// the others or be retried on every scan.
const failureRetryBaseMs = 5_000;
const failureRetryMaxMs = 5 * 60_000;
const maxTrackedFailures = 256;

export type SourceReaderMode = "live" | "history";

export type ActivitySource = Readonly<{
  adapterId: string;
  roots: readonly string[];
  format?: "jsonl" | "opencode-sqlite" | "json-messages" | "goose-sqlite" | "zed-sqlite";
  sourceDisplayName?: string;
  /** For json-messages sources: the top-level messages array field. */
  messagesField?: string;
  /** For json-messages sources: how documents are read and delivered. */
  document?: JSONDocumentOptions;
  /**
   * Optional regular expression matched against each file path relative to
   * its root, with `/` separators. Only matching files belong to the source.
   */
  pathPattern?: string;
  /**
   * Capabilities the identity of each of this source's files carries, for a
   * file only the observer writes. Records cannot add any.
   */
  sourceCapabilities?: readonly string[];
}>;

export type SourceRecord = Readonly<{
  adapterId: string;
  sourceId: string;
  sourceRecordId: string;
  sourceDisplayName?: string;
  sourceCapabilities?: readonly string[];
  observedAt: Date;
  initialReplay?: boolean;
  value: unknown;
}>;

/** A source, or one of its files, that failed and is being skipped. */
export type SourceFailure = Readonly<{
  adapterId: string;
  /** Consecutive failed attempts. */
  failures: number;
  message: string;
  failedAt: Date;
  retryAt: Date;
}>;

export type SourceReaderMetrics = Readonly<{
  files: number;
  discoveredFiles: number;
  records: number;
  malformed: number;
  oversized: number;
}>;

type CursorState = Readonly<{
  version: 1;
  files: Readonly<Record<string, number>>;
  /** When the scan that produced these cursors started. */
  scanned_at?: string;
}>;

export type SavedCursors = Readonly<{
  cursors: Map<string, number>;
  /** When the scan that produced them started; absent before any save. */
  scannedAt?: number;
}>;

export type ActivitySourceCheckpoint = Readonly<{
  generation: number;
  cursors: ReadonlyMap<string, number>;
  /** When this scan started, in epoch milliseconds. */
  scannedAt: number;
}>;

/** Where a reader's next scan starts; see `JSONLSourceReader.position`. */
export type SourceReaderPosition = Readonly<{
  cursors: ReadonlyMap<string, number> | undefined;
  oversizedContinuations: ReadonlySet<string>;
  completedHistoryFiles: ReadonlyMap<string, number>;
  completedHistoryDatabases: ReadonlyMap<string, string>;
  initialScanComplete: boolean;
  unbaselinedSources: ReadonlySet<string>;
}>;

type FileIdentity = Readonly<{
  size: number;
  dev: number;
  ino: number;
  birthtimeMs: number;
}>;

type SourceFile = Readonly<{
  adapterId: string;
  sourceDisplayName?: string;
  sourceCapabilities?: readonly string[];
  root: string;
  path: string;
  modifiedMs: number;
  /** Listing-time metadata; lets an unchanged live file be skipped. */
  identity?: FileIdentity;
}>;

type CanonicalSourcePath = Readonly<{
  path: string;
  identity: string;
}>;

/**
 * Source cursors in least-recently-used order, so a full store evicts the
 * cursors of sessions nobody reads any more instead of live ones (an
 * evicted live cursor is re-baselined after a restart, which skips what
 * was written while the observer was stopped). Reads are only recorded and
 * applied by `settle`, so iterating the map never observes reordering.
 */
class RecentCursors extends Map<string, number> {
  readonly #used = new Set<string>();
  // Values from before `track`, for each cursor changed since.
  #journal: Map<string, number | undefined> | undefined;

  override get(key: string): number | undefined {
    const value = super.get(key);
    if (value !== undefined) this.#used.add(key);
    return value;
  }

  override set(key: string, value: number): this {
    this.#remember(key);
    super.delete(key);
    return super.set(key, value);
  }

  override delete(key: string): boolean {
    this.#remember(key);
    return super.delete(key);
  }

  /** Start remembering the cursors a source changes. */
  track(): void {
    this.#journal = new Map();
  }

  /** Stop remembering; with `rollback`, undo every change since `track`. */
  untrack(rollback: boolean): void {
    const journal = this.#journal;
    this.#journal = undefined;
    if (!rollback || journal === undefined) return;
    for (const [key, value] of journal) {
      if (value === undefined) super.delete(key);
      else super.set(key, value);
    }
  }

  #remember(key: string): void {
    if (this.#journal !== undefined && !this.#journal.has(key)) {
      this.#journal.set(key, super.get(key));
    }
  }

  /** Move cursors read since the last call to the recent end, then bound. */
  settle(limit: number): void {
    for (const key of this.#used) {
      const value = super.get(key);
      if (value === undefined) continue;
      super.delete(key);
      super.set(key, value);
    }
    this.#used.clear();
    for (const key of super.keys()) {
      if (this.size <= limit) break;
      super.delete(key);
    }
  }
}

export class ActivityCursorStore {
  readonly #dataDirectory: string;
  readonly #path: string;

  constructor(dataDirectory: string) {
    this.#dataDirectory = dataDirectory;
    this.#path = join(dataDirectory, "activity-cursors.json");
  }

  async load(): Promise<SavedCursors> {
    let raw: string;
    try {
      raw = await readFile(this.#path, "utf8");
    } catch (error) {
      if (isNodeError(error) && error.code === "ENOENT") return { cursors: new Map() };
      throw error;
    }
    let value: unknown;
    try {
      value = JSON.parse(raw);
    } catch {
      // Offsets are an optimization, not source history. Keep the damaged
      // checkpoint for inspection and rescan the original source records.
      // Their stable source IDs let the server deduplicate retained events.
      await writeFile(`${this.#path}.${randomUUID()}.corrupt`, raw, {
        encoding: "utf8", flag: "wx", mode: 0o600, flush: true,
      });
      const recovered = new Map<string, number>();
      await this.save(recovered);
      process.emitWarning("Saved activity checkpoints were unreadable. Available source history will be rescanned using stable record IDs.", { code: "PHIGON_CURSOR_RECOVERY" });
      return { cursors: recovered };
    }
    if (
      typeof value !== "object" ||
      value === null ||
      !("version" in value) ||
      value.version !== 1 ||
      !("files" in value) ||
      typeof value.files !== "object" ||
      value.files === null
    ) {
      throw new Error("Activity cursor state is invalid.");
    }
    // Saved oldest-first (see save); keep the most recently used cursors.
    const entries = Object.entries(value.files).slice(-maxCursorEntries);
    const result = new Map<string, number>();
    for (const [key, offset] of entries) {
      if (
        /^[a-f0-9]{64}$/u.test(key) &&
        typeof offset === "number" &&
        Number.isSafeInteger(offset) &&
        offset >= 0
      ) {
        result.set(key, offset);
      }
    }
    const scannedAt = "scanned_at" in value && typeof value.scanned_at === "string"
      ? Date.parse(value.scanned_at)
      : Number.NaN;
    return Number.isFinite(scannedAt)
      ? { cursors: result, scannedAt }
      : { cursors: result };
  }

  async save(
    cursors: ReadonlyMap<string, number>,
    scannedAt?: number,
  ): Promise<void> {
    await mkdir(this.#dataDirectory, { recursive: true, mode: 0o700 });
    await makeDirectoryPrivate(this.#dataDirectory);
    // Keep the map's order (least recently used first) so a restarted
    // reader still knows which cursors are stale.
    const files = Object.fromEntries(
      [...cursors.entries()].slice(-maxCursorEntries),
    );
    const state: CursorState = {
      version: 1,
      files,
      ...(scannedAt === undefined ? {} : { scanned_at: new Date(scannedAt).toISOString() }),
    };
    const temporary = `${this.#path}.${process.pid}.${randomUUID()}.tmp`;
    try {
      await writeFile(temporary, `${JSON.stringify(state)}\n`, {
        encoding: "utf8",
        flag: "wx",
        mode: 0o600,
        flush: true,
      });
      await atomicReplace(temporary, this.#path);
      await chmod(this.#path, 0o600);
    } catch (error) {
      try {
        await unlink(temporary);
      } catch {
        // The temporary file may not have been created.
      }
      throw error;
    }
  }
}

export class JSONLSourceReader {
  readonly #cursorStore: ActivityCursorStore;
  readonly #replayOnFirstStart: boolean;
  readonly #initialReplayBytes: number;
  readonly #initialReplaySessions: number;
  readonly #mode: SourceReaderMode;
  #cursors: RecentCursors | undefined;
  // The cursor state that is already durable. An idle scan produces an
  // identical checkpoint every tick; rewriting and flushing it would cost a
  // synchronous disk write per scan interval without changing anything.
  #savedCursors: ReadonlyMap<string, number> | undefined;
  #savedScannedAt: number | undefined;
  // When the scan behind the saved cursors started, as loaded at startup.
  // Undefined on the first start ever. A file without a cursor that began
  // after it was created while the observer was stopped.
  #lastRunAt: number | undefined;
  // The cursors as the previous scan left them, which is where the next
  // scan starts. Kept so a position costs no copy on every scan.
  #scanStart: ReadonlyMap<string, number> | undefined;
  #initialScanComplete = false;
  #generation = 0;
  #committedGeneration = 0;
  #sourceCache: { key: string; at: number; files: SourceFile[] } | undefined;
  // Canonical paths from the previous listing, keyed by resolved root and
  // listed path. Holds only files seen in the latest listing.
  #canonicalPaths = new Map<string, CanonicalSourcePath>();
  #completedHistoryFiles = new Map<string, number>();
  #completedHistoryDatabases: CompletedHistory = new Map();
  // Cursors that stopped inside a record above the line limit. The next read
  // skips to that record's end instead of parsing its tail as a new record.
  #oversizedContinuations = new Set<string>();
  // Live database connections kept between scans, so an unchanged database
  // is recognized without reopening it and rerunning every session query.
  readonly #openCodeConnections = new SQLiteConnections();
  // Folder listings for JSON-document agents, reused while folders are unchanged.
  readonly #documentListings = new DirectoryListingCache();
  readonly #gooseConnections = new SQLiteConnections();
  readonly #zedConnections = new SQLiteConnections();
  readonly #failures = new Map<string, SourceFailure>();
  // Live sources that were skipped or failed while their first scan would
  // have baselined them. Their first successful scan baselines instead, so
  // an old archive is not read as new work once the source recovers.
  #unbaselinedSources = new Set<string>();
  readonly #clock: () => number;

  constructor(
    dataDirectory: string,
    replayOnFirstStart = false,
    initialReplayBytes = defaultInitialReplayBytes,
    initialReplaySessions = 1,
    mode: SourceReaderMode = "live",
    clock: () => number = Date.now,
  ) {
    this.#cursorStore = new ActivityCursorStore(dataDirectory);
    this.#replayOnFirstStart = replayOnFirstStart;
    this.#initialReplayBytes = Math.min(
      maxReadBytesPerFile,
      Math.max(1, initialReplayBytes),
    );
    this.#initialReplaySessions = Math.min(
      maxSourceFiles,
      Math.max(1, initialReplaySessions),
    );
    this.#mode = mode;
    this.#clock = clock;
  }

  async scan(sources: readonly ActivitySource[], maxRecords?: number): Promise<
    Readonly<{
      records: readonly SourceRecord[];
      metrics: SourceReaderMetrics;
      checkpoint: ActivitySourceCheckpoint;
      complete: boolean;
    }>
  > {
    if (this.#cursors === undefined) {
      const loaded = await this.#cursorStore.load();
      this.#cursors = new RecentCursors();
      for (const [key, offset] of loaded.cursors) this.#cursors.set(key, offset);
      this.#savedCursors = loaded.cursors;
      this.#savedScannedAt = loaded.scannedAt;
      this.#lastRunAt = loaded.scannedAt;
      this.#scanStart = loaded.cursors;
    }
    const scannedAt = this.#clock();
    const records: SourceRecord[] = [];
    let fileCount = 0;
    let malformed = 0;
    let oversized = 0;
    let candidates: SourceFile[] = [];
    const initialScan = !this.#initialScanComplete;
    // Files of sources that missed their baseline, baselined on this scan.
    const baselinePaths = new Set<string>();
    const cacheKey = JSON.stringify(sources);
    if (this.#mode === "history" && this.#sourceCache?.key === cacheKey && Date.now() - this.#sourceCache.at < 5_000) {
      candidates = this.#sourceCache.files;
    } else {
    const canonicalPaths = new Map<string, CanonicalSourcePath>();
    for (const source of sources) {
      if (source.format !== undefined && source.format !== "jsonl") continue;
      const key = sourceKey(source);
      const sourceInitial = initialScan || this.#unbaselinedSources.has(key);
      const listed = await this.#isolated(key, source.adapterId, sourceInitial, () =>
        this.#listJSONLSource(source, canonicalPaths)
      );
      if (listed === undefined) continue;
      for (const file of listed) {
        candidates.push(file);
        if (sourceInitial && !initialScan) baselinePaths.add(file.path);
        if (candidates.length > maxCursorEntries * 2) {
          candidates = reconciledSourceFiles(candidates);
          candidates.sort(recentFileFirst);
          candidates.length = maxCursorEntries;
        }
      }
    }
    this.#sourceCache = { key: cacheKey, at: Date.now(), files: candidates };
    this.#canonicalPaths = canonicalPaths;
    }
    const recentCandidates = reconciledSourceFiles(candidates)
      .sort(recentFileFirst)
      .slice(0, maxCursorEntries);
    const selected = this.#mode === "history"
      ? await this.#pendingHistoryFiles(recentCandidates)
      : recentCandidates.slice(0, maxSourceFiles);
    const replayFiles = initialScan && this.#replayOnFirstStart
      ? newestFilesPerAdapter(selected, this.#initialReplaySessions)
      : new Set<string>();
    if (this.#mode === "live" && (initialScan || baselinePaths.size > 0)) {
      for (const file of [...recentCandidates].reverse()) {
        if (!initialScan && !baselinePaths.has(file.path)) continue;
        if (!replayFiles.has(file.path)) {
          try {
            await this.#baselineFile(file.root, file.path);
          } catch (error) {
            if (!isTransientSourceError(error)) {
              this.#recordFailure(fileKey(file.path), file.adapterId, error);
            }
          }
        }
      }
    }
    let remainingRecords = maxRecords ?? (this.#mode === "history"
      ? historicalRecordsPerScan
      : Number.MAX_SAFE_INTEGER);
    // A busy JSONL source must not starve OpenCode's independent database.
    const reservedDatabaseRecords = sources.some((source) => source.format === "opencode-sqlite")
      ? Math.floor(remainingRecords / 2)
      : 0;
    const rootRealPaths = new Map<string, string>();
    for (const file of selected) {
      if (remainingRecords <= reservedDatabaseRecords) break;
      if (this.#unchangedLiveFile(file)) {
        fileCount++;
        continue;
      }
      if (this.#skipping(fileKey(file.path))) continue;
      let result;
      try {
        const rootReal = rootRealPaths.get(file.root) ??
          await realpath(file.root);
        rootRealPaths.set(file.root, rootReal);
        result = await this.#readFile(
          file.adapterId,
          rootReal,
          file.path,
          replayFiles.has(file.path),
          file.sourceDisplayName,
          remainingRecords - reservedDatabaseRecords,
          file.sourceCapabilities,
        );
      } catch (error) {
        if (!isTransientSourceError(error)) {
          this.#recordFailure(fileKey(file.path), file.adapterId, error);
        }
        continue;
      }
      this.#failures.delete(fileKey(file.path));
      fileCount++;
      records.push(...result.records);
      malformed += result.malformed;
      oversized += result.oversized;
      remainingRecords -= result.processedRecords;
      if (this.#mode === "history" && result.processedRecords === 0) {
        // An unfinished final JSONL line is retried when its file changes.
        // Keep its cursor untouched without blocking every other archive.
        this.#completedHistoryFiles.set(file.path, file.modifiedMs);
      }
    }
    let documentsComplete = true;
    let documentFiles = 0;
    const cursors = this.#cursors;
    for (const source of sources) {
      if (source.format !== "json-messages") continue;
      const key = sourceKey(source);
      const sourceInitial = initialScan || this.#unbaselinedSources.has(key);
      const documents = await this.#isolated(key, source.adapterId, sourceInitial, () => scanJSONDocumentSource({
        adapterId: source.adapterId,
        roots: source.roots.map(expandedActivityRoot),
        pathPattern: source.pathPattern ?? "\\.json$",
        messagesField: source.messagesField ?? "messages",
        ...source.document,
      }, {
        cursors,
        listings: this.#documentListings,
        initialScan: sourceInitial,
        replayOnFirstStart: this.#replayOnFirstStart,
        replaySessions: this.#initialReplaySessions,
        maxReplayRecords: Math.max(
          32,
          Math.floor(this.#initialReplayBytes / 1_024),
        ),
        maxRecords: Math.max(0, remainingRecords - reservedDatabaseRecords),
        historical: this.#mode === "history",
        ...(this.#lastRunAt === undefined ? {} : { newSince: this.#lastRunAt }),
      }));
      if (documents === undefined) continue;
      records.push(...documents.records);
      fileCount += documents.files;
      malformed += documents.malformed;
      oversized += documents.oversized;
      documentFiles += documents.files;
      remainingRecords -= documents.records.length;
      documentsComplete = documentsComplete && documents.complete;
    }
    for (const source of sources) {
      if (source.format !== "goose-sqlite") continue;
      if (remainingRecords <= reservedDatabaseRecords) {
        documentsComplete = false;
        break;
      }
      // Loaded on demand for the same reason as the OpenCode source below.
      const { scanGooseSQLiteSources } = await import(
        "./goose-sqlite-source.js"
      );
      const key = sourceKey(source);
      const sourceInitial = initialScan || this.#unbaselinedSources.has(key);
      const goose = await this.#isolated(key, source.adapterId, sourceInitial, () => scanGooseSQLiteSources({
        adapterId: source.adapterId,
        roots: source.roots.map(expandedActivityRoot),
        cursors,
        initialScan: sourceInitial,
        replayOnFirstStart: this.#replayOnFirstStart,
        maxReplayRecords: Math.max(
          32,
          Math.floor(this.#initialReplayBytes / 1_024),
        ),
        maxRecords: remainingRecords - reservedDatabaseRecords,
        historical: this.#mode === "history",
        ...(this.#mode === "live" ? { connections: this.#gooseConnections } : { completedHistory: this.#completedHistoryDatabases }),
      }));
      if (goose === undefined) continue;
      records.push(...goose.records);
      fileCount += goose.files;
      malformed += goose.malformed;
      oversized += goose.oversized;
      documentFiles += goose.files;
      remainingRecords -= goose.records.length;
      documentsComplete = documentsComplete && goose.complete;
    }
    for (const source of sources) {
      if (source.format !== "zed-sqlite") continue;
      if (remainingRecords <= reservedDatabaseRecords) {
        documentsComplete = false;
        break;
      }
      const { scanZedSQLiteSources } = await import("./zed-sqlite-source.js");
      const key = sourceKey(source);
      const sourceInitial = initialScan || this.#unbaselinedSources.has(key);
      const zed = await this.#isolated(key, source.adapterId, sourceInitial, () => scanZedSQLiteSources({
        adapterId: source.adapterId,
        roots: source.roots.map(expandedActivityRoot),
        cursors,
        initialScan: sourceInitial,
        replayOnFirstStart: this.#replayOnFirstStart,
        replaySessions: this.#initialReplaySessions,
        maxReplayRecords: Math.max(
          32,
          Math.floor(this.#initialReplayBytes / 1_024),
        ),
        maxRecords: remainingRecords - reservedDatabaseRecords,
        historical: this.#mode === "history",
        ...(this.#mode === "live" ? { connections: this.#zedConnections } : { completedHistory: this.#completedHistoryDatabases }),
      }));
      if (zed === undefined) continue;
      records.push(...zed.records);
      fileCount += zed.files;
      malformed += zed.malformed;
      oversized += zed.oversized;
      documentFiles += zed.files;
      remainingRecords -= zed.records.length;
      documentsComplete = documentsComplete && zed.complete;
    }
    let sqliteComplete = true;
    let sqliteFiles = 0;
    for (const source of sources) {
      if (source.format !== "opencode-sqlite") continue;
      if (remainingRecords <= 0) {
        sqliteComplete = false;
        break;
      }
      // node:sqlite is experimental on supported Node releases. Load it only
      // when an OpenCode data source is actually scanned so commands such as
      // pair, doctor, and help stay warning-free.
      const { scanOpenCodeSQLiteSources } = await import(
        "./opencode-sqlite-source.js"
      );
      const key = sourceKey(source);
      const sourceInitial = initialScan || this.#unbaselinedSources.has(key);
      const sqlite = await this.#isolated(key, source.adapterId, sourceInitial, () => scanOpenCodeSQLiteSources({
        adapterId: source.adapterId,
        roots: source.roots.map(expandedActivityRoot),
        cursors,
        initialScan: sourceInitial,
        replayOnFirstStart: this.#replayOnFirstStart,
        maxReplayRecords: Math.min(
          remainingRecords,
          Math.max(
            this.#mode === "history" ? 1 : 32,
            Math.floor(this.#initialReplayBytes / 1_024),
          ),
        ),
        historical: this.#mode === "history",
        ...(this.#mode === "live" ? { connections: this.#openCodeConnections } : { completedHistory: this.#completedHistoryDatabases }),
      }));
      if (sqlite === undefined) continue;
      records.push(...sqlite.records);
      fileCount += sqlite.files;
      malformed += sqlite.malformed;
      oversized += sqlite.oversized;
      sqliteFiles += sqlite.files;
      remainingRecords -= sqlite.records.length;
      sqliteComplete = sqliteComplete && sqlite.complete;
    }
    this.#openCodeConnections.retain(configuredRoots(sources, "opencode-sqlite"));
    this.#gooseConnections.retain(configuredRoots(sources, "goose-sqlite"));
    this.#zedConnections.retain(configuredRoots(sources, "zed-sqlite"));
    this.#initialScanComplete = true;
    this.#cursors.settle(maxCursorEntries);
    const checkpoint = Object.freeze({
      generation: ++this.#generation,
      cursors: new Map(this.#cursors),
      scannedAt,
    });
    this.#scanStart = checkpoint.cursors;
    const jsonlComplete = this.#mode !== "history" || selected.length === 0;
    return {
      records,
      metrics: {
        files: fileCount,
        discoveredFiles: recentCandidates.length + sqliteFiles + documentFiles,
        records: records.length,
        malformed,
        oversized,
      },
      checkpoint,
      complete: jsonlComplete && sqliteComplete && documentsComplete,
    };
  }

  async commit(checkpoint: ActivitySourceCheckpoint): Promise<void> {
    if (checkpoint.generation <= this.#committedGeneration) return;
    if (checkpoint.generation > this.#generation) {
      throw new Error("Activity source checkpoint is invalid.");
    }
    // Saved once more when the time is missing, so the next start knows
    // when this one ran. Later idle scans keep the time of the last change:
    // a file read since then would have changed the cursors.
    if (
      this.#savedCursors === undefined ||
      this.#savedScannedAt === undefined ||
      !sameCursors(checkpoint.cursors, this.#savedCursors)
    ) {
      await this.#cursorStore.save(checkpoint.cursors, checkpoint.scannedAt);
      this.#savedCursors = checkpoint.cursors;
      this.#savedScannedAt = checkpoint.scannedAt;
    }
    this.#committedGeneration = checkpoint.generation;
  }

  /**
   * Where the next scan starts. A scan moves the cursors past every record
   * it returns, before the caller delivers them; `rewind` puts the reader
   * back here when they could not be delivered, so the next scan returns
   * the same records instead of skipping them.
   */
  position(): SourceReaderPosition {
    return {
      cursors: this.#scanStart,
      oversizedContinuations: new Set(this.#oversizedContinuations),
      completedHistoryFiles: new Map(this.#completedHistoryFiles),
      completedHistoryDatabases: new Map(this.#completedHistoryDatabases),
      initialScanComplete: this.#initialScanComplete,
      unbaselinedSources: new Set(this.#unbaselinedSources),
    };
  }

  rewind(position: SourceReaderPosition): void {
    if (position.cursors === undefined) {
      // Taken before the first scan: reload what is durable.
      this.#cursors = undefined;
    } else {
      this.#cursors = new RecentCursors();
      for (const [key, offset] of position.cursors) {
        this.#cursors.set(key, offset);
      }
    }
    this.#scanStart = position.cursors;
    this.#oversizedContinuations = new Set(position.oversizedContinuations);
    this.#completedHistoryFiles = new Map(position.completedHistoryFiles);
    this.#completedHistoryDatabases = new Map(position.completedHistoryDatabases);
    this.#initialScanComplete = position.initialScanComplete;
    this.#unbaselinedSources = new Set(position.unbaselinedSources);
  }

  /** Sources and files that failed and are skipped until `retryAt`. */
  sourceFailures(): readonly SourceFailure[] {
    return [...this.#failures.values()];
  }

  /**
   * Run one source's scan so that its failure cannot fail the others. A
   * failed source is recorded, skipped until its retry time, and its cursor
   * changes are undone so none of its records is skipped. Returns undefined
   * when the source was skipped or failed.
   */
  async #isolated<T>(
    key: string,
    adapterId: string,
    baselines: boolean,
    scan: () => Promise<T>,
  ): Promise<T | undefined> {
    const remember = (missed: boolean) => {
      if (this.#mode !== "live") return;
      if (missed && baselines) this.#unbaselinedSources.add(key);
      else if (!missed) this.#unbaselinedSources.delete(key);
    };
    if (this.#skipping(key)) {
      remember(true);
      return undefined;
    }
    this.#cursors?.track();
    try {
      const result = await scan();
      this.#cursors?.untrack(false);
      this.#failures.delete(key);
      remember(false);
      return result;
    } catch (error) {
      this.#cursors?.untrack(true);
      this.#recordFailure(key, adapterId, error);
      remember(true);
      return undefined;
    }
  }

  #skipping(key: string): boolean {
    const failure = this.#failures.get(key);
    return failure !== undefined && this.#clock() < failure.retryAt.getTime();
  }

  #recordFailure(key: string, adapterId: string, error: unknown): void {
    const failures = (this.#failures.get(key)?.failures ?? 0) + 1;
    const now = this.#clock();
    this.#failures.delete(key);
    this.#failures.set(key, Object.freeze({
      adapterId,
      failures,
      message: (error instanceof Error ? error.message : String(error))
        .replace(/\s+/gu, " ")
        .slice(0, 200),
      failedAt: new Date(now),
      retryAt: new Date(now + Math.min(
        failureRetryMaxMs,
        failureRetryBaseMs * 2 ** Math.min(failures - 1, 16),
      )),
    }));
    for (const oldest of this.#failures.keys()) {
      if (this.#failures.size <= maxTrackedFailures) break;
      this.#failures.delete(oldest);
    }
  }

  /**
   * Close the database connections kept between scans. A later scan opens
   * them again, so this only releases files, for example before shutdown.
   */
  close(): void {
    this.#openCodeConnections.closeAll();
    this.#gooseConnections.closeAll();
    this.#zedConnections.closeAll();
  }

  /**
   * A live file whose listed size equals its cursor has nothing to read:
   * reading it would resolve, stat and find zero bytes. Its identity comes
   * from the listing done in the same scan, so growth is never missed.
   */
  #unchangedLiveFile(file: SourceFile): boolean {
    if (this.#mode !== "live" || file.identity === undefined) return false;
    const cursorId = fileCursorId(file.path, file.identity);
    return (
      this.#cursors?.get(cursorId) === file.identity.size &&
      !this.#oversizedContinuations.has(cursorId)
    );
  }

  async #readFile(
    adapterId: string,
    rootReal: string,
    file: string,
    initialReplay: boolean,
    sourceDisplayName?: string,
    maxRecords = Number.MAX_SAFE_INTEGER,
    sourceCapabilities?: readonly string[],
  ): Promise<
    Readonly<{
      records: readonly SourceRecord[];
      malformed: number;
      oversized: number;
      processedRecords: number;
    }>
  > {
    const fileReal = await realpath(file);
    if (!isWithin(rootReal, fileReal)) {
      return { records: [], malformed: 0, oversized: 0, processedRecords: 0 };
    }
    const metadata = await stat(fileReal);
    if (!metadata.isFile()) {
      return { records: [], malformed: 0, oversized: 0, processedRecords: 0 };
    }
    const sourceId = digest(fileReal);
    const cursorId = fileCursorId(fileReal, metadata);
    const legacyCursorId = sourceId;
    const knownOffset =
      this.#cursors?.get(cursorId) ??
      this.#cursors?.get(legacyCursorId);
    let offset =
      knownOffset ??
      (this.#mode === "history"
        ? 0
        : Math.max(
          0,
          metadata.size -
            (initialReplay ? this.#initialReplayBytes : maxReadBytesPerFile),
        ));
    if (metadata.size < offset) offset = 0;
    let length = Math.min(
      metadata.size - offset,
      maxReadBytesPerFile,
      Math.max(readWindowBytes + 1, Math.min(1_024, maxRecords) * 16_384),
    );
    if (length <= 0) {
      this.#setCursor(cursorId, legacyCursorId, metadata.size);
      this.#oversizedContinuations.delete(cursorId);
      return { records: [], malformed: 0, oversized: 0, processedRecords: 0 };
    }
    // Starting mid-file, read one byte early: if it is a newline the first
    // record starts exactly at the offset and must not be skipped as partial.
    // A cursor left inside an oversized record also resumes after its end.
    const continuingOversized = this.#oversizedContinuations.has(cursorId);
    const resync =
      (knownOffset === undefined && offset > 0) || continuingOversized;
    if (resync) {
      offset -= 1;
      length += 1;
    }
    let content = await readRange(fileReal, offset, length);
    if (resync) {
      const firstNewline = content.indexOf(0x0a);
      if (firstNewline < 0) {
        this.#setCursor(
          cursorId,
          legacyCursorId,
          offset + content.length,
        );
        this.#rememberOversizedContinuation(cursorId);
        return continuingOversized
          ? { records: [], malformed: 0, oversized: 0, processedRecords: 1 }
          : { records: [], malformed: 0, oversized: 1, processedRecords: 1 };
      }
      this.#oversizedContinuations.delete(cursorId);
      offset += firstNewline + 1;
      content = content.subarray(firstNewline + 1);
    }
    let lastNewline = content.lastIndexOf(0x0a);
    if (lastNewline < 0) {
      // One complete record can be larger than the normal read window, for
      // example a tool result or a pasted screenshot. Widen once, bounded by
      // the record limit, instead of discarding it as oversized.
      const widened = Math.min(metadata.size - offset, maxLineBytes + 1);
      if (widened > content.length) {
        content = await readRange(fileReal, offset, widened);
        lastNewline = content.lastIndexOf(0x0a);
      }
    }
    if (lastNewline < 0) {
      if (content.length > maxLineBytes) {
        this.#setCursor(
          cursorId,
          legacyCursorId,
          offset + content.length,
        );
        this.#rememberOversizedContinuation(cursorId);
        return { records: [], malformed: 0, oversized: 1, processedRecords: 1 };
      }
      return { records: [], malformed: 0, oversized: 0, processedRecords: 0 };
    }
    const complete = content.subarray(0, lastNewline + 1);
    const records: SourceRecord[] = [];
    let malformed = 0;
    let oversized = 0;
    let processedRecords = 0;
    let processedThrough = 0;
    let lineStart = 0;
    while (lineStart < complete.length) {
      const newline = complete.indexOf(0x0a, lineStart);
      if (newline < 0) break;
      let lineEnd = newline;
      if (lineEnd > lineStart && complete[lineEnd - 1] === 0x0d) {
        lineEnd--;
      }
      const lineBuffer = complete.subarray(lineStart, lineEnd);
      const recordOffset = offset + lineStart;
      lineStart = newline + 1;
      processedThrough = lineStart;
      const line = lineBuffer.toString("utf8");
      if (line.trim() === "") continue;
      if (processedRecords >= maxRecords) {
        processedThrough = recordOffset - offset;
        break;
      }
      processedRecords++;
      if (lineBuffer.byteLength > maxLineBytes) {
        oversized++;
        continue;
      }
      try {
        records.push({
          adapterId,
          sourceId: `ses_${sourceId.slice(0, 32)}`,
          sourceRecordId: digest(`${cursorId}:${recordOffset}`),
          ...(sourceDisplayName === undefined
            ? {}
            : { sourceDisplayName }),
          ...(sourceCapabilities === undefined ? {} : { sourceCapabilities }),
          observedAt: metadata.mtime,
          initialReplay: initialReplay || this.#mode === "history",
          value: JSON.parse(line),
        });
      } catch {
        malformed++;
      }
    }
    this.#setCursor(cursorId, legacyCursorId, offset + processedThrough);
    return { records, malformed, oversized, processedRecords };
  }

  /** The files of one JSONL source, with their canonical paths. */
  async #listJSONLSource(
    source: ActivitySource,
    canonicalPaths: Map<string, CanonicalSourcePath>,
  ): Promise<SourceFile[]> {
    let files: SourceFile[] = [];
    const pathPattern = source.pathPattern === undefined
      ? undefined
      : new RegExp(source.pathPattern, "u");
    for (const configuredRoot of source.roots) {
      const root = expandedActivityRoot(configuredRoot);
      const rootFiles = await listJSONLFiles(root);
      let rootReal: string | undefined;
      for (const file of rootFiles) {
        if (
          pathPattern !== undefined &&
          !pathPattern.test(relative(root, file.path).split(sep).join("/"))
        ) {
          continue;
        }
        let canonicalPath: string;
        try {
          // The listing never follows links, so a listed file keeps its
          // canonical path while its root resolves to the same place and
          // the file keeps its identity. Resolve each file only once.
          rootReal ??= await realpath(root);
          const key = `${rootReal}\u0000${file.path}`;
          const identity = fileIdentityKey(file.identity);
          const known = this.#canonicalPaths.get(key);
          canonicalPath =
            known !== undefined && identity !== undefined &&
              known.identity === identity
              ? known.path
              : await realpath(file.path);
          if (identity !== undefined) {
            canonicalPaths.set(key, { path: canonicalPath, identity });
          }
        } catch (error) {
          if (isTransientSourceError(error)) continue;
          throw error;
        }
        files.push({
          adapterId: source.adapterId,
          ...(source.sourceDisplayName === undefined
            ? {}
            : { sourceDisplayName: source.sourceDisplayName }),
          ...(source.sourceCapabilities === undefined
            ? {}
            : { sourceCapabilities: source.sourceCapabilities }),
          root,
          path: canonicalPath,
          modifiedMs: file.modifiedMs,
          identity: file.identity,
        });
        if (files.length > maxCursorEntries * 2) {
          files = reconciledSourceFiles(files);
          files.sort(recentFileFirst);
          files.length = maxCursorEntries;
        }
      }
    }
    return files;
  }

  async #pendingHistoryFiles(
    files: readonly SourceFile[],
  ): Promise<SourceFile[]> {
    const pending: SourceFile[] = [];
    for (const file of files) {
      if (this.#completedHistoryFiles.get(file.path) === file.modifiedMs) continue;
      // A failing file is retried later without holding the import open.
      if (this.#skipping(fileKey(file.path))) continue;
      try {
        const metadata = await stat(file.path);
        const offset = this.#cursors?.get(fileCursorId(file.path, metadata)) ??
          this.#cursors?.get(digest(file.path));
        if (offset === undefined || offset !== metadata.size) {
          pending.push(file);
          if (pending.length >= historicalFilesPerScan) break;
        } else {
          this.#completedHistoryFiles.set(file.path, file.modifiedMs);
        }
      } catch (error) {
        if (!isTransientSourceError(error)) {
          this.#recordFailure(fileKey(file.path), file.adapterId, error);
        }
      }
    }
    return pending;
  }

  #rememberOversizedContinuation(cursorId: string): void {
    this.#oversizedContinuations.add(cursorId);
    if (this.#oversizedContinuations.size <= maxSourceFiles) return;
    const oldest = this.#oversizedContinuations.values().next().value;
    if (oldest !== undefined) this.#oversizedContinuations.delete(oldest);
  }

  #setCursor(
    cursorId: string,
    legacyCursorId: string,
    offset: number,
  ): void {
    this.#cursors?.set(cursorId, offset);
    if (cursorId !== legacyCursorId) {
      this.#cursors?.delete(legacyCursorId);
    }
  }

  async #baselineFile(root: string, file: string): Promise<void> {
    const rootReal = await realpath(root);
    const fileReal = await realpath(file);
    if (!isWithin(rootReal, fileReal)) return;
    const metadata = await stat(fileReal);
    if (!metadata.isFile()) return;
    if (this.#cursors?.has(fileCursorId(fileReal, metadata)) || this.#cursors?.has(digest(fileReal))) return;
    // A session that began while the observer was stopped is read from its
    // start; any other file without a cursor starts at its end, as before.
    this.#setCursor(
      fileCursorId(fileReal, metadata),
      digest(fileReal),
      this.#lastRunAt !== undefined && startedAfter(metadata, this.#lastRunAt)
        ? 0
        : metadata.size,
    );
  }
}

export function expandedActivityRoot(root: string): string {
  if (root === "~") return homedir();
  if (root.startsWith("~/") || root.startsWith("~\\")) {
    return join(homedir(), root.slice(2));
  }
  return root;
}

type ListedFile = Readonly<{
  path: string;
  modifiedMs: number;
  identity: FileIdentity;
}>;

async function listJSONLFiles(
  root: string,
): Promise<ListedFile[]> {
  let metadata;
  try {
    metadata = await stat(root);
  } catch (error) {
    if (
      isNodeError(error) &&
      (error.code === "ENOENT" ||
        error.code === "EACCES" ||
        error.code === "EPERM")
    ) {
      return [];
    }
    throw error;
  }
  if (!metadata.isDirectory()) return [];
  const result: ListedFile[] = [];
  const walk = async (directory: string, depth: number): Promise<void> => {
    if (depth > maxDirectoryDepth) return;
    let entries;
    try {
      entries = await readdir(directory, { withFileTypes: true });
    } catch (error) {
      if (
        isNodeError(error) &&
        (error.code === "ENOENT" ||
          error.code === "EACCES" ||
          error.code === "EPERM" ||
          error.code === "ENOTDIR")
      ) {
        return;
      }
      throw error;
    }
    for (const entry of entries) {
      const path = join(directory, entry.name);
      if (entry.isDirectory()) await walk(path, depth + 1);
      else if (
        entry.isFile() &&
        basename(entry.name).toLowerCase().endsWith(".jsonl")
      ) {
        try {
          const metadata = await stat(path);
          result.push({
            path,
            modifiedMs: metadata.mtimeMs,
            identity: {
              size: metadata.size,
              dev: metadata.dev,
              ino: metadata.ino,
              birthtimeMs: metadata.birthtimeMs,
            },
          });
          if (result.length > maxCursorEntries * 2) {
            result.sort(recentFileFirst);
            result.length = maxCursorEntries;
          }
        } catch (error) {
          if (
            isNodeError(error) &&
            (error.code === "ENOENT" ||
              error.code === "EACCES" ||
              error.code === "EPERM")
          ) {
            continue;
          }
          throw error;
        }
      }
    }
  };
  await walk(root, 0);
  return result.sort(recentFileFirst).slice(0, maxCursorEntries);
}

async function readRange(
  path: string,
  position: number,
  length: number,
): Promise<Buffer> {
  const handle = await open(path, "r");
  try {
    const content = Buffer.alloc(length);
    const read = await handle.read(content, 0, length, position);
    return content.subarray(0, read.bytesRead);
  } finally {
    await handle.close();
  }
}

function recentFileFirst(
  left: Readonly<{ path: string; modifiedMs: number }>,
  right: Readonly<{ path: string; modifiedMs: number }>,
): number {
  return (
    right.modifiedMs - left.modifiedMs || left.path.localeCompare(right.path)
  );
}

/**
 * A file can be reached through overlapping configured roots. Resolve that
 * once, independently of scan order: one native adapter outranks generic
 * labeling, conflicting generic labels lose their label, and conflicting
 * native adapters fall back to an unattributed generic source.
 */
function reconciledSourceFiles(files: readonly SourceFile[]): SourceFile[] {
  const claimsByPath = new Map<string, SourceFile[]>();
  for (const file of files) {
    const claims = claimsByPath.get(file.path) ?? [];
    claims.push(file);
    claimsByPath.set(file.path, claims);
  }
  return [...claimsByPath.values()].map(reconciledSourceFile);
}

function reconciledSourceFile(claims: readonly SourceFile[]): SourceFile {
  const ordered = [...claims].sort(compareSourceClaim);
  const adapterIDs = new Set(ordered.map((claim) => claim.adapterId));
  const nativeAdapterIDs = new Set(
    ordered
      .map((claim) => claim.adapterId)
      .filter((adapterID) => adapterID !== "generic"),
  );
  let adapterId: string;
  let sourceDisplayName: string | undefined;
  if (adapterIDs.size === 1) {
    adapterId = ordered[0]?.adapterId ?? "generic";
    if (adapterId === "generic") {
      const labels = new Set(
        ordered.flatMap((claim) =>
          claim.sourceDisplayName === undefined
            ? []
            : [claim.sourceDisplayName]
        ),
      );
      if (
        labels.size === 1 &&
        ordered.every((claim) => claim.sourceDisplayName !== undefined)
      ) {
        sourceDisplayName = [...labels][0];
      }
    }
  } else if (nativeAdapterIDs.size === 1) {
    adapterId = [...nativeAdapterIDs][0] ?? "generic";
  } else {
    adapterId = "generic";
  }
  const representative =
    ordered.find((claim) => claim.adapterId === adapterId) ??
    ordered[0];
  if (representative === undefined) {
    throw new Error("Activity source reconciliation requires one file claim.");
  }
  // A file another source also claims keeps capabilities only when every
  // claim gives the same ones.
  const capabilityClaims = new Set(ordered.map((claim) => JSON.stringify(claim.sourceCapabilities ?? [])));
  const sourceCapabilities = capabilityClaims.size === 1 ? representative.sourceCapabilities : undefined;
  return {
    adapterId,
    ...(sourceDisplayName === undefined ? {} : { sourceDisplayName }),
    ...(sourceCapabilities === undefined ? {} : { sourceCapabilities }),
    root: representative.root,
    path: representative.path,
    modifiedMs: Math.max(...ordered.map((claim) => claim.modifiedMs)),
    ...(representative.identity === undefined
      ? {}
      : { identity: representative.identity }),
  };
}

function compareSourceClaim(left: SourceFile, right: SourceFile): number {
  return left.adapterId.localeCompare(right.adapterId) ||
    (left.sourceDisplayName ?? "").localeCompare(
      right.sourceDisplayName ?? "",
    ) ||
    left.root.localeCompare(right.root);
}

function fileIdentityKey(
  identity: FileIdentity | undefined,
): string | undefined {
  if (identity === undefined || (identity.ino <= 0 && identity.dev <= 0)) {
    return undefined;
  }
  return `${identity.dev}:${identity.ino}:${identity.birthtimeMs}`;
}

/**
 * Whether saved `cursors` are at the end of the file at `path`, so every
 * record in it was read. A file that grew or was replaced since does not
 * count.
 */
export async function fileReadThrough(
  path: string,
  cursors: ReadonlyMap<string, number>,
): Promise<boolean> {
  const fileReal = await realpath(path);
  const metadata = await stat(fileReal);
  const offset = cursors.get(fileCursorId(fileReal, metadata)) ??
    cursors.get(digest(fileReal));
  return offset === metadata.size;
}

function fileCursorId(
  path: string,
  metadata: Readonly<{ dev: number; ino: number; birthtimeMs: number }>,
): string {
  const identity =
    metadata.ino > 0 || metadata.dev > 0
      ? `inode:${metadata.dev}:${metadata.ino}:${metadata.birthtimeMs}`
      : metadata.birthtimeMs > 0
        ? `birth:${metadata.birthtimeMs}`
        : "path";
  return digest(`${path}\u0000${identity}`);
}

function newestFilesPerAdapter(
  files: readonly SourceFile[],
  limit: number,
): Set<string> {
  const adapterCounts = new Map<string, number>();
  const selected = new Set<string>();
  for (const file of files) {
    const count = adapterCounts.get(file.adapterId) ?? 0;
    if (count >= limit) continue;
    adapterCounts.set(file.adapterId, count + 1);
    selected.add(file.path);
  }
  return selected;
}

function configuredRoots(
  sources: readonly ActivitySource[],
  format: NonNullable<ActivitySource["format"]>,
): Set<string> {
  return new Set(sources.flatMap((source) =>
    source.format === format ? source.roots.map(expandedActivityRoot) : []
  ));
}

function sourceKey(source: ActivitySource): string {
  return JSON.stringify([source.format ?? "jsonl", source.adapterId, source.roots, source.pathPattern ?? ""]);
}

function fileKey(path: string): string {
  return `file\u0000${path}`;
}

function sameCursors(
  left: ReadonlyMap<string, number>,
  right: ReadonlyMap<string, number>,
): boolean {
  if (left.size !== right.size) return false;
  for (const [key, offset] of left) {
    if (right.get(key) !== offset) return false;
  }
  return true;
}

function isWithin(root: string, candidate: string): boolean {
  const path = relative(resolve(root), resolve(candidate));
  return path === "" || (!path.startsWith(`..${sep}`) && path !== "..");
}

function digest(value: string): string {
  return createHash("sha256").update(value).digest("hex");
}

function isNodeError(error: unknown): error is NodeJS.ErrnoException {
  return error instanceof Error && "code" in error;
}

function isTransientSourceError(error: unknown): boolean {
  return (
    isNodeError(error) &&
    (error.code === "ENOENT" ||
      error.code === "EACCES" ||
      error.code === "EPERM" ||
      error.code === "ENOTDIR" ||
      error.code === "EBUSY" ||
      error.code === "ESTALE")
  );
}
