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

const maxSourceFiles = 256;
const historicalFilesPerScan = 16;
const historicalRecordsPerScan = 4;
const maxDirectoryDepth = 8;
const maxReadBytesPerFile = 8 << 20;
const defaultInitialReplayBytes = 256 << 10;
const maxLineBytes = 1 << 20;
const maxCursorEntries = 16_384;

export type SourceReaderMode = "live" | "history";

export type ActivitySource = Readonly<{
  adapterId: string;
  roots: readonly string[];
  format?: "jsonl" | "opencode-sqlite";
  sourceDisplayName?: string;
}>;

export type SourceRecord = Readonly<{
  adapterId: string;
  sourceId: string;
  sourceRecordId: string;
  sourceDisplayName?: string;
  observedAt: Date;
  initialReplay?: boolean;
  value: unknown;
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
}>;

export type ActivitySourceCheckpoint = Readonly<{
  generation: number;
  cursors: ReadonlyMap<string, number>;
}>;

type SourceFile = Readonly<{
  adapterId: string;
  sourceDisplayName?: string;
  root: string;
  path: string;
  modifiedMs: number;
}>;

export class ActivityCursorStore {
  readonly #dataDirectory: string;
  readonly #path: string;

  constructor(dataDirectory: string) {
    this.#dataDirectory = dataDirectory;
    this.#path = join(dataDirectory, "activity-cursors.json");
  }

  async load(): Promise<Map<string, number>> {
    let raw: string;
    try {
      raw = await readFile(this.#path, "utf8");
    } catch (error) {
      if (isNodeError(error) && error.code === "ENOENT") return new Map();
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
      return recovered;
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
    const entries = Object.entries(value.files).slice(0, maxCursorEntries);
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
    return result;
  }

  async save(cursors: ReadonlyMap<string, number>): Promise<void> {
    await mkdir(this.#dataDirectory, { recursive: true, mode: 0o700 });
    await makeDirectoryPrivate(this.#dataDirectory);
    const files = Object.fromEntries(
      [...cursors.entries()]
        .slice(-maxCursorEntries)
        .sort(([left], [right]) => left.localeCompare(right)),
    );
    const state: CursorState = { version: 1, files };
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
  #cursors: Map<string, number> | undefined;
  #initialScanComplete = false;
  #generation = 0;
  #committedGeneration = 0;
  #sourceCache: { key: string; at: number; files: SourceFile[] } | undefined;
  readonly #completedHistoryFiles = new Map<string, number>();

  constructor(
    dataDirectory: string,
    replayOnFirstStart = false,
    initialReplayBytes = defaultInitialReplayBytes,
    initialReplaySessions = 1,
    mode: SourceReaderMode = "live",
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
  }

  async scan(sources: readonly ActivitySource[], maxRecords?: number): Promise<
    Readonly<{
      records: readonly SourceRecord[];
      metrics: SourceReaderMetrics;
      checkpoint: ActivitySourceCheckpoint;
      complete: boolean;
    }>
  > {
    this.#cursors ??= await this.#cursorStore.load();
    const records: SourceRecord[] = [];
    let fileCount = 0;
    let malformed = 0;
    let oversized = 0;
    let candidates: SourceFile[] = [];
    const cacheKey = JSON.stringify(sources);
    if (this.#mode === "history" && this.#sourceCache?.key === cacheKey && Date.now() - this.#sourceCache.at < 5_000) {
      candidates = this.#sourceCache.files;
    } else {
    for (const source of sources) {
      if (source.format === "opencode-sqlite") continue;
      for (const configuredRoot of source.roots) {
        const root = expandedActivityRoot(configuredRoot);
        const rootFiles = await listJSONLFiles(root);
        for (const file of rootFiles) {
          let canonicalPath: string;
          try {
            canonicalPath = await realpath(file.path);
          } catch (error) {
            if (isTransientSourceError(error)) continue;
            throw error;
          }
          candidates.push({
            adapterId: source.adapterId,
            ...(source.sourceDisplayName === undefined
              ? {}
              : { sourceDisplayName: source.sourceDisplayName }),
            root,
            path: canonicalPath,
            modifiedMs: file.modifiedMs,
          });
          if (candidates.length > maxCursorEntries * 2) {
            candidates = reconciledSourceFiles(candidates);
            candidates.sort(recentFileFirst);
            candidates.length = maxCursorEntries;
          }
        }
      }
    }
    this.#sourceCache = { key: cacheKey, at: Date.now(), files: candidates };
    }
    const recentCandidates = reconciledSourceFiles(candidates)
      .sort(recentFileFirst)
      .slice(0, maxCursorEntries);
    const initialScan = !this.#initialScanComplete;
    const selected = this.#mode === "history"
      ? await this.#pendingHistoryFiles(recentCandidates)
      : recentCandidates.slice(0, maxSourceFiles);
    const replayFiles = initialScan && this.#replayOnFirstStart
      ? newestFilesPerAdapter(selected, this.#initialReplaySessions)
      : new Set<string>();
    if (initialScan && this.#mode === "live") {
      for (const file of [...recentCandidates].reverse()) {
        if (!replayFiles.has(file.path)) {
          try {
            await this.#baselineFile(file.root, file.path);
          } catch (error) {
            if (!isTransientSourceError(error)) throw error;
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
    for (const file of selected) {
      if (remainingRecords <= reservedDatabaseRecords) break;
      let result;
      try {
        result = await this.#readFile(
          file.adapterId,
          file.root,
          file.path,
          replayFiles.has(file.path),
          file.sourceDisplayName,
          remainingRecords - reservedDatabaseRecords,
        );
      } catch (error) {
        if (isTransientSourceError(error)) continue;
        throw error;
      }
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
      const sqlite = await scanOpenCodeSQLiteSources({
        adapterId: source.adapterId,
        roots: source.roots.map(expandedActivityRoot),
        cursors: this.#cursors,
        initialScan,
        replayOnFirstStart: this.#replayOnFirstStart,
        maxReplayRecords: Math.min(
          remainingRecords,
          Math.max(
            this.#mode === "history" ? 1 : 32,
            Math.floor(this.#initialReplayBytes / 1_024),
          ),
        ),
        historical: this.#mode === "history",
      });
      records.push(...sqlite.records);
      fileCount += sqlite.files;
      malformed += sqlite.malformed;
      oversized += sqlite.oversized;
      sqliteFiles += sqlite.files;
      remainingRecords -= sqlite.records.length;
      sqliteComplete = sqliteComplete && sqlite.complete;
    }
    this.#initialScanComplete = true;
    const checkpoint = Object.freeze({
      generation: ++this.#generation,
      cursors: new Map(this.#cursors),
    });
    const jsonlComplete = this.#mode !== "history" || selected.length === 0;
    return {
      records,
      metrics: {
        files: fileCount,
        discoveredFiles: recentCandidates.length + sqliteFiles,
        records: records.length,
        malformed,
        oversized,
      },
      checkpoint,
      complete: jsonlComplete && sqliteComplete,
    };
  }

  async commit(checkpoint: ActivitySourceCheckpoint): Promise<void> {
    if (checkpoint.generation <= this.#committedGeneration) return;
    if (checkpoint.generation > this.#generation) {
      throw new Error("Activity source checkpoint is invalid.");
    }
    await this.#cursorStore.save(checkpoint.cursors);
    this.#committedGeneration = checkpoint.generation;
  }

  async #readFile(
    adapterId: string,
    root: string,
    file: string,
    initialReplay: boolean,
    sourceDisplayName?: string,
    maxRecords = Number.MAX_SAFE_INTEGER,
  ): Promise<
    Readonly<{
      records: readonly SourceRecord[];
      malformed: number;
      oversized: number;
      processedRecords: number;
    }>
  > {
    const rootReal = await realpath(root);
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
    const length = Math.min(
      metadata.size - offset,
      maxReadBytesPerFile,
      Math.max(maxLineBytes + 1, Math.min(1_024, maxRecords) * 16_384),
    );
    if (length <= 0) {
      this.#setCursor(cursorId, legacyCursorId, metadata.size);
      return { records: [], malformed: 0, oversized: 0, processedRecords: 0 };
    }
    const handle = await open(fileReal, "r");
    let content: Buffer;
    try {
      content = Buffer.alloc(length);
      const read = await handle.read(content, 0, length, offset);
      content = content.subarray(0, read.bytesRead);
    } finally {
      await handle.close();
    }
    if (knownOffset === undefined && offset > 0) {
      const firstNewline = content.indexOf(0x0a);
      if (firstNewline < 0) {
        this.#setCursor(
          cursorId,
          legacyCursorId,
          offset + content.length,
        );
        return { records: [], malformed: 0, oversized: 1, processedRecords: 1 };
      }
      offset += firstNewline + 1;
      content = content.subarray(firstNewline + 1);
    }
    const lastNewline = content.lastIndexOf(0x0a);
    if (lastNewline < 0) {
      if (content.length > maxLineBytes) {
        this.#setCursor(
          cursorId,
          legacyCursorId,
          offset + content.length,
        );
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

  async #pendingHistoryFiles(
    files: readonly SourceFile[],
  ): Promise<SourceFile[]> {
    const pending: SourceFile[] = [];
    for (const file of files) {
      if (this.#completedHistoryFiles.get(file.path) === file.modifiedMs) continue;
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
        if (!isTransientSourceError(error)) throw error;
      }
    }
    return pending;
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
    this.#setCursor(
      fileCursorId(fileReal, metadata),
      digest(fileReal),
      metadata.size,
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

async function listJSONLFiles(
  root: string,
): Promise<Array<Readonly<{ path: string; modifiedMs: number }>>> {
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
  const result: Array<Readonly<{ path: string; modifiedMs: number }>> = [];
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
          result.push({ path, modifiedMs: metadata.mtimeMs });
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
  return {
    adapterId,
    ...(sourceDisplayName === undefined ? {} : { sourceDisplayName }),
    root: representative.root,
    path: representative.path,
    modifiedMs: Math.max(...ordered.map((claim) => claim.modifiedMs)),
  };
}

function compareSourceClaim(left: SourceFile, right: SourceFile): number {
  return left.adapterId.localeCompare(right.adapterId) ||
    (left.sourceDisplayName ?? "").localeCompare(
      right.sourceDisplayName ?? "",
    ) ||
    left.root.localeCompare(right.root);
}

function fileCursorId(
  path: string,
  metadata: Awaited<ReturnType<typeof stat>>,
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
      error.code === "ESTALE")
  );
}
