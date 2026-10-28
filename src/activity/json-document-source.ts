import { createHash } from "node:crypto";
import { readFile, readdir, realpath, stat } from "node:fs/promises";
import { join, relative, resolve, sep } from "node:path";
import type { SourceRecord } from "./source-reader.js";

const maxDocumentBytes = 32 << 20;
const maxLiveDocuments = 256;
const maxTrackedDocuments = 1_024;
const maxDirectoryDepth = 6;
// A cursor packs the delivered message count (17 bits) and a 36-bit
// fingerprint of the last delivered message into one safe integer.
const maxMessagesPerDocument = (1 << 17) - 1;
const fingerprintSpace = 2 ** 36;
// A document unchanged for this long is settled: its final message is
// complete even without a completion marker (the agent stopped or crashed).
const settleMilliseconds = 10 * 60_000;

export type JSONDocumentOptions = Readonly<{
  /**
   * `json` (default): one JSON document. `jsonl`: one message per line; a
   * final line that is still being written is read once it is complete.
   * `mutation-log`: a VS Code chat session log (an initial state followed
   * by set, push and delete entries) replayed into its document.
   */
  documentFormat?: "json" | "jsonl" | "mutation-log";
  /**
   * Regular expression matched against each directory's `/`-separated
   * relative path. Only matching directories are walked.
   */
  directoryPattern?: string;
  /** Dotted path of a stable id inside each message. */
  messageIdField?: string;
  /**
   * Dotted fields that mark a message as finished. The last message is held
   * back while it has none of them set, so a reply that is still being
   * written is delivered once, complete. An earlier message is final even
   * without them: the agent has moved on from it.
   */
  completeFields?: readonly string[];
  /**
   * Top-level field that holds the agent's own session id. When present it
   * names the session and its records, so two files holding the same
   * session produce the same record identities.
   */
  sessionIdField?: string;
}>;

export type JSONDocumentSource = Readonly<{
  adapterId: string;
  roots: readonly string[];
  /** Regular expression matched against the `/`-separated relative path. */
  pathPattern: string;
  /** Top-level array that holds the conversation messages. */
  messagesField: string;
}> & JSONDocumentOptions;

type ScanOptions = Readonly<{
  cursors: Map<string, number>;
  /** Reused folder listings; without one every scan lists every folder. */
  listings?: DirectoryListingCache;
  initialScan: boolean;
  replayOnFirstStart: boolean;
  replaySessions: number;
  maxReplayRecords: number;
  maxRecords: number;
  historical: boolean;
}>;

type DocumentFile = Readonly<{
  root: string;
  path: string;
  modifiedMs: number;
  size: number;
}>;

/**
 * Reads agents that keep each conversation as one JSON document rewritten
 * in place (for example `{ messages: [...] }`). A document's cursor holds
 * the number of messages already delivered and a fingerprint of the last
 * one, so new messages are emitted once although the whole file is
 * rewritten. A document whose delivered prefix changed (compaction or a
 * rewind) resumes after the remembered message, or is re-baselined when
 * that message is gone. Unchanged documents are not parsed again.
 */
export async function scanJSONDocumentSource(
  source: JSONDocumentSource,
  options: ScanOptions,
): Promise<Readonly<{
  records: readonly SourceRecord[];
  files: number;
  malformed: number;
  oversized: number;
  complete: boolean;
}>> {
  const pattern = new RegExp(source.pathPattern, "u");
  const directoryPattern = source.directoryPattern === undefined
    ? undefined
    : new RegExp(source.directoryPattern, "u");
  const files: DocumentFile[] = [];
  for (const root of source.roots) {
    files.push(...await listDocuments(root, pattern, directoryPattern, options.listings, options.historical));
  }
  files.sort((left, right) =>
    right.modifiedMs - left.modifiedMs || left.path.localeCompare(right.path)
  );
  // The first live scan baselines every tracked document so an old
  // conversation that is resumed later continues from its last message.
  const selected = files.slice(
    0,
    options.historical || options.initialScan
      ? maxTrackedDocuments
      : maxLiveDocuments,
  );
  const replayPaths = new Set(
    options.initialScan && options.replayOnFirstStart && !options.historical
      ? selected.slice(0, options.replaySessions).map((file) => file.path)
      : [],
  );
  const records: SourceRecord[] = [];
  let malformed = 0;
  let oversized = 0;
  let complete = true;
  let remaining = options.maxRecords;
  for (const file of selected) {
    const cursorKey = digest(`json-document-cursor\u0000${file.path}`);
    const versionKey = digest(`json-document-version\u0000${file.path}`);
    const pendingKey = digest(`json-document-pending\u0000${file.path}`);
    const cursor = options.cursors.get(cursorKey);
    const version = documentVersion(file);
    const settled = Date.now() - file.modifiedMs >= settleMilliseconds;
    if (
      cursor !== undefined &&
      options.cursors.get(versionKey) === version &&
      !(settled && options.cursors.has(pendingKey))
    ) {
      continue;
    }
    if (file.size > maxDocumentBytes) {
      options.cursors.set(versionKey, version);
      oversized++;
      continue;
    }
    const baselineOnly =
      cursor === undefined &&
      options.initialScan &&
      !options.historical &&
      !replayPaths.has(file.path);
    if (remaining <= 0 && !baselineOnly) {
      complete = false;
      continue;
    }
    let messages: readonly unknown[];
    let identity = file.path;
    try {
      const rootReal = await realpath(file.root);
      const pathReal = await realpath(file.path);
      if (!isWithin(rootReal, pathReal)) continue;
      const document = readMessages(
        await readFile(pathReal, "utf8"),
        source,
      );
      if (document === undefined) {
        options.cursors.set(versionKey, version);
        malformed++;
        continue;
      }
      messages = document.messages.slice(0, maxMessagesPerDocument);
      if (document.sessionId !== undefined) {
        identity = `session\u0000${source.adapterId}\u0000${document.sessionId}`;
      }
    } catch (error) {
      if (isTransientError(error)) continue;
      // The agent rewrites the document in place, so a read can observe a
      // partial write. Its next modification is read again.
      if (error instanceof SyntaxError) continue;
      throw error;
    }
    const idField = source.messageIdField;
    // A final message that is still being written is held back and is
    // delivered once it is finished.
    const available = settled
      ? messages.length
      : finishedMessageCount(messages, source.completeFields);
    let start: number;
    if (cursor === undefined) {
      if (options.historical) start = 0;
      else if (replayPaths.has(file.path)) {
        start = Math.max(0, available - options.maxReplayRecords);
      } else if (options.initialScan) start = available;
      else start = 0;
    } else {
      start = resumeIndex(messages, cursor, idField);
    }
    const end = Math.max(
      start,
      Math.min(available, start + Math.max(0, remaining)),
    );
    const sourceID = `ses_${digest(identity).slice(0, 32)}`;
    for (let index = start; index < end; index++) {
      records.push({
        adapterId: source.adapterId,
        sourceId: sourceID,
        sourceRecordId: digest(
          `${identity}\u0000${messageKey(messages[index], index, idField)}`,
        ),
        // The document is rewritten as the conversation grows, so its
        // modification time is the newest message's time. Each record keeps
        // its own message time so the raw source record and the events
        // normalized from it carry the same timestamp.
        observedAt: messageTime(messages[index]) ??
          new Date(file.modifiedMs),
        initialReplay: options.historical || replayPaths.has(file.path),
        value: messages[index],
      });
    }
    remaining -= end - start;
    options.cursors.set(cursorKey, packCursor(messages, end, idField));
    if (end < available) {
      complete = false;
      options.cursors.delete(versionKey);
    } else {
      // A held-back unfinished message is read again when the file changes
      // or once the document has settled.
      options.cursors.set(versionKey, version);
    }
    if (available < messages.length) options.cursors.set(pendingKey, 1);
    else options.cursors.delete(pendingKey);
  }
  return { records, files: selected.length, malformed, oversized, complete };
}

function packCursor(
  messages: readonly unknown[],
  count: number,
  idField: string | undefined,
): number {
  return count === 0
    ? 0
    : count * fingerprintSpace +
      fingerprint(messages[count - 1], count - 1, idField);
}

/**
 * Index of the first undelivered message. The delivered prefix must still
 * end with the remembered message; if it moved, resume after it; if it is
 * gone the document was rewritten and everything present is treated as
 * already delivered.
 */
function resumeIndex(
  messages: readonly unknown[],
  cursor: number,
  idField: string | undefined,
): number {
  const count = Math.floor(cursor / fingerprintSpace);
  const last = cursor % fingerprintSpace;
  if (count === 0) return 0;
  if (
    count <= messages.length &&
    fingerprint(messages[count - 1], count - 1, idField) === last
  ) {
    return count;
  }
  for (let index = messages.length - 1; index >= 0; index--) {
    if (fingerprint(messages[index], index, idField) === last) return index + 1;
  }
  return messages.length;
}

// 2001-09-09 .. 2286-11-20 in epoch milliseconds. Smaller numbers are
// seconds or counters, not message times.
const minimumEpochMilliseconds = 1e12;
const maximumEpochMilliseconds = 1e13;

/**
 * A message's own time: an epoch-milliseconds `ts` or `timestamp` number
 * (Cline, VS Code chat) or an ISO `timestamp` string.
 */
function messageTime(message: unknown): Date | undefined {
  if (typeof message !== "object" || message === null) return undefined;
  const object = message as Record<string, unknown>;
  for (const field of ["ts", "timestamp"]) {
    const value = object[field];
    let time: number | undefined;
    if (
      typeof value === "number" &&
      value >= minimumEpochMilliseconds &&
      value < maximumEpochMilliseconds
    ) {
      time = value;
    } else if (typeof value === "string" && value.length <= 64) {
      const parsed = Date.parse(value);
      if (Number.isFinite(parsed)) time = parsed;
    }
    if (time !== undefined) return new Date(time);
  }
  return undefined;
}

/**
 * The document's messages, or undefined when the document does not hold a
 * message list. A JSON document that is still being written throws a
 * SyntaxError and is read again after its next change.
 */
function readMessages(
  text: string,
  source: JSONDocumentSource,
): Readonly<{ messages: readonly unknown[]; sessionId?: string }> | undefined {
  if (source.documentFormat === "jsonl") return { messages: jsonLines(text) };
  const document = source.documentFormat === "mutation-log"
    ? replayMutationLog(text)
    : JSON.parse(text) as unknown;
  if (!isRecord(document)) return undefined;
  const messages = document[source.messagesField];
  if (!Array.isArray(messages)) return undefined;
  const sessionId = source.sessionIdField === undefined
    ? undefined
    : document[source.sessionIdField];
  return typeof sessionId === "string" &&
      sessionId !== "" &&
      sessionId.length <= 128 &&
      !/[\u0000-\u001f\u007f]/u.test(sessionId)
    ? { messages, sessionId }
    : { messages };
}

/**
 * One value per line. A final line without its newline is included once it
 * parses: some agents write the separator before each record, not after.
 */
function jsonLines(text: string): unknown[] {
  const lines = text.split("\n");
  const values: unknown[] = [];
  for (const [index, line] of lines.entries()) {
    if (line.trim() === "") continue;
    try {
      values.push(JSON.parse(line));
    } catch {
      // The final line may still be being written. An earlier damaged line
      // is skipped so it cannot block the rest of the conversation.
      if (index === lines.length - 1) break;
    }
  }
  return values;
}

const forbiddenPathKeys = new Set(["__proto__", "constructor", "prototype"]);

/**
 * Rebuilds a VS Code chat session from its operation log: kind 0 is the
 * initial state, 1 sets the value at path `k`, 2 appends `v` to the array
 * at `k` after truncating it to `i`, and 3 deletes the value at `k`. A final
 * line that is still being written ends the replay. Returns undefined for a
 * log that cannot be replayed.
 */
function replayMutationLog(text: string): unknown {
  const lines = text.split("\n");
  let state: unknown;
  for (const [index, line] of lines.entries()) {
    if (line.trim() === "") continue;
    let entry: unknown;
    try {
      entry = JSON.parse(line);
    } catch {
      if (index === lines.length - 1) break;
      return undefined;
    }
    if (!isRecord(entry)) return undefined;
    if (entry["kind"] === 0) {
      state = entry["v"];
      continue;
    }
    const path = entry["k"];
    if (
      state === undefined ||
      !Array.isArray(path) ||
      path.length === 0 ||
      path.length > 64 ||
      !path.every((key) =>
        (typeof key === "string" && !forbiddenPathKeys.has(key)) ||
        (typeof key === "number" && Number.isSafeInteger(key) && key >= 0)
      )
    ) {
      return undefined;
    }
    const keys = path as readonly (string | number)[];
    const parent = containerAt(state, keys.slice(0, -1));
    const last = keys[keys.length - 1];
    if (parent === undefined || last === undefined) return undefined;
    if (entry["kind"] === 1) {
      parent[last] = entry["v"];
    } else if (entry["kind"] === 3) {
      delete parent[last];
    } else if (entry["kind"] === 2) {
      const current = parent[last] ?? [];
      const values = entry["v"] ?? [];
      const truncate = entry["i"];
      if (!Array.isArray(current) || !Array.isArray(values)) return undefined;
      if (truncate !== undefined) {
        if (
          typeof truncate !== "number" ||
          !Number.isSafeInteger(truncate) ||
          truncate < 0
        ) {
          return undefined;
        }
        if (truncate < current.length) current.length = truncate;
      }
      for (const value of values) current.push(value);
      parent[last] = current;
    } else {
      return undefined;
    }
  }
  return state;
}

function containerAt(
  value: unknown,
  path: readonly (string | number)[],
): Record<string | number, unknown> | undefined {
  let current = value;
  for (const key of path) {
    if (typeof current !== "object" || current === null) return undefined;
    current = (current as Record<string | number, unknown>)[key];
  }
  return typeof current === "object" && current !== null
    ? current as Record<string | number, unknown>
    : undefined;
}

function finishedMessageCount(
  messages: readonly unknown[],
  completeFields: readonly string[] | undefined,
): number {
  if (completeFields === undefined || completeFields.length === 0) {
    return messages.length;
  }
  const last = messages.at(-1);
  const finished = last === undefined || completeFields.some((field) => {
    const value = fieldAt(last, field);
    return value !== undefined && value !== null && value !== false;
  });
  return finished ? messages.length : messages.length - 1;
}

function fieldAt(value: unknown, path: string): unknown {
  let current = value;
  for (const key of path.split(".")) {
    if (!isRecord(current)) return undefined;
    current = current[key];
  }
  return current;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function messageKey(
  message: unknown,
  index: number,
  idField = "id",
): string {
  const id = fieldAt(message, idField);
  return typeof id === "string" && id !== "" && id.length <= 256
    ? `id:${id}`
    : `index:${index}`;
}

function fingerprint(
  message: unknown,
  index: number,
  idField: string | undefined,
): number {
  const key = messageKey(message, index, idField);
  return Number.parseInt(
    digest(key.startsWith("id:") ? key : `${key}:${safeJSON(message)}`)
      .slice(0, 9),
    16,
  );
}

function documentVersion(file: DocumentFile): number {
  return Number.parseInt(
    digest(`${file.size}:${file.modifiedMs}`).slice(0, 13),
    16,
  );
}

function safeJSON(value: unknown): string {
  try {
    return JSON.stringify(value) ?? "";
  } catch {
    return "";
  }
}

type DirectoryEntry = Readonly<{ name: string; directory: boolean; file: boolean }>;
type DirectoryListing = Readonly<{
  entries: readonly DirectoryEntry[];
  modifiedMs: number;
  listedAt: number;
  checkedAt: number;
  /** False when the folder changed too recently for its time to be trusted. */
  settled: boolean;
}>;
type FileMetadata = Readonly<{ modifiedMs: number; size: number; checkedAt: number }>;

type ListingFileSystem = Readonly<{
  readdir: (directory: string) => Promise<readonly DirectoryEntry[]>;
  modifiedMs: (directory: string) => Promise<number>;
  metadata: (file: string) => Promise<Readonly<{ modifiedMs: number; size: number }>>;
  now: () => number;
}>;

const nodeListingFileSystem: ListingFileSystem = {
  readdir: async (directory) => (await readdir(directory, { withFileTypes: true }))
    .map((entry) => ({ name: entry.name, directory: entry.isDirectory(), file: entry.isFile() })),
  modifiedMs: async (directory) => (await stat(directory)).mtimeMs,
  metadata: async (file) => {
    const metadata = await stat(file);
    return { modifiedMs: metadata.mtimeMs, size: metadata.size };
  },
  now: () => Date.now(),
};

/**
 * Folder listings reused across scans. Adding, removing or renaming an entry
 * changes its folder's modified time, so a folder is listed again only when
 * that time moved. Checking a folder costs about half of listing it, and
 * most folders under an agent's session store never change. A folder that
 * changed within the last two seconds is listed again on the next scan,
 * because coarse file-system clocks can hide a second change in the same
 * tick, and every folder is listed afresh at least every 30 seconds.
 *
 * Folders and documents untouched for ten minutes are cold: they are checked
 * every ten seconds instead of on every scan, so a conversation resumed in a
 * quiet project is noticed within ten seconds while active ones stay live.
 */
export class DirectoryListingCache {
  static readonly relistAfterMs = 30_000;
  static readonly settleMs = 2_000;
  static readonly coldAfterMs = 10 * 60_000;
  static readonly coldCheckMs = 10_000;
  static readonly maxFolders = 8_192;
  readonly #listings = new Map<string, DirectoryListing>();
  readonly #files = new Map<string, FileMetadata>();
  readonly #fs: ListingFileSystem;

  constructor(fileSystem: ListingFileSystem = nodeListingFileSystem) {
    this.#fs = fileSystem;
  }

  /**
   * The folder's entries. `trustMs` skips even the folder check while the
   * listing is younger than that; history imports use it, since live
   * collection already follows new conversations.
   */
  async list(directory: string, trustMs = 0): Promise<readonly DirectoryEntry[]> {
    const now = this.#fs.now();
    const cached = this.#listings.get(directory);
    const age = cached === undefined ? Number.POSITIVE_INFINITY : now - cached.listedAt;
    if (cached !== undefined && age < DirectoryListingCache.relistAfterMs) {
      if (age < trustMs) return cached.entries;
      if (cached.settled && now - cached.modifiedMs >= DirectoryListingCache.coldAfterMs &&
        now - cached.checkedAt < DirectoryListingCache.coldCheckMs) return cached.entries;
    }
    let modifiedMs: number;
    try {
      modifiedMs = await this.#fs.modifiedMs(directory);
    } catch (error) {
      this.#listings.delete(directory);
      throw error;
    }
    if (cached !== undefined && cached.settled && cached.modifiedMs === modifiedMs &&
      age < DirectoryListingCache.relistAfterMs) {
      this.#listings.set(directory, { ...cached, checkedAt: now });
      return cached.entries;
    }
    // Checked before listing: an entry added while listing moves the time on.
    const entries = await this.#fs.readdir(directory);
    this.#listings.delete(directory);
    this.#listings.set(directory, {
      entries,
      modifiedMs,
      listedAt: now,
      checkedAt: now,
      settled: now - modifiedMs >= DirectoryListingCache.settleMs,
    });
    evictOldest(this.#listings);
    return entries;
  }

  /** A document's time and size; a cold document is checked every ten seconds. */
  async metadata(file: string): Promise<Readonly<{ modifiedMs: number; size: number }>> {
    const now = this.#fs.now();
    const cached = this.#files.get(file);
    if (cached !== undefined && now - cached.modifiedMs >= DirectoryListingCache.coldAfterMs &&
      now - cached.checkedAt < DirectoryListingCache.coldCheckMs) return cached;
    let metadata: Readonly<{ modifiedMs: number; size: number }>;
    try {
      metadata = await this.#fs.metadata(file);
    } catch (error) {
      this.#files.delete(file);
      throw error;
    }
    this.#files.delete(file);
    this.#files.set(file, { ...metadata, checkedAt: now });
    evictOldest(this.#files);
    return metadata;
  }
}

function evictOldest(map: Map<string, unknown>): void {
  if (map.size <= DirectoryListingCache.maxFolders) return;
  const oldest = map.keys().next().value;
  if (oldest !== undefined) map.delete(oldest);
}

const historyListingTrustMs = DirectoryListingCache.relistAfterMs;

async function listDocuments(
  root: string,
  pattern: RegExp,
  directoryPattern: RegExp | undefined,
  listings: DirectoryListingCache | undefined,
  historical: boolean,
): Promise<DocumentFile[]> {
  const result: DocumentFile[] = [];
  // `inRoot` is the folder's `/`-separated path below root, built as the walk
  // descends instead of with path.relative for every entry on every scan.
  const walk = async (directory: string, inRoot: string, depth: number): Promise<void> => {
    if (depth > maxDirectoryDepth) return;
    let entries: readonly DirectoryEntry[];
    try {
      entries = listings === undefined
        ? await nodeListingFileSystem.readdir(directory)
        : await listings.list(directory, historical ? historyListingTrustMs : 0);
    } catch (error) {
      if (isTransientError(error)) return;
      throw error;
    }
    for (const entry of entries) {
      const relativePath = inRoot === "" ? entry.name : `${inRoot}/${entry.name}`;
      if (entry.directory) {
        if (directoryPattern === undefined || directoryPattern.test(relativePath)) {
          await walk(join(directory, entry.name), relativePath, depth + 1);
        }
        continue;
      }
      if (!entry.file || !pattern.test(relativePath)) continue;
      const path = join(directory, entry.name);
      try {
        const metadata = listings === undefined
          ? await nodeListingFileSystem.metadata(path)
          : await listings.metadata(path);
        result.push({
          root,
          path,
          modifiedMs: metadata.modifiedMs,
          size: metadata.size,
        });
      } catch (error) {
        if (!isTransientError(error)) throw error;
      }
    }
  };
  await walk(root, "", 0);
  return result;
}

function isWithin(root: string, candidate: string): boolean {
  const path = relative(resolve(root), resolve(candidate));
  return path === "" || (!path.startsWith(`..${sep}`) && path !== "..");
}

function digest(value: string): string {
  return createHash("sha256").update(value).digest("hex");
}

function isTransientError(error: unknown): boolean {
  return error instanceof Error &&
    "code" in error &&
    ["ENOENT", "EACCES", "EPERM", "ENOTDIR", "EBUSY", "ESTALE"].includes(
      String((error as NodeJS.ErrnoException).code),
    );
}
