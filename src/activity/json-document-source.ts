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

export type JSONDocumentSource = Readonly<{
  adapterId: string;
  roots: readonly string[];
  /** Regular expression matched against the `/`-separated relative path. */
  pathPattern: string;
  /** Top-level array that holds the conversation messages. */
  messagesField: string;
}>;

type ScanOptions = Readonly<{
  cursors: Map<string, number>;
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
  const files: DocumentFile[] = [];
  for (const root of source.roots) {
    files.push(...await listDocuments(root, pattern));
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
    const cursor = options.cursors.get(cursorKey);
    const version = documentVersion(file);
    if (cursor !== undefined && options.cursors.get(versionKey) === version) {
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
    try {
      const rootReal = await realpath(file.root);
      const pathReal = await realpath(file.path);
      if (!isWithin(rootReal, pathReal)) continue;
      const parsed: unknown = JSON.parse(await readFile(pathReal, "utf8"));
      const value = typeof parsed === "object" && parsed !== null
        ? (parsed as Record<string, unknown>)[source.messagesField]
        : undefined;
      if (!Array.isArray(value)) {
        options.cursors.set(versionKey, version);
        malformed++;
        continue;
      }
      messages = value.slice(0, maxMessagesPerDocument);
    } catch (error) {
      if (isTransientError(error)) continue;
      // The agent rewrites the document in place, so a read can observe a
      // partial write. Its next modification is read again.
      if (error instanceof SyntaxError) continue;
      throw error;
    }
    let start: number;
    if (cursor === undefined) {
      if (options.historical) start = 0;
      else if (replayPaths.has(file.path)) {
        start = Math.max(0, messages.length - options.maxReplayRecords);
      } else if (options.initialScan) start = messages.length;
      else start = 0;
    } else {
      start = resumeIndex(messages, cursor);
    }
    const end = Math.min(messages.length, start + Math.max(0, remaining));
    const sourceID = `ses_${digest(file.path).slice(0, 32)}`;
    for (let index = start; index < end; index++) {
      records.push({
        adapterId: source.adapterId,
        sourceId: sourceID,
        sourceRecordId: digest(
          `${file.path}\u0000${messageKey(messages[index], index)}`,
        ),
        observedAt: new Date(file.modifiedMs),
        initialReplay: options.historical || replayPaths.has(file.path),
        value: messages[index],
      });
    }
    remaining -= end - start;
    options.cursors.set(cursorKey, packCursor(messages, end));
    if (end < messages.length) {
      complete = false;
      options.cursors.delete(versionKey);
    } else {
      options.cursors.set(versionKey, version);
    }
  }
  return { records, files: selected.length, malformed, oversized, complete };
}

function packCursor(messages: readonly unknown[], count: number): number {
  return count === 0
    ? 0
    : count * fingerprintSpace + fingerprint(messages[count - 1], count - 1);
}

/**
 * Index of the first undelivered message. The delivered prefix must still
 * end with the remembered message; if it moved, resume after it; if it is
 * gone the document was rewritten and everything present is treated as
 * already delivered.
 */
function resumeIndex(messages: readonly unknown[], cursor: number): number {
  const count = Math.floor(cursor / fingerprintSpace);
  const last = cursor % fingerprintSpace;
  if (count === 0) return 0;
  if (
    count <= messages.length &&
    fingerprint(messages[count - 1], count - 1) === last
  ) {
    return count;
  }
  for (let index = messages.length - 1; index >= 0; index--) {
    if (fingerprint(messages[index], index) === last) return index + 1;
  }
  return messages.length;
}

function messageKey(message: unknown, index: number): string {
  const id = typeof message === "object" && message !== null
    ? (message as Record<string, unknown>)["id"]
    : undefined;
  return typeof id === "string" && id !== "" ? `id:${id}` : `index:${index}`;
}

function fingerprint(message: unknown, index: number): number {
  const key = messageKey(message, index);
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

async function listDocuments(
  root: string,
  pattern: RegExp,
): Promise<DocumentFile[]> {
  const result: DocumentFile[] = [];
  const walk = async (directory: string, depth: number): Promise<void> => {
    if (depth > maxDirectoryDepth) return;
    let entries;
    try {
      entries = await readdir(directory, { withFileTypes: true });
    } catch (error) {
      if (isTransientError(error)) return;
      throw error;
    }
    for (const entry of entries) {
      const path = join(directory, entry.name);
      if (entry.isDirectory()) {
        await walk(path, depth + 1);
        continue;
      }
      if (
        !entry.isFile() ||
        !pattern.test(relative(root, path).split(sep).join("/"))
      ) {
        continue;
      }
      try {
        const metadata = await stat(path);
        result.push({
          root,
          path,
          modifiedMs: metadata.mtimeMs,
          size: metadata.size,
        });
      } catch (error) {
        if (!isTransientError(error)) throw error;
      }
    }
  };
  await walk(root, 0);
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
