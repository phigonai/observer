import { createHash } from "node:crypto";
import { realpath, stat } from "node:fs/promises";
import { join, relative, resolve, sep } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { zstdDecompressSync } from "node:zlib";
import { packCursor, resumeIndex } from "./json-document-source.js";
import type { SourceRecord } from "./source-reader.js";
import { type CompletedHistory, databaseSignature, type IdleCursors, type SQLiteConnections } from "./sqlite-connections.js";

const databaseName = "threads.db";
// The newest threads are followed. An older thread is read again once Zed
// saves it, which moves it to the front.
const maxTrackedThreads = 1_024;
const maxThreadBytes = 32 << 20;
// A cursor packs the delivered item count in 17 bits (see packCursor).
const maxItemsPerThread = (1 << 17) - 1;
const maxBlocksPerMessage = 1_024;
const itemIdField = "id";

type ScanOptions = Readonly<{
  adapterId: string;
  roots: readonly string[];
  cursors: Map<string, number>;
  initialScan: boolean;
  replayOnFirstStart: boolean;
  /** Newest threads replayed on a first live start. */
  replaySessions: number;
  maxReplayRecords: number;
  maxRecords: number;
  historical: boolean;
  /** Connections a live reader keeps open between scans. */
  connections?: SQLiteConnections;
  /** History only: databases already read to the end. */
  completedHistory?: CompletedHistory;
}>;

type ScanResult = Readonly<{
  records: readonly SourceRecord[];
  files: number;
  malformed: number;
  oversized: number;
  complete: boolean;
}>;

type ThreadRow = Readonly<{ id: string; updatedAt: string; size: number }>;

/**
 * One delivered unit of a Zed thread: a user prompt, one block of an agent
 * reply (text, thinking or a tool call) or one tool result. `complete` is
 * false for a tool call whose input was still streaming when Zed saved.
 */
export type ZedThreadItem = Readonly<{
  id: string;
  complete: boolean;
  value: Readonly<Record<string, unknown>>;
}>;

/**
 * Zed's agent panel keeps every thread in one SQLite database,
 * `<data dir>/threads/threads.db`: one `threads` row per thread whose `data`
 * is the whole thread as JSON, zstd-compressed (`data_type` "zstd") or plain
 * ("json"), rewritten on every save. Each thread is split into items (see
 * zedThreadItems) and a per-thread cursor remembers how many were delivered
 * and the last one's id, so only items added since are emitted. A thread
 * whose `updated_at` and size are unchanged is not decompressed again.
 * Messages carry no times of their own; items take the thread's save time.
 */
export async function scanZedSQLiteSources(
  options: ScanOptions,
): Promise<ScanResult> {
  const records: SourceRecord[] = [];
  let files = 0;
  let malformed = 0;
  let oversized = 0;
  let complete = true;
  for (const root of options.roots) {
    try {
      const result = await scanDatabase(root, {
        ...options,
        maxRecords: Math.max(0, options.maxRecords - records.length),
      });
      records.push(...result.records);
      files += result.files;
      malformed += result.malformed;
      oversized += result.oversized;
      complete = complete && result.complete;
    } catch (error) {
      options.connections?.release(root);
      if (!isUnavailableDatabase(error)) throw error;
    }
  }
  return { records, files, malformed, oversized, complete };
}

async function scanDatabase(
  root: string,
  options: ScanOptions,
): Promise<ScanResult> {
  const empty = { records: [], files: 0, malformed: 0, oversized: 0, complete: true };
  const rootReal = await realpath(root);
  const databaseReal = await realpath(join(rootReal, databaseName));
  const metadata = isWithin(rootReal, databaseReal)
    ? await stat(databaseReal)
    : undefined;
  if (metadata?.isFile() !== true) {
    options.connections?.release(root);
    return empty;
  }
  // A history import skips a database it already read to the end.
  const signature = options.historical && options.completedHistory !== undefined
    ? await databaseSignature(databaseReal, metadata)
    : undefined;
  if (signature !== undefined && options.completedHistory?.get(databaseReal) === signature) {
    return { ...empty, files: 1 };
  }
  // Only a live reader skips unchanged databases; see SQLiteConnections.
  const scan = options.historical
    ? undefined
    : await options.connections?.check(root, databaseReal, metadata, options.cursors, openDatabase);
  if (scan?.unchanged === true) return { ...empty, files: 1 };
  const database = scan?.database ?? openDatabase(databaseReal);
  try {
    if (!hasThreadColumns(database)) {
      scan?.finish(undefined);
      return { ...empty, files: 1, malformed: 1 };
    }
    const threads = listThreads(database);
    const replay = new Set(
      options.initialScan && options.replayOnFirstStart && !options.historical
        ? threads.slice(0, options.replaySessions).map((thread) => thread.id)
        : [],
    );
    const records: SourceRecord[] = [];
    let malformed = 0;
    let oversized = 0;
    let complete = true;
    let remaining = options.maxRecords;
    // The cursors this scan read, for the idle check when no thread changed.
    const read: Array<readonly [string, number | undefined]> = [];
    let changed = 0;
    for (const thread of threads) {
      const identity = `${databaseReal}\u0000${thread.id}`;
      const cursorKey = digest(`zed-thread-cursor\u0000${identity}`);
      const versionKey = digest(`zed-thread-version\u0000${identity}`);
      const cursor = options.cursors.get(cursorKey);
      const version = threadVersion(thread);
      const savedVersion = options.cursors.get(versionKey);
      read.push([cursorKey, cursor], [versionKey, savedVersion]);
      if (savedVersion === version) continue;
      changed++;
      const baselineOnly =
        cursor === undefined &&
        options.initialScan &&
        !options.historical &&
        !replay.has(thread.id);
      if (remaining <= 0 && !baselineOnly) {
        complete = false;
        continue;
      }
      let items: readonly ZedThreadItem[] | undefined;
      try {
        items = zedThreadItems(threadDocument(database, thread.id));
      } catch (error) {
        if (isOversized(error)) oversized++;
        else if (isUndecodable(error)) malformed++;
        else throw error;
        options.cursors.set(versionKey, version);
        continue;
      }
      if (items === undefined) {
        malformed++;
        options.cursors.set(versionKey, version);
        continue;
      }
      // A tool call whose input was still streaming is held back until Zed
      // saves it complete.
      const available = items.at(-1)?.complete === false
        ? items.length - 1
        : items.length;
      let start: number;
      if (cursor === undefined) {
        if (options.historical) start = 0;
        else if (replay.has(thread.id)) {
          start = Math.max(0, available - options.maxReplayRecords);
        } else if (options.initialScan) start = available;
        else start = 0;
      } else {
        start = resumeIndex(items, cursor, itemIdField);
      }
      const end = Math.max(
        start,
        Math.min(available, start + Math.max(0, remaining)),
      );
      const observedAt = threadTime(thread.updatedAt) ?? metadata.mtime;
      const sourceId = `ses_${digest(identity).slice(0, 32)}`;
      for (let index = start; index < end; index++) {
        const item = items[index];
        if (item === undefined) break;
        records.push({
          adapterId: options.adapterId,
          sourceId,
          sourceRecordId: digest(`${identity}\u0000${item.id}`),
          observedAt,
          initialReplay: options.historical || replay.has(thread.id),
          value: {
            ...item.value,
            thread_id: thread.id,
            timestamp: observedAt.toISOString(),
          },
        });
      }
      remaining -= end - start;
      options.cursors.set(cursorKey, packCursor(items, end, itemIdField));
      if (end < available) {
        complete = false;
        options.cursors.delete(versionKey);
      } else {
        options.cursors.set(versionKey, version);
      }
    }
    // No thread changed, so the same data and cursors give the same scan.
    const idle: IdleCursors | undefined = changed === 0 ? read : undefined;
    scan?.finish(idle);
    if (signature !== undefined && complete && records.length === 0) {
      options.completedHistory?.set(databaseReal, signature);
    }
    return { records, files: 1, malformed, oversized, complete };
  } catch (error) {
    scan?.fail();
    throw error;
  } finally {
    if (scan === undefined) database.close();
  }
}

function openDatabase(path: string): DatabaseSync {
  const database = new DatabaseSync(path, { readOnly: true });
  try {
    database.exec("PRAGMA query_only = ON; PRAGMA trusted_schema = OFF;");
  } catch (error) {
    database.close();
    throw error;
  }
  return database;
}

function hasThreadColumns(database: DatabaseSync): boolean {
  const columns = new Set(
    database.prepare("PRAGMA table_info(threads)").all().flatMap((value) =>
      isRecord(value) && typeof value["name"] === "string" ? [value["name"]] : []
    ),
  );
  return ["id", "updated_at", "data_type", "data"].every((column) => columns.has(column));
}

/**
 * The newest threads, newest first. length() of a blob is read from the
 * row header, so listing never loads the compressed threads.
 */
function listThreads(database: DatabaseSync): ThreadRow[] {
  return database.prepare(
    "SELECT id, updated_at, length(data) AS size FROM threads " +
    "ORDER BY updated_at DESC, id ASC LIMIT ?",
  ).all(maxTrackedThreads).flatMap((value) => {
    if (!isRecord(value)) return [];
    const id = value["id"];
    const updatedAt = value["updated_at"];
    const size = value["size"];
    return typeof id === "string" &&
        isBoundedId(id) &&
        typeof updatedAt === "string" &&
        updatedAt.length <= 64 &&
        typeof size === "number"
      ? [{ id, updatedAt, size }]
      : [];
  });
}

function threadVersion(thread: ThreadRow): number {
  return Number.parseInt(
    digest(`${thread.updatedAt}\u0000${thread.size}`).slice(0, 13),
    16,
  );
}

/** The thread's saved JSON. Throws for data that cannot be decoded. */
function threadDocument(database: DatabaseSync, id: string): unknown {
  const row = database.prepare(
    "SELECT data_type, data FROM threads WHERE id = ? LIMIT 1",
  ).get(id);
  if (!isRecord(row)) return undefined;
  const type = row["data_type"];
  const data = row["data"];
  const bytes = typeof data === "string"
    ? Buffer.from(data, "utf8")
    : data instanceof Uint8Array
      ? data
      : undefined;
  if (bytes === undefined) return undefined;
  let json: Uint8Array;
  if (type === "zstd") {
    json = zstdDecompressSync(bytes, { maxOutputLength: maxThreadBytes });
  } else if (type === "json") {
    if (bytes.byteLength > maxThreadBytes) {
      throw new RangeError("thread_too_large");
    }
    json = bytes;
  } else {
    return undefined;
  }
  return JSON.parse(
    Buffer.from(json.buffer, json.byteOffset, json.byteLength).toString("utf8"),
  ) as unknown;
}

/**
 * Splits a saved Zed thread into items, in order. Zed's own format
 * (version 0.3.0) stores `messages` as tagged values: `{ User: { id,
 * content } }`, `{ Agent: { content, tool_results } }`, `"Resume"` and
 * `{ Compaction: ... }`. A user message becomes one item; each Text,
 * Thinking or ToolUse block of an agent message becomes one, followed by
 * one per tool result. Older threads from Zed's first agent store messages
 * as `{ id, role, segments, tool_uses, tool_results }` and are read into the
 * same items.
 *
 * Item ids are stable across saves: they hang off the id of the user
 * message that started the turn, so a turn rewound and sent again gets new
 * ids. Large payloads are left out: images, the full text of mentioned files
 * and Zed's debugging copy of tool output. Returns undefined when the
 * document holds no message list.
 */
export function zedThreadItems(
  document: unknown,
): readonly ZedThreadItem[] | undefined {
  if (!isRecord(document) || !Array.isArray(document["messages"])) {
    return undefined;
  }
  const items: ZedThreadItem[] = [];
  let turn = "start";
  let agentMessages = 0;
  for (const [index, message] of document["messages"].entries()) {
    if (items.length >= maxItemsPerThread) break;
    if (!isRecord(message)) continue;
    if (typeof message["role"] === "string") {
      items.push(...legacyItems(message, index));
      continue;
    }
    const user = message["User"];
    if (isRecord(user)) {
      turn = boundedId(user["id"]) ?? `message-${index}`;
      agentMessages = 0;
      const content = userContent(user["content"]);
      if (content.length > 0) {
        items.push({
          id: `user:${turn}`,
          complete: true,
          value: { type: "zed_message", role: "user", content },
        });
      }
      continue;
    }
    const agent = message["Agent"];
    if (!isRecord(agent)) continue;
    const prefix = `${turn}:agent-${agentMessages++}`;
    const blocks = Array.isArray(agent["content"]) ? agent["content"] : [];
    for (const [blockIndex, block] of blocks.slice(0, maxBlocksPerMessage).entries()) {
      const item = agentBlock(block, `${prefix}:${blockIndex}`, prefix);
      if (item !== undefined) items.push(item);
    }
    const results = isRecord(agent["tool_results"]) ? agent["tool_results"] : {};
    for (const [toolUseId, result] of Object.entries(results).slice(0, maxBlocksPerMessage)) {
      const item = toolResult(result, toolUseId, prefix);
      if (item !== undefined) items.push(item);
    }
  }
  return items.slice(0, maxItemsPerThread);
}

function agentBlock(
  block: unknown,
  positionalId: string,
  prefix: string,
): ZedThreadItem | undefined {
  if (!isRecord(block)) return undefined;
  const text = block["Text"];
  if (typeof text === "string") {
    return text.trim() === "" ? undefined : assistantItem(positionalId, { Text: text });
  }
  const thinking = block["Thinking"];
  if (isRecord(thinking)) {
    const value = thinking["text"];
    return typeof value === "string" && value.trim() !== ""
      ? assistantItem(positionalId, { Thinking: { text: value } })
      : undefined;
  }
  const toolUse = block["ToolUse"];
  if (!isRecord(toolUse)) return undefined;
  const id = boundedId(toolUse["id"]);
  const inputComplete = toolUse["is_input_complete"] !== false;
  return {
    ...assistantItem(id === undefined ? positionalId : `${prefix}:tool:${id}`, {
      ToolUse: {
        id: id ?? "",
        name: typeof toolUse["name"] === "string" ? toolUse["name"] : "",
        input: toolInput(toolUse["input"]),
        is_input_complete: inputComplete,
      },
    }),
    complete: inputComplete,
  };
}

function assistantItem(id: string, block: Record<string, unknown>): ZedThreadItem {
  return {
    id,
    complete: true,
    value: { type: "zed_message", role: "assistant", content: [block] },
  };
}

function toolResult(
  result: unknown,
  toolUseId: string,
  prefix: string,
): ZedThreadItem | undefined {
  if (!isRecord(result) || !isBoundedId(toolUseId)) return undefined;
  return {
    id: `${prefix}:result:${toolUseId}`,
    complete: true,
    value: {
      type: "zed_tool_result",
      tool_use_id: toolUseId,
      tool_name: typeof result["tool_name"] === "string" ? result["tool_name"] : "",
      is_error: result["is_error"] === true,
      content: toolResultText(result["content"]),
    },
  };
}

/**
 * A thread saved by Zed's first agent (format 0.1 and 0.2): `{ id, role,
 * segments: [{ type: "text" | "thinking", text }], tool_uses: [{ id, name,
 * input }], tool_results: [{ tool_use_id, is_error, content }], is_hidden }`.
 * Tool results sit on the user message after the call.
 */
function legacyItems(
  message: Record<string, unknown>,
  index: number,
): ZedThreadItem[] {
  const role = message["role"];
  const prefix = `legacy-${boundedId(message["id"]) ?? index}`;
  const segments = Array.isArray(message["segments"]) ? message["segments"] : [];
  const items: ZedThreadItem[] = [];
  if (role === "user" && message["is_hidden"] !== true) {
    const text = segments.flatMap((segment) =>
      isRecord(segment) && typeof segment["text"] === "string" ? [segment["text"]] : []
    ).join("\n");
    if (text.trim() !== "") {
      items.push({
        id: `${prefix}:user`,
        complete: true,
        value: { type: "zed_message", role: "user", content: [{ Text: text }] },
      });
    }
  } else if (role === "assistant") {
    for (const [segmentIndex, segment] of segments.slice(0, maxBlocksPerMessage).entries()) {
      if (!isRecord(segment) || typeof segment["text"] !== "string") continue;
      const block = segment["type"] === "thinking"
        ? { Thinking: { text: segment["text"] } }
        : segment["type"] === "text"
          ? { Text: segment["text"] }
          : undefined;
      if (block !== undefined && segment["text"].trim() !== "") {
        items.push(assistantItem(`${prefix}:${segmentIndex}`, block));
      }
    }
    const toolUses = Array.isArray(message["tool_uses"]) ? message["tool_uses"] : [];
    for (const [toolIndex, toolUse] of toolUses.slice(0, maxBlocksPerMessage).entries()) {
      if (!isRecord(toolUse)) continue;
      const id = boundedId(toolUse["id"]);
      items.push(assistantItem(`${prefix}:tool:${id ?? toolIndex}`, {
        ToolUse: {
          id: id ?? "",
          name: typeof toolUse["name"] === "string" ? toolUse["name"] : "",
          input: toolInput(toolUse["input"]),
          is_input_complete: true,
        },
      }));
    }
  }
  if (role === "user" || role === "assistant") {
    const results = Array.isArray(message["tool_results"]) ? message["tool_results"] : [];
    for (const result of results.slice(0, maxBlocksPerMessage)) {
      if (!isRecord(result)) continue;
      const id = boundedId(result["tool_use_id"]);
      const item = id === undefined ? undefined : toolResult(result, id, prefix);
      if (item !== undefined) items.push(item);
    }
  }
  return items;
}

/**
 * The user's words and mentions. A mention keeps what it points at (a file,
 * symbol, thread or URL) but not the text Zed attached for the model; an
 * image keeps only that it was there.
 */
function userContent(content: unknown): Array<Record<string, unknown>> {
  if (!Array.isArray(content)) return [];
  return content.slice(0, maxBlocksPerMessage).flatMap((part): Array<Record<string, unknown>> => {
    if (typeof part === "string") return part === "" ? [] : [{ Text: part }];
    if (!isRecord(part)) return [];
    if (typeof part["Text"] === "string") return [{ Text: part["Text"] }];
    const mention = part["Mention"];
    if (isRecord(mention)) return [{ Mention: { uri: mention["uri"] } }];
    if ("Image" in part) return [{ Image: {} }];
    return [];
  });
}

/**
 * Tool input as the model sent it. Current Zed saves `{ type: "json" |
 * "text", value }`; older threads saved the JSON value itself.
 */
function toolInput(input: unknown): unknown {
  if (
    isRecord(input) &&
    Object.keys(input).length === 2 &&
    (input["type"] === "json" || input["type"] === "text") &&
    "value" in input
  ) {
    return input["value"];
  }
  return input;
}

/**
 * The text of a tool result. Zed saves one part or a list of parts, each a
 * string, `{ Text }`, `{ type: "text", text }`, `{ text }` or an image.
 */
function toolResultText(content: unknown): string {
  const parts = Array.isArray(content) ? content : [content];
  return parts.slice(0, maxBlocksPerMessage).flatMap((part) => {
    if (typeof part === "string") return [part];
    if (!isRecord(part)) return [];
    for (const [key, value] of Object.entries(part)) {
      if (key.toLowerCase() === "text" && typeof value === "string") return [value];
    }
    return [];
  }).join("\n");
}

/** Zed saves `updated_at` as RFC 3339. */
function threadTime(value: string): Date | undefined {
  const parsed = Date.parse(value);
  return Number.isFinite(parsed) ? new Date(parsed) : undefined;
}

function boundedId(value: unknown): string | undefined {
  const id = typeof value === "number" && Number.isSafeInteger(value)
    ? String(value)
    : value;
  return typeof id === "string" && isBoundedId(id) ? id : undefined;
}

function isBoundedId(value: string): boolean {
  return value !== "" &&
    Buffer.byteLength(value, "utf8") <= 128 &&
    !/[\u0000-\u001f\u007f]/u.test(value);
}

function isOversized(error: unknown): boolean {
  return error instanceof RangeError;
}

/** Data that is not valid zstd or JSON. */
function isUndecodable(error: unknown): boolean {
  return error instanceof SyntaxError ||
    (error instanceof Error && "code" in error && String(error.code).startsWith("ZSTD_error_"));
}

function digest(value: string): string {
  return createHash("sha256").update(value).digest("hex");
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isWithin(root: string, candidate: string): boolean {
  const path = relative(resolve(root), resolve(candidate));
  return path === "" || (!path.startsWith(`..${sep}`) && path !== "..");
}

function isUnavailableDatabase(error: unknown): boolean {
  return error instanceof Error && (
    "code" in error && [
      "ENOENT",
      "EACCES",
      "EPERM",
      "ENOTDIR",
      "EBUSY",
      "ESTALE",
    ].includes(String(error.code)) ||
    /database is locked|unable to open database file/iu.test(error.message)
  );
}
