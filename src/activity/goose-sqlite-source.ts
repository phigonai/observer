import { createHash } from "node:crypto";
import { realpath, stat } from "node:fs/promises";
import { join, relative, resolve, sep } from "node:path";
import { DatabaseSync } from "node:sqlite";
import type { SourceRecord } from "./source-reader.js";

const databaseName = "sessions.db";
const maxRowsPerScan = 4_096;
const maxContentBytes = 4 << 20;

type ScanOptions = Readonly<{
  adapterId: string;
  roots: readonly string[];
  cursors: Map<string, number>;
  initialScan: boolean;
  replayOnFirstStart: boolean;
  maxReplayRecords: number;
  maxRecords: number;
  historical: boolean;
}>;

type MessageRow = Readonly<{
  id: number;
  messageID: string;
  sessionID: string;
  role: string;
  content: string;
  created: number;
  metadata: string;
}>;

/**
 * Goose (1.10+) stores every session in one SQLite database,
 * `<data dir>/sessions/sessions.db`, with one `messages` row per message
 * (`content_json` holds the message content blocks). Rows are delivered in
 * insertion order; the cursor is the last delivered row id, so a scan reads
 * only rows added since. Records keep Goose's own message id, so a
 * conversation that Goose rewrites keeps stable source record identities.
 */
export async function scanGooseSQLiteSources(
  options: ScanOptions,
): Promise<Readonly<{
  records: readonly SourceRecord[];
  files: number;
  malformed: number;
  oversized: number;
  complete: boolean;
}>> {
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
      if (!isUnavailableDatabase(error)) throw error;
    }
  }
  return { records, files, malformed, oversized, complete };
}

async function scanDatabase(
  root: string,
  options: ScanOptions,
): Promise<Readonly<{
  records: readonly SourceRecord[];
  files: number;
  malformed: number;
  oversized: number;
  complete: boolean;
}>> {
  const empty = { records: [], files: 0, malformed: 0, oversized: 0, complete: true };
  const rootReal = await realpath(root);
  const databaseReal = await realpath(join(rootReal, databaseName));
  if (!isWithin(rootReal, databaseReal)) return empty;
  const metadata = await stat(databaseReal);
  if (!metadata.isFile()) return empty;
  const database = new DatabaseSync(databaseReal, { readOnly: true });
  try {
    database.exec("PRAGMA query_only = ON; PRAGMA trusted_schema = OFF;");
    const columns = supportedColumns(database);
    if (columns === undefined) {
      return { ...empty, files: 1, malformed: 1 };
    }
    const cursorKey = digest(`goose-sqlite-v1:${databaseReal}`);
    const newest = maxRowID(database);
    let cursor = options.cursors.get(cursorKey);
    // AUTOINCREMENT never reuses ids; a smaller maximum means the database
    // was recreated, so its rows are all new.
    if (cursor !== undefined && newest < cursor) cursor = 0;
    let rows: MessageRow[];
    let replay = false;
    if (cursor === undefined && !options.historical && options.initialScan) {
      replay = options.replayOnFirstStart;
      rows = replay
        ? latestRows(
          database,
          columns,
          Math.min(options.maxReplayRecords, options.maxRecords),
        )
        : [];
      // Live collection starts at the current end of the database; only a
      // bounded first-start replay reads saved messages. A database created
      // after startup holds only new work and is read from its first row.
      options.cursors.set(cursorKey, newest);
    } else {
      const limit = Math.min(maxRowsPerScan, options.maxRecords);
      rows = limit > 0 ? rowsAfter(database, columns, cursor ?? 0, limit) : [];
      const last = rows.at(-1);
      if (last !== undefined) options.cursors.set(cursorKey, last.id);
      else if (cursor === undefined) options.cursors.set(cursorKey, 0);
    }
    const records: SourceRecord[] = [];
    let malformed = 0;
    let oversized = 0;
    for (const row of rows) {
      if (Buffer.byteLength(row.content, "utf8") > maxContentBytes) {
        oversized++;
        continue;
      }
      let content: unknown;
      try {
        content = JSON.parse(row.content);
      } catch {
        malformed++;
        continue;
      }
      const created = createdAt(row.created, metadata.mtime);
      records.push({
        adapterId: options.adapterId,
        sourceId: `ses_${digest(`${databaseReal}\u0000${row.sessionID}`).slice(0, 32)}`,
        sourceRecordId: digest(
          `${databaseReal}\u0000${row.sessionID}\u0000${row.messageID || `row:${row.id}`}`,
        ),
        observedAt: created,
        initialReplay: replay || options.historical,
        value: {
          type: "goose_message",
          role: row.role,
          content,
          created: row.created,
          timestamp: created.toISOString(),
          metadata: parseMetadata(row.metadata),
        },
      });
    }
    const delivered = options.cursors.get(cursorKey) ?? 0;
    return {
      records,
      files: 1,
      malformed,
      oversized,
      complete: !options.historical || delivered >= newest,
    };
  } finally {
    database.close();
  }
}

function rowsAfter(
  database: DatabaseSync,
  columns: string,
  cursor: number,
  limit: number,
): MessageRow[] {
  return database.prepare(
    `SELECT ${columns} FROM messages WHERE id > ? ORDER BY id ASC LIMIT ?`,
  ).all(cursor, limit).flatMap(messageRow);
}

function latestRows(
  database: DatabaseSync,
  columns: string,
  limit: number,
): MessageRow[] {
  if (limit <= 0) return [];
  return database.prepare(
    `SELECT ${columns} FROM messages ORDER BY id DESC LIMIT ?`,
  ).all(limit).flatMap(messageRow).reverse();
}

function maxRowID(database: DatabaseSync): number {
  const value = database.prepare("SELECT MAX(id) AS id FROM messages").get();
  const id = isRecord(value) ? value["id"] : undefined;
  return typeof id === "number" && Number.isSafeInteger(id) ? id : 0;
}

function messageRow(value: unknown): MessageRow[] {
  if (!isRecord(value)) return [];
  const id = value["id"];
  const sessionID = value["session_id"];
  const role = value["role"];
  const content = value["content_json"];
  const created = value["created_timestamp"];
  if (
    typeof id !== "number" ||
    !Number.isSafeInteger(id) ||
    typeof sessionID !== "string" ||
    sessionID.length === 0 ||
    Buffer.byteLength(sessionID, "utf8") > 128 ||
    typeof role !== "string" ||
    typeof content !== "string"
  ) {
    return [];
  }
  return [{
    id,
    messageID: typeof value["message_id"] === "string" ? value["message_id"] : "",
    sessionID,
    role,
    content,
    created: typeof created === "number" ? created : 0,
    metadata: typeof value["metadata_json"] === "string" ? value["metadata_json"] : "",
  }];
}

/** Goose stores epoch seconds; values above 1e10 are milliseconds. */
function createdAt(value: number, fallback: Date): Date {
  if (!Number.isFinite(value) || value <= 0) return fallback;
  const parsed = new Date(value > 1e10 ? value : value * 1_000);
  return Number.isNaN(parsed.getTime()) ? fallback : parsed;
}

function parseMetadata(value: string): unknown {
  if (value === "") return undefined;
  try {
    return JSON.parse(value);
  } catch {
    return undefined;
  }
}

/**
 * The SELECT list for the messages table, or undefined when the required
 * columns are missing. message_id and metadata_json were added by later
 * schema migrations and are optional.
 */
function supportedColumns(database: DatabaseSync): string | undefined {
  const columns = new Set(
    database.prepare("PRAGMA table_info(messages)").all().flatMap((value) =>
      isRecord(value) && typeof value["name"] === "string" ? [value["name"]] : []
    ),
  );
  const required = ["id", "session_id", "role", "content_json", "created_timestamp"];
  if (!required.every((column) => columns.has(column))) return undefined;
  return [
    ...required,
    columns.has("message_id") ? "message_id" : "NULL AS message_id",
    columns.has("metadata_json") ? "metadata_json" : "NULL AS metadata_json",
  ].join(", ");
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
