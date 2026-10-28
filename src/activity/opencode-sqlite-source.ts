import { createHash } from "node:crypto";
import { realpath, stat } from "node:fs/promises";
import { join, relative, resolve, sep } from "node:path";
import { DatabaseSync } from "node:sqlite";
import type { SourceRecord } from "./source-reader.js";
import { type CompletedHistory, databaseSignature, type IdleCursors, type SQLiteConnections } from "./sqlite-connections.js";

const databaseName = "opencode.db";
const maxDatabaseEventsPerScan = 4_096;
const maxTrackedSessions = 4_000;
const maxLiveSessionsPerScan = 256;
const maxReplaySessions = 32;
const maxRecordBytes = 1 << 20;

type ScanOptions = Readonly<{
  adapterId: string;
  roots: readonly string[];
  cursors: Map<string, number>;
  initialScan: boolean;
  replayOnFirstStart: boolean;
  maxReplayRecords: number;
  historical?: boolean;
  /** Connections a live reader keeps open between scans. */
  connections?: SQLiteConnections;
  /** History only: databases already read to the end. */
  completedHistory?: CompletedHistory;
}>;

type SessionSequence = Readonly<{
  aggregateID: string;
  maxSequence: number;
}>;

type EventRow = Readonly<{
  sequence: number;
  type: string;
  data: string;
}>;

export async function scanOpenCodeSQLiteSources(
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
      const result = await scanDatabase(root, options);
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
): Promise<Readonly<{
  records: readonly SourceRecord[];
  files: number;
  malformed: number;
  oversized: number;
  complete: boolean;
}>> {
  const rootReal = await realpath(root);
  const databaseReal = await realpath(join(rootReal, databaseName));
  const metadata = isWithin(rootReal, databaseReal)
    ? await stat(databaseReal)
    : undefined;
  if (metadata?.isFile() !== true) {
    options.connections?.release(root);
    return { records: [], files: 0, malformed: 0, oversized: 0, complete: true };
  }

  // A history import skips a database it already read to the end.
  const signature = options.historical === true && options.completedHistory !== undefined
    ? await databaseSignature(databaseReal, metadata)
    : undefined;
  if (signature !== undefined && options.completedHistory?.get(databaseReal) === signature) {
    return { records: [], files: 1, malformed: 0, oversized: 0, complete: true };
  }
  // Only a live reader skips unchanged databases (see SQLiteConnections). A
  // history import opens one connection per bounded batch, as before.
  const scan = options.historical === true
    ? undefined
    : await options.connections?.check(root, databaseReal, metadata, options.cursors, openDatabase);
  if (scan?.unchanged === true) {
    return { records: [], files: 1, malformed: 0, oversized: 0, complete: true };
  }
  const database = scan?.database ?? openDatabase(databaseReal);
  try {
    if (!hasSupportedSchema(database)) {
      scan?.finish(undefined);
      return { records: [], files: 1, malformed: 1, oversized: 0, complete: true };
    }
    const sessions = readSessionSequences(database, options.historical ? -1 : maxTrackedSessions);
    const marker = cursorID(databaseReal, "initialized");
    const firstDatabaseScan = options.cursors.get(marker) !== 1;
    let rows: Array<Readonly<{ sessionID: string; row: EventRow }>> = [];
    let idle: IdleCursors | undefined;

    if (options.historical) {
      rows = unreadRows(
        database,
        databaseReal,
        sessions,
        options.cursors,
        options.maxReplayRecords,
      );
      options.cursors.set(marker, 1);
    } else if (firstDatabaseScan) {
      if (options.initialScan && options.replayOnFirstStart) {
        rows = replayRows(
          database,
          sessions.slice(0, maxReplaySessions),
          options.maxReplayRecords,
        );
      }
      // First-start replay is intentionally bounded. Baseline every known
      // session after selecting that bounded slice so an old archive cannot
      // silently flood or reappear after restart.
      for (const session of sessions) {
        options.cursors.set(
          cursorID(databaseReal, session.aggregateID),
          session.maxSequence,
        );
      }
      options.cursors.set(marker, 1);
    } else {
      const unread = unreadEvents(
        database,
        databaseReal,
        sessions.slice(0, maxLiveSessionsPerScan),
        options.cursors,
        Math.min(maxDatabaseEventsPerScan, options.maxReplayRecords),
      );
      rows = unread.rows;
      if (unread.selected === 0) {
        // No session had any row past its cursor, so the row limit did not
        // matter: the same database and cursors give the same empty scan.
        idle = [[marker, 1], ...unread.cursors];
      }
    }

    const sourceID = `ses_${digest(databaseReal).slice(0, 32)}`;
    // Older OpenCode conversations can exist only in message/part tables.
    // Import those snapshots as well; event-backed sessions retain their
    // original event log and are deliberately excluded from this fallback.
    const legacy = options.historical
      ? legacyRows(database, databaseReal, options.cursors, Math.max(0, options.maxReplayRecords - rows.length))
      : { rows: [], complete: true };
    rows.push(...legacy.rows);
    const hasMessages = database.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name='message'").get() !== undefined;
    const messageLookup = hasMessages
      ? database.prepare("SELECT id, session_id, data FROM message WHERE id = ? AND session_id = ?")
      : undefined;
    const records: SourceRecord[] = [];
    let malformed = 0;
    let oversized = 0;
    for (const item of rows) {
      if (Buffer.byteLength(item.row.data, "utf8") > maxRecordBytes) {
        oversized++;
        continue;
      }
      try {
        const parsed: unknown = JSON.parse(item.row.data);
        if (!isRecord(parsed)) {
          malformed++;
          continue;
        }
        const observedAt = eventObservedAt(parsed, metadata.mtime);
        const part = isRecord(parsed["part"]) ? parsed["part"] : undefined;
        const messageID = part?.["messageID"];
        let messageInfo: Record<string, string> | undefined;
        if (typeof messageID === "string" && messageLookup !== undefined) {
          const message = messageLookup.get(messageID, item.sessionID);
          if (typeof message?.["data"] === "string") {
            const data: unknown = parseObject(message["data"]);
            if (isRecord(data) && (data["role"] === "user" || data["role"] === "assistant")) {
              messageInfo = { id: messageID, role: data["role"], sessionID: item.sessionID };
            }
          }
        }
        records.push({
          adapterId: options.adapterId,
          sourceId: sourceID,
          sourceRecordId: digest(
            `${databaseReal}\u0000${item.sessionID}\u0000${item.row.sequence}`,
          ),
          observedAt,
          initialReplay: options.historical === true,
          value: {
            ...parsed,
            ...(messageInfo === undefined ? {} : { message_info: messageInfo }),
            type: item.row.type,
            timestamp: observedAt.getTime(),
          },
        });
      } catch {
        malformed++;
      }
    }
    const complete = !options.historical || legacy.complete && sessions.every((session) =>
      (options.cursors.get(cursorID(databaseReal, session.aggregateID)) ?? 0) >=
        session.maxSequence
    );
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

function legacyRows(
  database: DatabaseSync,
  databasePath: string,
  cursors: Map<string, number>,
  limit: number,
): { rows: Array<{ sessionID: string; row: EventRow }>; complete: boolean } {
  const tables = database.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name IN ('message','part')").all();
  if (tables.length !== 2) return { rows: [], complete: true };
  const key = cursorID(databasePath, "legacy-parts");
  const values = database.prepare(
    "SELECT p.rowid AS row_id, p.id, p.session_id, p.message_id, p.data, p.time_updated " +
    "FROM part p JOIN message m ON m.id=p.message_id AND m.session_id=p.session_id " +
    "WHERE p.rowid > ? AND NOT EXISTS (SELECT 1 FROM event_sequence e WHERE e.aggregate_id=p.session_id) " +
    "ORDER BY p.rowid LIMIT ?",
  ).all(cursors.get(key) ?? 0, limit + 1);
  const rows: Array<{ sessionID: string; row: EventRow }> = [];
  for (const value of values.slice(0, limit)) {
    if (typeof value["row_id"] !== "number" || typeof value["session_id"] !== "string") continue;
    const part = typeof value["data"] === "string" ? parseObject(value["data"]) : undefined;
    if (part !== undefined) rows.push({ sessionID: value["session_id"], row: {
      sequence: -value["row_id"], type: "message.part.updated.1",
      data: JSON.stringify({ sessionID: value["session_id"], time: value["time_updated"], part: {
        ...part, id: value["id"], messageID: value["message_id"], sessionID: value["session_id"],
      } }),
    } });
    cursors.set(key, value["row_id"]);
  }
  return { rows, complete: values.length <= limit };
}

function parseObject(value: string): Record<string, unknown> | undefined {
  try {
    const parsed: unknown = JSON.parse(value);
    return isRecord(parsed) ? parsed : undefined;
  } catch { return undefined; }
}

/**
 * History rows past each session's cursor. A session with no event row past
 * its cursor is caught up: its cursor moves to the session's sequence
 * counter. OpenCode deletes events once it has applied them to its message
 * tables, so a counter can be far ahead of the newest event row, and without
 * this the import would never count that session as complete.
 */
function unreadRows(
  database: DatabaseSync,
  databasePath: string,
  sessions: readonly SessionSequence[],
  cursors: Map<string, number>,
  limit: number,
): Array<Readonly<{ sessionID: string; row: EventRow }>> {
  return unreadEvents(database, databasePath, sessions, cursors, limit, true).rows;
}

/**
 * Rows past each session's cursor, with what an idle check needs: how many
 * rows the queries selected, valid or not, and each cursor read in order.
 */
function unreadEvents(
  database: DatabaseSync,
  databasePath: string,
  sessions: readonly SessionSequence[],
  cursors: Map<string, number>,
  limit: number,
  catchUp = false,
): Readonly<{
  rows: Array<Readonly<{ sessionID: string; row: EventRow }>>;
  selected: number;
  cursors: Array<readonly [string, number | undefined]>;
}> {
  const result: Array<Readonly<{ sessionID: string; row: EventRow }>> = [];
  const read: Array<readonly [string, number | undefined]> = [];
  let selected = 0;
  const statement = database.prepare(
    "SELECT seq, type, data FROM event " +
      "WHERE aggregate_id = ? AND seq > ? ORDER BY seq ASC LIMIT ?",
  );
  for (const session of sessions) {
    if (result.length >= limit) break;
    const key = cursorID(databasePath, session.aggregateID);
    const saved = cursors.get(key);
    read.push([key, saved]);
    const cursor = saved ?? 0;
    const rows = statement.all(
      session.aggregateID,
      cursor,
      limit - result.length,
    );
    selected += rows.length;
    let newestSequence = cursor;
    for (const value of rows) {
      const row = eventRow(value);
      if (row === undefined) continue;
      newestSequence = Math.max(newestSequence, row.sequence);
      result.push({ sessionID: session.aggregateID, row });
    }
    if (newestSequence > cursor) cursors.set(key, newestSequence);
    else if (catchUp && rows.length === 0 && session.maxSequence > cursor) cursors.set(key, session.maxSequence);
  }
  return { rows: result, selected, cursors: read };
}

function replayRows(
  database: DatabaseSync,
  sessions: readonly SessionSequence[],
  limit: number,
): Array<Readonly<{ sessionID: string; row: EventRow }>> {
  const result: Array<Readonly<{ sessionID: string; row: EventRow }>> = [];
  const statement = database.prepare(
    "SELECT seq, type, data FROM event " +
      "WHERE aggregate_id = ? ORDER BY seq DESC LIMIT ?",
  );
  for (const session of sessions) {
    if (result.length >= limit) break;
    const rows = statement
      .all(session.aggregateID, limit - result.length)
      .map(eventRow)
      .filter((row): row is EventRow => row !== undefined)
      .reverse();
    result.push(...rows.map((row) => ({
      sessionID: session.aggregateID,
      row,
    })));
  }
  return result.slice(-limit);
}

function readSessionSequences(
  database: DatabaseSync,
  limit: number,
): SessionSequence[] {
  const rows = database.prepare(
    "SELECT es.aggregate_id AS aggregate_id, es.seq AS max_seq " +
      "FROM event_sequence es " +
      "JOIN session s ON s.id = es.aggregate_id " +
      "ORDER BY s.time_updated DESC, es.aggregate_id ASC LIMIT ?",
  ).all(limit);
  const result: SessionSequence[] = [];
  for (const value of rows) {
    if (!isRecord(value)) continue;
    const aggregateID = value["aggregate_id"];
    const maxSequence = value["max_seq"];
    if (
      typeof aggregateID === "string" &&
      aggregateID.length > 0 &&
      Buffer.byteLength(aggregateID, "utf8") <= 128 &&
      !/[\u0000-\u001f\u007f]/u.test(aggregateID) &&
      typeof maxSequence === "number" &&
      Number.isSafeInteger(maxSequence) &&
      maxSequence >= 0
    ) {
      result.push({ aggregateID, maxSequence });
    }
  }
  return result;
}

function eventRow(value: unknown): EventRow | undefined {
  if (!isRecord(value)) return undefined;
  const sequence = value["seq"];
  const type = value["type"];
  const data = value["data"];
  if (
    typeof sequence !== "number" ||
    !Number.isSafeInteger(sequence) ||
    sequence < 0 ||
    typeof type !== "string" ||
    type.length === 0 ||
    Buffer.byteLength(type, "utf8") > 128 ||
    typeof data !== "string"
  ) {
    return undefined;
  }
  return { sequence, type, data };
}

function eventObservedAt(
  event: Record<string, unknown>,
  fallback: Date,
): Date {
  const part = isRecord(event["part"]) ? event["part"] : undefined;
  const partTime = isRecord(part?.["time"]) ? part["time"] : undefined;
  const info = isRecord(event["info"]) ? event["info"] : undefined;
  const infoTime = isRecord(info?.["time"]) ? info["time"] : undefined;
  for (const candidate of [
    event["time"],
    partTime?.["end"],
    partTime?.["start"],
    infoTime?.["completed"],
    infoTime?.["updated"],
    infoTime?.["created"],
  ]) {
    if (typeof candidate !== "number" || !Number.isFinite(candidate)) {
      continue;
    }
    const parsed = new Date(candidate);
    if (!Number.isNaN(parsed.getTime())) return parsed;
  }
  return fallback;
}

function hasSupportedSchema(database: DatabaseSync): boolean {
  const rows = database.prepare(
    "SELECT name FROM sqlite_schema WHERE type = 'table' " +
      "AND name IN ('event', 'event_sequence', 'session')",
  ).all();
  return new Set(rows.flatMap((value) =>
    isRecord(value) && typeof value["name"] === "string"
      ? [value["name"]]
      : []
  )).size === 3;
}

function cursorID(databasePath: string, scope: string): string {
  return digest(`opencode-sqlite-v1:${databasePath}\u0000${scope}`);
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
      "ESTALE",
    ].includes(String(error.code)) ||
    /database is locked|unable to open database file/iu.test(error.message)
  );
}
