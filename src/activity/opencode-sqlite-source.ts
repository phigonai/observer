import { createHash } from "node:crypto";
import { realpath, stat } from "node:fs/promises";
import { join, relative, resolve, sep } from "node:path";
import { DatabaseSync } from "node:sqlite";
import {
  historyTableRows,
  liveTableRows,
  readableTables,
  type TableScan,
  tableColumns,
} from "./opencode-message-tables.js";
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
  /** The time in milliseconds, for deciding when a row has settled. */
  clock?: () => number;
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
    // Sessions without event rows exist only in the message tables (see
    // opencode-message-tables.ts). Each row is read from one place: its
    // session's events when it has any, else the tables. A database only
    // OpenCode 2 has used may have no OpenCode 1 event log at all.
    const hasEvents = hasSupportedSchema(database);
    const columns = tableColumns(database);
    const hasTables = readableTables(columns).length > 0;
    if (!hasEvents && !hasTables) {
      scan?.finish(undefined);
      return { records: [], files: 1, malformed: 1, oversized: 0, complete: true };
    }
    const sessions = hasEvents
      ? readSessionSequences(database, options.historical ? -1 : maxTrackedSessions)
      : [];
    const marker = cursorID(databaseReal, "initialized");
    const firstDatabaseScan = options.cursors.get(marker) !== 1;
    const tableContext = (limit: number) => ({
      database,
      columns,
      cursors: options.cursors,
      key: (scope: string) => cursorID(databaseReal, scope),
      now: (options.clock ?? Date.now)(),
      limit: Math.max(0, limit),
    });
    let rows: Array<Readonly<{ sessionID: string; row: EventRow }>> = [];
    let tables: TableScan | undefined;
    let eventsComplete = true;
    let idle: IdleCursors | undefined;

    if (options.historical) {
      const unread = unreadEvents(
        database,
        databaseReal,
        sessions,
        options.cursors,
        options.maxReplayRecords,
      );
      rows = unread.rows;
      eventsComplete = unread.exhausted;
      if (hasTables) {
        tables = historyTableRows({
          ...tableContext(options.maxReplayRecords - rows.length),
          // A history cursor is set only by delivering events, so a session
          // stays with its event log even once OpenCode deletes those events.
          deliveredByEvents: (sessionID) =>
            options.cursors.get(cursorID(databaseReal, sessionID)) !== undefined,
          importedParts: options.cursors.get(cursorID(databaseReal, "legacy-parts")) ?? 0,
        });
      }
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
      if (hasTables) {
        const limit = options.maxReplayRecords - rows.length;
        tables = liveTableRows({
          ...tableContext(limit),
          replay: options.initialScan && options.replayOnFirstStart ? limit : 0,
        });
      }
      options.cursors.set(marker, 1);
    } else {
      const limit = Math.min(maxDatabaseEventsPerScan, options.maxReplayRecords);
      const unread = unreadEvents(
        database,
        databaseReal,
        sessions.slice(0, maxLiveSessionsPerScan),
        options.cursors,
        limit,
      );
      rows = unread.rows;
      if (hasTables) {
        tables = liveTableRows({ ...tableContext(limit - rows.length), replay: 0 });
      }
      if (unread.selected === 0 && (!hasTables || tables?.idle !== undefined)) {
        // No session had any row past its cursor, so the row limit did not
        // matter: the same database and cursors give the same empty scan,
        // until a row the tables wait for settles.
        idle = [[marker, 1], ...unread.cursors, ...tables?.idle ?? []];
      }
    }

    const sourceID = `ses_${digest(databaseReal).slice(0, 32)}`;
    const hasMessages = columns.has("message");
    const messageLookup = hasMessages
      ? database.prepare("SELECT id, session_id, data FROM message WHERE id = ? AND session_id = ?")
      : undefined;
    const records: SourceRecord[] = [];
    let malformed = tables?.malformed ?? 0;
    let oversized = tables?.oversized ?? 0;
    const record = (
      sessionID: string,
      key: string,
      type: string,
      parsed: Record<string, unknown>,
      messageInfo: Readonly<Record<string, string>> | undefined,
    ): SourceRecord => {
      const observedAt = eventObservedAt(parsed, metadata.mtime);
      return {
        adapterId: options.adapterId,
        sourceId: sourceID,
        sourceRecordId: digest(`${databaseReal}\u0000${sessionID}\u0000${key}`),
        observedAt,
        initialReplay: options.historical === true,
        value: {
          ...parsed,
          ...(messageInfo === undefined ? {} : { message_info: messageInfo }),
          type,
          timestamp: observedAt.getTime(),
        },
      };
    };
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
        records.push(record(item.sessionID, String(item.row.sequence), item.row.type, parsed, messageInfo));
      } catch {
        malformed++;
      }
    }
    // Table records carry the role their query joined, so no lookup.
    for (const item of tables?.items ?? []) {
      records.push(record(item.sessionID, item.key, item.type, item.value, item.messageInfo));
    }
    const complete = !options.historical || eventsComplete && (tables?.complete ?? true);
    scan?.finish(idle, tables?.recheckAt);
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

function parseObject(value: string): Record<string, unknown> | undefined {
  try {
    const parsed: unknown = JSON.parse(value);
    return isRecord(parsed) ? parsed : undefined;
  } catch { return undefined; }
}

/**
 * Rows past each session's cursor, with what an idle check needs: how many
 * rows the queries selected, valid or not, and each cursor read in order.
 * `exhausted` is true when every session was read to its last row.
 *
 * A cursor moves only past rows its query returned. A session's counter can
 * be far ahead of its newest event row (OpenCode 2 deletes every event row
 * when it first starts, and later bumps the counter without keeping rows),
 * so a history import counts a session as read once its query comes back
 * short, not once its cursor reaches the counter.
 */
function unreadEvents(
  database: DatabaseSync,
  databasePath: string,
  sessions: readonly SessionSequence[],
  cursors: Map<string, number>,
  limit: number,
): Readonly<{
  rows: Array<Readonly<{ sessionID: string; row: EventRow }>>;
  selected: number;
  cursors: Array<readonly [string, number | undefined]>;
  exhausted: boolean;
}> {
  if (sessions.length === 0) return { rows: [], selected: 0, cursors: [], exhausted: true };
  const result: Array<Readonly<{ sessionID: string; row: EventRow }>> = [];
  const read: Array<readonly [string, number | undefined]> = [];
  let selected = 0;
  let visited = 0;
  const statement = database.prepare(
    "SELECT seq, type, data FROM event " +
      "WHERE aggregate_id = ? AND seq > ? ORDER BY seq ASC LIMIT ?",
  );
  for (const session of sessions) {
    if (result.length >= limit) break;
    visited++;
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
  }
  return {
    rows: result,
    selected,
    cursors: read,
    // Each query asked for every row left in the limit, so a total below
    // the limit means each one returned all it had.
    exhausted: visited === sessions.length && selected < limit,
  };
}

function replayRows(
  database: DatabaseSync,
  sessions: readonly SessionSequence[],
  limit: number,
): Array<Readonly<{ sessionID: string; row: EventRow }>> {
  if (sessions.length === 0) return [];
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
