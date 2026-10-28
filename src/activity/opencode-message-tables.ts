import type { DatabaseSync, SQLInputValue } from "node:sqlite";

/**
 * OpenCode 1 keeps each conversation in its `message` and `part` tables and
 * also records an event log in `event`. OpenCode 2 deletes every event row on
 * its first start and records new ones only when configured to, so a session
 * can exist only as table rows. These functions read the rows of sessions
 * that have no event row. A session with event rows is read from its events
 * instead, never from both.
 *
 * OpenCode rewrites a part row in place while a reply streams, so a row is
 * delivered once it is final: when its own fields mark it finished, when its
 * message is complete, or when it has not changed for `settleMilliseconds`.
 * Records keep OpenCode's own message and part ids, so a row read again (by
 * the history import and the live reader, say) keeps one record identity.
 */

/** A row unchanged this long is final even without a finish marker. */
export const settleMilliseconds = 10 * 60_000;
/** Unfinished rows a live reader waits for, per table. */
const maxPendingRows = 32;
/** Rows one scan selects from one table. */
const maxRowsPerScan = 1_024;
/** Newest rows a live reader checks for unfinished work when it starts. */
const startRows = 64;
const maxRowBytes = 1 << 20;

type Table = "message" | "part";
const tables: readonly Table[] = ["message", "part"];

export type TableColumns = Readonly<Record<Table, ReadonlySet<string>>>;

export type TableItem = Readonly<{
  sessionID: string;
  /** Distinguishes the record within its session. */
  key: string;
  type: string;
  value: Record<string, unknown>;
  /** The part's message id and role, when its message names one. */
  messageInfo: Readonly<Record<string, string>> | undefined;
}>;

export type TableScan = Readonly<{
  items: readonly TableItem[];
  malformed: number;
  oversized: number;
  /** History: every row has been read. */
  complete: boolean;
  /** Live: the cursors read, in order, when the scan changed nothing. */
  idle: ReadonlyArray<readonly [string, number | undefined]> | undefined;
  /** Live: when the first unfinished row settles, so an idle scan is stale. */
  recheckAt: number | undefined;
}>;

type Context = Readonly<{
  database: DatabaseSync;
  columns: TableColumns;
  cursors: Map<string, number>;
  /** The cursor key for a scope within this database. */
  key: (scope: string) => string;
  now: number;
}>;

type TableRow = Readonly<{
  rowID: number;
  sessionID: string;
  hasEvents: boolean;
  hasSequence: boolean;
  /** time_updated, or 0 when the table has none. */
  updated: number;
  problem: "malformed" | "oversized" | undefined;
  /** Finished by its own fields or its message. */
  finished: boolean;
  item: TableItem | undefined;
}>;

/** The message and part columns, or undefined without both tables. */
export function tableColumns(database: DatabaseSync): TableColumns | undefined {
  const found: Record<Table, Set<string>> = { message: new Set(), part: new Set() };
  const rows = database.prepare(
    "SELECT t.name AS table_name, c.name AS column_name FROM sqlite_schema t " +
      "JOIN pragma_table_info(t.name) c WHERE t.type = 'table' AND t.name IN ('message', 'part')",
  ).all();
  for (const value of rows) {
    const table = value["table_name"];
    const column = value["column_name"];
    if ((table === "message" || table === "part") && typeof column === "string") {
      found[table].add(column);
    }
  }
  const required: Record<Table, readonly string[]> = {
    message: ["id", "session_id", "data"],
    part: ["id", "message_id", "session_id", "data"],
  };
  return tables.every((table) => required[table].every((column) => found[table].has(column)))
    ? found
    : undefined;
}

/**
 * History: rows after each table's cursor, up to `limit` records. Rows of a
 * session with event rows are left to the event log. So are rows of a
 * session whose events this import already delivered, even after OpenCode
 * deleted those events, and part rows an earlier import read by row id.
 * A row still being written is left to the live reader.
 */
export function historyTableRows(
  context: Context & Readonly<{
    limit: number;
    deliveredByEvents: (sessionID: string) => boolean;
    /** Parts with this row id or lower were imported for sessions without a sequence. */
    importedParts: number;
  }>,
): TableScan {
  const items: TableItem[] = [];
  let malformed = 0;
  let oversized = 0;
  let complete = true;
  for (const table of tables) {
    const limit = Math.min(maxRowsPerScan, context.limit - items.length);
    if (limit <= 0) {
      complete = false;
      break;
    }
    const cursorKey = context.key(`history:${table}`);
    const cursor = context.cursors.get(cursorKey) ?? 0;
    const rows = selectRows(
      context,
      table,
      "t.rowid > ? AND NOT EXISTS (SELECT 1 FROM event e WHERE e.aggregate_id = t.session_id)",
      [cursor],
      "ASC",
      limit,
    );
    for (const row of rows) {
      if (row.problem === "malformed") malformed++;
      else if (row.problem === "oversized") oversized++;
      else if (
        row.item !== undefined &&
        !row.hasEvents &&
        (row.finished || settled(row, context.now)) &&
        !(table === "part" && !row.hasSequence && row.rowID <= context.importedParts) &&
        !context.deliveredByEvents(row.sessionID)
      ) {
        items.push(row.item);
      }
    }
    const last = rows.at(-1);
    if (last !== undefined) context.cursors.set(cursorKey, last.rowID);
    if (rows.length >= limit) complete = false;
  }
  return { items, malformed, oversized, complete, idle: undefined, recheckAt: undefined };
}

/**
 * Live: rows added since the previous scan and held-back rows that are now
 * final, up to `limit` records. A database seen for the first time starts at
 * the end of each table; a first start may replay its newest final rows.
 */
export function liveTableRows(
  context: Context & Readonly<{ limit: number; replay: number }>,
): TableScan {
  const items: TableItem[] = [];
  const read: Array<readonly [string, number | undefined]> = [];
  let malformed = 0;
  let oversized = 0;
  let idle = true;
  let recheckAt: number | undefined;
  for (const table of tables) {
    // A replay shows recent conversation, which the parts hold.
    const result = liveTable(
      context,
      table,
      context.limit - items.length,
      table === "part" ? context.replay : 0,
      read,
    );
    items.push(...result.items);
    malformed += result.malformed;
    oversized += result.oversized;
    idle = idle && result.idle;
    if (result.recheckAt !== undefined) {
      recheckAt = Math.min(recheckAt ?? result.recheckAt, result.recheckAt);
    }
  }
  return {
    items,
    malformed,
    oversized,
    complete: true,
    idle: idle ? read : undefined,
    recheckAt,
  };
}

function liveTable(
  context: Context,
  table: Table,
  budget: number,
  replay: number,
  read: Array<readonly [string, number | undefined]>,
): Readonly<{
  items: TableItem[];
  malformed: number;
  oversized: number;
  idle: boolean;
  recheckAt: number | undefined;
}> {
  const items: TableItem[] = [];
  let malformed = 0;
  let oversized = 0;
  const count = (row: TableRow) => {
    if (row.problem === "malformed") malformed++;
    else if (row.problem === "oversized") oversized++;
  };
  const cursorKey = context.key(`rows:${table}`);
  const saved = context.cursors.get(cursorKey);
  read.push([cursorKey, saved]);
  const newest = maxRowID(context.database, table);
  const kept: TableRow[] = [];

  if (saved === undefined) {
    // Older rows are the history import's. Rows still being written are
    // waited for, and a first start may replay the newest final rows.
    const finals: TableItem[] = [];
    for (const row of selectRows(context, table, "1", [], "DESC", startRows).reverse()) {
      if (row.hasEvents || row.item === undefined) continue;
      if (row.finished || settled(row, context.now)) finals.push(row.item);
      else if (kept.length < maxPendingRows) kept.push(row);
    }
    const replayed = Math.min(replay, budget);
    if (replayed > 0) items.push(...finals.slice(-replayed));
    context.cursors.set(cursorKey, newest);
    writePending(context, table, kept);
    return { items, malformed, oversized, idle: false, recheckAt: recheckTime(kept) };
  }

  // When the newest rows were deleted (a revert), rows written after them
  // reuse their row ids, so reading resumes at the new end.
  let cursor = Math.min(saved, newest);
  const stored = readPending(context, table, read);
  const pending = stored.rowIDs.filter((rowID) => rowID <= cursor);
  let changed = cursor !== saved || pending.length !== (stored.count ?? 0);
  if (pending.length > 0) {
    const rows = new Map(selectRows(
      context,
      table,
      `t.rowid IN (${pending.map(() => "?").join(", ")})`,
      pending,
      "ASC",
      pending.length,
    ).map((row) => [row.rowID, row]));
    for (const rowID of pending) {
      const row = rows.get(rowID);
      if (row === undefined || row.hasEvents || row.item === undefined) {
        // Deleted, now read from the session's events, or no longer valid.
        if (row !== undefined) count(row);
        changed = true;
      } else if (!(row.finished || settled(row, context.now)) || items.length >= budget) {
        kept.push(row);
      } else {
        items.push(row.item);
        changed = true;
      }
    }
  }

  let looked = false;
  let selected = 0;
  if (items.length < budget) {
    looked = true;
    // Rows past the record budget would only be read again next scan.
    const limit = Math.min(maxRowsPerScan, budget - items.length + maxPendingRows);
    const rows = selectRows(context, table, "t.rowid > ?", [cursor], "ASC", limit);
    selected = rows.length;
    for (const row of rows) {
      if (!row.hasEvents && row.item !== undefined) {
        if (row.finished || settled(row, context.now)) {
          if (items.length >= budget) break;
          items.push(row.item);
        } else {
          // Full: stop here and read this row again next scan.
          if (kept.length >= maxPendingRows) break;
          kept.push(row);
        }
      } else {
        count(row);
      }
      cursor = row.rowID;
    }
  }
  if (cursor !== saved) context.cursors.set(cursorKey, cursor);
  if (changed || kept.length !== pending.length) writePending(context, table, kept);
  return {
    items,
    malformed,
    oversized,
    idle: looked && selected === 0 && !changed && kept.length === pending.length,
    recheckAt: recheckTime(kept),
  };
}

function settled(row: TableRow, now: number): boolean {
  return row.updated <= 0 || now - row.updated >= settleMilliseconds;
}

function recheckTime(rows: readonly TableRow[]): number | undefined {
  let earliest: number | undefined;
  for (const row of rows) {
    if (row.updated <= 0) continue;
    const at = row.updated + settleMilliseconds;
    earliest = Math.min(earliest ?? at, at);
  }
  return earliest;
}

/**
 * Held-back row ids and how many were stored, recording each cursor read
 * for the idle check.
 */
function readPending(
  context: Context,
  table: Table,
  read: Array<readonly [string, number | undefined]>,
): Readonly<{ rowIDs: number[]; count: number | undefined }> {
  const countKey = context.key(`pending:${table}`);
  const count = context.cursors.get(countKey);
  read.push([countKey, count]);
  const rowIDs: number[] = [];
  for (let index = 0; index < Math.min(count ?? 0, maxPendingRows); index++) {
    const key = context.key(`pending:${table}:${index}`);
    const rowID = context.cursors.get(key);
    read.push([key, rowID]);
    if (rowID !== undefined && Number.isSafeInteger(rowID) && rowID > 0) rowIDs.push(rowID);
  }
  return { rowIDs, count };
}

function writePending(context: Context, table: Table, rows: readonly TableRow[]): void {
  const countKey = context.key(`pending:${table}`);
  const previous = Math.min(context.cursors.get(countKey) ?? 0, maxPendingRows);
  if (rows.length === 0) context.cursors.delete(countKey);
  else context.cursors.set(countKey, rows.length);
  for (let index = 0; index < Math.max(previous, rows.length); index++) {
    const key = context.key(`pending:${table}:${index}`);
    const row = rows[index];
    if (row === undefined) context.cursors.delete(key);
    else context.cursors.set(key, row.rowID);
  }
}

function maxRowID(database: DatabaseSync, table: Table): number {
  const value = database.prepare(`SELECT max(rowid) AS row_id FROM ${table}`).get()?.["row_id"];
  return typeof value === "number" && Number.isSafeInteger(value) ? value : 0;
}

/**
 * Rows of one table. A row of a session with event rows is returned without
 * its data, so skipping it never reads a large tool output.
 */
function selectRows(
  context: Context,
  table: Table,
  where: string,
  parameters: readonly SQLInputValue[],
  order: "ASC" | "DESC",
  limit: number,
): TableRow[] {
  const columns = context.columns[table];
  const hasEvents = "EXISTS (SELECT 1 FROM event e WHERE e.aggregate_id = t.session_id)";
  const common =
    "t.rowid AS row_id, t.id AS id, t.session_id AS session_id, " +
    `${columns.has("time_updated") ? "t.time_updated" : "0"} AS updated, ` +
    `${columns.has("time_created") ? "t.time_created" : "NULL"} AS created, ` +
    `${hasEvents} AS has_events, ` +
    "EXISTS (SELECT 1 FROM event_sequence s WHERE s.aggregate_id = t.session_id) AS has_sequence, " +
    `CASE WHEN ${hasEvents} THEN NULL ELSE t.data END AS data`;
  const sql = table === "message"
    ? `SELECT ${common} FROM message t`
    : `SELECT ${common}, t.message_id AS message_id, ` +
      "CASE WHEN json_valid(m.data) THEN json_extract(m.data, '$.role') END AS role, " +
      // Matches the message rule in tableRow: a completion time or an error.
      "CASE WHEN json_valid(m.data) THEN " +
      "coalesce(json_type(m.data, '$.time.completed') IN ('integer', 'real'), 0) " +
      "OR coalesce(json_type(m.data, '$.error') <> 'null', 0) END AS message_done " +
      "FROM part t LEFT JOIN message m ON m.id = t.message_id AND m.session_id = t.session_id";
  return context.database
    .prepare(`${sql} WHERE ${where} ORDER BY t.rowid ${order} LIMIT ?`)
    .all(...parameters, limit)
    .flatMap((value) => tableRow(table, value));
}

function tableRow(table: Table, value: Record<string, unknown>): TableRow[] {
  const rowID = value["row_id"];
  if (typeof rowID !== "number" || !Number.isSafeInteger(rowID)) return [];
  const sessionID = value["session_id"];
  const id = value["id"];
  const updated = value["updated"];
  const base = {
    rowID,
    sessionID: typeof sessionID === "string" ? sessionID : "",
    hasEvents: value["has_events"] === 1,
    hasSequence: value["has_sequence"] === 1,
    updated: typeof updated === "number" && Number.isFinite(updated) ? updated : 0,
  };
  if (base.hasEvents) return [{ ...base, problem: undefined, finished: true, item: undefined }];
  const malformed = { ...base, problem: "malformed" as const, finished: true, item: undefined };
  const raw = value["data"];
  if (typeof raw !== "string" || !validID(sessionID) || !validID(id)) return [malformed];
  if (Buffer.byteLength(raw, "utf8") > maxRowBytes) {
    return [{ ...base, problem: "oversized", finished: true, item: undefined }];
  }
  const data = parseObject(raw);
  if (data === undefined) return [malformed];

  if (table === "message") {
    const time = objectField(data, "time");
    // A user message is written complete. An assistant message is complete
    // once OpenCode records when it finished or why it failed.
    const finished = data["role"] !== "assistant" ||
      typeof time?.["completed"] === "number" ||
      (data["error"] !== undefined && data["error"] !== null);
    return [{
      ...base,
      problem: undefined,
      finished,
      item: {
        sessionID,
        key: `message:${id}`,
        type: "message.updated.1",
        value: { sessionID, info: { ...data, id, sessionID } },
        messageInfo: undefined,
      },
    }];
  }

  const messageID = value["message_id"];
  if (!validID(messageID)) return [malformed];
  const role = value["role"];
  const time = partTime(data, value["created"], base.updated);
  return [{
    ...base,
    problem: undefined,
    finished: value["message_done"] === 1 || role === "user" || partFinished(data),
    item: {
      sessionID,
      key: `part:${id}`,
      type: "message.part.updated.1",
      value: {
        sessionID,
        ...(time === undefined ? {} : { time }),
        part: { ...data, id, messageID, sessionID },
      },
      messageInfo: role === "user" || role === "assistant"
        ? { id: messageID, role, sessionID }
        : undefined,
    },
  }];
}

/** Whether a part's own fields mark it finished. */
function partFinished(part: Record<string, unknown>): boolean {
  const type = part["type"];
  if (type === "text" || type === "reasoning") {
    return typeof objectField(part, "time")?.["end"] === "number";
  }
  if (type === "tool") {
    const status = objectField(part, "state")?.["status"];
    return status === "completed" || status === "error";
  }
  // Other parts (step boundaries, patches, files) are written once.
  return true;
}

/** When the part happened: its own end or start, else when it was written. */
function partTime(
  part: Record<string, unknown>,
  created: unknown,
  updated: number,
): number | undefined {
  const time = objectField(part, "time");
  const stateTime = objectField(objectField(part, "state") ?? {}, "time");
  for (const candidate of [
    time?.["end"],
    stateTime?.["end"],
    time?.["start"],
    stateTime?.["start"],
    created,
    updated,
  ]) {
    if (typeof candidate === "number" && Number.isFinite(candidate) && candidate > 0) {
      return candidate;
    }
  }
  return undefined;
}

function validID(value: unknown): value is string {
  return typeof value === "string" &&
    value.length > 0 &&
    Buffer.byteLength(value, "utf8") <= 128 &&
    !/[\u0000-\u001f\u007f]/u.test(value);
}

function objectField(
  value: Record<string, unknown>,
  field: string,
): Record<string, unknown> | undefined {
  const nested = value[field];
  return typeof nested === "object" && nested !== null && !Array.isArray(nested)
    ? nested as Record<string, unknown>
    : undefined;
}

function parseObject(value: string): Record<string, unknown> | undefined {
  try {
    const parsed: unknown = JSON.parse(value);
    return typeof parsed === "object" && parsed !== null && !Array.isArray(parsed)
      ? parsed as Record<string, unknown>
      : undefined;
  } catch {
    return undefined;
  }
}
