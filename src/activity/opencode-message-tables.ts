import type { DatabaseSync, SQLInputValue } from "node:sqlite";

/**
 * OpenCode 1 keeps each conversation in its `message` and `part` tables and
 * also records an event log in `event`. OpenCode 2 deletes every event row on
 * its first start and records new ones only when configured to, so a session
 * can exist only as table rows. These functions read the rows of sessions
 * that have no event row. A session with event rows is read from its events
 * instead, never from both.
 *
 * OpenCode 2 keeps each message as one `session_message` row (its parts are
 * items inside it) and copies every OpenCode 1 session into that table on
 * its first start, keeping the session id and each message's creation time.
 * A copied row is left to the OpenCode 1 rows it came from: a row counts as
 * copied when its session has an OpenCode 1 message at least as new. Rows
 * added to a copied session later are OpenCode 2's own.
 *
 * OpenCode rewrites a row in place while a reply streams, so a row is
 * delivered once it is final: when its own fields mark it finished, when its
 * message is complete, or when it has not changed for `settleMilliseconds`.
 * Records keep OpenCode's own ids, so a row read again (by the history import
 * and the live reader, say) keeps the same record identities.
 */

/** A row unchanged this long is final even without a finish marker. */
export const settleMilliseconds = 10 * 60_000;
/** Unfinished rows a live reader waits for, per table. */
const maxPendingRows = 32;
/** Rows one scan selects from one table. */
const maxRowsPerScan = 1_024;
/** Newest rows a live reader checks for unfinished work when it starts. */
const startRows = 64;
/** The largest record; a larger OpenCode 2 item is left out. */
const maxRecordBytes = 1 << 20;
/** An OpenCode 2 row holds a whole message, every tool output included. */
const maxMessageRowBytes = 32 << 20;

type Table = "message" | "part" | "session_message";

/** The columns of each table these functions read or consult, by table name. */
export type TableColumns = ReadonlyMap<string, ReadonlySet<string>>;

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
  /**
   * Read from another place instead: the session's event log, or for a
   * copied OpenCode 1 message, its OpenCode 1 rows.
   */
  elsewhere: boolean;
  hasSequence: boolean;
  /** time_updated, or 0 when the table has none. */
  updated: number;
  problem: "malformed" | "oversized" | undefined;
  /** Finished by its own fields or its message. */
  finished: boolean;
  /** The row's records; none for a problem or a row read elsewhere. */
  items: readonly TableItem[];
  /** Records the row would have had but for their size. */
  oversizedItems: number;
}>;

const requiredColumns: Readonly<Record<Table, readonly string[]>> = {
  message: ["id", "session_id", "data"],
  part: ["id", "message_id", "session_id", "data"],
  session_message: ["id", "session_id", "type", "data"],
};

/** The columns of OpenCode's message tables and event log tables. */
export function tableColumns(database: DatabaseSync): TableColumns {
  const found = new Map<string, Set<string>>();
  const rows = database.prepare(
    "SELECT t.name AS table_name, c.name AS column_name FROM sqlite_schema t " +
      "JOIN pragma_table_info(t.name) c WHERE t.type = 'table' " +
      "AND t.name IN ('message', 'part', 'session_message', 'event', 'event_sequence')",
  ).all();
  for (const value of rows) {
    const table = value["table_name"];
    const column = value["column_name"];
    if (typeof table !== "string" || typeof column !== "string") continue;
    const columns = found.get(table) ?? new Set<string>();
    columns.add(column);
    found.set(table, columns);
  }
  return found;
}

/**
 * The tables to read: OpenCode 1's message and part tables when both exist,
 * and OpenCode 2's session_message table.
 */
export function readableTables(columns: TableColumns): readonly Table[] {
  const complete = (table: Table) =>
    requiredColumns[table].every((column) => columns.get(table)?.has(column) === true);
  return [
    ...complete("message") && complete("part") ? ["message", "part"] as const : [],
    ...complete("session_message") ? ["session_message"] as const : [],
  ];
}

/**
 * History: rows after each table's cursor, up to about `limit` records. Rows
 * of a session with event rows are left to the event log. So are rows of a
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
  for (const table of readableTables(context.columns)) {
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
      `t.rowid > ? AND NOT ${elsewhere(context.columns, table)}`,
      [cursor],
      "ASC",
      limit,
    );
    for (const row of rows) {
      if (row.problem === "malformed") malformed++;
      else if (row.problem === "oversized") oversized++;
      else if (
        !row.elsewhere &&
        (row.finished || settled(row, context.now)) &&
        !(table === "part" && !row.hasSequence && row.rowID <= context.importedParts) &&
        // Only OpenCode 1 rows can repeat what an event log delivered.
        (table === "session_message" || !context.deliveredByEvents(row.sessionID))
      ) {
        items.push(...row.items);
        oversized += row.oversizedItems;
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
 * final, up to about `limit` records. A database seen for the first time
 * starts at the end of each table; a first start may replay its newest final
 * rows.
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
  for (const table of readableTables(context.columns)) {
    // A replay shows recent conversation, which parts and messages hold.
    const result = liveTable(
      context,
      table,
      context.limit - items.length,
      table === "message" ? 0 : Math.max(0, context.replay - items.length),
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
  const deliver = (row: TableRow) => {
    items.push(...row.items);
    oversized += row.oversizedItems;
  };
  const readable = (row: TableRow) => !row.elsewhere && row.problem === undefined;
  const cursorKey = context.key(`rows:${table}`);
  const saved = context.cursors.get(cursorKey);
  read.push([cursorKey, saved]);
  const newest = maxRowID(context.database, table);
  const kept: TableRow[] = [];

  if (saved === undefined) {
    // Older rows are the history import's. Rows still being written are
    // waited for, and a first start may replay the newest final rows.
    const finals: TableRow[] = [];
    for (const row of selectRows(context, table, "1", [], "DESC", startRows).reverse()) {
      if (!readable(row)) continue;
      if (row.finished || settled(row, context.now)) finals.push(row);
      else if (kept.length < maxPendingRows) kept.push(row);
    }
    // The newest final rows, until they hold the replay's records.
    const limit = Math.min(replay, budget);
    let start = finals.length;
    for (let total = 0; start > 0 && total < limit; start--) {
      total += finals[start - 1]?.items.length ?? 0;
    }
    for (const row of finals.slice(start)) deliver(row);
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
      if (row === undefined || !readable(row)) {
        // Deleted, now read from elsewhere, or no longer valid.
        if (row !== undefined) count(row);
        changed = true;
      } else if (!(row.finished || settled(row, context.now)) || items.length >= budget) {
        kept.push(row);
      } else {
        deliver(row);
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
      if (readable(row)) {
        if (row.finished || settled(row, context.now)) {
          if (items.length >= budget) break;
          deliver(row);
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
 * SQL, over the table alias `t`, that is true when a row is read from
 * another place: a session with event rows is read from its events, and an
 * OpenCode 2 row copied from OpenCode 1 from the OpenCode 1 rows.
 */
function elsewhere(columns: TableColumns, table: Table): string {
  if (table !== "session_message") {
    return columns.get("event")?.has("aggregate_id") === true
      ? "EXISTS (SELECT 1 FROM event e WHERE e.aggregate_id = t.session_id)"
      : "0";
  }
  const message = columns.get("message");
  if (message?.has("session_id") !== true) return "0";
  // A copied row keeps its OpenCode 1 creation time, so an OpenCode 1
  // message at least as new means the row came from OpenCode 1. Without
  // those times, a session with OpenCode 1 messages is left to them.
  return message.has("time_created") && columns.get("session_message")?.has("time_created") === true
    ? "EXISTS (SELECT 1 FROM message v WHERE v.session_id = t.session_id AND v.time_created >= t.time_created)"
    : "EXISTS (SELECT 1 FROM message v WHERE v.session_id = t.session_id)";
}

/**
 * Rows of one table. A row read elsewhere is returned without its data, so
 * skipping it never reads a large tool output.
 */
function selectRows(
  context: Context,
  table: Table,
  where: string,
  parameters: readonly SQLInputValue[],
  order: "ASC" | "DESC",
  limit: number,
): TableRow[] {
  const columns = context.columns.get(table) ?? new Set<string>();
  const readElsewhere = elsewhere(context.columns, table);
  const hasSequence = context.columns.get("event_sequence")?.has("aggregate_id") === true
    ? "EXISTS (SELECT 1 FROM event_sequence s WHERE s.aggregate_id = t.session_id)"
    : "0";
  const common =
    "t.rowid AS row_id, t.id AS id, t.session_id AS session_id, " +
    `${columns.has("time_updated") ? "t.time_updated" : "0"} AS updated, ` +
    `${columns.has("time_created") ? "t.time_created" : "NULL"} AS created, ` +
    `${readElsewhere} AS elsewhere, ` +
    `${hasSequence} AS has_sequence, ` +
    `CASE WHEN ${readElsewhere} THEN NULL ELSE t.data END AS data`;
  const sql = table === "message"
    ? `SELECT ${common} FROM message t`
    : table === "session_message"
    ? `SELECT ${common}, t.type AS row_type FROM session_message t`
    : `SELECT ${common}, t.message_id AS message_id, ` +
      "CASE WHEN json_valid(m.data) THEN json_extract(m.data, '$.role') END AS role, " +
      // Matches the message rule in parseMessage: a completion time or an error.
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
    elsewhere: value["elsewhere"] === 1,
    hasSequence: value["has_sequence"] === 1,
    updated: typeof updated === "number" && Number.isFinite(updated) ? updated : 0,
  };
  const none = { finished: true, items: [], oversizedItems: 0 };
  if (base.elsewhere) return [{ ...base, ...none, problem: undefined }];
  const malformed = { ...base, ...none, problem: "malformed" as const };
  const raw = value["data"];
  if (typeof raw !== "string" || !validID(sessionID) || !validID(id)) return [malformed];
  const limit = table === "session_message" ? maxMessageRowBytes : maxRecordBytes;
  if (Buffer.byteLength(raw, "utf8") > limit) {
    return [{ ...base, ...none, problem: "oversized" }];
  }
  const data = parseObject(raw);
  if (data === undefined) return [malformed];
  const parsed = table === "message"
    ? parseMessage(data, id, sessionID)
    : table === "session_message"
    ? parseSessionMessage(data, id, sessionID, value["row_type"], value["created"])
    : parsePart(data, id, sessionID, value, base.updated);
  return parsed === undefined
    ? [malformed]
    : [{ ...base, oversizedItems: 0, problem: undefined, ...parsed }];
}

type ParsedRow = Readonly<{
  finished: boolean;
  items: readonly TableItem[];
  oversizedItems?: number;
}>;

/** The list inside an OpenCode 2 message whose entries become records. */
const sessionMessageItems: Readonly<Record<string, Readonly<{ field: string; type?: string }>>> = {
  assistant: { field: "content" },
  user: { field: "files", type: "file" },
};

/**
 * An OpenCode 2 message: one record for the message, without its parts,
 * and one per part (an assistant's text, reasoning and tool calls, or a
 * user's files), so a long reply never becomes one oversized record.
 */
function parseSessionMessage(
  data: Record<string, unknown>,
  id: string,
  sessionID: string,
  rowType: unknown,
  created: unknown,
): ParsedRow | undefined {
  if (typeof rowType !== "string" || !/^[a-z][a-z0-9_-]{0,63}$/u.test(rowType)) return undefined;
  const time = objectField(data, "time");
  // An assistant step is complete once OpenCode records when it ended or
  // failed, after its tool calls settle; a user's shell command once it
  // exits; a compaction once it completes or fails. The rest are written
  // complete.
  const finished = rowType === "assistant" || rowType === "shell"
    ? typeof time?.["completed"] === "number"
    : rowType === "compaction"
    ? data["status"] === "completed" || data["status"] === "failed"
    : true;
  const listed = sessionMessageItems[rowType];
  const info: Record<string, unknown> = { ...data, id, sessionID, type: rowType };
  if (listed !== undefined) delete info[listed.field];
  const items: TableItem[] = [];
  let oversizedItems = 0;
  const add = (key: string, type: string, value: Record<string, unknown>) => {
    if (Buffer.byteLength(JSON.stringify(value), "utf8") > maxRecordBytes) oversizedItems++;
    else items.push({ sessionID, key, type, value, messageInfo: undefined });
  };
  add(`session_message:${id}`, `session_message.${rowType}`, { sessionID, info });
  const list = listed === undefined ? undefined : data[listed.field];
  if (listed !== undefined && Array.isArray(list)) {
    // A part without its own time happened after the part before it.
    let at = firstTime([time?.["created"], created]);
    for (const [index, entry] of list.entries()) {
      if (typeof entry !== "object" || entry === null || Array.isArray(entry)) continue;
      const part = entry as Record<string, unknown>;
      const ownTime = objectField(part, "time");
      at = firstTime([ownTime?.["completed"], ownTime?.["ran"], ownTime?.["created"]]) ?? at;
      const partType = listed.type ??
        (typeof part["type"] === "string" && /^[a-z][a-z0-9_-]{0,31}$/u.test(part["type"])
          ? part["type"]
          : "part");
      add(
        `session_message:${id}:${index}`,
        `session_message.${rowType}.${partType}`,
        { sessionID, messageID: id, ...(at === undefined ? {} : { time: at }), part },
      );
    }
  }
  return { finished, items, oversizedItems };
}

function parseMessage(
  data: Record<string, unknown>,
  id: string,
  sessionID: string,
): ParsedRow {
  const time = objectField(data, "time");
  // A user message is written complete. An assistant message is complete
  // once OpenCode records when it finished or why it failed.
  const finished = data["role"] !== "assistant" ||
    typeof time?.["completed"] === "number" ||
    (data["error"] !== undefined && data["error"] !== null);
  return {
    finished,
    items: [{
      sessionID,
      key: `message:${id}`,
      type: "message.updated.1",
      value: { sessionID, info: { ...data, id, sessionID } },
      messageInfo: undefined,
    }],
  };
}

function parsePart(
  data: Record<string, unknown>,
  id: string,
  sessionID: string,
  value: Record<string, unknown>,
  updated: number,
): ParsedRow | undefined {
  const messageID = value["message_id"];
  if (!validID(messageID)) return undefined;
  const role = value["role"];
  const time = partTime(data, value["created"], updated);
  return {
    finished: value["message_done"] === 1 || role === "user" || partFinished(data),
    items: [{
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
    }],
  };
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
  return firstTime([
    time?.["end"],
    stateTime?.["end"],
    time?.["start"],
    stateTime?.["start"],
    created,
    updated,
  ]);
}

function firstTime(candidates: readonly unknown[]): number | undefined {
  for (const candidate of candidates) {
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
