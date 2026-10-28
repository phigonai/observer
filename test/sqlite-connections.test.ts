import assert from "node:assert/strict";
import type { Stats } from "node:fs";
import { mkdir, mkdtemp, rm, stat, utimes } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";
import test from "node:test";
import { scanGooseSQLiteSources } from "../src/activity/goose-sqlite-source.js";
import { scanOpenCodeSQLiteSources } from "../src/activity/opencode-sqlite-source.js";
import { JSONLSourceReader } from "../src/activity/source-reader.js";
import { SQLiteConnections } from "../src/activity/sqlite-connections.js";

const baseTime = 1_785_686_000_000;

/** Connections that count opens and record every statement prepared. */
class CountingConnections extends SQLiteConnections {
  readonly #prepared: string[] = [];
  opened = 0;

  override check(
    root: string,
    path: string,
    metadata: Stats,
    cursors: ReadonlyMap<string, number>,
    open: (path: string) => DatabaseSync,
  ) {
    const prepared = this.#prepared;
    return super.check(root, path, metadata, cursors, (databasePath) => {
      this.opened++;
      return new Proxy(open(databasePath), {
        get(target, property) {
          if (property === "prepare") {
            return (sql: string) => {
              prepared.push(sql);
              return target.prepare(sql);
            };
          }
          const value: unknown = Reflect.get(target, property);
          return typeof value === "function" ? value.bind(target) : value;
        },
      });
    });
  }

  /** The statements prepared since the previous call. */
  take(): string[] {
    return this.#prepared.splice(0);
  }
}

function openCodeDatabase(path: string): DatabaseSync {
  const database = new DatabaseSync(path);
  database.exec(
    "PRAGMA journal_mode = WAL;" +
    "CREATE TABLE session (id TEXT PRIMARY KEY, time_updated INTEGER NOT NULL);" +
    "CREATE TABLE event_sequence (aggregate_id TEXT PRIMARY KEY, seq INTEGER NOT NULL);" +
    "CREATE TABLE event (aggregate_id TEXT NOT NULL, seq INTEGER NOT NULL, " +
    "type TEXT NOT NULL, data TEXT NOT NULL, UNIQUE (aggregate_id, seq));",
  );
  return database;
}

/** Commit one OpenCode event, creating its session on first use. */
function addOpenCodeEvent(database: DatabaseSync, session: string): number {
  database.exec("BEGIN");
  database.prepare(
    "INSERT OR IGNORE INTO session (id, time_updated) VALUES (?, 0)",
  ).run(session);
  database.prepare(
    "INSERT OR IGNORE INTO event_sequence (aggregate_id, seq) VALUES (?, 0)",
  ).run(session);
  database.prepare(
    "UPDATE event_sequence SET seq = seq + 1 WHERE aggregate_id = ?",
  ).run(session);
  const value = database.prepare(
    "SELECT seq FROM event_sequence WHERE aggregate_id = ?",
  ).get(session)?.["seq"];
  const sequence = Number(value);
  database.prepare(
    "INSERT INTO event (aggregate_id, seq, type, data) VALUES (?, ?, 'session.updated.1', ?)",
  ).run(session, sequence, JSON.stringify({ sessionID: session, time: baseTime + sequence }));
  database.prepare("UPDATE session SET time_updated = ? WHERE id = ?")
    .run(baseTime + sequence, session);
  database.exec("COMMIT");
  return sequence;
}

function gooseDatabase(path: string): DatabaseSync {
  const database = new DatabaseSync(path);
  database.exec(
    "PRAGMA journal_mode = WAL;" +
    "CREATE TABLE sessions (id TEXT PRIMARY KEY, working_dir TEXT NOT NULL);" +
    "CREATE TABLE messages (id INTEGER PRIMARY KEY AUTOINCREMENT, message_id TEXT, " +
    "session_id TEXT NOT NULL REFERENCES sessions(id), role TEXT NOT NULL, " +
    "content_json TEXT NOT NULL, created_timestamp INTEGER NOT NULL, metadata_json TEXT);" +
    "INSERT INTO sessions (id, working_dir) VALUES ('20260724_1', '/workspace');",
  );
  return database;
}

function addGooseMessage(database: DatabaseSync, text: string): void {
  database.prepare(
    "INSERT INTO messages (message_id, session_id, role, content_json, created_timestamp) " +
    "VALUES (?, '20260724_1', 'user', ?, 1785000000)",
  ).run(`msg_${text}`, JSON.stringify([{ type: "text", text }]));
}

/** Main and -wal file sizes: what a size-only change check would compare. */
async function fileSizes(path: string): Promise<[number, number]> {
  return [(await stat(path)).size, (await stat(`${path}-wal`)).size];
}

function sequences(records: readonly { value: unknown }[]): number[] {
  return records.map((record) =>
    (record.value as { timestamp: number }).timestamp - baseTime
  );
}

test("a kept OpenCode connection skips an unchanged database and still reads every commit", async () => {
  const directory = await mkdtemp(join(tmpdir(), "phigon-sqlite-kept-"));
  const root = join(directory, "opencode");
  await mkdir(root);
  const path = join(root, "opencode.db");
  // The writer stays open, like a running OpenCode, so the WAL persists.
  const writer = openCodeDatabase(path);
  // The clock never advances, so the connection is never idle long enough
  // to close.
  const connections = new CountingConnections({ clock: () => 0 });
  const cursors = new Map<string, number>();
  const scan = (initialScan = false) => scanOpenCodeSQLiteSources({
    adapterId: "opencode",
    roots: [root],
    cursors,
    initialScan,
    replayOnFirstStart: false,
    maxReplayRecords: 64,
    connections,
  });
  try {
    addOpenCodeEvent(writer, "ses_kept");
    assert.deepEqual((await scan(true)).records, []);
    assert.deepEqual((await scan()).records, []);
    connections.take();

    const idle = await scan();
    assert.deepEqual(idle.records, []);
    assert.equal(idle.files, 1);
    assert.deepEqual(connections.take(), ["PRAGMA data_version"]);

    addOpenCodeEvent(writer, "ses_kept");
    assert.deepEqual(sequences((await scan()).records), [2]);
    assert.deepEqual((await scan()).records, []);
    assert.deepEqual((await scan()).records, []);
    assert.deepEqual(connections.take().at(-1), "PRAGMA data_version");

    // After the WAL restarts, a small commit overwrites the start of the log:
    // both files keep their sizes, yet the commit is still read.
    writer.exec("PRAGMA wal_checkpoint(RESTART)");
    assert.deepEqual((await scan()).records, []);
    const sizes = await fileSizes(path);
    addOpenCodeEvent(writer, "ses_kept");
    assert.deepEqual(await fileSizes(path), sizes);
    assert.deepEqual(sequences((await scan()).records), [3]);

    // A cursor that changed since the idle scan, here one evicted, is never
    // answered from the idle state.
    assert.deepEqual((await scan()).records, []);
    const session = [...cursors].find(([, value]) => value === 3)?.[0];
    assert.ok(session !== undefined);
    cursors.delete(session);
    assert.deepEqual(sequences((await scan()).records), [1, 2, 3]);

    // History imports do not keep a connection.
    connections.closeAll();
    await scanOpenCodeSQLiteSources({
      adapterId: "opencode",
      roots: [root],
      cursors: new Map(),
      initialScan: false,
      replayOnFirstStart: false,
      maxReplayRecords: 64,
      historical: true,
      connections,
    });
    assert.equal(connections.openConnections, 0);
  } finally {
    connections.closeAll();
    writer.close();
    await rm(directory, { recursive: true, force: true });
  }
});

test("an idle OpenCode database is closed, then reopened by a file change or the 60 s full scan", async () => {
  const directory = await mkdtemp(join(tmpdir(), "phigon-sqlite-idle-"));
  const root = join(directory, "opencode");
  await mkdir(root);
  const path = join(root, "opencode.db");
  const writer = openCodeDatabase(path);
  let now = 1_000_000;
  const connections = new CountingConnections({ clock: () => now });
  const cursors = new Map<string, number>();
  const scan = (initialScan = false) => scanOpenCodeSQLiteSources({
    adapterId: "opencode",
    roots: [root],
    cursors,
    initialScan,
    replayOnFirstStart: false,
    maxReplayRecords: 64,
    connections,
  });
  // Pins both files' modification times, standing in for a commit that a
  // coarse file timestamp cannot show.
  const fixed = new Date("2026-01-01T00:00:00.000Z");
  const pinTimes = async () => {
    await utimes(path, fixed, fixed);
    await utimes(`${path}-wal`, fixed, fixed);
  };
  try {
    addOpenCodeEvent(writer, "ses_idle");
    await scan(true);
    assert.deepEqual((await scan()).records, []);
    assert.equal(connections.openConnections, 1);

    // Idle close: 60 s without a commit closes the connection.
    now += 59_999;
    await scan();
    assert.equal(connections.openConnections, 1);
    now += 1;
    assert.deepEqual((await scan()).records, []);
    assert.equal(connections.openConnections, 0);
    connections.take();
    const opened = connections.opened;
    for (let tick = 0; tick < 5; tick++) {
      now += 1_000;
      assert.deepEqual((await scan()).records, []);
    }
    // While closed, a tick only reads file metadata: no connection, no query.
    assert.equal(connections.opened, opened);
    assert.deepEqual(connections.take(), []);

    // A file change reopens the database for a full scan, and it stays open
    // while active.
    addOpenCodeEvent(writer, "ses_idle");
    now += 1_000;
    assert.deepEqual(sequences((await scan()).records), [2]);
    assert.equal(connections.opened, opened + 1);
    assert.equal(connections.openConnections, 1);
    assert.deepEqual((await scan()).records, []);

    // A commit the file metadata does not show: after a WAL restart a small
    // commit keeps both file sizes, and the times are pinned.
    writer.exec("PRAGMA wal_checkpoint(RESTART)");
    assert.deepEqual((await scan()).records, []);
    await pinTimes();
    now += 60_000;
    assert.deepEqual((await scan()).records, []);
    assert.equal(connections.openConnections, 0);
    const sizes = await fileSizes(path);
    addOpenCodeEvent(writer, "ses_idle");
    await pinTimes();
    assert.deepEqual(await fileSizes(path), sizes);
    now += 59_999;
    assert.deepEqual((await scan()).records, []);
    assert.equal(connections.openConnections, 0);
    // The periodic full scan finds it at most 60 s after the last check, and
    // closes again since nothing showed the database to be active.
    now += 1;
    assert.deepEqual(sequences((await scan()).records), [3]);
    assert.equal(connections.openConnections, 0);
    assert.deepEqual((await scan()).records, []);
  } finally {
    connections.closeAll();
    writer.close();
    await rm(directory, { recursive: true, force: true });
  }
});

test("a kept connection holds no read transaction between ticks", async () => {
  const directory = await mkdtemp(join(tmpdir(), "phigon-sqlite-checkpoint-"));
  const root = join(directory, "opencode");
  await mkdir(root);
  const path = join(root, "opencode.db");
  const writer = openCodeDatabase(path);
  const connections = new SQLiteConnections({ clock: () => 0 });
  const cursors = new Map<string, number>();
  const scan = (initialScan = false) => scanOpenCodeSQLiteSources({
    adapterId: "opencode",
    roots: [root],
    cursors,
    initialScan,
    replayOnFirstStart: false,
    maxReplayRecords: 64,
    connections,
  });
  const truncate = () =>
    writer.prepare("PRAGMA wal_checkpoint(TRUNCATE)").get()?.["busy"];
  try {
    addOpenCodeEvent(writer, "ses_checkpoint");
    await scan(true);
    for (let tick = 0; tick < 3; tick++) {
      addOpenCodeEvent(writer, "ses_checkpoint");
      assert.equal((await scan()).records.length, 1);
      await scan();
    }
    assert.equal(connections.openConnections, 1);
    // The open connection does not stop a full checkpoint that empties the WAL.
    assert.equal(truncate(), 0);
    assert.equal((await stat(`${path}-wal`)).size, 0);

    // The check itself detects a reader that keeps a transaction open.
    addOpenCodeEvent(writer, "ses_checkpoint");
    const holder = new DatabaseSync(path, { readOnly: true });
    try {
      holder.exec("BEGIN");
      holder.prepare("SELECT count(*) FROM event").get();
      addOpenCodeEvent(writer, "ses_checkpoint");
      assert.equal(truncate(), 1);
      holder.exec("COMMIT");
    } finally {
      holder.close();
    }
  } finally {
    connections.closeAll();
    writer.close();
    await rm(directory, { recursive: true, force: true });
  }
});

test("kept OpenCode connections return what a fresh connection returns", async () => {
  const directory = await mkdtemp(join(tmpdir(), "phigon-sqlite-equal-"));
  const root = join(directory, "opencode");
  await mkdir(root);
  const writer = openCodeDatabase(join(root, "opencode.db"));
  const connections = new SQLiteConnections({ clock: () => 0 });
  const keptCursors = new Map<string, number>();
  const freshCursors = new Map<string, number>();
  const scan = (cursors: Map<string, number>, kept: boolean, initialScan: boolean) =>
    scanOpenCodeSQLiteSources({
      adapterId: "opencode",
      roots: [root],
      cursors,
      initialScan,
      replayOnFirstStart: false,
      maxReplayRecords: 3,
      ...(kept ? { connections } : {}),
    });
  // Deterministic pseudo-random steps: commits to several sessions, WAL
  // restarts, evicted cursors and idle scans, compared with a reader that
  // opens a new connection for every scan.
  let seed = 7;
  const next = () => (seed = (seed * 1_103_515_245 + 12_345) % 2_147_483_648) / 2_147_483_648;
  try {
    addOpenCodeEvent(writer, "ses_0");
    for (let step = 0; step < 80; step++) {
      const roll = next();
      if (roll < 0.4) {
        const commits = 1 + Math.floor(next() * 5);
        for (let index = 0; index < commits; index++) {
          addOpenCodeEvent(writer, `ses_${Math.floor(next() * 4)}`);
        }
      } else if (roll < 0.5) {
        writer.exec("PRAGMA wal_checkpoint(RESTART)");
      } else if (roll < 0.55 && keptCursors.size > 0) {
        const key = [...keptCursors.keys()][Math.floor(next() * keptCursors.size)];
        assert.ok(key !== undefined);
        keptCursors.delete(key);
        freshCursors.delete(key);
      }
      const kept = await scan(keptCursors, true, step === 0);
      const fresh = await scan(freshCursors, false, step === 0);
      assert.deepEqual(
        kept.records.map((record) => record.sourceRecordId),
        fresh.records.map((record) => record.sourceRecordId),
        `step ${step}`,
      );
      assert.deepEqual([...keptCursors].sort(), [...freshCursors].sort(), `step ${step}`);
    }
    assert.equal(connections.openConnections, 1);
  } finally {
    connections.closeAll();
    writer.close();
    await rm(directory, { recursive: true, force: true });
  }
});

test("a kept Goose connection skips an unchanged database and still reads every commit", async () => {
  const directory = await mkdtemp(join(tmpdir(), "phigon-sqlite-goose-"));
  const root = join(directory, "sessions");
  await mkdir(root);
  const path = join(root, "sessions.db");
  const writer = gooseDatabase(path);
  const connections = new CountingConnections({ clock: () => 0 });
  const cursors = new Map<string, number>();
  const scan = (initialScan = false) => scanGooseSQLiteSources({
    adapterId: "goose-session",
    roots: [root],
    cursors,
    initialScan,
    replayOnFirstStart: false,
    maxReplayRecords: 32,
    maxRecords: 32,
    historical: false,
    connections,
  });
  const texts = (result: Awaited<ReturnType<typeof scan>>) =>
    result.records.map((record) =>
      (record.value as { content: Array<{ text: string }> }).content[0]?.text
    );
  try {
    addGooseMessage(writer, "first");
    assert.deepEqual(texts(await scan(true)), []);
    assert.deepEqual(texts(await scan()), []);
    connections.take();
    const idle = await scan();
    assert.deepEqual(texts(idle), []);
    assert.equal(idle.files, 1);
    assert.deepEqual(connections.take(), ["PRAGMA data_version"]);

    addGooseMessage(writer, "second");
    assert.deepEqual(texts(await scan()), ["second"]);
    assert.deepEqual(texts(await scan()), []);

    writer.exec("PRAGMA wal_checkpoint(RESTART)");
    assert.deepEqual(texts(await scan()), []);
    const sizes = await fileSizes(path);
    addGooseMessage(writer, "third");
    assert.deepEqual(await fileSizes(path), sizes);
    assert.deepEqual(texts(await scan()), ["third"]);
  } finally {
    connections.closeAll();
    writer.close();
    await rm(directory, { recursive: true, force: true });
  }
});

test("a live reader closes the connection of a database it no longer reads", async () => {
  const directory = await mkdtemp(join(tmpdir(), "phigon-sqlite-retain-"));
  const root = join(directory, "opencode");
  await mkdir(root);
  const writer = openCodeDatabase(join(root, "opencode.db"));
  addOpenCodeEvent(writer, "ses_retained");
  writer.close();
  const reader = new JSONLSourceReader(join(directory, "data"), false);
  try {
    const source = { adapterId: "opencode", roots: [root], format: "opencode-sqlite" as const };
    await reader.scan([source]);
    await reader.scan([source]);
    // Without the OpenCode source the kept connection is closed, so the
    // database can be removed (Windows refuses to delete an open file).
    await reader.scan([]);
    await rm(root, { recursive: true });
    await reader.scan([source]);
  } finally {
    reader.close();
    await rm(directory, { recursive: true, force: true });
  }
});
