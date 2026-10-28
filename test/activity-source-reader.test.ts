import assert from "node:assert/strict";
import {
  appendFile,
  mkdtemp,
  mkdir,
  readFile,
  readdir,
  rename,
  rm,
  stat,
  utimes,
  writeFile,
} from "node:fs/promises";
import { homedir, tmpdir } from "node:os";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";
import test from "node:test";
import {
  expandedActivityRoot,
  JSONLSourceReader,
} from "../src/activity/source-reader.js";

test("corrupt source checkpoints rescan stable record identities and retain the damaged file", async () => {
  const directory = await mkdtemp(join(tmpdir(), "phigon-source-recovery-"));
  const root = join(directory, "sessions");
  const data = join(directory, "data");
  await mkdir(root);
  const file = join(root, "session.jsonl");
  const sources = [{ adapterId: "codex", roots: [root] }];
  try {
    await writeFile(file, '{"type":"old"}\n');
    const first = new JSONLSourceReader(data, true, 4096, 1, "history");
    const original = await first.scan(sources);
    assert.equal(original.records.length, 1);
    await first.commit(original.checkpoint);
    const corrupt = "\u0000".repeat(128);
    await writeFile(join(data, "activity-cursors.json"), corrupt);
    await appendFile(file, '{"type":"new"}\n');
    const recovered = new JSONLSourceReader(data, true, 4096, 1, "history");
    const replay = await recovered.scan(sources);
    assert.deepEqual(replay.records.map((record) => record.value), [{ type: "old" }, { type: "new" }]);
    assert.equal(replay.records[0]?.sourceRecordId, original.records[0]?.sourceRecordId);
    const retained = (await readdir(data)).filter((name) => name.endsWith(".corrupt"));
    assert.equal(retained.length, 1);
    assert.equal(await readFile(join(data, retained[0]!), "utf8"), corrupt);
    await recovered.commit(replay.checkpoint);
    const restarted = new JSONLSourceReader(data, true, 4096, 1, "history");
    assert.equal((await restarted.scan(sources)).records.length, 0);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("activity source roots expand the current user's home directory", () => {
  assert.equal(expandedActivityRoot("~"), homedir());
  assert.equal(
    expandedActivityRoot("~/.release-bot/sessions"),
    join(homedir(), ".release-bot", "sessions"),
  );
  assert.equal(expandedActivityRoot("/var/lib/agent"), "/var/lib/agent");
});

test("JSONL source reader tails only new complete records by default", async () => {
  const directory = await mkdtemp(join(tmpdir(), "phigon-source-"));
  const sourceRoot = join(directory, "sessions");
  const dataDirectory = join(directory, "data");
  await mkdir(sourceRoot, { recursive: true });
  const sourceFile = join(sourceRoot, "session.jsonl");
  await writeFile(sourceFile, '{"type":"existing"}\n', "utf8");
  const reader = new JSONLSourceReader(dataDirectory, false);

  try {
    const first = await reader.scan([
      { adapterId: "codex", roots: [sourceRoot] },
    ]);
    assert.equal(first.records.length, 0);
    await reader.commit(first.checkpoint);

    await appendFile(sourceFile, '{"type":"new"}\n{"type":"partial"', "utf8");
    const second = await reader.scan([
      { adapterId: "codex", roots: [sourceRoot] },
    ]);
    assert.equal(second.records.length, 1);
    assert.deepEqual(second.records[0]?.value, { type: "new" });
    assert.match(second.records[0]?.sourceId ?? "", /^ses_[a-f0-9]{32}$/u);
    await reader.commit(second.checkpoint);

    await appendFile(sourceFile, "}\nnot-json\n", "utf8");
    const third = await reader.scan([
      { adapterId: "codex", roots: [sourceRoot] },
    ]);
    assert.equal(third.records.length, 1);
    assert.equal(third.metrics.malformed, 1);
    await reader.commit(third.checkpoint);

    if (process.platform !== "win32") {
      const cursors = await stat(join(dataDirectory, "activity-cursors.json"));
      assert.equal(cursors.mode & 0o777, 0o600);
    }
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("JSONL source reader replays records after restart until their checkpoint is committed", async () => {
  const directory = await mkdtemp(join(tmpdir(), "phigon-source-"));
  const sourceRoot = join(directory, "sessions");
  const dataDirectory = join(directory, "data");
  await mkdir(sourceRoot, { recursive: true });
  await writeFile(
    join(sourceRoot, "session.jsonl"),
    '{"type":"must-survive-restart"}\n',
    "utf8",
  );

  try {
    const unacknowledgedReader = new JSONLSourceReader(dataDirectory, true);
    const unacknowledged = await unacknowledgedReader.scan([
      { adapterId: "codex", roots: [sourceRoot] },
    ]);
    assert.deepEqual(
      unacknowledged.records.map((record) => record.value),
      [{ type: "must-survive-restart" }],
    );

    const restartedReader = new JSONLSourceReader(dataDirectory, true);
    const replayed = await restartedReader.scan([
      { adapterId: "codex", roots: [sourceRoot] },
    ]);
    assert.deepEqual(
      replayed.records.map((record) => record.value),
      [{ type: "must-survive-restart" }],
    );
    await restartedReader.commit(replayed.checkpoint);

    const acknowledgedReader = new JSONLSourceReader(dataDirectory, true);
    const afterAcknowledgement = await acknowledgedReader.scan([
      { adapterId: "codex", roots: [sourceRoot] },
    ]);
    assert.deepEqual(afterAcknowledgement.records, []);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("JSONL source reader optionally replays existing bounded records", async () => {
  const directory = await mkdtemp(join(tmpdir(), "phigon-source-"));
  const sourceRoot = join(directory, "sessions");
  await mkdir(sourceRoot, { recursive: true });
  await writeFile(
    join(sourceRoot, "session.jsonl"),
    '{"type":"one"}\n{"type":"two"}\n',
    "utf8",
  );
  const reader = new JSONLSourceReader(join(directory, "data"), true);

  try {
    const scan = await reader.scan([
      { adapterId: "codex", roots: [sourceRoot] },
    ]);
    assert.deepEqual(
      scan.records.map((record) => record.value),
      [{ type: "one" }, { type: "two" }],
    );
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("historical source reader uploads every record in bounded resumable passes", async () => {
  const directory = await mkdtemp(join(tmpdir(), "phigon-history-source-"));
  const sourceRoot = join(directory, "sessions");
  const dataDirectory = join(directory, "history-state");
  await mkdir(sourceRoot, { recursive: true });
  await writeFile(
    join(sourceRoot, "archive.jsonl"),
    Array.from({ length: 35 }, (_, index) =>
      JSON.stringify({ type: "message", index })
    ).join("\n") + "\n",
    "utf8",
  );
  const reader = new JSONLSourceReader(
    dataDirectory,
    false,
    4_096,
    1,
    "history",
  );

  try {
    const values: number[] = [];
    let complete = false;
    while (!complete) {
      const scan = await reader.scan([
        { adapterId: "codex", roots: [sourceRoot] },
      ]);
      values.push(...scan.records.map((record) =>
        (record.value as { index: number }).index
      ));
      assert.ok(scan.records.every((record) =>
        /^[a-f0-9]{64}$/u.test(record.sourceRecordId)
      ));
      await reader.commit(scan.checkpoint);
      complete = scan.complete;
    }
    assert.deepEqual(values, Array.from({ length: 35 }, (_, index) => index));

    const restarted = new JSONLSourceReader(
      dataDirectory,
      false,
      4_096,
      1,
      "history",
    );
    const alreadyUploaded = await restarted.scan([
      { adapterId: "codex", roots: [sourceRoot] },
    ]);
    assert.equal(alreadyUploaded.complete, true);
    assert.deepEqual(alreadyUploaded.records, []);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("overlapping generic source labels fail closed independent of scan order", async () => {
  const directory = await mkdtemp(join(tmpdir(), "phigon-source-conflict-"));
  const sourceRoot = join(directory, "sessions");
  await mkdir(sourceRoot, { recursive: true });
  await writeFile(join(sourceRoot, "session.jsonl"), '{"type":"live"}\n', "utf8");

  try {
    for (const [index, sources] of [
      [
        { adapterId: "generic", roots: [sourceRoot], sourceDisplayName: "Alpha" },
        { adapterId: "generic", roots: [sourceRoot], sourceDisplayName: "Beta" },
      ],
      [
        { adapterId: "generic", roots: [sourceRoot], sourceDisplayName: "Beta" },
        { adapterId: "generic", roots: [sourceRoot], sourceDisplayName: "Alpha" },
      ],
    ].entries()) {
      const reader = new JSONLSourceReader(join(directory, `data-${index}`), true);
      const scan = await reader.scan(sources);
      assert.equal(scan.records.length, 1);
      assert.equal(scan.records[0]?.adapterId, "generic");
      assert.equal(scan.records[0]?.sourceDisplayName, undefined);
    }
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("missing generic source coverage cannot inherit another root's label", async () => {
  const directory = await mkdtemp(join(tmpdir(), "phigon-source-missing-"));
  const sourceRoot = join(directory, "sessions");
  await mkdir(sourceRoot, { recursive: true });
  await writeFile(join(sourceRoot, "session.jsonl"), '{"type":"live"}\n', "utf8");
  const reader = new JSONLSourceReader(join(directory, "data"), true);

  try {
    const scan = await reader.scan([
      { adapterId: "generic", roots: [sourceRoot], sourceDisplayName: "Alpha" },
      { adapterId: "generic", roots: [sourceRoot] },
    ]);
    assert.equal(scan.records.length, 1);
    assert.equal(scan.records[0]?.sourceDisplayName, undefined);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("native source coverage outranks an overlapping custom label", async () => {
  const directory = await mkdtemp(join(tmpdir(), "phigon-source-native-"));
  const sourceRoot = join(directory, "sessions");
  const nativeRoot = join(sourceRoot, "native");
  await mkdir(nativeRoot, { recursive: true });
  await writeFile(join(nativeRoot, "session.jsonl"), '{"type":"live"}\n', "utf8");
  const reader = new JSONLSourceReader(join(directory, "data"), true);

  try {
    const scan = await reader.scan([
      { adapterId: "generic", roots: [sourceRoot], sourceDisplayName: "Pretend Codex" },
      { adapterId: "codex", roots: [nativeRoot] },
    ]);
    assert.equal(scan.records.length, 1);
    assert.equal(scan.records[0]?.adapterId, "codex");
    assert.equal(scan.records[0]?.sourceDisplayName, undefined);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("first-start replay warms only the newest session for each adapter", async () => {
  const directory = await mkdtemp(join(tmpdir(), "phigon-source-"));
  const codexRoot = join(directory, "codex");
  const claudeRoot = join(directory, "claude");
  await mkdir(codexRoot, { recursive: true });
  await mkdir(claudeRoot, { recursive: true });
  const oldTime = new Date("2026-01-01T00:00:00Z");
  const newTime = new Date("2026-01-02T00:00:00Z");
  const oldCodex = join(codexRoot, "old.jsonl");
  const activeCodex = join(codexRoot, "active.jsonl");
  const activeClaude = join(claudeRoot, "active.jsonl");
  await writeFile(oldCodex, '{"type":"old-codex"}\n', "utf8");
  await writeFile(activeCodex, '{"type":"active-codex"}\n', "utf8");
  await writeFile(activeClaude, '{"type":"active-claude"}\n', "utf8");
  await utimes(oldCodex, oldTime, oldTime);
  await utimes(activeCodex, newTime, newTime);
  await utimes(activeClaude, newTime, newTime);
  const reader = new JSONLSourceReader(
    join(directory, "data"),
    true,
    4_096,
  );

  try {
    const scan = await reader.scan([
      { adapterId: "codex", roots: [codexRoot] },
      { adapterId: "claude", roots: [claudeRoot] },
    ]);
    assert.deepEqual(
      scan.records.map((record) => record.value),
      [{ type: "active-claude" }, { type: "active-codex" }],
    );
    await reader.commit(scan.checkpoint);

    const restarted = new JSONLSourceReader(
      join(directory, "data"),
      true,
      4_096,
    );
    const afterRestart = await restarted.scan([
      { adapterId: "codex", roots: [codexRoot] },
      { adapterId: "claude", roots: [claudeRoot] },
    ]);
    assert.deepEqual(afterRestart.records, []);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("first-start replay can include a consented number of saved sessions", async () => {
  const directory = await mkdtemp(join(tmpdir(), "phigon-source-history-"));
  const sourceRoot = join(directory, "codex");
  await mkdir(sourceRoot, { recursive: true });
  const times = [
    new Date("2026-01-01T00:00:00Z"),
    new Date("2026-01-02T00:00:00Z"),
    new Date("2026-01-03T00:00:00Z"),
  ];
  for (const [index, observedAt] of times.entries()) {
    const source = join(sourceRoot, `session-${index + 1}.jsonl`);
    await writeFile(source, `${JSON.stringify({ session: index + 1 })}\n`, "utf8");
    await utimes(source, observedAt, observedAt);
  }
  const reader = new JSONLSourceReader(
    join(directory, "data"),
    true,
    4_096,
    2,
  );

  try {
    const scan = await reader.scan([
      { adapterId: "codex", roots: [sourceRoot] },
    ]);
    assert.deepEqual(
      scan.records.map((record) => record.value),
      [{ session: 3 }, { session: 2 }],
    );
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("first-start replay reads only the configured tail window", async () => {
  const directory = await mkdtemp(join(tmpdir(), "phigon-source-"));
  const sourceRoot = join(directory, "sessions");
  await mkdir(sourceRoot, { recursive: true });
  const sourceFile = join(sourceRoot, "session.jsonl");
  const oldRecord = JSON.stringify({
    type: "outside-window",
    padding: "x".repeat(8_192),
  });
  await writeFile(
    sourceFile,
    `${oldRecord}\n{"type":"recent-context"}\n`,
    "utf8",
  );
  const reader = new JSONLSourceReader(
    join(directory, "data"),
    true,
    4_096,
  );

  try {
    const scan = await reader.scan([
      { adapterId: "codex", roots: [sourceRoot] },
    ]);
    assert.deepEqual(
      scan.records.map((record) => record.value),
      [{ type: "recent-context" }],
    );
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("JSONL source reader captures the first records of files created after startup", async () => {
  const directory = await mkdtemp(join(tmpdir(), "phigon-source-"));
  const sourceRoot = join(directory, "sessions");
  await mkdir(sourceRoot, { recursive: true });
  const reader = new JSONLSourceReader(join(directory, "data"), false);

  try {
    await reader.scan([{ adapterId: "codex", roots: [sourceRoot] }]);
    await writeFile(
      join(sourceRoot, "new-session.jsonl"),
      '{"type":"created-after-start"}\n',
      "utf8",
    );
    const scan = await reader.scan([
      { adapterId: "codex", roots: [sourceRoot] },
    ]);
    assert.deepEqual(
      scan.records.map((record) => record.value),
      [{ type: "created-after-start" }],
    );
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("JSONL source reader starts at the beginning when a tailed path is atomically replaced", async () => {
  const directory = await mkdtemp(join(tmpdir(), "phigon-source-"));
  const sourceRoot = join(directory, "sessions");
  const dataDirectory = join(directory, "data");
  await mkdir(sourceRoot, { recursive: true });
  const sourceFile = join(sourceRoot, "session.jsonl");
  const replacementFile = join(sourceRoot, "replacement.tmp");
  await writeFile(sourceFile, '{"type":"old"}\n', "utf8");
  const reader = new JSONLSourceReader(dataDirectory, false);

  try {
    const baseline = await reader.scan([
      { adapterId: "codex", roots: [sourceRoot] },
    ]);
    await reader.commit(baseline.checkpoint);

    await writeFile(
      replacementFile,
      '{"type":"replacement-first"}\n' +
        '{"type":"replacement-second","padding":"xxxxxxxx"}\n',
      "utf8",
    );
    await rename(replacementFile, sourceFile);

    const scan = await reader.scan([
      { adapterId: "codex", roots: [sourceRoot] },
    ]);
    assert.deepEqual(
      scan.records.map((record) => record.value),
      [
        { type: "replacement-first" },
        { type: "replacement-second", padding: "xxxxxxxx" },
      ],
    );
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("JSONL source reader skips source roots that disappear", async () => {
  const directory = await mkdtemp(join(tmpdir(), "phigon-source-"));
  const missingRoot = join(directory, "rotated-session-root");
  const reader = new JSONLSourceReader(join(directory, "data"), false);

  try {
    const scan = await reader.scan([
      { adapterId: "codex", roots: [missingRoot] },
    ]);
    assert.deepEqual(scan.records, []);
    assert.equal(scan.metrics.files, 0);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("JSONL source reader prioritizes recent files before applying the scan cap", async () => {
  const directory = await mkdtemp(join(tmpdir(), "phigon-source-"));
  const sourceRoot = join(directory, "sessions");
  await mkdir(sourceRoot, { recursive: true });
  const oldTime = new Date("2025-01-01T00:00:00Z");
  for (let index = 0; index < 256; index++) {
    const path = join(
      sourceRoot,
      `old-${String(index).padStart(3, "0")}.jsonl`,
    );
    await writeFile(path, '{"type":"old"}\n', "utf8");
    await utimes(path, oldTime, oldTime);
  }
  const active = join(sourceRoot, "zz-current.jsonl");
  await writeFile(active, '{"type":"startup"}\n', "utf8");
  const reader = new JSONLSourceReader(join(directory, "data"), false);

  try {
    const baseline = await reader.scan([
      { adapterId: "codex", roots: [sourceRoot] },
    ]);
    assert.equal(baseline.metrics.files, 256);
    await appendFile(active, '{"type":"live"}\n', "utf8");
    const scan = await reader.scan([
      { adapterId: "codex", roots: [sourceRoot] },
    ]);
    assert.equal(scan.metrics.files, 256);
    assert.deepEqual(
      scan.records.map((record) => record.value),
      [{ type: "live" }],
    );
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("OpenCode SQLite replay preserves native ordered message evidence", async () => {
  const directory = await mkdtemp(join(tmpdir(), "phigon-opencode-source-"));
  const sourceRoot = join(directory, "opencode");
  await mkdir(sourceRoot, { recursive: true });
  const databasePath = join(sourceRoot, "opencode.db");
  const database = createOpenCodeDatabase(databasePath);
  insertOpenCodeConversation(database, {
    sessionID: "ses_opencode_replay",
    prompt: "Inspect the isolated OpenCode thread.",
    response: "The OpenCode thread is isolated.",
    updatedAt: 1_785_686_000_000,
  });
  database.close();
  const reader = new JSONLSourceReader(join(directory, "data"), true);

  try {
    const scan = await reader.scan([{
      adapterId: "opencode",
      roots: [sourceRoot],
      format: "opencode-sqlite",
    }]);
    assert.equal(scan.metrics.files, 1);
    assert.deepEqual(
      scan.records.map((record) => ({
        sourceId: record.sourceId,
        type: (record.value as { type?: string }).type,
      })),
      [
        {
          sourceId: scan.records[0]?.sourceId,
          type: "message.updated.1",
        },
        {
          sourceId: scan.records[0]?.sourceId,
          type: "message.part.updated.1",
        },
        {
          sourceId: scan.records[0]?.sourceId,
          type: "message.updated.1",
        },
        {
          sourceId: scan.records[0]?.sourceId,
          type: "message.part.updated.1",
        },
      ],
    );
    assert.match(scan.records[0]?.sourceId ?? "", /^ses_[a-f0-9]{32}$/u);
    assert.deepEqual(
      scan.records.map((record) => record.observedAt.toISOString()),
      [
        "2026-08-02T15:53:20.000Z",
        "2026-08-02T15:53:20.001Z",
        "2026-08-02T15:53:20.002Z",
        "2026-08-02T15:53:20.003Z",
      ],
    );
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("OpenCode SQLite source baselines old rows and resumes only after acknowledgement", async () => {
  const directory = await mkdtemp(join(tmpdir(), "phigon-opencode-tail-"));
  const sourceRoot = join(directory, "opencode");
  const dataDirectory = join(directory, "data");
  await mkdir(sourceRoot, { recursive: true });
  const databasePath = join(sourceRoot, "opencode.db");
  let database = createOpenCodeDatabase(databasePath);
  insertOpenCodeConversation(database, {
    sessionID: "ses_before_pairing",
    prompt: "Existing prompt",
    response: "Existing response",
    updatedAt: 1_785_686_000_000,
  });
  database.close();
  const source = {
    adapterId: "opencode",
    roots: [sourceRoot],
    format: "opencode-sqlite" as const,
  };
  const reader = new JSONLSourceReader(dataDirectory, false);

  try {
    const baseline = await reader.scan([source]);
    assert.deepEqual(baseline.records, []);
    await reader.commit(baseline.checkpoint);

    database = new DatabaseSync(databasePath);
    insertOpenCodeConversation(database, {
      sessionID: "ses_after_pairing",
      prompt: "New isolated prompt",
      response: "New isolated response",
      updatedAt: 1_785_686_100_000,
    });
    database.close();

    const live = await reader.scan([source]);
    assert.equal(live.records.length, 4);
    assert.ok(live.records.every((record) =>
      JSON.stringify(record.value).includes("ses_after_pairing")
    ));

    const beforeAckRestart = new JSONLSourceReader(dataDirectory, false);
    const replayed = await beforeAckRestart.scan([source]);
    assert.equal(replayed.records.length, 4);
    await beforeAckRestart.commit(replayed.checkpoint);

    const afterAckRestart = new JSONLSourceReader(dataDirectory, false);
    const acknowledged = await afterAckRestart.scan([source]);
    assert.deepEqual(acknowledged.records, []);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

function createOpenCodeDatabase(path: string): DatabaseSync {
  const database = new DatabaseSync(path);
  database.exec(`
    CREATE TABLE session (
      id TEXT PRIMARY KEY,
      time_updated INTEGER NOT NULL
    );
    CREATE TABLE event_sequence (
      aggregate_id TEXT PRIMARY KEY,
      seq INTEGER NOT NULL
    );
    CREATE TABLE event (
      aggregate_id TEXT NOT NULL,
      seq INTEGER NOT NULL,
      type TEXT NOT NULL,
      data TEXT NOT NULL,
      UNIQUE (aggregate_id, seq)
    );
  `);
  return database;
}

function insertOpenCodeConversation(
  database: DatabaseSync,
  conversation: Readonly<{
    sessionID: string;
    prompt: string;
    response: string;
    updatedAt: number;
  }>,
): void {
  database.prepare(
    "INSERT INTO session (id, time_updated) VALUES (?, ?)",
  ).run(conversation.sessionID, conversation.updatedAt);
  database.prepare(
    "INSERT INTO event_sequence (aggregate_id, seq) VALUES (?, 4)",
  ).run(conversation.sessionID);
  const insert = database.prepare(
    "INSERT INTO event (aggregate_id, seq, type, data) VALUES (?, ?, ?, ?)",
  );
  const userMessageID = `msg_user_${conversation.sessionID}`;
  const agentMessageID = `msg_agent_${conversation.sessionID}`;
  insert.run(
    conversation.sessionID,
    1,
    "message.updated.1",
    JSON.stringify({
      sessionID: conversation.sessionID,
      info: {
        id: userMessageID,
        role: "user",
        time: { created: conversation.updatedAt },
      },
    }),
  );
  insert.run(
    conversation.sessionID,
    2,
    "message.part.updated.1",
    JSON.stringify({
      sessionID: conversation.sessionID,
      part: {
        id: `part_prompt_${conversation.sessionID}`,
        messageID: userMessageID,
        type: "text",
        text: conversation.prompt,
      },
      time: conversation.updatedAt + 1,
    }),
  );
  insert.run(
    conversation.sessionID,
    3,
    "message.updated.1",
    JSON.stringify({
      sessionID: conversation.sessionID,
      info: {
        id: agentMessageID,
        role: "assistant",
        time: { created: conversation.updatedAt + 2 },
      },
    }),
  );
  insert.run(
    conversation.sessionID,
    4,
    "message.part.updated.1",
    JSON.stringify({
      sessionID: conversation.sessionID,
      part: {
        id: `part_response_${conversation.sessionID}`,
        messageID: agentMessageID,
        type: "text",
        text: conversation.response,
      },
      time: conversation.updatedAt + 3,
    }),
  );
}

test("first replay keeps a record that starts exactly at the replay offset", async () => {
  const directory = await mkdtemp(join(tmpdir(), "phigon-source-boundary-"));
  const root = join(directory, "sessions");
  await mkdir(root, { recursive: true });
  try {
    // Two 8-byte records; replaying the last 8 bytes lands on a line boundary.
    await writeFile(join(root, "session.jsonl"), '{"a":1}\n{"b":2}\n', "utf8");
    const reader = new JSONLSourceReader(join(directory, "data"), true, 8);
    const scan = await reader.scan([{ adapterId: "codex", roots: [root] }]);
    assert.deepEqual(scan.records.map((record) => record.value), [{ b: 2 }]);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("JSON document sources deliver each rewritten message once", async () => {
  const directory = await mkdtemp(join(tmpdir(), "phigon-json-document-"));
  const root = join(directory, "sessions");
  const sessionDirectory = join(root, "1789500000000_abcde");
  const file = join(sessionDirectory, "1789500000000_abcde.messages.json");
  const data = join(directory, "data");
  await mkdir(sessionDirectory, { recursive: true });
  const sources = [{
    adapterId: "cline-cli",
    roots: [root],
    format: "json-messages" as const,
    pathPattern: "^[^/]+/[^/]+\\.messages\\.json$",
    messagesField: "messages",
  }];
  const message = (id: string) => ({
    id,
    role: "user",
    content: [{ type: "text", text: id }],
    ts: 1789500000000,
  });
  const document = async (ids: readonly string[], mtimeSeconds: number) => {
    await writeFile(file, JSON.stringify({
      version: 1,
      sessionId: "1789500000000_abcde",
      messages: ids.map(message),
    }, null, 2));
    await utimes(file, mtimeSeconds, mtimeSeconds);
  };
  const ids = (scan: Awaited<ReturnType<JSONLSourceReader["scan"]>>) =>
    scan.records.map((record) => (record.value as { id: string }).id);
  try {
    await document(["m1", "m2"], 1_000);
    const reader = new JSONLSourceReader(data, false);
    const baseline = await reader.scan(sources, 32);
    assert.deepEqual(ids(baseline), []);
    await reader.commit(baseline.checkpoint);

    await document(["m1", "m2", "m3", "m4"], 1_010);
    const appended = await reader.scan(sources, 32);
    assert.deepEqual(ids(appended), ["m3", "m4"]);
    assert.equal(new Set(appended.records.map((record) => record.sourceRecordId)).size, 2);
    await reader.commit(appended.checkpoint);
    assert.deepEqual(ids(await reader.scan(sources, 32)), []);

    // A partially written document is retried, not treated as history.
    await writeFile(file, '{"version":1,"messages":[{"id":"m1"');
    await utimes(file, 1_020, 1_020);
    assert.deepEqual(ids(await reader.scan(sources, 32)), []);

    // Compaction drops old messages; delivery resumes after the last one.
    await document(["summary", "m4", "m5"], 1_030);
    const compacted = await reader.scan(sources, 32);
    assert.deepEqual(ids(compacted), ["m5"]);
    await reader.commit(compacted.checkpoint);

    // A rewrite without the delivered message is re-baselined.
    await document(["other-1", "other-2"], 1_040);
    assert.deepEqual(ids(await reader.scan(sources, 32)), []);
    await document(["other-1", "other-2", "other-3"], 1_050);
    const afterRewrite = await reader.scan(sources, 32);
    assert.deepEqual(ids(afterRewrite), ["other-3"]);
    await reader.commit(afterRewrite.checkpoint);

    // Work written while the observer was stopped is caught up on restart.
    await document(["other-1", "other-2", "other-3", "other-4"], 1_060);
    const restarted = new JSONLSourceReader(data, false);
    assert.deepEqual(ids(await restarted.scan(sources, 32)), ["other-4"]);

    // A conversation started after startup is read from its first message.
    const second = join(root, "1789500009999_fghij");
    await mkdir(second);
    await writeFile(
      join(second, "1789500009999_fghij.messages.json"),
      JSON.stringify({ messages: [message("n1"), message("n2")] }),
    );
    assert.deepEqual(ids(await restarted.scan(sources, 32)), ["n1", "n2"]);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("JSON document history sync pages through every saved message", async () => {
  const directory = await mkdtemp(join(tmpdir(), "phigon-json-history-"));
  const root = join(directory, "sessions");
  await mkdir(join(root, "s1"), { recursive: true });
  await writeFile(join(root, "s1", "s1.messages.json"), JSON.stringify({
    messages: Array.from({ length: 7 }, (_, index) => ({ id: `m${index}`, role: "user", content: "x" })),
  }));
  const sources = [{
    adapterId: "cline-cli",
    roots: [root],
    format: "json-messages" as const,
    pathPattern: "^[^/]+/[^/]+\\.messages\\.json$",
  }];
  try {
    const reader = new JSONLSourceReader(join(directory, "history"), false, 4096, 1, "history");
    const seen: string[] = [];
    let complete = false;
    for (let pass = 0; pass < 10 && !complete; pass++) {
      const scan = await reader.scan(sources, 3);
      seen.push(...scan.records.map((record) => (record.value as { id: string }).id));
      await reader.commit(scan.checkpoint);
      complete = scan.complete;
    }
    assert.equal(complete, true);
    assert.deepEqual(seen, Array.from({ length: 7 }, (_, index) => `m${index}`));
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

function gooseDatabase(path: string): DatabaseSync {
  const database = new DatabaseSync(path);
  database.exec(
    "CREATE TABLE sessions (id TEXT PRIMARY KEY, working_dir TEXT NOT NULL);" +
    "CREATE TABLE messages (id INTEGER PRIMARY KEY AUTOINCREMENT, message_id TEXT, " +
    "session_id TEXT NOT NULL REFERENCES sessions(id), role TEXT NOT NULL, " +
    "content_json TEXT NOT NULL, created_timestamp INTEGER NOT NULL, " +
    "timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP, tokens INTEGER, metadata_json TEXT);" +
    "INSERT INTO sessions (id, working_dir) VALUES ('20260724_1', '/workspace');",
  );
  return database;
}

function addGooseMessage(database: DatabaseSync, messageID: string, text: string): void {
  database.prepare(
    "INSERT INTO messages (message_id, session_id, role, content_json, created_timestamp, metadata_json) " +
    "VALUES (?, '20260724_1', 'user', ?, 1785000000, ?)",
  ).run(
    messageID,
    JSON.stringify([{ type: "text", text }]),
    JSON.stringify({ userVisible: true, agentVisible: true }),
  );
}

test("Goose session database rows are delivered once in insertion order", async () => {
  const directory = await mkdtemp(join(tmpdir(), "phigon-goose-source-"));
  const root = join(directory, "sessions");
  const data = join(directory, "data");
  await mkdir(root, { recursive: true });
  const sources = [{ adapterId: "goose-session", roots: [root], format: "goose-sqlite" as const }];
  const texts = (scan: Awaited<ReturnType<JSONLSourceReader["scan"]>>) =>
    scan.records.map((record) =>
      ((record.value as { content: Array<{ text: string }> }).content[0]?.text ?? "")
    );
  try {
    // A database created after startup holds only new work.
    const reader = new JSONLSourceReader(data, false);
    await reader.commit((await reader.scan(sources, 32)).checkpoint);
    const database = gooseDatabase(join(root, "sessions.db"));
    try {
      addGooseMessage(database, "msg_1", "first");
      const created = await reader.scan(sources, 32);
      assert.deepEqual(texts(created), ["first"]);
      const value = created.records[0]?.value as { type: string; timestamp: string; metadata: unknown };
      assert.equal(value.type, "goose_message");
      assert.equal(value.timestamp, new Date(1785000000 * 1000).toISOString());
      await reader.commit(created.checkpoint);
      assert.deepEqual(texts(await reader.scan(sources, 32)), []);

      // Work written while the observer was stopped is caught up on restart.
      addGooseMessage(database, "msg_2", "second");
      addGooseMessage(database, "msg_3", "third");
      const restarted = new JSONLSourceReader(data, false);
      const caughtUp = await restarted.scan(sources, 1);
      assert.deepEqual(texts(caughtUp), ["second"]);
      assert.deepEqual(texts(await restarted.scan(sources, 32)), ["third"]);

      // A fresh install baselines saved history instead of replaying it.
      const fresh = new JSONLSourceReader(join(directory, "fresh"), false);
      assert.deepEqual(texts(await fresh.scan(sources, 32)), []);
      addGooseMessage(database, "msg_4", "fourth");
      assert.deepEqual(texts(await fresh.scan(sources, 32)), ["fourth"]);

      // History sync uploads every saved message.
      const history = new JSONLSourceReader(join(directory, "history"), false, 4096, 1, "history");
      const all: string[] = [];
      let complete = false;
      for (let pass = 0; pass < 10 && !complete; pass++) {
        const scan = await history.scan(sources, 3);
        all.push(...texts(scan));
        await history.commit(scan.checkpoint);
        complete = scan.complete;
      }
      assert.deepEqual(all, ["first", "second", "third", "fourth"]);
    } finally {
      database.close();
    }
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("a source path pattern limits which files belong to the source", async () => {
  const directory = await mkdtemp(join(tmpdir(), "phigon-source-pattern-"));
  const root = join(directory, "tmp");
  await mkdir(join(root, "my-project", "chats", "parent-session"), { recursive: true });
  await mkdir(join(root, "my-project", "tool-output"), { recursive: true });
  try {
    await writeFile(join(root, "my-project", "chats", "session-1.jsonl"), '{"type":"chat"}\n');
    await writeFile(join(root, "my-project", "chats", "parent-session", "sub.jsonl"), '{"type":"subagent"}\n');
    await writeFile(join(root, "my-project", "tool-output", "other.jsonl"), '{"type":"other"}\n');
    const reader = new JSONLSourceReader(join(directory, "data"), false, 4096, 1, "history");
    const scan = await reader.scan([{
      adapterId: "gemini-cli",
      roots: [root],
      pathPattern: "^[^/]+/chats/",
    }], 16);
    assert.deepEqual(
      scan.records.map((record) => (record.value as { type: string }).type).sort(),
      ["chat", "subagent"],
    );
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("JSONL source reader keeps records larger than one read window", async () => {
  const directory = await mkdtemp(join(tmpdir(), "phigon-source-large-"));
  const root = join(directory, "sessions");
  await mkdir(root, { recursive: true });
  const file = join(root, "session.jsonl");
  await writeFile(file, '{"type":"existing"}\n', "utf8");
  const reader = new JSONLSourceReader(join(directory, "data"), false);
  const sources = [{ adapterId: "claude", roots: [root] }];
  try {
    await reader.commit((await reader.scan(sources, 4)).checkpoint);
    // A tool result or pasted screenshot can make one transcript line larger
    // than the normal read window. It is still one complete source record.
    const large = JSON.stringify({
      type: "user",
      message: {
        role: "user",
        content: [{
          type: "tool_result",
          tool_use_id: "toolu_large",
          content: "x".repeat(3 << 20),
        }],
      },
    });
    await appendFile(file, `${large}\n{"type":"after"}\n`, "utf8");
    const values: unknown[] = [];
    let oversized = 0;
    for (let pass = 0; pass < 4; pass++) {
      const scan = await reader.scan(sources, 4);
      values.push(...scan.records.map((record) =>
        (record.value as { type: string }).type
      ));
      oversized += scan.metrics.oversized;
      await reader.commit(scan.checkpoint);
    }
    assert.deepEqual(values, ["user", "after"]);
    assert.equal(oversized, 0);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("JSONL source reader skips a record above the line limit and resumes after it", async () => {
  const directory = await mkdtemp(join(tmpdir(), "phigon-source-oversized-"));
  const root = join(directory, "sessions");
  await mkdir(root, { recursive: true });
  const file = join(root, "session.jsonl");
  await writeFile(file, '{"type":"existing"}\n', "utf8");
  const reader = new JSONLSourceReader(join(directory, "data"), false);
  const sources = [{ adapterId: "claude", roots: [root] }];
  try {
    await reader.commit((await reader.scan(sources, 4)).checkpoint);
    await appendFile(
      file,
      `{"type":"huge","pad":"${"y".repeat(7 << 20)}"}\n{"type":"after"}\n`,
      "utf8",
    );
    const values: unknown[] = [];
    let oversized = 0;
    for (let pass = 0; pass < 6; pass++) {
      const scan = await reader.scan(sources, 4);
      values.push(...scan.records.map((record) =>
        (record.value as { type: string }).type
      ));
      oversized += scan.metrics.oversized;
      await reader.commit(scan.checkpoint);
    }
    assert.deepEqual(values, ["after"]);
    assert.equal(oversized, 1);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});
