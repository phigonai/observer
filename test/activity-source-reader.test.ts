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
