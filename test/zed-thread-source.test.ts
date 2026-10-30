import assert from "node:assert/strict";
import { mkdir, mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";
import test from "node:test";
import { zstdCompressSync } from "node:zlib";
import { JSONLSourceReader } from "../src/activity/source-reader.js";
import { zedThreadItems } from "../src/activity/zed-sqlite-source.js";

type Scan = Awaited<ReturnType<JSONLSourceReader["scan"]>>;

/** The threads table as Zed creates and migrates it. */
function zedDatabase(path: string): DatabaseSync {
  const database = new DatabaseSync(path);
  database.exec(
    "CREATE TABLE threads (id TEXT PRIMARY KEY, summary TEXT NOT NULL, updated_at TEXT NOT NULL, " +
    "data_type TEXT NOT NULL, data BLOB NOT NULL, parent_id TEXT, folder_paths TEXT, " +
    "folder_paths_order TEXT, created_at TEXT)",
  );
  return database;
}

function saveThread(
  database: DatabaseSync,
  id: string,
  messages: readonly unknown[],
  updatedAt: string,
  options: Readonly<{ dataType?: "zstd" | "json"; version?: string }> = {},
): void {
  const json = Buffer.from(JSON.stringify({
    title: "Thread",
    messages,
    updated_at: updatedAt,
    version: options.version ?? "0.3.0",
  }));
  const dataType = options.dataType ?? "zstd";
  database.prepare(
    "INSERT INTO threads (id, summary, updated_at, data_type, data, created_at) VALUES (?, 'Thread', ?, ?, ?, ?) " +
    "ON CONFLICT(id) DO UPDATE SET updated_at = excluded.updated_at, data_type = excluded.data_type, data = excluded.data",
  ).run(id, updatedAt, dataType, dataType === "zstd" ? zstdCompressSync(json) : json, updatedAt);
}

const user = (id: string, text: string) => ({ User: { id, content: [{ Text: text }] } });
const agent = (content: readonly unknown[], results: Record<string, unknown> = {}) => ({
  Agent: { content, tool_results: results, reasoning_details: null },
});
const toolUse = (id: string, name: string, input: unknown, complete = true) => ({
  ToolUse: {
    id,
    name,
    raw_input: JSON.stringify(input),
    input: { type: "json", value: input },
    is_input_complete: complete,
    thought_signature: null,
  },
});
const toolResult = (id: string, name: string, text: string) => ({
  tool_use_id: id,
  tool_name: name,
  is_error: false,
  content: [{ Text: text }],
  output: { debugging: "state" },
});

/** Each record as `kind:detail`, from the delivered item values. */
function describe(scan: Scan): string[] {
  return scan.records.map((record) => {
    const value = record.value as {
      type: string;
      role?: string;
      content: unknown;
      tool_use_id?: string;
    };
    if (value.type === "zed_tool_result") return `result:${value.tool_use_id}:${String(value.content)}`;
    const block = (value.content as Array<Record<string, unknown>>)[0] ?? {};
    if (value.role === "user") return `user:${String(block["Text"])}`;
    if ("Text" in block) return `text:${String(block["Text"])}`;
    if ("Thinking" in block) return `thinking:${String((block["Thinking"] as { text: string }).text)}`;
    return `tool:${String((block["ToolUse"] as { name: string }).name)}`;
  });
}

const sources = (root: string) => [{ adapterId: "zed-thread", roots: [root], format: "zed-sqlite" as const }];

test("Zed thread items are delivered once, as Zed saves them", async () => {
  const directory = await mkdtemp(join(tmpdir(), "phigon-zed-source-"));
  const root = join(directory, "threads");
  const data = join(directory, "data");
  await mkdir(root, { recursive: true });
  const readers: JSONLSourceReader[] = [];
  const liveReader = () => {
    const reader = new JSONLSourceReader(data, false);
    readers.push(reader);
    return reader;
  };
  const database = zedDatabase(join(root, "threads.db"));
  try {
    const turn = [user("u1", "Fix the bug"), agent([{ Text: "Looking." }])];
    saveThread(database, "thread-a", turn, "2026-07-24T10:00:00+00:00");
    const reader = liveReader();
    // Saved threads are baselined on the first start, not replayed.
    const first = await reader.scan(sources(root), 32);
    assert.deepEqual(describe(first), []);
    await reader.commit(first.checkpoint);

    // A tool call whose input was still streaming waits until it is complete.
    saveThread(database, "thread-a", [
      ...turn,
      agent([{ Thinking: { text: "Run the tests.", signature: "sig" } }, toolUse("tool_1", "terminal", { command: "cargo test" }, false)]),
    ], "2026-07-24T10:00:05+00:00");
    const streaming = await reader.scan(sources(root), 32);
    assert.deepEqual(describe(streaming), ["thinking:Run the tests."]);
    await reader.commit(streaming.checkpoint);

    const finished = [
      ...turn,
      agent(
        [{ Thinking: { text: "Run the tests.", signature: "sig" } }, toolUse("tool_1", "terminal", { command: "cargo test" })],
        { tool_1: toolResult("tool_1", "terminal", "2 passed") },
      ),
    ];
    saveThread(database, "thread-a", finished, "2026-07-24T10:00:09+00:00");
    const done = await reader.scan(sources(root), 32);
    assert.deepEqual(describe(done), ["tool:terminal", "result:tool_1:2 passed"]);
    const call = done.records[0]?.value as Record<string, unknown>;
    assert.equal(call["thread_id"], "thread-a");
    assert.equal(call["timestamp"], "2026-07-24T10:00:09.000Z");
    assert.deepEqual((call["content"] as unknown[])[0], {
      ToolUse: { id: "tool_1", name: "terminal", input: { command: "cargo test" }, is_input_complete: true },
    });
    assert.equal("output" in (done.records[1]?.value as object), false, "Zed's debugging copy of tool output is left out");
    assert.equal(done.records[0]?.sourceId, done.records[1]?.sourceId);
    await reader.commit(done.checkpoint);
    assert.deepEqual(describe(await reader.scan(sources(root), 32)), []);

    // A thread started after startup is read from its first message.
    saveThread(database, "thread-b", [user("u9", "Second thread")], "2026-07-24T10:01:00+00:00");
    const created = await reader.scan(sources(root), 32);
    assert.deepEqual(describe(created), ["user:Second thread"]);
    await reader.commit(created.checkpoint);

    // Work saved while the observer was stopped is caught up on restart.
    const resumed = [...finished, user("u2", "Now add a test"), agent([{ Text: "Added." }])];
    saveThread(database, "thread-a", resumed, "2026-07-24T10:02:00+00:00");
    const restarted = liveReader();
    const caughtUp = await restarted.scan(sources(root), 32);
    assert.deepEqual(describe(caughtUp), ["user:Now add a test", "text:Added."]);
    await restarted.commit(caughtUp.checkpoint);

    // A rewound turn is saved without it, then the new prompt arrives.
    saveThread(database, "thread-a", finished, "2026-07-24T10:03:00+00:00");
    const rewound = await restarted.scan(sources(root), 32);
    assert.deepEqual(describe(rewound), []);
    await restarted.commit(rewound.checkpoint);
    saveThread(database, "thread-a", [...finished, user("u3", "Add a test instead"), agent([{ Text: "Done." }])], "2026-07-24T10:03:30+00:00");
    assert.deepEqual(describe(await restarted.scan(sources(root), 32)), ["user:Add a test instead", "text:Done."]);
  } finally {
    database.close();
    for (const reader of readers) reader.close();
    await rm(directory, { recursive: true, force: true });
  }
});

test("a first start with replay sends the newest Zed thread", async () => {
  const directory = await mkdtemp(join(tmpdir(), "phigon-zed-replay-"));
  const root = join(directory, "threads");
  await mkdir(root, { recursive: true });
  const database = zedDatabase(join(root, "threads.db"));
  const reader = new JSONLSourceReader(join(directory, "data"), true, 4096, 1);
  try {
    saveThread(database, "old", [user("u1", "Older")], "2026-07-20T10:00:00+00:00");
    saveThread(database, "new", [user("u2", "Newer"), agent([{ Text: "Reply." }])], "2026-07-24T10:00:00+00:00");
    const scan = await reader.scan(sources(root), 32);
    assert.deepEqual(describe(scan), ["user:Newer", "text:Reply."]);
    assert.ok(scan.records.every((record) => record.initialReplay === true));
  } finally {
    database.close();
    reader.close();
    await rm(directory, { recursive: true, force: true });
  }
});

test("a Zed history import reads every thread, including older formats, and completes", async () => {
  const directory = await mkdtemp(join(tmpdir(), "phigon-zed-history-"));
  const root = join(directory, "threads");
  await mkdir(root, { recursive: true });
  const database = zedDatabase(join(root, "threads.db"));
  const reader = new JSONLSourceReader(join(directory, "history"), false, 4096, 1, "history");
  try {
    saveThread(database, "current", [
      user("u1", "Explain the build"),
      agent([{ Text: "It uses cargo." }, toolUse("call_1", "read_file", { path: "Cargo.toml" })], { call_1: toolResult("call_1", "read_file", "[package]") }),
    ], "2026-07-24T10:00:00+00:00");
    // Zed's first agent saved role-based messages, sometimes as plain JSON.
    saveThread(database, "legacy", [
      { id: 0, role: "user", segments: [{ type: "text", text: "Old question" }], tool_uses: [], tool_results: [], context: "", creases: [], is_hidden: false },
      {
        id: 1,
        role: "assistant",
        segments: [{ type: "thinking", text: "Hmm." }, { type: "text", text: "Old answer" }],
        tool_uses: [{ id: "legacy_tool", name: "grep", input: { regex: "fn main" } }],
        tool_results: [],
      },
      { id: 2, role: "user", segments: [], tool_uses: [], tool_results: [{ tool_use_id: "legacy_tool", is_error: false, content: "src/main.rs", output: null }], is_hidden: true },
    ], "2026-07-01T10:00:00+00:00", { dataType: "json", version: "0.2.0" });
    database.prepare(
      "INSERT INTO threads (id, summary, updated_at, data_type, data) VALUES ('broken', 'x', '2026-07-02T00:00:00+00:00', 'zstd', ?)",
    ).run(Buffer.from("not zstd"));
    const all: string[] = [];
    let malformed = 0;
    let scan: Scan | undefined;
    for (let pass = 0; pass < 20; pass++) {
      scan = await reader.scan(sources(root), 2);
      all.push(...describe(scan));
      malformed += scan.metrics.malformed;
      await reader.commit(scan.checkpoint);
      if (scan.complete && scan.records.length === 0) break;
    }
    assert.equal(scan?.complete, true);
    assert.deepEqual(all, [
      "user:Explain the build",
      "text:It uses cargo.",
      "tool:read_file",
      "result:call_1:[package]",
      "user:Old question",
      "thinking:Hmm.",
      "text:Old answer",
      "tool:grep",
      "result:legacy_tool:src/main.rs",
    ]);
    assert.equal(malformed, 1);
  } finally {
    database.close();
    reader.close();
    await rm(directory, { recursive: true, force: true });
  }
});

test("Zed thread items keep mentions but not attached file text or images", () => {
  const items = zedThreadItems({
    messages: [
      {
        User: {
          id: "u1",
          content: [
            { Text: "Review " },
            { Mention: { uri: { File: { abs_path: "/w/a.rs" } }, content: "fn main() {}" } },
            { Image: { source: "aGVsbG8=", size: { width: 1, height: 1 } } },
          ],
        },
      },
      "Resume",
      { Compaction: { Summary: "Earlier work." } },
      agent([{ RedactedThinking: "opaque" }, { Text: "  " }, { Text: "Looks fine." }]),
    ],
  });
  assert.deepEqual(items?.map((item) => item.id), ["user:u1", "u1:agent-0:2"]);
  assert.deepEqual(items?.[0]?.value, {
    type: "zed_message",
    role: "user",
    content: [{ Text: "Review " }, { Mention: { uri: { File: { abs_path: "/w/a.rs" } } } }, { Image: {} }],
  });
  assert.equal(zedThreadItems({ title: "draft" }), undefined);
});
