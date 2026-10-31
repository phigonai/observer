import assert from "node:assert/strict";
import { mkdtemp, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { zstdCompressSync } from "node:zlib";
import { create, toJsonString } from "@bufbuild/protobuf";
import {
  timestampDate,
  timestampFromDate,
} from "@bufbuild/protobuf/wkt";
import test from "node:test";
import {
  ActivityCollector,
  attributedRuntimeAgentID,
  historyRest,
  mergeInventoryWithSourceIdentities,
  reportedGenericAgentIdentity,
  reportedProcessIdentity,
  reportedSessionID,
} from "../src/activity/collector.js";
import { loadConfig } from "../src/config.js";
import {
  ActivityKind,
  AgentKind,
  AgentState,
} from "../src/generated/phigon/v1/common_pb.js";
import {
  AgentIdentitySchema,
  AgentInventorySchema,
  type AgentIdentity,
} from "../src/generated/phigon/v1/identity_pb.js";
import { processKeyCapability } from "../src/discovery/process-identity.js";
import {
  EventEnvelopeSchema,
  type EventEnvelope,
} from "../src/generated/phigon/v1/telemetry_pb.js";

test("reported generic sessions remain exact and conflicts or coverage loss fail closed", () => {
  assert.equal(
    reportedSessionID(
      "generic",
      { session_id: "thread-exact-01", content: "unchanged" },
      "source-fallback",
    ),
    "thread-exact-01",
  );
  assert.equal(
    reportedSessionID(
      "generic",
      {
        session_id: "thread-a",
        metadata: { threadId: "thread-b" },
      },
      "source-conflict",
    ),
    "source-conflict",
  );
  assert.equal(
    reportedSessionID("generic", { content: "missing identity" }, "source-missing"),
    "source-missing",
  );
  assert.equal(
    reportedSessionID(
      "codex",
      { session_id: "partial-record-only" },
      "source-coverage-loss",
    ),
    "source-coverage-loss",
  );
});

test("custom agent labels require consistent complete evidence", () => {
  assert.deepEqual(
    reportedGenericAgentIdentity(
      { phigon_agent_name: "Release Bot", agent: "Release Bot" },
    ),
    {
      hint: "release-bot",
      displayName: "Release Bot",
      conflict: false,
      coverageComplete: true,
    },
  );
  assert.deepEqual(
    reportedGenericAgentIdentity(
      { agent: "Another Agent" },
      "Release Bot",
    ),
    { conflict: true, coverageComplete: false },
  );
  assert.deepEqual(
    reportedGenericAgentIdentity({ content: "missing label" }),
    { conflict: false, coverageComplete: false },
  );
  assert.deepEqual(
    reportedGenericAgentIdentity(
      { agent: "Release Bot\nforged" },
      "Release Bot",
    ),
    { conflict: false, coverageComplete: false },
  );
});

test("process claims require a complete non-conflicting process key", () => {
  assert.deepEqual(
    reportedProcessIdentity({
      process_key: "process-runtime-a",
      process_id: 303,
    }),
    {
      processKey: "process-runtime-a",
      processID: 303n,
      conflict: false,
      coverageComplete: true,
    },
  );
  assert.deepEqual(
    reportedProcessIdentity({
      process_key: "process-runtime-a",
      metadata: { processKey: "process-runtime-b" },
    }),
    {
      conflict: true,
      coverageComplete: false,
    },
  );
  assert.deepEqual(
    reportedProcessIdentity({ process_id: 303 }),
    {
      processID: 303n,
      conflict: false,
      coverageComplete: false,
    },
  );
});

test("runtime attribution fails closed on conflict, missing evidence, and coverage loss", () => {
  const keyCapability = processKeyCapability("process-runtime-a");
  assert.ok(keyCapability);
  const runtime = create(AgentIdentitySchema, {
    agentId: "agt_runtime_a",
    kind: AgentKind.CODEX,
    displayName: "OpenAI Codex · PID 303",
    state: AgentState.RUNNING,
    processId: 303n,
    capabilities: ["process-instance", keyCapability],
    lastObservedAt: timestampFromDate(new Date()),
  });

  assert.equal(
    attributedRuntimeAgentID([runtime], {
      process_key: "process-runtime-a",
      process_id: 303,
    }),
    "agt_runtime_a",
  );
  assert.equal(
    attributedRuntimeAgentID([runtime], {
      process_key: "process-runtime-a",
      metadata: { processKey: "process-runtime-b" },
    }),
    undefined,
  );
  assert.equal(
    attributedRuntimeAgentID([runtime], { process_id: 303 }),
    undefined,
  );
  assert.equal(
    attributedRuntimeAgentID([
      create(AgentIdentitySchema, {
        ...runtime,
        capabilities: ["process-instance"],
      }),
    ], { process_key: "process-runtime-a" }),
    undefined,
  );
  assert.equal(
    attributedRuntimeAgentID([runtime], {
      process_key: "process-runtime-a",
      process_id: 404,
    }),
    undefined,
  );
});

test("activity collector throttles without losing source records and resolves discovered agent IDs", async () => {
  const directory = await mkdtemp(join(tmpdir(), "phigon-collector-"));
  const sourceRoot = join(directory, "sessions");
  const dataDirectory = join(directory, "data");
  await mkdir(sourceRoot, { recursive: true });
  const fixture = await readFile(
    new URL("../../test/fixtures/activity/codex.jsonl", import.meta.url),
    "utf8",
  );
  await writeFile(join(sourceRoot, "codex.jsonl"), fixture, "utf8");
  const emitted: EventEnvelope[] = [];
  const surfacedSources: AgentIdentity[] = [];
  let now = new Date("2026-07-24T10:10:00.000Z");
  const config = loadConfig({
    PHIGON_DATA_DIR: dataDirectory,
    PHIGON_ACTIVITY_REPLAY_ON_FIRST_START: "true",
    PHIGON_ACTIVITY_RATE_LIMIT_PER_MINUTE: "3",
    PHIGON_COLLECT_VENDOR_PAYLOAD: "true",
  });
  const collector = new ActivityCollector({
    config,
    credential: {
      machineId: "5f1b4cb4-a77d-4f53-af66-197e184683f4",
      tenantId: "7d1b4cb4-a77d-4f53-af66-197e184683f4",
      credential:
        "phg_m_0123456789012345678901234567890123456789012",
      controlPlaneOrigin: "http://127.0.0.1:8080",
      createdAt: "2026-07-24T00:00:00.000Z",
    },
    initialSequence: 10n,
    emit: (event) => emitted.push(event),
    sources: [{ adapterId: "codex", roots: [sourceRoot] }],
    clock: () => now,
    onSourceIdentity: (identity) => {
      surfacedSources.push(identity);
    },
  });
  collector.updateInventory(create(AgentInventorySchema, {
    machineId: "5f1b4cb4-a77d-4f53-af66-197e184683f4",
    observedAt: timestampFromDate(new Date()),
    agents: [{
      $typeName: "phigon.v1.AgentIdentity",
      agentId: "agt_real_codex",
      kind: AgentKind.CODEX,
      displayName: "OpenAI Codex",
      version: "0.144.5",
      runtime: "",
      state: AgentState.RUNNING,
      processId: 42n,
      lastObservedAt: timestampFromDate(new Date()),
      capabilities: ["terminal"],
      executablePathDigest: "a".repeat(64),
    }],
  }));

  try {
    const metrics = await collector.scanOnce();

    assert.deepEqual(
      emitted.map((event) => event.sequence),
      [11n, 12n],
    );
    assert.ok(emitted.every((event) => event.agentId !== "agt_real_codex"));
    assert.equal(new Set(emitted.map((event) => event.agentId)).size, 1);
    assert.equal(surfacedSources.length, 1);
    assert.equal(surfacedSources[0]?.agentId, emitted[0]?.agentId);
    assert.equal(surfacedSources[0]?.state, AgentState.UNKNOWN);
    assert.equal(surfacedSources[0]?.processId, 0n);
    assert.ok(
      surfacedSources[0]?.capabilities.includes("source-isolated"),
    );
    assert.match(surfacedSources[0]?.displayName ?? "", /unattributed/u);
    const addressableInventory = mergeInventoryWithSourceIdentities(
      create(AgentInventorySchema, {
        machineId: "5f1b4cb4-a77d-4f53-af66-197e184683f4",
        observedAt: timestampFromDate(new Date()),
      }),
      surfacedSources,
    );
    assert.equal(
      addressableInventory.agents[0]?.agentId,
      emitted[0]?.agentId,
    );
    assert.ok(emitted.every((event) => event.tenantId ===
      "7d1b4cb4-a77d-4f53-af66-197e184683f4"));
    const nativeEvents = emitted.filter(
      (event) => event.payload.case === "vendor",
    );
    assert.ok(nativeEvents.length > 0);
    const serialized = nativeEvents
      .map((event) => toJsonString(EventEnvelopeSchema, event))
      .join("\n");
    assert.doesNotMatch(serialized, /sk-fixturesecret/u);
    assert.match(serialized, /session_meta/u);
    assert.equal(metrics.emittedEvents, 2);
    assert.equal(metrics.rateLimitedEvents, 0);
    assert.equal(metrics.lastSequence, 12n);

    await collector.scanOnce();
    const beforePause = emitted.length;
    await collector.scanOnce();
    assert.equal(emitted.length, beforePause);
    for (let index = 0; index < 12; index++) {
      now = new Date(now.getTime() + 60_001);
      await collector.scanOnce();
      await collector.acknowledge(collector.metrics().lastSequence);
    }
    // Every original source record survives throttling, in order, exactly once.
    assert.equal(emitted.filter(event => event.payload.case === "vendor").length, 8);
    assert.equal(new Set(emitted.map(event => event.sourceEventId)).size, emitted.length);
    assert.deepEqual(emitted.map(event => event.sequence), emitted.map((_,index) => BigInt(11 + index)));
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("message-only initial replay backfills chat without duplicating tool evidence", async () => {
  const directory = await mkdtemp(join(tmpdir(), "phigon-message-replay-"));
  const sourceRoot = join(directory, "sessions");
  await mkdir(sourceRoot, { recursive: true });
  await writeFile(
    join(sourceRoot, "codex.jsonl"),
    [
      {
        type: "response_item",
        payload: {
          type: "message",
          role: "user",
          content: [{ type: "input_text", text: "Backfill this chat." }],
        },
      },
      {
        type: "response_item",
        payload: {
          type: "custom_tool_call",
          call_id: "call-existing-tool",
          name: "exec_command",
          input: { cmd: "npm test" },
        },
      },
    ].map((record) => JSON.stringify(record)).join("\n") + "\n",
    "utf8",
  );
  const emitted: EventEnvelope[] = [];
  const collector = new ActivityCollector({
    config: loadConfig({
      PHIGON_DATA_DIR: join(directory, "data"),
      PHIGON_OBSERVABILITY_PROFILE: "full",
      PHIGON_ACTIVITY_REPLAY_ON_FIRST_START: "true",
      PHIGON_ACTIVITY_INITIAL_REPLAY_MODE: "messages",
      PHIGON_ACTIVITY_RATE_LIMIT_PER_MINUTE: "100",
    }),
    credential: {
      machineId: "5f1b4cb4-a77d-4f53-af66-197e184683f4",
      tenantId: "7d1b4cb4-a77d-4f53-af66-197e184683f4",
      credential: `phg_m_${"0".repeat(43)}`,
      controlPlaneOrigin: "http://127.0.0.1:8080",
      createdAt: "2026-07-24T00:00:00.000Z",
    },
    initialSequence: 0n,
    emit: (event) => emitted.push(event),
    sources: [{ adapterId: "codex", roots: [sourceRoot] }],
  });

  try {
    await collector.scanOnce();
    assert.equal(emitted.length, 1);
    assert.equal(emitted[0]?.payload.case, "activity");
    if (emitted[0]?.payload.case === "activity") {
      assert.equal(emitted[0].payload.value.kind, ActivityKind.PROMPT);
      assert.match(emitted[0].payload.value.content ?? "", /Backfill this chat/u);
    }
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("activity collector leaves source cursors untouched while delivery is backpressured", async () => {
  const directory = await mkdtemp(join(tmpdir(), "phigon-backpressure-"));
  const sourceRoot = join(directory, "sessions");
  await mkdir(sourceRoot, { recursive: true });
  await writeFile(
    join(sourceRoot, "codex.jsonl"),
    `${JSON.stringify({
      type: "event_msg",
      payload: {
        type: "user_message",
        message: "Do not lose this queued prompt.",
      },
    })}\n`,
    "utf8",
  );
  const emitted: EventEnvelope[] = [];
  let hasCapacity = false;
  const collector = new ActivityCollector({
    config: loadConfig({
      PHIGON_DATA_DIR: join(directory, "data"),
      PHIGON_ACTIVITY_REPLAY_ON_FIRST_START: "true",
      PHIGON_ACTIVITY_RATE_LIMIT_PER_MINUTE: "100",
      PHIGON_COLLECT_PROMPT_CONTENT: "true",
      PHIGON_COLLECT_VENDOR_PAYLOAD: "true",
    }),
    credential: {
      machineId: "5f1b4cb4-a77d-4f53-af66-197e184683f4",
      tenantId: "7d1b4cb4-a77d-4f53-af66-197e184683f4",
      credential: `phg_m_${"0".repeat(43)}`,
      controlPlaneOrigin: "http://127.0.0.1:8080",
      createdAt: "2026-07-24T00:00:00.000Z",
    },
    initialSequence: 0n,
    emit: (event) => emitted.push(event),
    sources: [{ adapterId: "codex", roots: [sourceRoot] }],
    canCollect: () => hasCapacity,
  });

  try {
    const paused = await collector.scanOnce();
    assert.equal(paused.backpressuredScans, 1);
    assert.equal(paused.sourceRecords, 0);
    assert.deepEqual(emitted, []);

    hasCapacity = true;
    const resumed = await collector.scanOnce();
    assert.ok(resumed.emittedEvents > 0);
    assert.match(
      emitted
        .map((event) => toJsonString(EventEnvelopeSchema, event))
        .join("\n"),
      /Do not lose this queued prompt/u,
    );
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("multiple source identity saves preserve the first persistence failure", async () => {
  const directory = await mkdtemp(join(tmpdir(), "phigon-source-save-fail-"));
  const sourceRoot = join(directory, "sessions");
  await mkdir(sourceRoot, { recursive: true });
  let callbacks = 0;
  const collector = new ActivityCollector({
    config: loadConfig({
      PHIGON_DATA_DIR: join(directory, "data"),
      PHIGON_ACTIVITY_RATE_LIMIT_PER_MINUTE: "100",
      PHIGON_COLLECT_VENDOR_PAYLOAD: "true",
    }),
    credential: {
      machineId: "5f1b4cb4-a77d-4f53-af66-197e184683f4",
      tenantId: "7d1b4cb4-a77d-4f53-af66-197e184683f4",
      credential: `phg_m_${"0".repeat(43)}`,
      controlPlaneOrigin: "http://127.0.0.1:8080",
      createdAt: "2026-07-24T00:00:00.000Z",
    },
    initialSequence: 0n,
    emit: () => undefined,
    sources: [{ adapterId: "generic", roots: [sourceRoot] }],
    onSourceIdentity: () => {
      callbacks++;
      return callbacks === 1
        ? Promise.reject(new Error("catalog persistence failed"))
        : Promise.resolve();
    },
  });

  try {
    await collector.scanOnce();
    await writeFile(
      join(sourceRoot, "source-a.jsonl"),
      `${JSON.stringify({ type: "message", content: "first" })}\n`,
      "utf8",
    );
    await writeFile(
      join(sourceRoot, "source-b.jsonl"),
      `${JSON.stringify({ type: "message", content: "second" })}\n`,
      "utf8",
    );

    await assert.rejects(
      collector.scanOnce(),
      /catalog persistence failed/u,
    );
    assert.equal(callbacks, 2);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("activity collector replaces stale agent identities on inventory refresh", async () => {
  const directory = await mkdtemp(join(tmpdir(), "phigon-inventory-refresh-"));
  const sourceRoot = join(directory, "sessions");
  const dataDirectory = join(directory, "data");
  await mkdir(sourceRoot, { recursive: true });
  await writeFile(
    join(sourceRoot, "codex.jsonl"),
    `${JSON.stringify({
      type: "event_msg",
      process_key: "process-current-codex",
      payload: {
        type: "user_message",
        message: "Inspect the current inventory.",
      },
    })}\n`,
    "utf8",
  );
  const emitted: EventEnvelope[] = [];
  const collector = new ActivityCollector({
    config: loadConfig({
      PHIGON_DATA_DIR: dataDirectory,
      PHIGON_ACTIVITY_REPLAY_ON_FIRST_START: "true",
      PHIGON_ACTIVITY_RATE_LIMIT_PER_MINUTE: "100",
      PHIGON_COLLECT_PROMPT_CONTENT: "true",
      PHIGON_COLLECT_VENDOR_PAYLOAD: "true",
    }),
    credential: {
      machineId: "5f1b4cb4-a77d-4f53-af66-197e184683f4",
      tenantId: "7d1b4cb4-a77d-4f53-af66-197e184683f4",
      credential: `phg_m_${"0".repeat(43)}`,
      controlPlaneOrigin: "http://127.0.0.1:8080",
      createdAt: "2026-07-24T00:00:00.000Z",
    },
    initialSequence: 0n,
    emit: (event) => emitted.push(event),
    sources: [{ adapterId: "codex", roots: [sourceRoot] }],
  });
  const inventory = (agentId: string) => create(AgentInventorySchema, {
    machineId: "5f1b4cb4-a77d-4f53-af66-197e184683f4",
    observedAt: timestampFromDate(new Date()),
    agents: [{
      $typeName: "phigon.v1.AgentIdentity",
      agentId,
      kind: AgentKind.CODEX,
      displayName: "OpenAI Codex",
      version: "",
      runtime: "",
      state: AgentState.RUNNING,
      processId: 42n,
      lastObservedAt: timestampFromDate(new Date()),
      capabilities: [
        "process-instance",
        processKeyCapability("process-current-codex") ?? "",
        "terminal",
      ],
      executablePathDigest: "a".repeat(64),
    }],
  });
  collector.updateInventory(inventory("agt_stale_codex"));
  collector.updateInventory(inventory("agt_current_codex"));

  try {
    await collector.scanOnce();
    assert.ok(emitted.length >= 2);
    assert.ok(
      emitted.every((event) => event.agentId === "agt_current_codex"),
    );
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("activity collector binds process-tagged records to the matching runtime identity", async () => {
  const directory = await mkdtemp(join(tmpdir(), "phigon-process-bind-"));
  const sourceRoot = join(directory, "sessions");
  const dataDirectory = join(directory, "data");
  await mkdir(sourceRoot, { recursive: true });
  await writeFile(
    join(sourceRoot, "codex.jsonl"),
    `${JSON.stringify({
      type: "event_msg",
      process_key: "process-codex-303-start-a",
      process_id: 303,
      payload: {
        type: "user_message",
        message: "Inspect this process only.",
      },
    })}\n`,
    "utf8",
  );
  const emitted: EventEnvelope[] = [];
  const collector = new ActivityCollector({
    config: loadConfig({
      PHIGON_DATA_DIR: dataDirectory,
      PHIGON_ACTIVITY_REPLAY_ON_FIRST_START: "true",
      PHIGON_OBSERVABILITY_PROFILE: "full",
    }),
    credential: {
      machineId: "5f1b4cb4-a77d-4f53-af66-197e184683f4",
      tenantId: "7d1b4cb4-a77d-4f53-af66-197e184683f4",
      credential: `phg_m_${"0".repeat(43)}`,
      controlPlaneOrigin: "http://127.0.0.1:8080",
      createdAt: "2026-07-24T00:00:00.000Z",
    },
    initialSequence: 0n,
    emit: (event) => emitted.push(event),
    sources: [{ adapterId: "codex", roots: [sourceRoot] }],
  });
  collector.updateInventory(create(AgentInventorySchema, {
    machineId: "5f1b4cb4-a77d-4f53-af66-197e184683f4",
    observedAt: timestampFromDate(new Date()),
    agents: [
      {
        $typeName: "phigon.v1.AgentIdentity",
        agentId: "agt_primary_codex",
        kind: AgentKind.CODEX,
        displayName: "OpenAI Codex",
        version: "",
        runtime: "",
        state: AgentState.RUNNING,
        processId: 202n,
        lastObservedAt: timestampFromDate(new Date()),
        capabilities: ["terminal"],
        executablePathDigest: "a".repeat(64),
      },
      {
        $typeName: "phigon.v1.AgentIdentity",
        agentId: "agt_process_codex",
        kind: AgentKind.CODEX,
        displayName: "OpenAI Codex · PID 303",
        version: "",
        runtime: "",
        state: AgentState.RUNNING,
        processId: 303n,
        lastObservedAt: timestampFromDate(new Date()),
        capabilities: [
          "process-instance",
          processKeyCapability("process-codex-303-start-a") ?? "",
          "terminal",
        ],
        executablePathDigest: "a".repeat(64),
      },
    ],
  }));

  try {
    await collector.scanOnce();
    assert.ok(emitted.length >= 2);
    assert.ok(
      emitted.every((event) => event.agentId === "agt_process_codex"),
    );
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("the default sources deliver Gemini CLI, Cline CLI, Cursor, Factory Droid, Zed and Roo Code conversations", async () => {
  const directory = await mkdtemp(join(tmpdir(), "phigon-native-sources-"));
  const geminiRoot = join(directory, "gemini-tmp");
  const clineRoot = join(directory, "cline-sessions");
  const cursorRoot = join(directory, "cursor-projects");
  const cursorTranscript = join(cursorRoot, "c-workspace", "agent-transcripts", "conv-1");
  const droidRoot = join(directory, "factory-sessions");
  const zedRoot = join(directory, "zed-threads");
  const rooRoot = join(directory, "roo-tasks");
  await mkdir(join(rooRoot, "6f1c2b9e-roo"), { recursive: true });
  await writeFile(
    join(rooRoot, "6f1c2b9e-roo", "ui_messages.json"),
    JSON.stringify([{ ts: 1785000004000, type: "say", say: "text", text: "Add a dark theme." }]),
  );
  await mkdir(join(droidRoot, "-workspace"), { recursive: true });
  await mkdir(zedRoot, { recursive: true });
  await writeFile(
    join(droidRoot, "-workspace", "8d2c6f0e-1b7a-4f3e-9c55-0a1b2c3d4e5f.jsonl"),
    [
      { type: "session_start", id: "8d2c6f0e-1b7a-4f3e-9c55-0a1b2c3d4e5f", title: "Docs", cwd: "/workspace" },
      { type: "message", id: "d1", timestamp: "2026-07-24T10:00:02.000Z", message: { role: "user", content: [{ type: "text", text: "Write the docs." }] } },
    ].map((line) => JSON.stringify(line)).join("\n") + "\n",
  );
  await writeFile(
    join(droidRoot, "-workspace", "8d2c6f0e-1b7a-4f3e-9c55-0a1b2c3d4e5f.settings.json"),
    JSON.stringify({ model: "claude" }),
  );
  const zed = new DatabaseSync(join(zedRoot, "threads.db"));
  zed.exec("CREATE TABLE threads (id TEXT PRIMARY KEY, summary TEXT NOT NULL, updated_at TEXT NOT NULL, data_type TEXT NOT NULL, data BLOB NOT NULL)");
  zed.prepare("INSERT INTO threads VALUES ('z1', 'Rename', '2026-07-24T10:00:03+00:00', 'zstd', ?)").run(
    zstdCompressSync(Buffer.from(JSON.stringify({ version: "0.3.0", messages: [{ User: { id: "u1", content: [{ Text: "Rename the module." }] } }] }))),
  );
  zed.close();
  await mkdir(join(geminiRoot, "my-project", "chats"), { recursive: true });
  await mkdir(join(clineRoot, "1789500000000_abcde"), { recursive: true });
  await mkdir(cursorTranscript, { recursive: true });
  await writeFile(
    join(cursorTranscript, "conv-1.jsonl"),
    JSON.stringify({ role: "user", message: { content: [{ type: "text", text: "<user_query>\nFix the login.\n</user_query>" }] } }),
  );
  await writeFile(
    join(geminiRoot, "my-project", "chats", "session-2026-07-24T10-00-8f0f8a62.jsonl"),
    [
      { sessionId: "8f0f8a62", projectHash: "b".repeat(64), startTime: "2026-07-24T10:00:00.000Z", lastUpdated: "2026-07-24T10:00:00.000Z" },
      { id: "g1", timestamp: "2026-07-24T10:00:01.000Z", type: "user", content: [{ text: "Explain the build." }] },
    ].map((line) => JSON.stringify(line)).join("\n") + "\n",
  );
  await writeFile(
    join(clineRoot, "1789500000000_abcde", "1789500000000_abcde.messages.json"),
    JSON.stringify({
      version: 1,
      sessionId: "1789500000000_abcde",
      messages: [{ id: "c1", role: "user", content: [{ type: "text", text: "Add a test." }], ts: 1789500000000 }],
    }),
  );
  const emitted: EventEnvelope[] = [];
  const collector = new ActivityCollector({
    config: loadConfig({
      PHIGON_DATA_DIR: join(directory, "data"),
      PHIGON_ACTIVITY_REPLAY_ON_FIRST_START: "true",
      PHIGON_ACTIVITY_RATE_LIMIT_PER_MINUTE: "600",
      PHIGON_COLLECT_PROMPT_CONTENT: "true",
      PHIGON_GEMINI_ACTIVITY_DIRS: geminiRoot,
      PHIGON_CLINE_ACTIVITY_DIRS: clineRoot,
      PHIGON_CURSOR_ACTIVITY_DIRS: cursorRoot,
      PHIGON_DROID_ACTIVITY_DIRS: droidRoot,
      PHIGON_ZED_ACTIVITY_DIRS: zedRoot,
      PHIGON_ROO_CODE_ACTIVITY_DIRS: rooRoot,
      PHIGON_CLINE_TASKS_ACTIVITY_DIRS: join(directory, "none"),
      PHIGON_KILO_CODE_ACTIVITY_DIRS: join(directory, "none"),
      PHIGON_COPILOT_CHAT_ACTIVITY_DIRS: join(directory, "none"),
      PHIGON_KIRO_ACTIVITY_DIRS: join(directory, "none"),
      PHIGON_GOOSE_ACTIVITY_DIRS: join(directory, "none"),
      PHIGON_CODEX_ACTIVITY_DIRS: join(directory, "none"),
      PHIGON_CLAUDE_ACTIVITY_DIRS: join(directory, "none"),
      PHIGON_HERMES_ACTIVITY_DIRS: join(directory, "none"),
      PHIGON_OPENCLAW_ACTIVITY_DIRS: join(directory, "none"),
      PHIGON_COPILOT_ACTIVITY_DIRS: join(directory, "none"),
      PHIGON_OPENCODE_ACTIVITY_DIRS: join(directory, "none"),
      PHIGON_GENERIC_ACTIVITY_DIRS: join(directory, "none"),
    }),
    credential: {
      machineId: "5f1b4cb4-a77d-4f53-af66-197e184683f4",
      tenantId: "7d1b4cb4-a77d-4f53-af66-197e184683f4",
      credential: `phg_m_${"0".repeat(43)}`,
      controlPlaneOrigin: "http://127.0.0.1:8080",
      createdAt: "2026-07-24T00:00:00.000Z",
    },
    initialSequence: 0n,
    emit: (event) => emitted.push(event),
  });
  try {
    await collector.scanOnce();
    const prompts = emitted.flatMap((event) =>
      event.payload.case === "activity" &&
      event.payload.value.kind === ActivityKind.PROMPT
        ? [event.payload.value.content]
        : []
    ).sort();
    assert.deepEqual(prompts, ["Add a dark theme.", "Add a test.", "Explain the build.", "Fix the login.", "Rename the module.", "Write the docs."]);
    assert.deepEqual(
      collector.sourceIdentities().map((identity) =>
        identity.displayName.split(" · ")[0]
      ).sort(),
      ["Cline", "Cursor", "Factory Droid", "Gemini CLI", "Roo Code", "Zed"],
    );
  } finally {
    // The live reader keeps the Zed database open between scans.
    collector.close();
    await rm(directory, { recursive: true, force: true });
  }
});

test("Cline source records keep their message time so the raw record pairs with its reply", async () => {
  const directory = await mkdtemp(join(tmpdir(), "phigon-cline-time-"));
  const clineRoot = join(directory, "cline-sessions");
  await mkdir(join(clineRoot, "1789500000000_abcde"), { recursive: true });
  const replyTime = Date.parse("2026-07-24T10:00:02.000Z");
  await writeFile(
    join(clineRoot, "1789500000000_abcde", "1789500000000_abcde.messages.json"),
    JSON.stringify({
      version: 1,
      sessionId: "1789500000000_abcde",
      messages: [
        { id: "c1", role: "user", content: [{ type: "text", text: "Fix the build." }], ts: replyTime - 1_000 },
        {
          id: "c2",
          role: "assistant",
          content: [
            { type: "thinking", thinking: "Line one.\nLine two." },
            { type: "text", text: "Done.\nAll good." },
          ],
          ts: replyTime,
        },
      ],
    }),
  );
  const emitted: EventEnvelope[] = [];
  const collector = new ActivityCollector({
    config: loadConfig({
      PHIGON_DATA_DIR: join(directory, "data"),
      PHIGON_OBSERVABILITY_PROFILE: "full",
      PHIGON_ACTIVITY_REPLAY_ON_FIRST_START: "true",
      PHIGON_ACTIVITY_RATE_LIMIT_PER_MINUTE: "200",
    }),
    credential: {
      machineId: "5f1b4cb4-a77d-4f53-af66-197e184683f4",
      tenantId: "7d1b4cb4-a77d-4f53-af66-197e184683f4",
      credential: `phg_m_${"0".repeat(43)}`,
      controlPlaneOrigin: "http://127.0.0.1:8080",
      createdAt: "2026-07-24T00:00:00.000Z",
    },
    initialSequence: 0n,
    emit: (event) => emitted.push(event),
    sources: [{
      adapterId: "cline-cli",
      roots: [clineRoot],
      format: "json-messages",
      pathPattern: "^[^/]+/[^/]+\\.messages\\.json$",
      messagesField: "messages",
    }],
  });
  try {
    await collector.scanOnce();
    const reply = emitted.find((event) =>
      event.payload.case === "activity" &&
      event.payload.value.kind === ActivityKind.RESPONSE
    );
    assert.equal(
      reply?.payload.case === "activity" ? reply.payload.value.content : "",
      "Done.\nAll good.",
    );
    const raw = emitted.find((event) =>
      event.payload.case === "vendor" &&
      (event.payload.value.payloadJson ?? "").includes("\"c2\"")
    );
    assert.ok(raw !== undefined && reply !== undefined);
    // The file was written now; both events must carry the message's time.
    assert.equal(
      timestampDate(raw.observedAt!).toISOString(),
      "2026-07-24T10:00:02.000Z",
    );
    assert.equal(
      timestampDate(reply.observedAt!).toISOString(),
      "2026-07-24T10:00:02.000Z",
    );
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("Copilot records without process evidence remain source-isolated", async () => {
  const directory = await mkdtemp(join(tmpdir(), "phigon-copilot-collector-"));
  const sourceRoot = join(directory, "session-state", "session-one");
  const dataDirectory = join(directory, "data");
  await mkdir(sourceRoot, { recursive: true });
  await writeFile(
    join(sourceRoot, "events.jsonl"),
    `${JSON.stringify({
      type: "message",
      message: {
        role: "user",
        content: "Run the release checks.",
      },
    })}\n`,
    "utf8",
  );
  const emitted: EventEnvelope[] = [];
  const collector = new ActivityCollector({
    config: loadConfig({
      PHIGON_DATA_DIR: dataDirectory,
      PHIGON_ACTIVITY_REPLAY_ON_FIRST_START: "true",
      PHIGON_ACTIVITY_RATE_LIMIT_PER_MINUTE: "100",
      PHIGON_COLLECT_PROMPT_CONTENT: "true",
      PHIGON_COLLECT_VENDOR_PAYLOAD: "true",
    }),
    credential: {
      machineId: "5f1b4cb4-a77d-4f53-af66-197e184683f4",
      tenantId: "7d1b4cb4-a77d-4f53-af66-197e184683f4",
      credential: `phg_m_${"0".repeat(43)}`,
      controlPlaneOrigin: "http://127.0.0.1:8080",
      createdAt: "2026-07-24T00:00:00.000Z",
    },
    initialSequence: 0n,
    emit: (event) => emitted.push(event),
    sources: [{ adapterId: "copilot", roots: [sourceRoot] }],
  });
  collector.updateInventory(create(AgentInventorySchema, {
    machineId: "5f1b4cb4-a77d-4f53-af66-197e184683f4",
    observedAt: timestampFromDate(new Date()),
    agents: [
      {
        $typeName: "phigon.v1.AgentIdentity",
        agentId: "agt_aider",
        kind: AgentKind.GENERIC,
        displayName: "Aider",
        version: "",
        runtime: "",
        state: AgentState.STOPPED,
        processId: 0n,
        lastObservedAt: timestampFromDate(new Date()),
        capabilities: ["terminal"],
        executablePathDigest: "b".repeat(64),
      },
      {
        $typeName: "phigon.v1.AgentIdentity",
        agentId: "agt_copilot",
        kind: AgentKind.GENERIC,
        displayName: "GitHub Copilot CLI",
        version: "1.0.75",
        runtime: "",
        state: AgentState.RUNNING,
        processId: 42n,
        lastObservedAt: timestampFromDate(new Date()),
        capabilities: ["terminal"],
        executablePathDigest: "c".repeat(64),
      },
    ],
  }));

  try {
    await collector.scanOnce();
    assert.ok(emitted.length >= 2);
    assert.ok(emitted.every((event) => event.agentId !== "agt_copilot"));
    assert.equal(new Set(emitted.map((event) => event.agentId)).size, 1);
    assert.ok(
      emitted.some(
        (event) =>
          event.payload.case === "vendor" &&
          event.payload.value.source === "copilot",
      ),
    );
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("activity collector commits source progress only through a server acknowledgement", async () => {
  const directory = await mkdtemp(join(tmpdir(), "phigon-collector-ack-"));
  const sourceRoot = join(directory, "sessions");
  const dataDirectory = join(directory, "data");
  const source = { adapterId: "codex", roots: [sourceRoot] } as const;
  await mkdir(sourceRoot, { recursive: true });
  await writeFile(
    join(sourceRoot, "codex.jsonl"),
    `${JSON.stringify({
      timestamp: "2026-07-24T10:10:00.000Z",
      type: "event_msg",
      payload: { type: "agent_message", message: "durable ack test" },
    })}\n`,
    "utf8",
  );
  const config = loadConfig({
    PHIGON_DATA_DIR: dataDirectory,
    PHIGON_ACTIVITY_REPLAY_ON_FIRST_START: "true",
    PHIGON_ACTIVITY_RATE_LIMIT_PER_MINUTE: "100",
    PHIGON_COLLECT_VENDOR_PAYLOAD: "true",
  });
  const credential = {
    machineId: "5f1b4cb4-a77d-4f53-af66-197e184683f4",
    tenantId: "7d1b4cb4-a77d-4f53-af66-197e184683f4",
    credential: `phg_m_${"0".repeat(43)}`,
    controlPlaneOrigin: "http://127.0.0.1:8080",
    createdAt: "2026-07-24T00:00:00.000Z",
  };

  try {
    const firstEvents: EventEnvelope[] = [];
    const first = new ActivityCollector({
      config,
      credential,
      initialSequence: 0n,
      emit: (event) => firstEvents.push(event),
      sources: [source],
    });
    const firstMetrics = await first.scanOnce();
    assert.ok(firstEvents.length > 0);

    const replayedEvents: EventEnvelope[] = [];
    const beforeAcknowledgement = new ActivityCollector({
      config,
      credential,
      initialSequence: 0n,
      emit: (event) => replayedEvents.push(event),
      sources: [source],
    });
    await beforeAcknowledgement.scanOnce();
    assert.ok(replayedEvents.length > 0);
    await beforeAcknowledgement.acknowledge(
      beforeAcknowledgement.metrics().lastSequence,
    );

    const afterAcknowledgementEvents: EventEnvelope[] = [];
    const afterAcknowledgement = new ActivityCollector({
      config,
      credential,
      initialSequence: firstMetrics.lastSequence,
      emit: (event) => afterAcknowledgementEvents.push(event),
      sources: [source],
    });
    await afterAcknowledgement.scanOnce();
    assert.deepEqual(afterAcknowledgementEvents, []);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("activity collector can hand source progress to a durable delivery spool", async () => {
  const directory = await mkdtemp(join(tmpdir(), "phigon-collector-spool-"));
  const sourceRoot = join(directory, "sessions");
  const dataDirectory = join(directory, "data");
  const source = { adapterId: "codex", roots: [sourceRoot] } as const;
  await mkdir(sourceRoot, { recursive: true });
  await writeFile(
    join(sourceRoot, "codex.jsonl"),
    `${JSON.stringify({
      timestamp: "2026-07-24T10:10:00.000Z",
      type: "event_msg",
      payload: { type: "agent_message", message: "durable spool handoff" },
    })}\n`,
    "utf8",
  );
  const config = loadConfig({
    PHIGON_DATA_DIR: dataDirectory,
    PHIGON_ACTIVITY_REPLAY_ON_FIRST_START: "true",
    PHIGON_ACTIVITY_RATE_LIMIT_PER_MINUTE: "100",
    PHIGON_COLLECT_VENDOR_PAYLOAD: "true",
  });
  const credential = {
    machineId: "5f1b4cb4-a77d-4f53-af66-197e184683f4",
    tenantId: "7d1b4cb4-a77d-4f53-af66-197e184683f4",
    credential: `phg_m_${"0".repeat(43)}`,
    controlPlaneOrigin: "http://127.0.0.1:8080",
    createdAt: "2026-07-24T00:00:00.000Z",
  };

  try {
    const delivered: EventEnvelope[] = [];
    const first = new ActivityCollector({
      config,
      credential,
      initialSequence: 0n,
      durableDelivery: true,
      emit: (event) => delivered.push(event),
      sources: [source],
    });
    await first.scanOnce();
    assert.ok(delivered.length > 0);
    assert.equal(first.metrics().pendingCheckpoints, 0);

    const replayed: EventEnvelope[] = [];
    const restarted = new ActivityCollector({
      config,
      credential,
      initialSequence: first.metrics().lastSequence,
      initialAcknowledgedSequence: 0n,
      durableDelivery: true,
      emit: (event) => replayed.push(event),
      sources: [source],
    });
    await restarted.scanOnce();
    assert.deepEqual(replayed, []);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("activity collector lowers durable acknowledgement after a server restore", async () => {
  const directory = await mkdtemp(join(tmpdir(), "phigon-collector-reset-"));
  const sourceRoot = join(directory, "sessions");
  const dataDirectory = join(directory, "data");
  const source = { adapterId: "codex", roots: [sourceRoot] } as const;
  await mkdir(sourceRoot, { recursive: true });
  await writeFile(
    join(sourceRoot, "codex.jsonl"),
    `${JSON.stringify({
      timestamp: "2026-07-24T10:10:00.000Z",
      type: "event_msg",
      payload: { type: "agent_message", message: "restore durability" },
    })}\n`,
    "utf8",
  );
  const config = loadConfig({
    PHIGON_DATA_DIR: dataDirectory,
    PHIGON_ACTIVITY_REPLAY_ON_FIRST_START: "true",
    PHIGON_ACTIVITY_RATE_LIMIT_PER_MINUTE: "100",
    PHIGON_COLLECT_VENDOR_PAYLOAD: "true",
  });
  const credential = {
    machineId: "5f1b4cb4-a77d-4f53-af66-197e184683f4",
    tenantId: "7d1b4cb4-a77d-4f53-af66-197e184683f4",
    credential: `phg_m_${"0".repeat(43)}`,
    controlPlaneOrigin: "http://127.0.0.1:8080",
    createdAt: "2026-07-24T00:00:00.000Z",
  };

  try {
    const collector = new ActivityCollector({
      config,
      credential,
      initialSequence: 100n,
      emit: () => undefined,
      sources: [source],
    });
    collector.resetSequence(50n, 50n);
    const metrics = await collector.scanOnce();
    assert.ok(metrics.lastSequence > 50n);

    const replayed: EventEnvelope[] = [];
    const restartedBeforeAck = new ActivityCollector({
      config,
      credential,
      initialSequence: 50n,
      emit: (event) => replayed.push(event),
      sources: [source],
    });
    await restartedBeforeAck.scanOnce();
    assert.ok(replayed.length > 0);

    await collector.acknowledge(metrics.lastSequence);
    const afterAck: EventEnvelope[] = [];
    const restartedAfterAck = new ActivityCollector({
      config,
      credential,
      initialSequence: metrics.lastSequence,
      emit: (event) => afterAck.push(event),
      sources: [source],
    });
    await restartedAfterAck.scanOnce();
    assert.deepEqual(afterAck, []);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("activity collector coalesces checkpoint snapshots during an outage", async () => {
  const directory = await mkdtemp(join(tmpdir(), "phigon-collector-outage-"));
  const sourceRoot = join(directory, "sessions");
  await mkdir(sourceRoot, { recursive: true });
  await writeFile(
    join(sourceRoot, "codex.jsonl"),
    `${JSON.stringify({
      type: "event_msg",
      payload: { type: "agent_message", message: "unacknowledged" },
    })}\n`,
    "utf8",
  );
  const collector = new ActivityCollector({
    config: loadConfig({
      PHIGON_DATA_DIR: join(directory, "data"),
      PHIGON_ACTIVITY_REPLAY_ON_FIRST_START: "true",
      PHIGON_ACTIVITY_RATE_LIMIT_PER_MINUTE: "100",
      PHIGON_COLLECT_VENDOR_PAYLOAD: "true",
    }),
    credential: {
      machineId: "5f1b4cb4-a77d-4f53-af66-197e184683f4",
      tenantId: "7d1b4cb4-a77d-4f53-af66-197e184683f4",
      credential: `phg_m_${"0".repeat(43)}`,
      controlPlaneOrigin: "http://127.0.0.1:8080",
      createdAt: "2026-07-24T00:00:00.000Z",
    },
    initialSequence: 0n,
    emit: () => undefined,
    sources: [{ adapterId: "codex", roots: [sourceRoot] }],
  });

  try {
    for (let scan = 0; scan < 64; scan++) {
      await collector.scanOnce();
      assert.equal(collector.metrics().pendingCheckpoints, 1);
    }
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("activity collector retains the checkpoint for a partially acknowledged scan", async () => {
  const directory = await mkdtemp(join(tmpdir(), "phigon-collector-partial-"));
  const sourceRoot = join(directory, "sessions");
  const dataDirectory = join(directory, "data");
  const sourceFile = join(sourceRoot, "generic.jsonl");
  const source = { adapterId: "generic", roots: [sourceRoot] } as const;
  await mkdir(sourceRoot, { recursive: true });
  const firstRecord = JSON.stringify({
    agent: "aider",
    type: "message",
    message: { role: "assistant", content: "first accepted record" },
  });
  const secondRecord = JSON.stringify({
    agent: "aider",
    type: "message",
    message: { role: "assistant", content: "second pending record" },
  });
  await writeFile(sourceFile, `${firstRecord}\n`, "utf8");
  const config = loadConfig({
    PHIGON_DATA_DIR: dataDirectory,
    PHIGON_ACTIVITY_REPLAY_ON_FIRST_START: "true",
    PHIGON_ACTIVITY_RATE_LIMIT_PER_MINUTE: "100",
    PHIGON_COLLECT_RESPONSE_CONTENT: "true",
    PHIGON_COLLECT_VENDOR_PAYLOAD: "true",
  });
  const credential = {
    machineId: "5f1b4cb4-a77d-4f53-af66-197e184683f4",
    tenantId: "7d1b4cb4-a77d-4f53-af66-197e184683f4",
    credential: `phg_m_${"0".repeat(43)}`,
    controlPlaneOrigin: "http://127.0.0.1:8080",
    createdAt: "2026-07-24T00:00:00.000Z",
  };

  try {
    const collector = new ActivityCollector({
      config,
      credential,
      initialSequence: 0n,
      emit: () => undefined,
      sources: [source],
    });
    const first = await collector.scanOnce();
    await writeFile(
      sourceFile,
      `${firstRecord}\n${secondRecord}\n`,
      "utf8",
    );
    await collector.scanOnce();
    assert.equal(collector.metrics().pendingCheckpoints, 2);

    await collector.acknowledge(first.lastSequence);
    assert.equal(collector.metrics().pendingCheckpoints, 1);

    const replayed: EventEnvelope[] = [];
    const restarted = new ActivityCollector({
      config,
      credential,
      initialSequence: first.lastSequence,
      emit: (event) => replayed.push(event),
      sources: [source],
    });
    await restarted.scanOnce();
    const serialized = replayed
      .map((event) => toJsonString(EventEnvelopeSchema, event))
      .join("\n");
    assert.doesNotMatch(serialized, /first accepted record/u);
    assert.match(serialized, /second pending record/u);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("activity collector clamps future vendor clocks to the local observation time", async () => {
  const directory = await mkdtemp(join(tmpdir(), "phigon-clock-skew-"));
  const sourceRoot = join(directory, "sessions");
  const dataDirectory = join(directory, "data");
  const now = new Date("2026-07-24T10:10:00.000Z");
  await mkdir(sourceRoot, { recursive: true });
  await writeFile(
    join(sourceRoot, "future.jsonl"),
    `${JSON.stringify({
      timestamp: "2036-07-24T10:10:00.000Z",
      type: "event_msg",
      payload: { type: "agent_message", message: "clock skew test" },
    })}\n`,
    "utf8",
  );
  const emitted: EventEnvelope[] = [];
  const collector = new ActivityCollector({
    config: loadConfig({
      PHIGON_DATA_DIR: dataDirectory,
      PHIGON_ACTIVITY_REPLAY_ON_FIRST_START: "true",
      PHIGON_ACTIVITY_RATE_LIMIT_PER_MINUTE: "100",
      PHIGON_COLLECT_VENDOR_PAYLOAD: "true",
    }),
    credential: {
      machineId: "5f1b4cb4-a77d-4f53-af66-197e184683f4",
      tenantId: "7d1b4cb4-a77d-4f53-af66-197e184683f4",
      credential:
        "phg_m_0123456789012345678901234567890123456789012",
      controlPlaneOrigin: "http://127.0.0.1:8080",
      createdAt: now.toISOString(),
    },
    initialSequence: 0n,
    emit: (event) => emitted.push(event),
    sources: [{ adapterId: "codex", roots: [sourceRoot] }],
    clock: () => now,
  });

  try {
    await collector.scanOnce();
    assert.ok(emitted.length > 0);
    assert.ok(
      emitted.every(
        (event) =>
          event.observedAt !== undefined &&
          timestampDate(event.observedAt).toISOString() === now.toISOString(),
      ),
    );
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("generic records without runtime evidence stay on source identity", async () => {
  const directory = await mkdtemp(join(tmpdir(), "phigon-generic-owner-"));
  const sourceRoot = join(directory, "sessions");
  await mkdir(sourceRoot, { recursive: true });
  await writeFile(
    join(sourceRoot, "agents.jsonl"),
    [
      JSON.stringify({
        agent: "aider",
        type: "message",
        message: { role: "assistant", content: "Aider reply" },
      }),
      JSON.stringify({
        agent: "gemini",
        type: "message",
        message: { role: "assistant", content: "Gemini reply" },
      }),
      JSON.stringify({
        agent: "Acme Research Agent",
        type: "message",
        message: { role: "assistant", content: "Acme reply" },
      }),
      "",
    ].join("\n"),
    "utf8",
  );
  const emitted: EventEnvelope[] = [];
  const collector = new ActivityCollector({
    config: loadConfig({
      PHIGON_DATA_DIR: join(directory, "data"),
      PHIGON_ACTIVITY_REPLAY_ON_FIRST_START: "true",
      PHIGON_ACTIVITY_RATE_LIMIT_PER_MINUTE: "100",
      PHIGON_COLLECT_VENDOR_PAYLOAD: "true",
    }),
    credential: {
      machineId: "5f1b4cb4-a77d-4f53-af66-197e184683f4",
      tenantId: "7d1b4cb4-a77d-4f53-af66-197e184683f4",
      credential:
        "phg_m_0123456789012345678901234567890123456789012",
      controlPlaneOrigin: "http://127.0.0.1:8080",
      createdAt: "2026-07-24T00:00:00.000Z",
    },
    initialSequence: 0n,
    emit: (event) => emitted.push(event),
    sources: [{ adapterId: "generic", roots: [sourceRoot] }],
  });
  collector.updateInventory(create(AgentInventorySchema, {
    machineId: "5f1b4cb4-a77d-4f53-af66-197e184683f4",
    observedAt: timestampFromDate(new Date()),
    agents: [
      {
        $typeName: "phigon.v1.AgentIdentity",
        agentId: "agt_aider",
        kind: AgentKind.GENERIC,
        displayName: "Aider",
        version: "",
        runtime: "",
        state: AgentState.RUNNING,
        processId: 41n,
        capabilities: [],
        executablePathDigest: "a".repeat(64),
      },
      {
        $typeName: "phigon.v1.AgentIdentity",
        agentId: "agt_gemini",
        kind: AgentKind.GENERIC,
        displayName: "Gemini CLI",
        version: "",
        runtime: "",
        state: AgentState.RUNNING,
        processId: 42n,
        capabilities: [],
        executablePathDigest: "b".repeat(64),
      },
    ],
  }));

  try {
    await collector.scanOnce();
    const owners = new Map(
      emitted.flatMap((event) => {
        if (event.payload.case !== "vendor") return [];
        const payload = event.payload.value.payloadJson;
        if (payload === undefined) return [];
        const record = JSON.parse(payload);
        return [[record.agent, event.agentId] as const];
      }),
    );
    assert.notEqual(owners.get("aider"), "agt_aider");
    assert.notEqual(owners.get("gemini"), "agt_gemini");
    assert.equal(owners.get("aider"), owners.get("gemini"));
    const acmeEvent = emitted.find(
      (event) =>
        event.payload.case === "vendor" &&
        event.payload.value.source === "acme-research-agent",
    );
    assert.ok(acmeEvent);
    assert.match(acmeEvent.agentId, /^agt_/u);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("a history import rests as long as each batch worked, at most a second", () => {
  assert.equal(historyRest(0), 0);
  assert.equal(historyRest(-5), 0);
  assert.equal(historyRest(Number.NaN), 0);
  assert.equal(historyRest(12.4), 12);
  assert.equal(historyRest(480), 480);
  assert.equal(historyRest(5_000), 1_000);
});
