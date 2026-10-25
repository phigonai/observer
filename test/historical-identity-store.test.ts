import assert from "node:assert/strict";
import test from "node:test";
import {
  mkdtemp,
  mkdir,
  readFile,
  rm,
  stat,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { create } from "@bufbuild/protobuf";
import { timestampFromDate } from "@bufbuild/protobuf/wkt";
import {
  AgentKind,
  AgentState,
} from "../src/generated/phigon/v1/common_pb.js";
import {
  AgentIdentitySchema,
  AgentInventorySchema,
  type AgentIdentity,
} from "../src/generated/phigon/v1/identity_pb.js";
import {
  HistoricalIdentityStore,
  mergeInventoryWithHistoricalIdentities,
  type HistoricalIdentityScope,
} from "../src/historical-identity-store.js";

const scope: HistoricalIdentityScope = {
  tenantId: "7d1b4cb4-a77d-4f53-af66-197e184683f4",
  machineId: "5f1b4cb4-a77d-4f53-af66-197e184683f4",
};

test("historical identities survive restart with current discovery authoritative", async () => {
  const directory = await mkdtemp(join(tmpdir(), "phigon-history-store-"));
  const runtime = runtimeIdentity(1, AgentState.RUNNING, 303n);
  const source = sourceIdentity(2);

  try {
    const first = new HistoricalIdentityStore(directory, scope);
    const remembered = await first.remember([runtime, source]);
    assert.equal(remembered.length, 2);

    if (process.platform !== "win32") {
      const metadata = await stat(
        join(directory, "historical-agent-identities.json"),
      );
      assert.equal(metadata.mode & 0o777, 0o600);
    }
    const raw = await readFile(
      join(directory, "historical-agent-identities.json"),
      "utf8",
    );
    assert.doesNotMatch(raw, /prompt|tool output|credential|raw-process-key/u);

    const restarted = new HistoricalIdentityStore(directory, scope);
    const restored = await restarted.load();
    assert.equal(restored.length, 2);
    assert.equal(
      restored.find((identity) => identity.agentId === runtime.agentId)?.state,
      AgentState.STOPPED,
    );
    assert.equal(
      restored.find((identity) => identity.agentId === runtime.agentId)
        ?.processId,
      303n,
    );
    assert.equal(
      restored.find((identity) => identity.agentId === source.agentId)?.state,
      AgentState.UNKNOWN,
    );

    const current = create(AgentInventorySchema, {
      machineId: scope.machineId,
      observedAt: timestampFromDate(new Date("2026-08-02T13:00:00.000Z")),
      agents: [runtime],
    });
    const merged = mergeInventoryWithHistoricalIdentities(current, restored);
    assert.equal(merged.agents.length, 2);
    assert.equal(
      merged.agents.find((identity) => identity.agentId === runtime.agentId)
        ?.state,
      AgentState.RUNNING,
    );
    assert.equal(
      merged.agents.find((identity) => identity.agentId === source.agentId)
        ?.state,
      AgentState.UNKNOWN,
    );

    const afterCompleteExit = mergeInventoryWithHistoricalIdentities(
      create(AgentInventorySchema, {
        machineId: scope.machineId,
        observedAt: timestampFromDate(new Date("2026-08-02T14:00:00.000Z")),
        agents: [create(AgentIdentitySchema, {
          agentId: `agt_${"f".repeat(32)}`,
          kind: AgentKind.CODEX,
          displayName: "OpenAI Codex",
          state: AgentState.STOPPED,
          processId: 0n,
          lastObservedAt: timestampFromDate(
            new Date("2026-08-02T14:00:00.000Z"),
          ),
          capabilities: ["activity", "agent-product:codex"],
          executablePathDigest: "a".repeat(64),
        })],
      }),
      restored,
    );
    assert.equal(afterCompleteExit.agents.length, 2);
    assert.equal(
      afterCompleteExit.agents.some(
        (identity) => identity.displayName === "OpenAI Codex",
      ),
      false,
    );
    assert.equal(
      afterCompleteExit.agents.find(
        (identity) => identity.agentId === runtime.agentId,
      )?.state,
      AgentState.STOPPED,
    );
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("malformed catalogs fail closed and are atomically replaced", async () => {
  const directory = await mkdtemp(join(tmpdir(), "phigon-history-broken-"));
  const path = join(directory, "historical-agent-identities.json");
  await writeFile(path, "{not-json", "utf8");

  try {
    const store = new HistoricalIdentityStore(directory, scope);
    assert.deepEqual(await store.load(), []);
    await store.remember([]);
    const repaired = JSON.parse(await readFile(path, "utf8"));
    assert.equal(repaired.tenant_id, scope.tenantId);
    assert.equal(repaired.machine_id, scope.machineId);
    assert.deepEqual(repaired.identities, []);
    if (process.platform !== "win32") {
      assert.equal((await stat(path)).mode & 0o777, 0o600);
    }
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("catalog identities never cross tenant or machine scope", async () => {
  for (const mismatch of [
    { tenantId: "tenant-b", machineId: scope.machineId },
    { tenantId: scope.tenantId, machineId: "machine-b" },
  ]) {
    const directory = await mkdtemp(join(tmpdir(), "phigon-history-scope-"));
    try {
      await new HistoricalIdentityStore(directory, scope).remember([
        runtimeIdentity(3, AgentState.RUNNING, 404n),
      ]);
      const repairedScope = new HistoricalIdentityStore(directory, mismatch);
      assert.deepEqual(await repairedScope.load(), []);
      await repairedScope.remember([]);
      const stored = JSON.parse(await readFile(
        join(directory, "historical-agent-identities.json"),
        "utf8",
      ));
      assert.equal(stored.tenant_id, mismatch.tenantId);
      assert.equal(stored.machine_id, mismatch.machineId);
      assert.deepEqual(stored.identities, []);
      assert.deepEqual(
        await new HistoricalIdentityStore(directory, scope).load(),
        [],
      );
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  }
});

test("historical catalog remains bounded to 256 recent identities", async () => {
  const directory = await mkdtemp(join(tmpdir(), "phigon-history-bound-"));
  try {
    const identities = Array.from(
      { length: 300 },
      (_, index) => runtimeIdentity(
        index + 1,
        AgentState.RUNNING,
        BigInt(index + 1),
        new Date(1_700_000_000_000 + index * 1_000),
      ),
    );
    const store = new HistoricalIdentityStore(directory, scope);
    assert.equal((await store.remember(identities)).length, 256);
    const restored = await new HistoricalIdentityStore(directory, scope).load();
    assert.equal(restored.length, 256);
    assert.equal(
      restored.some((identity) => identity.agentId === identities[299]?.agentId),
      true,
    );
    assert.equal(
      restored.some((identity) => identity.agentId === identities[0]?.agentId),
      false,
    );
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("conflicting, missing, and coverage-lost identities are not persisted", async () => {
  const directory = await mkdtemp(join(tmpdir(), "phigon-history-evidence-"));
  const valid = runtimeIdentity(10, AgentState.RUNNING, 501n);
  const conflict = create(AgentIdentitySchema, {
    ...runtimeIdentity(11, AgentState.RUNNING, 502n),
    capabilities: [
      "process-instance",
      "process-key-sha256:11111111111111111111111111111111",
      "source-isolated",
      "unattributed",
    ],
  });
  const missingProcessKey = create(AgentIdentitySchema, {
    ...runtimeIdentity(12, AgentState.RUNNING, 503n),
    capabilities: ["agent-product:codex", "process-instance"],
  });
  const coverageLostSource = create(AgentIdentitySchema, {
    ...sourceIdentity(13),
    capabilities: ["activity", "source-isolated"],
  });

  try {
    const store = new HistoricalIdentityStore(directory, scope);
    const remembered = await store.remember([
      valid,
      conflict,
      missingProcessKey,
      coverageLostSource,
    ]);
    assert.deepEqual(
      remembered.map((identity) => identity.agentId),
      [valid.agentId],
    );
    assert.deepEqual(
      (await new HistoricalIdentityStore(directory, scope).load())
        .map((identity) => identity.agentId),
      [valid.agentId],
    );
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("one malformed stored identity invalidates the complete catalog", async () => {
  const directory = await mkdtemp(join(tmpdir(), "phigon-history-tamper-"));
  const path = join(directory, "historical-agent-identities.json");
  try {
    await new HistoricalIdentityStore(directory, scope).remember([
      runtimeIdentity(20, AgentState.RUNNING, 601n),
      sourceIdentity(21),
    ]);
    const catalog = JSON.parse(await readFile(path, "utf8"));
    catalog.identities[1].capabilities.push("secret value");
    await writeFile(path, JSON.stringify(catalog), "utf8");

    assert.deepEqual(
      await new HistoricalIdentityStore(directory, scope).load(),
      [],
    );
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("catalog persistence failures are surfaced", async () => {
  const directory = await mkdtemp(join(tmpdir(), "phigon-history-failure-"));
  const path = join(directory, "historical-agent-identities.json");
  try {
    const store = new HistoricalIdentityStore(directory, scope);
    assert.deepEqual(await store.load(), []);
    await mkdir(path);
    await assert.rejects(
      store.remember([runtimeIdentity(30, AgentState.RUNNING, 701n)]),
    );
    assert.deepEqual(store.identities(), [
      create(AgentIdentitySchema, {
        ...runtimeIdentity(30, AgentState.RUNNING, 701n),
        state: AgentState.STOPPED,
      }),
    ]);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

function runtimeIdentity(
  index: number,
  state: AgentState,
  processID: bigint,
  observedAt = new Date("2026-08-02T12:00:00.000Z"),
): AgentIdentity {
  const hex = index.toString(16).padStart(32, "0").slice(-32);
  return create(AgentIdentitySchema, {
    agentId: `agt_${hex}`,
    kind: AgentKind.CODEX,
    displayName: `OpenAI Codex · PID ${processID}`,
    version: "0.145.0",
    state,
    processId: processID,
    startedAt: timestampFromDate(new Date("2026-08-02T11:00:00.000Z")),
    lastObservedAt: timestampFromDate(observedAt),
    capabilities: [
      "activity",
      "agent-product:codex",
      "process-instance",
      `process-key-sha256:${hex}`,
    ],
    executablePathDigest: "a".repeat(64),
  });
}

function sourceIdentity(index: number): AgentIdentity {
  const hex = index.toString(16).padStart(32, "0").slice(-32);
  return create(AgentIdentitySchema, {
    agentId: `agt_${hex}`,
    kind: AgentKind.CLAUDE,
    displayName: `Claude Code · Source ${hex.slice(-8)} (unattributed)`,
    state: AgentState.UNKNOWN,
    processId: 0n,
    lastObservedAt: timestampFromDate(new Date("2026-08-02T12:30:00.000Z")),
    capabilities: ["activity", "source-isolated", "unattributed"],
  });
}
