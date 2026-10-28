import { create } from "@bufbuild/protobuf";
import { timestampFromDate } from "@bufbuild/protobuf/wkt";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { randomUUID } from "node:crypto";
import { once } from "node:events";
import { mkdtemp, mkdir, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { AgentActionExecutor } from "../src/agent-action-executor.js";
import { SystemEvidenceProvider } from "../src/discovery/system-evidence.js";
import {
  AgentActionCommandSchema,
  RemoteActionResultState,
  RemoteActionType,
} from "../src/generated/phigon/v1/action_pb.js";
import { AgentState } from "../src/generated/phigon/v1/common_pb.js";
import {
  AgentIdentitySchema,
  AgentInventorySchema,
} from "../src/generated/phigon/v1/identity_pb.js";

const machineID = "68fd2b0b-7e8c-4b0d-890d-7f2d8e94dc2f";
const actionID = "72b1f93f-6317-46c7-bbba-6174d19c4119";
const idempotencyKey = "f3303823-6c43-4ad8-9320-ee80c8bd61a2"; // gitleaks:allow -- Public test UUID; this deduplication identifier is not a credential.

test("disabled executor advertises no capability and returns an idempotent rejection", async () => {
  const directory = await mkdtemp(join(tmpdir(), "phigon-agent-action-"));
  let inventoryReads = 0;
  const executor = new AgentActionExecutor({
    enabled: false,
    machineID,
    dataDirectory: directory,
    inventory: async () => {
      inventoryReads += 1;
      return create(AgentInventorySchema, { machineId: machineID });
    },
  });
  assert.deepEqual(executor.capabilities(), []);
  assert.equal(executor.manifest().enabled, false);
  const command = create(AgentActionCommandSchema, {
    actionId: actionID,
    idempotencyKey,
    machineId: machineID,
    agentId: "agent-runtime",
    processId: 42n,
    expectedStartedAt: timestampFromDate(new Date()),
    expiresAt: timestampFromDate(new Date(Date.now() + 60_000)),
    action: RemoteActionType.KILL_AGENT,
  });
  const first = await executor.execute(command);
  const replay = await executor.execute(command);
  assert.equal(first.state, RemoteActionResultState.REJECTED);
  assert.equal(first.resultCode, "executor_disabled");
  assert.deepEqual(replay, first);
  assert.equal(inventoryReads, 0);
  assert.equal((await executor.execute({ ...command, action: RemoteActionType.STOP_AGENT })).resultCode, "idempotency_conflict");
});

test("corrupt execution records never become an empty replay history", async () => {
  const directory = await mkdtemp(join(tmpdir(), "phigon-agent-action-corrupt-"));
  await writeFile(join(directory, "agent-action-receipts.json"), "{broken");
  let reads = 0;
  const executor = new AgentActionExecutor({ enabled: true, machineID, dataDirectory: directory, inventory: async () => { reads++; return create(AgentInventorySchema, { machineId: machineID }); } });
  const result = await executor.execute(create(AgentActionCommandSchema, {
    actionId: actionID, idempotencyKey, machineId: machineID, agentId: "runtime", processId: 42n,
    expectedStartedAt: timestampFromDate(new Date()), expiresAt: timestampFromDate(new Date(Date.now() + 60000)), action: RemoteActionType.KILL_AGENT,
  }));
  assert.equal(result.resultCode, "execution_journal_unavailable");
  assert.equal(reads, 0);
});

test("enabled executor rejects an expired command before process discovery", async () => {
  const directory = await mkdtemp(join(tmpdir(), "phigon-agent-action-expired-"));
  let inventoryReads = 0;
  const executor = new AgentActionExecutor({
    enabled: true,
    machineID,
    dataDirectory: directory,
    inventory: async () => {
      inventoryReads += 1;
      return create(AgentInventorySchema, { machineId: machineID });
    },
  });
  const result = await executor.execute(create(AgentActionCommandSchema, {
    actionId: actionID,
    idempotencyKey,
    machineId: machineID,
    agentId: "agent-runtime",
    processId: 42n,
    expectedStartedAt: timestampFromDate(new Date(Date.now() - 10_000)),
    expiresAt: timestampFromDate(new Date(Date.now() - 1_000)),
    action: executor.capabilities()[0]!,
  }));
  assert.equal(result.state, RemoteActionResultState.EXPIRED);
  assert.equal(result.resultCode, "command_expired");
  assert.equal(inventoryReads, 0);
});

test("force stop signals only the exact freshly discovered process lifetime", async (t) => {
  const directory = await mkdtemp(join(tmpdir(), "phigon-agent-action-process-"));
  const child = spawn(process.execPath, ["-e", "setInterval(() => {}, 1000)"], {
    stdio: "ignore",
  });
  t.after(() => { if (child.exitCode === null && child.signalCode === null) child.kill("SIGKILL"); });
  await once(child, "spawn");
  assert.ok(child.pid);
  const evidence = await new SystemEvidenceProvider().listProcesses();
  assert.equal(evidence.status, "ok");
  const observed = evidence.status === "ok" ? evidence.value.find((entry) => entry.processId === child.pid) : undefined;
  assert.ok(observed, "the test process must have an OS-observed lifetime");
  const startedAt = observed.startedAt;
  const executor = new AgentActionExecutor({
    enabled: true,
    machineID,
    dataDirectory: directory,
    inventory: async () => create(AgentInventorySchema, {
      machineId: machineID,
      agents: [create(AgentIdentitySchema, {
        agentId: "test-agent-runtime",
        state: AgentState.RUNNING,
        processId: BigInt(child.pid!),
        startedAt: timestampFromDate(startedAt),
        capabilities: ["process-instance"],
      })],
    }),
  });
  try {
    const command = create(AgentActionCommandSchema, {
      actionId: actionID,
      idempotencyKey,
      machineId: machineID,
      agentId: "test-agent-runtime",
      processId: BigInt(child.pid),
      expectedStartedAt: timestampFromDate(startedAt),
      expiresAt: timestampFromDate(new Date(Date.now() + 60_000)),
      action: RemoteActionType.KILL_AGENT,
    });
    const [result, repeated] = await Promise.all([executor.execute(command), executor.execute(command)]);
    assert.deepEqual(repeated, result);
    assert.equal(result.state, RemoteActionResultState.SUCCEEDED);
    assert.equal(result.resultCode, "process_stopped");
    assert.equal(result.targetStillRunning, false);
  } finally {
    if (child.exitCode === null && child.signalCode === null) child.kill("SIGKILL");
  }
});

test("a durable claim blocks another signal when the completion journal is missing", async (t) => {
  const directory = await mkdtemp(join(tmpdir(), "phigon-agent-action-claim-"));
  const child = spawn(process.execPath, ["-e", "setInterval(() => {}, 1000)"], { stdio: "ignore" });
  t.after(() => { if (child.exitCode === null && child.signalCode === null) child.kill("SIGKILL"); });
  await once(child, "spawn");
  const startedAt = timestampFromDate(new Date());
  const executor = new AgentActionExecutor({ enabled: true, machineID, dataDirectory: directory,
    inventory: async () => create(AgentInventorySchema, { machineId: machineID, agents: [create(AgentIdentitySchema, {
      agentId: "claimed-runtime", processId: BigInt(child.pid!), state: AgentState.RUNNING, startedAt, capabilities: ["process-instance"],
    })] }),
  });
  const claims = join(directory, "process-operation-claims");
  await mkdir(claims);
  await writeFile(join(claims, `${idempotencyKey}.claim`), "previously claimed");
  const result = await executor.execute(create(AgentActionCommandSchema, {
    actionId: actionID, idempotencyKey, machineId: machineID, agentId: "claimed-runtime", processId: BigInt(child.pid!),
    expectedStartedAt: startedAt, expiresAt: timestampFromDate(new Date(Date.now() + 60000)), action: RemoteActionType.KILL_AGENT,
  }));
  assert.equal(result.resultCode, "execution_interrupted");
  assert.equal(result.state, RemoteActionResultState.FAILED);
  assert.equal(child.exitCode, null); assert.equal(child.signalCode, null);
  assert.doesNotThrow(() => process.kill(child.pid!, 0));
});

test("a command that expires during slow process discovery is never dispatched", async (t) => {
  const directory = await mkdtemp(join(tmpdir(), "phigon-agent-action-slow-discovery-"));
  const child = spawn(process.execPath, ["-e", "setInterval(() => {}, 1000)"], { stdio: "ignore" });
  t.after(() => { if (child.exitCode === null && child.signalCode === null) child.kill("SIGKILL"); });
  await once(child, "spawn");
  const evidence = await new SystemEvidenceProvider().listProcesses();
  const observed = evidence.status === "ok" ? evidence.value.find((entry) => entry.processId === child.pid) : undefined;
  assert.ok(observed, "the test process must have an OS-observed lifetime");
  const startedAt = timestampFromDate(observed.startedAt);
  const executor = new AgentActionExecutor({ enabled: true, machineID, dataDirectory: directory,
    inventory: async () => {
      await new Promise((resolve) => setTimeout(resolve, 900));
      return create(AgentInventorySchema, { machineId: machineID, agents: [create(AgentIdentitySchema, {
        agentId: "slow-runtime", processId: BigInt(child.pid!), state: AgentState.RUNNING, startedAt, capabilities: ["process-instance"],
      })] });
    },
  });
  const result = await executor.execute(create(AgentActionCommandSchema, {
    actionId: actionID, idempotencyKey, machineId: machineID, agentId: "slow-runtime", processId: BigInt(child.pid!),
    expectedStartedAt: startedAt, expiresAt: timestampFromDate(new Date(Date.now() + 400)), action: RemoteActionType.KILL_AGENT,
  }));
  assert.equal(result.state, RemoteActionResultState.EXPIRED);
  assert.equal(result.resultCode, "command_expired");
  assert.equal(result.targetStillRunning, true);
  assert.equal(child.exitCode, null); assert.equal(child.signalCode, null);
});

test("a discovery deadline set by the expiry reports expiry even if the timer fires early", async (t) => {
  const directory = await mkdtemp(join(tmpdir(), "phigon-agent-action-early-timer-"));
  const realNow = Date.now.bind(Date);
  const expiresAt = new Date(realNow() + 150);
  // Timers can fire a millisecond before Date.now() reaches the deadline;
  // pin the clock just short of expiry once discovery has started.
  let pinned = false;
  t.mock.method(Date, "now", () => pinned ? expiresAt.getTime() - 1 : realNow());
  const executor = new AgentActionExecutor({ enabled: true, machineID, dataDirectory: directory,
    inventory: () => { pinned = true; return new Promise<never>(() => {}); },
  });
  const result = await executor.execute(create(AgentActionCommandSchema, {
    actionId: actionID, idempotencyKey, machineId: machineID, agentId: "slow-runtime", processId: 4242n,
    expectedStartedAt: timestampFromDate(new Date(realNow() - 60_000)), expiresAt: timestampFromDate(expiresAt), action: RemoteActionType.KILL_AGENT,
  }));
  assert.equal(result.state, RemoteActionResultState.EXPIRED);
  assert.equal(result.resultCode, "command_expired");
});

test("a replay after the command expires returns the original receipt, not a false expiry", async (t) => {
  const directory = await mkdtemp(join(tmpdir(), "phigon-agent-action-retained-"));
  const child = spawn(process.execPath, ["-e", "setInterval(() => {}, 1000)"], { stdio: "ignore" });
  t.after(() => { if (child.exitCode === null && child.signalCode === null) child.kill("SIGKILL"); });
  await once(child, "spawn");
  const evidence = await new SystemEvidenceProvider().listProcesses();
  const observed = evidence.status === "ok" ? evidence.value.find((entry) => entry.processId === child.pid) : undefined;
  assert.ok(observed, "the test process must have an OS-observed lifetime");
  const startedAt = timestampFromDate(observed.startedAt);
  let running = true;
  const executor = new AgentActionExecutor({ enabled: true, machineID, dataDirectory: directory,
    inventory: async () => create(AgentInventorySchema, { machineId: machineID, agents: running ? [create(AgentIdentitySchema, {
      agentId: "retained-runtime", processId: BigInt(child.pid!), state: AgentState.RUNNING, startedAt, capabilities: ["process-instance"],
    })] : [] }),
  });
  const expiresAt = Date.now() + 3_000;
  const command = create(AgentActionCommandSchema, {
    actionId: actionID, idempotencyKey, machineId: machineID, agentId: "retained-runtime", processId: BigInt(child.pid!),
    expectedStartedAt: startedAt, expiresAt: timestampFromDate(new Date(expiresAt)), action: RemoteActionType.KILL_AGENT,
  });
  const first = await executor.execute(command);
  assert.equal(first.resultCode, "process_stopped");
  running = false;
  await new Promise((resolve) => setTimeout(resolve, Math.max(0, expiresAt + 100 - Date.now())));
  // Any later operation rewrites the journal; the expired receipt must survive it.
  await executor.execute(create(AgentActionCommandSchema, { ...command, actionId: randomUUID(),
    idempotencyKey: randomUUID(), expiresAt: timestampFromDate(new Date(Date.now() + 60_000)) }));
  const replay = await new AgentActionExecutor({ enabled: true, machineID, dataDirectory: directory,
    inventory: async () => create(AgentInventorySchema, { machineId: machineID }) }).execute(command);
  assert.deepEqual(replay, first);
});

test("retained expired receipts make room instead of blocking new commands", async () => {
  const directory = await mkdtemp(join(tmpdir(), "phigon-agent-action-capacity-"));
  const expired = new Date(Date.now() - 60_000).toISOString();
  const hex = (value: number) => value.toString(16).padStart(12, "0");
  await writeFile(join(directory, "agent-action-receipts.json"), JSON.stringify(Array.from({ length: 256 }, (_, index) => ({
    commandDigest: "a".repeat(64), expiresAt: expired, actionId: `00000000-0000-4000-8000-${hex(index)}`,
    idempotencyKey: `00000000-0000-4000-9000-${hex(index)}`, machineId: machineID, state: RemoteActionResultState.SUCCEEDED,
    resultCode: "process_stopped", detail: "Synthetic", observedAt: expired, targetStillRunning: false,
  }))));
  const executor = new AgentActionExecutor({ enabled: false, machineID, dataDirectory: directory,
    inventory: async () => create(AgentInventorySchema, { machineId: machineID }) });
  const result = await executor.execute(create(AgentActionCommandSchema, {
    actionId: actionID, idempotencyKey, machineId: machineID, agentId: "runtime", processId: 42n,
    expectedStartedAt: timestampFromDate(new Date()), expiresAt: timestampFromDate(new Date(Date.now() + 60_000)), action: RemoteActionType.KILL_AGENT,
  }));
  assert.equal(result.resultCode, "executor_disabled");
});

test("a claimed signal without a receipt is reported as interrupted, even after expiry", async () => {
  const directory = await mkdtemp(join(tmpdir(), "phigon-agent-action-claim-expired-"));
  await mkdir(join(directory, "process-operation-claims"));
  await writeFile(join(directory, "process-operation-claims", `${idempotencyKey}.claim`), "previously claimed");
  let reads = 0;
  const executor = new AgentActionExecutor({ enabled: true, machineID, dataDirectory: directory,
    inventory: async () => { reads++; return create(AgentInventorySchema, { machineId: machineID }); } });
  const result = await executor.execute(create(AgentActionCommandSchema, {
    actionId: actionID, idempotencyKey, machineId: machineID, agentId: "claimed-runtime", processId: 4242n,
    expectedStartedAt: timestampFromDate(new Date()), expiresAt: timestampFromDate(new Date(Date.now() - 1_000)), action: RemoteActionType.KILL_AGENT,
  }));
  assert.equal(result.state, RemoteActionResultState.FAILED);
  assert.equal(result.resultCode, "execution_interrupted");
  assert.equal(reads, 0);
});

test("process discovery that never answers ends within the command window without a signal", async () => {
  const directory = await mkdtemp(join(tmpdir(), "phigon-agent-action-hung-discovery-"));
  const executor = new AgentActionExecutor({ enabled: true, machineID, dataDirectory: directory,
    inventory: () => new Promise(() => undefined),
  });
  const started = Date.now();
  const result = await executor.execute(create(AgentActionCommandSchema, {
    actionId: actionID, idempotencyKey, machineId: machineID, agentId: "hung-runtime", processId: 4242n,
    expectedStartedAt: timestampFromDate(new Date()), expiresAt: timestampFromDate(new Date(Date.now() + 500)), action: RemoteActionType.KILL_AGENT,
  }));
  assert.ok(Date.now() - started < 3_000);
  assert.equal(result.state, RemoteActionResultState.EXPIRED);
  assert.equal(result.resultCode, "command_expired");
});
