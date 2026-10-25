import { create } from "@bufbuild/protobuf";
import { timestampFromDate } from "@bufbuild/protobuf/wkt";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
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
  assert.equal(result.resultCode, "execution_journal_unavailable");
  assert.equal(child.exitCode, null); assert.equal(child.signalCode, null);
  assert.doesNotThrow(() => process.kill(child.pid!, 0));
});
