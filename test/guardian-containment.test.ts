import { create } from "@bufbuild/protobuf";
import { timestampFromDate } from "@bufbuild/protobuf/wkt";
import assert from "node:assert/strict";
import test from "node:test";
import { GuardianContainmentExecutor } from "../src/guardian-containment.js";
import { AgentState } from "../src/generated/phigon/v1/common_pb.js";
import {
  AgentIdentitySchema,
  AgentInventorySchema,
} from "../src/generated/phigon/v1/identity_pb.js";

const startedAt = new Date("2026-09-04T09:00:00.000Z");

function inventory(processID = 42n) {
  return create(AgentInventorySchema, {
    machineId: "machine-test",
    agents: [create(AgentIdentitySchema, {
      agentId: "codex:runtime:42",
      state: AgentState.RUNNING,
      processId: processID,
      startedAt: timestampFromDate(startedAt),
      capabilities: ["process-instance"],
    })],
  });
}

test("an unavailable containment executor fails closed", async () => {
  let inventoryReads = 0;
  const executor = new GuardianContainmentExecutor({
    enabled: false,
    inventory: async () => {
      inventoryReads += 1;
      return inventory();
    },
  });
  const response = await executor.execute({
    intervention: "kill_agent",
    agentId: "codex:runtime:42",
    processId: 42,
    expectedStartedAt: startedAt.toISOString(),
  });
  assert.equal(response.code, "containment_disabled");
  assert.equal(inventoryReads, 0);
});

test("containment rejects a stale process lifetime without signaling", async () => {
  let signalCount = 0;
  const executor = new GuardianContainmentExecutor({
    enabled: true,
    inventory: async () => inventory(43n),
    observerProcessID: 999,
    platform: "linux",
    signal: () => {
      signalCount += 1;
    },
  });
  const response = await executor.execute({
    intervention: "kill_agent",
    agentId: "codex:runtime:42",
    processId: 42,
    expectedStartedAt: startedAt.toISOString(),
  });
  assert.equal(response.code, "stale_target");
  assert.equal(signalCount, 0);
});

test("containment signals only the verified process instance", async () => {
  let alive = true;
  const dispatched: string[] = [];
  const executor = new GuardianContainmentExecutor({
    enabled: true,
    inventory: async () => inventory(),
    observerProcessID: 999,
    platform: "linux",
    signal: (_processID, signal) => {
      if (signal === 0) {
        if (!alive) throw Object.assign(new Error("gone"), { code: "ESRCH" });
        return;
      }
      dispatched.push(signal);
      alive = false;
    },
    sleep: async () => {},
  });
  const response = await executor.execute({
    intervention: "kill_agent",
    agentId: "codex:runtime:42",
    processId: 42,
    expectedStartedAt: startedAt.toISOString(),
  });
  assert.equal(response.state, "succeeded");
  assert.deepEqual(dispatched, ["SIGKILL"]);
});

test("Windows stop makes a bounded graceful attempt without force escalation", async () => {
  let alive = true;
  const graceful: number[] = [];
  const signals: string[] = [];
  const executor = new GuardianContainmentExecutor({
    enabled: true,
    inventory: async () => inventory(),
    observerProcessID: 999,
    platform: "win32",
    signal: (_processID, signal) => {
      if (signal === 0) {
        if (!alive) throw Object.assign(new Error("gone"), { code: "ESRCH" });
        return;
      }
      signals.push(signal);
    },
    windowsGracefulStop: async (processID) => {
      graceful.push(processID);
      alive = false;
    },
    sleep: async () => {},
  });
  const response = await executor.execute({
    intervention: "stop_agent",
    agentId: "codex:runtime:42",
    processId: 42,
    expectedStartedAt: startedAt.toISOString(),
  });
  assert.equal(response.state, "succeeded");
  assert.deepEqual(graceful, [42]);
  assert.deepEqual(signals, []);
});
