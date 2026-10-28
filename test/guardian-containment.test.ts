import { create } from "@bufbuild/protobuf";
import { timestampFromDate } from "@bufbuild/protobuf/wkt";
import assert from "node:assert/strict";
import test from "node:test";
import { GuardianContainmentExecutor } from "../src/guardian-containment.js";
import type { ExactProcess, ProcessTreeControl, TreeStopMode, TreeStopOutcome } from "../src/process-tree.js";
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

function recordingControl(outcome: TreeStopOutcome) {
  const calls: Array<{ target: ExactProcess; mode: TreeStopMode }> = [];
  const control: ProcessTreeControl = {
    stop: async (target, mode) => {
      calls.push({ target, mode });
      return outcome;
    },
  };
  return { control, calls };
}

const stopped: TreeStopOutcome = { outcome: "dispatched", rootRunning: false, descendants: 1, descendantsRunning: 0, descendantsDenied: 0 };

test("an unavailable containment executor fails closed", async () => {
  let inventoryReads = 0;
  const { control, calls } = recordingControl(stopped);
  const executor = new GuardianContainmentExecutor({
    enabled: false,
    processControl: control,
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
  assert.equal(calls.length, 0);
});

test("containment rejects a stale process lifetime without signaling", async () => {
  const { control, calls } = recordingControl(stopped);
  const executor = new GuardianContainmentExecutor({
    enabled: true,
    inventory: async () => inventory(43n),
    observerProcessID: 999,
    processControl: control,
  });
  const response = await executor.execute({
    intervention: "kill_agent",
    agentId: "codex:runtime:42",
    processId: 42,
    expectedStartedAt: startedAt.toISOString(),
  });
  assert.equal(response.code, "stale_target");
  assert.equal(calls.length, 0);
});

test("containment force-stops only the verified process lifetime and its tree", async () => {
  const { control, calls } = recordingControl(stopped);
  const executor = new GuardianContainmentExecutor({
    enabled: true,
    inventory: async () => inventory(),
    observerProcessID: 999,
    processControl: control,
  });
  const response = await executor.execute({
    intervention: "kill_agent",
    agentId: "codex:runtime:42",
    processId: 42,
    expectedStartedAt: startedAt.toISOString(),
  });
  assert.equal(response.state, "succeeded");
  assert.equal(response.targetStillRunning, false);
  assert.deepEqual(calls, [{ target: { processId: 42, startedAt }, mode: "kill" }]);
});

test("a graceful stop never escalates and reports what the platform could not do", async () => {
  const { control, calls } = recordingControl({ outcome: "graceful_unsupported" });
  const executor = new GuardianContainmentExecutor({
    enabled: true,
    inventory: async () => inventory(),
    observerProcessID: 999,
    processControl: control,
  });
  const response = await executor.execute({
    intervention: "stop_agent",
    agentId: "codex:runtime:42",
    processId: 42,
    expectedStartedAt: startedAt.toISOString(),
  });
  assert.equal(response.state, "rejected");
  assert.equal(response.code, "graceful_stop_unsupported");
  assert.equal(response.targetStillRunning, true);
  assert.deepEqual(calls.map((call) => call.mode), ["stop"]);
});

test("containment reports surviving children and refuses the observer itself", async () => {
  const { control, calls } = recordingControl({ outcome: "dispatched", rootRunning: false, descendants: 2, descendantsRunning: 0, descendantsDenied: 1 });
  const executor = new GuardianContainmentExecutor({
    enabled: true,
    inventory: async () => inventory(),
    observerProcessID: 999,
    processControl: control,
  });
  const response = await executor.execute({
    intervention: "kill_agent",
    agentId: "codex:runtime:42",
    processId: 42,
    expectedStartedAt: startedAt.toISOString(),
  });
  assert.equal(response.code, "process_stopped_children_running");
  const self = await executor.execute({
    intervention: "kill_agent",
    agentId: "codex:runtime:42",
    processId: 999,
    expectedStartedAt: startedAt.toISOString(),
  });
  assert.equal(self.code, "self_target_rejected");
  assert.equal(calls.length, 1);
});
