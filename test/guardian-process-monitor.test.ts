import { create } from "@bufbuild/protobuf";
import { timestampFromDate } from "@bufbuild/protobuf/wkt";
import assert from "node:assert/strict";
import test from "node:test";
import { GuardianProcessMonitor } from "../src/guardian-process-monitor.js";
import { AgentInventorySchema, AgentIdentitySchema } from "../src/generated/phigon/v1/identity_pb.js";
import { AgentState } from "../src/generated/phigon/v1/common_pb.js";
import type { GuardianIntervention } from "../src/action-policy.js";
import type { GuardianHostedClient } from "../src/guardian-hosted-client.js";

test("stalled reviews stay bounded and the next pass fairly starts unreviewed processes", async () => {
  const calls: string[] = [];
  const coverage: Record<string, unknown>[] = [];
  const inventory = create(AgentInventorySchema, { machineId: "machine", agents: Array.from({length: 8}, (_, index) => create(AgentIdentitySchema, {
    agentId: `agent:${index}`, processId: BigInt(index+1), startedAt: timestampFromDate(new Date()), state: AgentState.RUNNING, capabilities: ["process-instance"],
  })) });
  const monitor = new GuardianProcessMonitor({
    machineId: "machine", onStatus: () => undefined,
    policyStore: { load: async () => ({ machineId: "machine", policyDigest: "a".repeat(64), defaultEffect: "allow", rules: [], receivedAt: new Date().toISOString() }) },
    decisionClient: { decide: async proposal => { calls.push(proposal.agentId); return new Promise(() => {}); } },
    containment: { execute: async () => { throw new Error("An unverified review must not contain a process"); } },
    journal: { append: async () => {} },
    coverageClient: { post: async (_path, body) => {coverage.push(body as Record<string, unknown>);return {};} },
  });
  for (let pass=0;pass<2;pass++) {
    const controller = new AbortController();
    const running = monitor.review(inventory, controller.signal);
    await new Promise(resolve => setTimeout(resolve, 20));
    assert.equal(calls.length, (pass+1)*4);
    controller.abort();
    await running;
  }
  assert.equal(new Set(calls).size, 8);
  assert.equal(coverage[0]?.["process_review"], "degraded");
  assert.equal(coverage[0]?.["unverified"], 8);
});

test("partial discovery reports degraded coverage even with no discovered processes and recovers", async () => {
  const reports: Record<string, unknown>[] = [];
  const statuses: string[] = [];
  const post: GuardianHostedClient["post"] = async (_path, body) => { reports.push(body as Record<string, unknown>); return {}; };
  const monitor = new GuardianProcessMonitor({
    machineId: "machine", onStatus: (value) => statuses.push(value),
    policyStore: { load: async () => ({ machineId: "machine", policyDigest: "a".repeat(64), defaultEffect: "allow", rules: [], receivedAt: new Date().toISOString() }) },
    decisionClient: { decide: async () => { throw new Error("No processes should be reviewed"); } },
    containment: { execute: async () => { throw new Error("No processes should be stopped"); } },
    journal: { append: async () => { throw new Error("No action should be journaled"); } },
    coverageClient: { post },
  });
  for (const partial of [true, false]) await monitor.review(create(AgentInventorySchema, { machineId: "machine", partial, agents: [] }), new AbortController().signal);
  assert.equal(reports[0]?.["process_review"], "degraded");
  assert.equal(reports[0]?.["discovery_partial"], true);
  assert.equal(reports[0]?.["reviewed"], 0);
  assert.equal(reports[1]?.["process_review"], "active");
  assert.equal(reports[1]?.["discovery_partial"], false);
  assert.match(statuses.join("\n"), /discovery is incomplete/iu);
});

test("discovered agents require central containment authority and exact lifetime evidence", async () => {
  const started = new Date("2026-09-05T00:00:00Z");
  const inventory = create(AgentInventorySchema, { machineId: "machine", agents: [
    create(AgentIdentitySchema, { agentId: "codex:1", displayName: "Codex", processId: 42n, startedAt: timestampFromDate(started), state: AgentState.RUNNING, capabilities: ["process-instance"] }),
    create(AgentIdentitySchema, { agentId: "history-only", state: AgentState.STOPPED }),
  ] });
  let intervention: GuardianIntervention = "block_action";
  let calls = 0, kills = 0, receipts = 0;
  const monitor = new GuardianProcessMonitor({
    machineId: "machine", onStatus: () => undefined,
    policyStore: { load: async () => ({ machineId: "machine", policyDigest: "a".repeat(64), defaultEffect: "allow", rules: [], receivedAt: started.toISOString() }) },
    decisionClient: { decide: async (proposal) => {
      calls++;
      assert.equal(proposal.processId, 42); assert.equal(proposal.processStartedAt, started.toISOString());
      assert.equal(JSON.parse(proposal.resource).lifecycle, "already_running");
      return { decision: "deny", reason: "Codex is prohibited.", risk: "high", confidence: 1, model: "policy-gateway", cached: false, latencyMs: 1, intervention };
    } },
    containment: { execute: async (request) => { kills++; assert.equal(request.processId, 42); assert.equal(request.intervention, "kill_agent"); return { state: "succeeded", code: "process_stopped", detail: "Stopped by Phigon." }; } },
    journal: { append: async () => { receipts++; } },
  });
  const controller = new AbortController();
  await monitor.review(inventory, controller.signal);
  assert.equal(kills, 0, "a block_action must never become a background kill");
  intervention = "kill_agent";
  await monitor.review(inventory, controller.signal);
  assert.equal(kills, 1); assert.equal(calls, 2); assert.equal(receipts, 2);
  controller.abort(); await monitor.review(inventory, controller.signal);
  assert.equal(calls, 2, "shutdown must not dispatch new reviews");
});
