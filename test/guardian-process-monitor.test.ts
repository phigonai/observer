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

test("an allowed process is asked about again only after a minute, a new policy or a new lifetime", async () => {
  let now = Date.parse("2026-11-02T12:00:00.000Z");
  let digest = "a".repeat(64);
  const agent = (startedAt: string) => create(AgentIdentitySchema, {
    agentId: "codex:1", processId: 42n, startedAt: timestampFromDate(new Date(startedAt)),
    state: AgentState.RUNNING, capabilities: ["process-instance"],
  });
  let inventory = create(AgentInventorySchema, { machineId: "machine", agents: [agent("2026-11-02T11:00:00Z")] });
  let calls = 0;
  const reports: Record<string, unknown>[] = [];
  const monitor = new GuardianProcessMonitor({
    machineId: "machine", onStatus: () => undefined, now: () => now,
    policyStore: { load: async () => ({ machineId: "machine", policyDigest: digest, defaultEffect: "allow", rules: [], receivedAt: new Date(now).toISOString() }) },
    decisionClient: { decide: async () => { calls++; return { decision: "allow", reason: "Allowed.", risk: "low", confidence: 1, model: "policy-gateway", cached: false, latencyMs: 1, intervention: "none" }; } },
    containment: { execute: async () => { throw new Error("An allowed process must not be stopped"); } },
    journal: { append: async () => undefined },
    coverageClient: { post: async (_path, body) => { reports.push(body as Record<string, unknown>); return {}; } },
  });
  const signal = new AbortController().signal;
  for (let pass = 0; pass < 5; pass++) {
    await monitor.review(inventory, signal);
    now += 10_000;
  }
  assert.equal(calls, 1);
  // Allowed on the first pass, unchanged since: one degraded report before
  // the first decision and one active report after it.
  assert.deepEqual(reports.map((report) => report["process_review"]), ["degraded", "active"]);
  assert.equal(reports[1]?.["reviewed"], 1);

  now += 20_000;
  await monitor.review(inventory, signal);
  assert.equal(calls, 2, "an allow is asked again after a minute");

  digest = "b".repeat(64);
  await monitor.review(inventory, signal);
  assert.equal(calls, 3, "a new policy is asked again at once");

  inventory = create(AgentInventorySchema, { machineId: "machine", agents: [agent("2026-11-02T12:01:00Z")] });
  await monitor.review(inventory, signal);
  assert.equal(calls, 4, "a reused process ID is a new process");
});

test("unchanged coverage is reported again once a minute and a change at once", async () => {
  let now = Date.parse("2026-11-02T12:00:00.000Z");
  const reports: Record<string, unknown>[] = [];
  const monitor = new GuardianProcessMonitor({
    machineId: "machine", onStatus: () => undefined, now: () => now,
    policyStore: { load: async () => ({ machineId: "machine", policyDigest: "a".repeat(64), defaultEffect: "allow", rules: [], receivedAt: new Date(now).toISOString() }) },
    decisionClient: { decide: async () => { throw new Error("No processes should be reviewed"); } },
    containment: { execute: async () => { throw new Error("No processes should be stopped"); } },
    journal: { append: async () => undefined },
    coverageClient: { post: async (_path, body) => { reports.push(body as Record<string, unknown>); return {}; } },
  });
  const signal = new AbortController().signal;
  for (let pass = 0; pass < 6; pass++) {
    await monitor.review(create(AgentInventorySchema, { machineId: "machine", agents: [] }), signal);
    now += 10_000;
  }
  assert.equal(reports.length, 1);
  await monitor.review(create(AgentInventorySchema, { machineId: "machine", agents: [] }), signal);
  assert.equal(reports.length, 2, "the server marks coverage stale after two minutes");
  await monitor.review(create(AgentInventorySchema, { machineId: "machine", partial: true, agents: [] }), signal);
  assert.equal(reports.length, 3);
  assert.equal(reports[2]?.["process_review"], "degraded");
});

test("the person at the computer is told when Phigon stops a blocked agent, once per process", async () => {
  const started = new Date("2026-09-05T00:00:00Z");
  const inventory = create(AgentInventorySchema, { machineId: "machine", agents: [
    create(AgentIdentitySchema, { agentId: "claude:7", displayName: "Claude Code · PID 7", processId: 7n, startedAt: timestampFromDate(started), state: AgentState.RUNNING, capabilities: ["process-instance"] }),
  ] });
  let model = "agent-block";
  let stopped = true;
  const notices: string[] = [];
  const monitor = new GuardianProcessMonitor({
    machineId: "machine", onStatus: () => undefined,
    policyStore: { load: async () => ({ machineId: "machine", policyDigest: "a".repeat(64), defaultEffect: "allow", rules: [], receivedAt: started.toISOString() }) },
    decisionClient: { decide: async () => ({ decision: "deny", reason: "Claude Code is blocked by Phigon AI.", risk: "high", confidence: 1, model, cached: false, latencyMs: 1, intervention: "stop_agent" }) },
    containment: { execute: async () => stopped
      ? { state: "succeeded", code: "process_stopped", detail: "Stopped." }
      : { state: "failed", code: "already_exited", detail: "The agent process had already exited." } },
    journal: { append: async () => undefined },
    notices: {
      agentBlocked: (notice) => { notices.push(`blocked ${notice.key} ${notice.agent}: ${notice.reason}`); },
      agentStopped: (notice) => { notices.push(`stopped ${notice.key} ${notice.agent} forced=${String(notice.forced)}`); },
    },
  });
  const signal = new AbortController().signal;
  await monitor.review(inventory, signal);
  assert.deepEqual(notices, ["blocked claude:7:7 Claude Code: Claude Code is blocked by Phigon AI."]);
  model = "policy-gateway";
  await monitor.review(inventory, signal);
  assert.equal(notices[1], "stopped claude:7:7 Claude Code forced=false");
  stopped = false;
  await monitor.review(inventory, signal);
  assert.equal(notices.length, 2, "a process that was already gone was not stopped by Phigon");
});
