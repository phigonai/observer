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
  let digest = "a".repeat(64);
  let calls = 0, kills = 0, receipts = 0;
  const monitor = new GuardianProcessMonitor({
    machineId: "machine", onStatus: () => undefined,
    policyStore: { load: async () => ({ machineId: "machine", policyDigest: digest, defaultEffect: "allow", rules: [], receivedAt: started.toISOString() }) },
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
  // A new policy is asked about at once.
  digest = "b".repeat(64);
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
  let now = Date.parse("2026-11-02T12:00:00.000Z");
  const notices: string[] = [];
  const monitor = new GuardianProcessMonitor({
    machineId: "machine", onStatus: () => undefined, now: () => now,
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
  // A denied process is asked about again only after ten minutes.
  now += 10 * 60_000;
  model = "policy-gateway";
  await monitor.review(inventory, signal);
  assert.equal(notices[1], "stopped claude:7:7 Claude Code forced=false");
  now += 10 * 60_000;
  stopped = false;
  await monitor.review(inventory, signal);
  assert.equal(notices.length, 2, "a process that was already gone was not stopped by Phigon");
});

const runningAgent = (agentId: string, processId: bigint) => create(AgentIdentitySchema, {
  agentId, processId, startedAt: timestampFromDate(new Date("2026-11-02T11:00:00Z")),
  state: AgentState.RUNNING, capabilities: ["process-instance"],
});

test("a denied process stays denied and is asked about, journaled and reported once per ten minutes", async () => {
  let now = Date.parse("2026-11-02T12:00:00.000Z");
  let digest = "a".repeat(64);
  let calls = 0, receipts = 0;
  const statuses: string[] = [];
  const reports: Record<string, unknown>[] = [];
  const inventory = create(AgentInventorySchema, { machineId: "machine", agents: [runningAgent("codex:1", 42n)] });
  const monitor = new GuardianProcessMonitor({
    machineId: "machine", onStatus: (message) => statuses.push(message), now: () => now,
    policyStore: { load: async () => ({ machineId: "machine", policyDigest: digest, defaultEffect: "allow", rules: [], receivedAt: new Date(now).toISOString() }) },
    decisionClient: { decide: async () => { calls++; return { decision: "deny", reason: "Codex is prohibited.", risk: "high", confidence: 1, model: "policy-gateway", cached: false, latencyMs: 1, intervention: "block_action", matchedContractId: "c1", adminContract: "No Codex." }; } },
    containment: { execute: async () => { throw new Error("A block_action must not stop the process"); } },
    journal: { append: async () => { receipts++; } },
    coverageClient: { post: async (_path, body) => { reports.push(body as Record<string, unknown>); return {}; } },
  });
  const signal = new AbortController().signal;
  for (let pass = 0; pass < 59; pass++) {
    await monitor.review(inventory, signal);
    now += 10_000;
  }
  assert.equal(calls, 1);
  assert.equal(receipts, 1);
  assert.equal(statuses.filter((message) => message.startsWith("Phigon Guardian: codex:1.")).length, 1);
  const last = reports.at(-1);
  assert.equal(last?.["denied"], 1, "a remembered deny is still a deny");
  assert.equal(last?.["reviewed"], 1);

  now += 10_000;
  await monitor.review(inventory, signal);
  assert.equal(calls, 2, "a deny is asked again after ten minutes");
  assert.equal(receipts, 2);

  digest = "b".repeat(64);
  await monitor.review(inventory, signal);
  assert.equal(calls, 3, "a new policy is asked again at once");
});

test("a failing decision service is asked again after growing waits and logged once", async () => {
  let now = Date.parse("2026-11-02T12:00:00.000Z");
  let failing = true;
  const callTimes: number[] = [];
  const statuses: string[] = [];
  const reports: Record<string, unknown>[] = [];
  const inventory = create(AgentInventorySchema, { machineId: "machine", agents: [runningAgent("codex:1", 42n), runningAgent("claude:2", 43n)] });
  const monitor = new GuardianProcessMonitor({
    machineId: "machine", onStatus: (message) => statuses.push(message), now: () => now,
    policyStore: { load: async () => ({ machineId: "machine", policyDigest: "a".repeat(64), defaultEffect: "allow", rules: [], receivedAt: new Date(now).toISOString() }) },
    decisionClient: { decide: async () => {
      callTimes.push(now);
      if (failing) throw new Error("Guardian decision service returned 409.");
      return { decision: "allow", reason: "Allowed.", risk: "low", confidence: 1, model: "policy-gateway", cached: false, latencyMs: 1, intervention: "none" };
    } },
    containment: { execute: async () => { throw new Error("No process should be stopped"); } },
    journal: { append: async () => { throw new Error("No decision should be journaled"); } },
    coverageClient: { post: async (_path, body) => { reports.push(body as Record<string, unknown>); return {}; } },
  });
  const signal = new AbortController().signal;
  const start = now;
  for (let pass = 0; pass <= 30; pass++) {
    await monitor.review(inventory, signal);
    now += 10_000;
  }
  // Both processes are asked together; the waits after each failed pass
  // are 10, 20, 40, 80 and 160 seconds.
  assert.deepEqual([...new Set(callTimes.map((at) => (at - start) / 1_000))], [0, 10, 30, 70, 150]);
  assert.equal(callTimes.length, 10);
  const failures = statuses.filter((message) => message.startsWith("Guardian could not review running agents"));
  assert.deepEqual(failures, ["Guardian could not review running agents (Guardian decision service returned 409). It tries again later; until then they count as unverified."]);
  assert.equal(reports.at(-1)?.["unverified"], 2);
  assert.equal(reports.at(-1)?.["process_review"], "degraded");

  failing = false;
  now = start + 310_000;
  await monitor.review(inventory, signal);
  assert.equal(statuses.at(-1), "Guardian reviews running agents again.");
  assert.equal(reports.at(-1)?.["process_review"], "active");
  now += 10_000;
  await monitor.review(inventory, signal);
  assert.equal(statuses.filter((message) => message === "Guardian reviews running agents again.").length, 1);
});

test("a coverage report that fails waits before the next and is logged once", async () => {
  let now = Date.parse("2026-11-02T12:00:00.000Z");
  let failing = true;
  let posts = 0;
  const statuses: string[] = [];
  const monitor = new GuardianProcessMonitor({
    machineId: "machine", onStatus: (message) => statuses.push(message), now: () => now,
    policyStore: { load: async () => ({ machineId: "machine", policyDigest: "a".repeat(64), defaultEffect: "allow", rules: [], receivedAt: new Date(now).toISOString() }) },
    decisionClient: { decide: async () => { throw new Error("No processes should be reviewed"); } },
    containment: { execute: async () => { throw new Error("No processes should be stopped"); } },
    journal: { append: async () => undefined },
    coverageClient: { post: async () => { posts++; if (failing) throw new Error("Phigon Guardian could not reach your company's Phigon server (the server returned 503); the action remains blocked."); return {}; } },
  });
  const signal = new AbortController().signal;
  for (let pass = 0; pass < 7; pass++) {
    await monitor.review(create(AgentInventorySchema, { machineId: "machine", agents: [] }), signal);
    now += 10_000;
  }
  // Sent at 0, 10 and 30 seconds; the next waits until 70.
  assert.equal(posts, 3);
  assert.equal(statuses.filter((message) => message.startsWith("Guardian could not deliver its coverage report (")).length, 1);
  assert.match(statuses.join("\n"), /the server returned 503/u);

  failing = false;
  now += 10_000;
  await monitor.review(create(AgentInventorySchema, { machineId: "machine", agents: [] }), signal);
  assert.equal(posts, 4);
  assert.equal(statuses.at(-1), "Guardian delivers its coverage report again.");
});

test("waiting for a policy and incomplete discovery are logged when they start, not on every pass", async () => {
  let policy = false;
  const statuses: string[] = [];
  const monitor = new GuardianProcessMonitor({
    machineId: "machine", onStatus: (message) => statuses.push(message),
    policyStore: { load: async () => policy ? ({ machineId: "machine", policyDigest: "a".repeat(64), defaultEffect: "allow", rules: [], receivedAt: new Date().toISOString() }) : null },
    decisionClient: { decide: async () => { throw new Error("No processes should be reviewed"); } },
    containment: { execute: async () => { throw new Error("No processes should be stopped"); } },
    journal: { append: async () => undefined },
  });
  const signal = new AbortController().signal;
  const partial = create(AgentInventorySchema, { machineId: "machine", partial: true, agents: [] });
  for (let pass = 0; pass < 3; pass++) await monitor.review(partial, signal);
  policy = true;
  for (let pass = 0; pass < 3; pass++) await monitor.review(partial, signal);
  await monitor.review(create(AgentInventorySchema, { machineId: "machine", agents: [] }), signal);
  await monitor.review(partial, signal);
  assert.deepEqual(statuses, [
    "Guardian waits for the rules from your company's Phigon server, and reviews running agents once they arrive.",
    "Guardian discovery is incomplete; process protection coverage is degraded.",
    "Guardian discovery is incomplete; process protection coverage is degraded.",
  ]);
});

test("a new policy is checked against running agents at once, even while waiting after a failure", async () => {
  let now = Date.parse("2026-11-02T12:00:00.000Z");
  let digest = "a".repeat(64);
  let failing = true;
  const callTimes: number[] = [];
  const monitor = new GuardianProcessMonitor({
    machineId: "machine", onStatus: () => undefined, now: () => now,
    policyStore: { load: async () => ({ machineId: "machine", policyDigest: digest, defaultEffect: "allow", rules: [], receivedAt: new Date(now).toISOString() }) },
    decisionClient: { decide: async () => {
      callTimes.push(now);
      if (failing) throw new Error("Guardian decision service returned 503.");
      return { decision: "allow", reason: "Allowed.", risk: "low", confidence: 1, model: "policy-gateway", cached: false, latencyMs: 1, intervention: "none" };
    } },
    containment: { execute: async () => { throw new Error("No process should be stopped"); } },
    journal: { append: async () => undefined },
  });
  const inventory = create(AgentInventorySchema, { machineId: "machine", agents: [runningAgent("codex:1", 42n)] });
  const signal = new AbortController().signal;
  const start = now;
  await monitor.review(inventory, signal);
  now += 10_000;
  await monitor.review(inventory, signal);
  // Waiting until 30 s now; a new policy arrives at 20 s.
  now += 10_000;
  failing = false;
  digest = "b".repeat(64);
  await monitor.review(inventory, signal);
  assert.deepEqual(callTimes.map((at) => (at - start) / 1_000), [0, 10, 20]);
});

test("a failed stop of a denied agent that still runs is tried again under a decision asked for again", async () => {
  let now = Date.parse("2026-11-02T12:00:00.000Z");
  let decisions = 0;
  const stopTimes: number[] = [];
  const stops: ("failed" | "succeeded")[] = ["failed", "failed", "succeeded"];
  const journal: Record<string, unknown>[] = [];
  const statuses: string[] = [];
  const notices: string[] = [];
  const reports: Record<string, unknown>[] = [];
  const monitor = new GuardianProcessMonitor({
    machineId: "machine", onStatus: (message) => statuses.push(message), now: () => now,
    policyStore: { load: async () => ({ machineId: "machine", policyDigest: "a".repeat(64), defaultEffect: "allow", rules: [], receivedAt: new Date(now).toISOString() }) },
    decisionClient: { decide: async () => {
      decisions++;
      return { decision: "deny", reason: "Codex is prohibited.", risk: "high", confidence: 1, model: "policy-gateway", cached: false, latencyMs: 1, intervention: "stop_agent", matchedContractId: "c1", adminContract: "No Codex." };
    } },
    containment: { execute: async () => {
      stopTimes.push(now);
      const state = stops.shift() ?? "succeeded";
      return state === "succeeded"
        ? { state, code: "process_stopped", detail: "Stopped.", targetStillRunning: false }
        : { state, code: "process_table_unavailable", detail: "The process list could not be read.", targetStillRunning: true };
    } },
    journal: { append: async (entry) => { journal.push(entry as unknown as Record<string, unknown>); } },
    notices: {
      agentBlocked: () => { notices.push("blocked"); },
      agentStopped: () => { notices.push("stopped"); },
    },
    coverageClient: { post: async (_path, body) => { reports.push(body as Record<string, unknown>); return {}; } },
  });
  const inventory = create(AgentInventorySchema, { machineId: "machine", agents: [runningAgent("codex:1", 42n)] });
  const signal = new AbortController().signal;
  const start = now;
  for (let pass = 0; pass < 6; pass++) {
    await monitor.review(inventory, signal);
    if (pass === 1) assert.equal(reports.at(-1)?.["containment_failed"], 1, "a stop that keeps failing is reported");
    now += 10_000;
  }
  // Stopped at 0 s, tried again at 10 s, then after 20 s more, at 30 s.
  assert.deepEqual(stopTimes.map((at) => (at - start) / 1_000), [0, 10, 30]);
  assert.equal(decisions, 3, "each try of the stop is under a decision asked for then");
  assert.deepEqual(journal.map((entry) => (entry["containment"] as { state: string }).state), ["failed", "succeeded"]);
  assert.deepEqual(notices, ["stopped"]);
  assert.equal(statuses.filter((message) => message.startsWith("Phigon Guardian could not stop codex:1")).length, 1);
  assert.equal(reports.at(-1)?.["containment_failed"], 0);
});

test("an incomplete discovery does not make Guardian forget a running agent's denial", async () => {
  let now = Date.parse("2026-11-02T12:00:00.000Z");
  let decisions = 0, receipts = 0;
  const monitor = new GuardianProcessMonitor({
    machineId: "machine", onStatus: () => undefined, now: () => now,
    policyStore: { load: async () => ({ machineId: "machine", policyDigest: "a".repeat(64), defaultEffect: "allow", rules: [], receivedAt: new Date(now).toISOString() }) },
    decisionClient: { decide: async () => { decisions++; return { decision: "deny", reason: "Codex is prohibited.", risk: "high", confidence: 1, model: "policy-gateway", cached: false, latencyMs: 1, intervention: "block_action", matchedContractId: "c1", adminContract: "No Codex." }; } },
    containment: { execute: async () => { throw new Error("A block_action must not stop the process"); } },
    journal: { append: async () => { receipts++; } },
  });
  const agent = runningAgent("codex:1", 42n);
  const signal = new AbortController().signal;
  await monitor.review(create(AgentInventorySchema, { machineId: "machine", agents: [agent] }), signal);
  // A discovery adapter failed: the agent was not found this time.
  now += 10_000;
  await monitor.review(create(AgentInventorySchema, { machineId: "machine", partial: true, agents: [] }), signal);
  now += 10_000;
  await monitor.review(create(AgentInventorySchema, { machineId: "machine", agents: [agent] }), signal);
  assert.equal(decisions, 1);
  assert.equal(receipts, 1);
  // A complete discovery without it means it stopped.
  now += 10_000;
  await monitor.review(create(AgentInventorySchema, { machineId: "machine", agents: [] }), signal);
  now += 10_000;
  await monitor.review(create(AgentInventorySchema, { machineId: "machine", agents: [agent] }), signal);
  assert.equal(decisions, 2);
});

test("failing stops of several agents are each logged once, not on every try", async () => {
  let now = Date.parse("2026-11-02T12:00:00.000Z");
  let stops = 0;
  const statuses: string[] = [];
  const monitor = new GuardianProcessMonitor({
    machineId: "machine", onStatus: (message) => statuses.push(message), now: () => now,
    policyStore: { load: async () => ({ machineId: "machine", policyDigest: "a".repeat(64), defaultEffect: "allow", rules: [], receivedAt: new Date(now).toISOString() }) },
    decisionClient: { decide: async () => ({ decision: "deny", reason: "Blocked.", risk: "high", confidence: 1, model: "policy-gateway", cached: false, latencyMs: 1, intervention: "stop_agent", matchedContractId: "c1", adminContract: "No agents." }) },
    containment: { execute: async () => { stops++; return { state: "failed", code: "process_table_unavailable", detail: "The process list could not be read.", targetStillRunning: true }; } },
    journal: { append: async () => undefined },
  });
  const inventory = create(AgentInventorySchema, { machineId: "machine", agents: [runningAgent("codex:1", 42n), runningAgent("claude:2", 43n)] });
  const signal = new AbortController().signal;
  for (let pass = 0; pass <= 31; pass++) {
    await monitor.review(inventory, signal);
    now += 10_000;
  }
  // Tried at 0, 10, 30, 70, 150 and 310 seconds, for each agent.
  assert.equal(stops, 12);
  for (const agent of ["codex:1", "claude:2"]) {
    assert.equal(statuses.filter((message) => message.startsWith(`Phigon Guardian could not stop ${agent} `)).length, 1, agent);
  }
});

test("a failed stop is not tried again once an administrator lifts the agent block", async () => {
  let now = Date.parse("2026-11-02T12:00:00.000Z");
  let blocked = true;
  let stops = 0;
  let decisions = 0;
  const reports: Record<string, unknown>[] = [];
  const monitor = new GuardianProcessMonitor({
    machineId: "machine", onStatus: () => undefined, now: () => now,
    // An agent block does not change the policy digest.
    policyStore: { load: async () => ({ machineId: "machine", policyDigest: "a".repeat(64), defaultEffect: "allow", rules: [], receivedAt: new Date(now).toISOString() }) },
    decisionClient: { decide: async () => {
      decisions++;
      return blocked
        ? { decision: "deny", reason: "Codex is blocked.", risk: "high", confidence: 1, model: "agent-block", cached: false, latencyMs: 1, intervention: "stop_agent", matchedContractId: "block", adminContract: "Block Codex." }
        : { decision: "allow", reason: "Allowed.", risk: "low", confidence: 1, model: "policy-gateway", cached: false, latencyMs: 1, intervention: "none" };
    } },
    containment: { execute: async () => { stops++; return { state: "failed", code: "process_table_unavailable", detail: "The process list could not be read.", targetStillRunning: true }; } },
    journal: { append: async () => undefined },
    coverageClient: { post: async (_path, body) => { reports.push(body as Record<string, unknown>); return {}; } },
  });
  const inventory = create(AgentInventorySchema, { machineId: "machine", agents: [runningAgent("codex:1", 42n)] });
  const signal = new AbortController().signal;
  await monitor.review(inventory, signal);
  assert.equal(stops, 1);
  blocked = false;
  for (let pass = 0; pass < 6; pass++) {
    now += 10_000;
    await monitor.review(inventory, signal);
  }
  assert.equal(stops, 1, "a lifted block is never enforced");
  assert.equal(decisions, 2, "asked again when the stop was due, then remembered as allowed");
  assert.equal(reports.at(-1)?.["denied"], 0);
});

test("a failed stop of a process that is already gone is not tried again", async () => {
  let now = Date.parse("2026-11-02T12:00:00.000Z");
  let stops = 0;
  const monitor = new GuardianProcessMonitor({
    machineId: "machine", onStatus: () => undefined, now: () => now,
    policyStore: { load: async () => ({ machineId: "machine", policyDigest: "a".repeat(64), defaultEffect: "allow", rules: [], receivedAt: new Date(now).toISOString() }) },
    decisionClient: { decide: async () => ({ decision: "deny", reason: "Codex is prohibited.", risk: "high", confidence: 1, model: "policy-gateway", cached: false, latencyMs: 1, intervention: "kill_agent", matchedContractId: "c1", adminContract: "No Codex." }) },
    containment: { execute: async () => { stops++; return { state: "rejected", code: "stale_target", detail: "The exact discovered agent process lifetime is no longer running.", targetStillRunning: false }; } },
    journal: { append: async () => undefined },
  });
  const inventory = create(AgentInventorySchema, { machineId: "machine", agents: [runningAgent("codex:1", 42n)] });
  const signal = new AbortController().signal;
  for (let pass = 0; pass < 6; pass++) {
    await monitor.review(inventory, signal);
    now += 10_000;
  }
  assert.equal(stops, 1);
});
