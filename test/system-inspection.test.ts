import { create } from "@bufbuild/protobuf";
import { timestampFromDate } from "@bufbuild/protobuf/wkt";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { randomUUID } from "node:crypto";
import { once } from "node:events";
import { readFileSync } from "node:fs";
import { mkdtemp } from "node:fs/promises";
import { cpus, tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { AgentActionExecutor } from "../src/agent-action-executor.js";
import { SystemEvidenceProvider } from "../src/discovery/system-evidence.js";
import { AgentActionCommandSchema, RemoteActionResultState, RemoteActionType } from "../src/generated/phigon/v1/action_pb.js";
import { AgentState } from "../src/generated/phigon/v1/common_pb.js";
import { AgentIdentitySchema, AgentInventorySchema } from "../src/generated/phigon/v1/identity_pb.js";
import {
  formatInspection,
  inspectSystem,
  parseCpuTime,
  parseLinuxProcess,
  parsePsSample,
  parseWindowsSample,
  type ProcessReading,
  type ProcessSampler,
  type RunningAgent,
} from "../src/system-inspection.js";

const now = Date.parse("2026-10-28T12:00:00.000Z");
const agent = (name: string, processId: number, startedAt: number): RunningAgent => ({ name, processId, startedAt: new Date(startedAt) });
const reading = (startedAt: number | null, cpuMs: number | null, memoryBytes: number | null): ProcessReading => ({ startedAt, cpuMs, memoryBytes });
const sampler = (before: Record<number, ProcessReading>, after: Record<number, ProcessReading>, elapsedMs = 500): ProcessSampler =>
  async () => ({ before: new Map(Object.entries(before).map(([id, value]) => [Number(id), value])), after: new Map(Object.entries(after).map(([id, value]) => [Number(id), value])), elapsedMs });

/** The desktop's own acceptance check for an inspection receipt. */
function desktopAccepts(output: string): boolean {
  const value = JSON.parse(output) as Record<string, unknown>;
  return typeof value["platform"] === "string" && typeof value["release"] === "string" &&
    [value["logical_cpus"], value["memory_bytes"], value["free_memory_bytes"], value["uptime_seconds"]]
      .every((item) => typeof item === "number" && Number.isFinite(item) && item >= 0);
}

test("inspection keeps every original field and adds bounded machine facts", async () => {
  const report = await inspectSystem({ observerVersion: "9.9.9", windowMs: 50, now: () => now });
  for (const key of ["hostname", "platform", "release", "logical_cpus", "memory_bytes", "free_memory_bytes", "uptime_seconds", "observed_at"]) {
    assert.ok(key in report, key);
  }
  assert.equal(report.observed_at, new Date(now).toISOString());
  assert.equal(report.logical_cpus, cpus().length);
  assert.equal(report.observer_version, "9.9.9");
  assert.ok(report.cpu_load_percent === null || (report.cpu_load_percent >= 0 && report.cpu_load_percent <= 100));
  assert.ok(report.disk_total_bytes !== null && report.disk_total_bytes > 0);
  assert.ok(report.disk_free_bytes !== null && report.disk_free_bytes <= report.disk_total_bytes);
  assert.equal(report.disk_path, process.platform === "win32" ? `${(process.env["SystemDrive"] ?? "C:").toUpperCase()}\\` : "/");
  assert.equal(report.load_average === null, process.platform === "win32");
  // Without an agent source the list is honestly incomplete, not empty-and-complete.
  assert.deepEqual(report.agents, []);
  assert.equal(report.agents_complete, false);
  assert.ok(desktopAccepts(formatInspection(report)));
  const packageVersion = (JSON.parse(readFileSync(new URL("../../package.json", import.meta.url), "utf8")) as { version: string }).version;
  assert.equal((await inspectSystem({ windowMs: 10 })).observer_version, packageVersion);
});

test("agent CPU is the share of the whole machine over the sample window", async () => {
  const logical = Math.max(1, cpus().length);
  const report = await inspectSystem({
    windowMs: 10, now: () => now,
    agents: async () => ({ complete: true, agents: [agent("Claude Code", 11, now - 90_000), agent("Codex", 12, now - 5_000)] }),
    sampler: sampler(
      { 11: reading(now - 90_000, 1_000, 1), 12: reading(now - 5_000, 0, 1) },
      { 11: reading(now - 90_000, 1_250, 300_000_000), 12: reading(now - 5_000, 0, 120_000_000) },
    ),
  });
  assert.deepEqual(report.agents, [
    { name: "Claude Code", process_id: 11, cpu_percent: Math.round(250 / (500 * logical) * 1000) / 10, memory_bytes: 300_000_000, run_time_seconds: 90 },
    { name: "Codex", process_id: 12, cpu_percent: 0, memory_bytes: 120_000_000, run_time_seconds: 5 },
  ]);
  assert.equal(report.agents_complete, true);
  assert.equal(report.agents_omitted, 0);
});

test("exited agents and reused PIDs are dropped; unreadable metrics are null and marked incomplete", async () => {
  const report = await inspectSystem({
    windowMs: 10, now: () => now,
    agents: async () => ({ complete: true, agents: [agent("Gone", 21, now - 1_000), agent("Reused", 22, now - 60_000), agent("Protected", 23, now - 60_000)] }),
    sampler: sampler(
      { 22: reading(now - 2_000, 5, 1), 23: reading(null, null, 10) },
      { 22: reading(now - 2_000, 9, 1), 23: reading(null, null, 4_096) },
    ),
  });
  assert.deepEqual(report.agents, [{ name: "Protected", process_id: 23, cpu_percent: null, memory_bytes: 4_096, run_time_seconds: 60 }]);
  assert.equal(report.agents_complete, false);
});

test("a failed agent source or sampler never fails the inspection", async () => {
  const failedList = await inspectSystem({ windowMs: 10, agents: async () => { throw new Error("discovery failed"); } });
  assert.deepEqual(failedList.agents, []);
  assert.equal(failedList.agents_complete, false);
  const failedSample = await inspectSystem({
    windowMs: 10, now: () => now,
    agents: async () => ({ complete: true, agents: [agent("Claude Code", 31, now - 10_000)] }),
    sampler: async () => { throw new Error("sampler failed"); },
  });
  assert.deepEqual(failedSample.agents, [{ name: "Claude Code", process_id: 31, cpu_percent: null, memory_bytes: null, run_time_seconds: 10 }]);
  assert.equal(failedSample.agents_complete, false);
});

test("the report keeps the busiest agents and fits what Cortex reads", async () => {
  const many = Array.from({ length: 30 }, (_, index) => agent(`${"Long agent display name ".repeat(4)}${index}`, 100 + index, now - index * 1_000));
  const before = Object.fromEntries(many.map((item) => [item.processId, reading(item.startedAt.getTime(), 0, 1)]));
  const after = Object.fromEntries(many.map((item, index) => [item.processId, reading(item.startedAt.getTime(), index * 10, 2 ** 40 + index)]));
  const report = await inspectSystem({ windowMs: 10, now: () => now, agents: async () => ({ complete: true, agents: many }), sampler: sampler(before, after) });
  assert.equal(report.agents.length, 20);
  assert.equal(report.agents_omitted, 10);
  assert.equal(report.agents[0]!.process_id, 129);
  assert.ok(report.agents.every((item) => item.name.length <= 64));
  const output = formatInspection(report);
  assert.ok(output.length < 4_000, `inspection output is ${output.length} characters`);
  assert.deepEqual(JSON.parse(output), report);
});

test("native process readings parse without trusting their formatting", () => {
  const windows = parseWindowsSample(JSON.stringify({ a: { i: 7, s: "2026-10-28T10:00:00.1234567Z", c: 125.5, m: 2048 }, b: [{ i: 7, s: null, c: 130, m: 4096 }, { i: "x" }], e: 512.25 }));
  assert.deepEqual(windows.before.get(7), { startedAt: Date.parse("2026-10-28T10:00:00.123Z"), cpuMs: 125.5, memoryBytes: 2048 });
  assert.deepEqual(windows.after.get(7), { startedAt: null, cpuMs: 130, memoryBytes: 4096 });
  assert.equal(windows.after.size, 1); assert.equal(windows.elapsedMs, 512.25);
  const stat = "4242 (node (worker) x) S 1 4242 4242 0 -1 4194560 100 0 0 0 250 50 0 0 20 0 11 0 360000 1000 2000";
  assert.deepEqual(parseLinuxProcess(stat, "Name:\tnode\nVmRSS:\t  51200 kB\n", 1_790_000_000), { startedAt: 1_790_000_000_000 + 3_600_000, cpuMs: 3_000, memoryBytes: 51_200 * 1024 });
  assert.equal(parseLinuxProcess(stat.replace(") S ", ") Z "), "", 1), null);
  const ps = parsePsSample("  501  20480  1:02.50 Wed Oct 28 10:00:00 2026\nnot a row\n");
  assert.deepEqual(ps.get(501), { startedAt: Date.parse("Wed Oct 28 10:00:00 2026"), cpuMs: 62_500, memoryBytes: 20_480 * 1024 });
  assert.equal(parseCpuTime("1-02:03:04"), ((26 * 60 + 3) * 60 + 4) * 1000);
  assert.equal(parseCpuTime("00:00:07"), 7000);
  assert.equal(parseCpuTime("bad"), null);
});

test("inspect_system on this computer measures a running agent the test started", async (t) => {
  // A real process that keeps one core busy, then exits by itself.
  const busy = spawn(process.execPath, ["-e", "const end = Date.now() + 20000; while (Date.now() < end) {}"], { stdio: "ignore" });
  t.after(() => { if (busy.exitCode === null && busy.signalCode === null) busy.kill("SIGKILL"); });
  await once(busy, "spawn");
  const evidence = await new SystemEvidenceProvider().listProcesses();
  const observed = evidence.status === "ok" ? evidence.value.find((entry) => entry.processId === busy.pid) : undefined;
  assert.ok(observed, "the test agent must have an OS-observed lifetime");
  const machineID = randomUUID();
  const executor = new AgentActionExecutor({ enabled: false, commandsEnabled: true, machineID, dataDirectory: await mkdtemp(join(tmpdir(), "phigon-inspect-")),
    inventory: async () => { throw new Error("a recent inventory must be reused"); } });
  executor.observeInventory(create(AgentInventorySchema, { machineId: machineID, agents: [create(AgentIdentitySchema, {
    agentId: "busy-agent", displayName: "Busy test agent", processId: BigInt(busy.pid!), state: AgentState.RUNNING,
    startedAt: timestampFromDate(observed.startedAt), capabilities: ["process-instance"],
  })] }));
  const result = await executor.execute(create(AgentActionCommandSchema, {
    actionId: randomUUID(), idempotencyKey: randomUUID(), machineId: machineID, agentId: "__machine__", processId: 0n,
    action: RemoteActionType.INSPECT_SYSTEM, expiresAt: timestampFromDate(new Date(Date.now() + 60_000)),
  }));
  assert.equal(result.state, RemoteActionResultState.SUCCEEDED, result.detail);
  assert.ok(desktopAccepts(result.output));
  const report = JSON.parse(result.output) as Awaited<ReturnType<typeof inspectSystem>>;
  assert.equal(report.agents_complete, true, result.output);
  assert.equal(report.agents.length, 1, result.output);
  const [measured] = report.agents;
  assert.equal(measured!.name, "Busy test agent");
  assert.equal(measured!.process_id, busy.pid);
  assert.ok(measured!.cpu_percent !== null && measured!.cpu_percent > 0, result.output);
  assert.ok(measured!.memory_bytes !== null && measured!.memory_bytes > 1_000_000, result.output);
  assert.ok(measured!.run_time_seconds >= 0 && measured!.run_time_seconds < 120);
  assert.ok(report.cpu_load_percent !== null && report.cpu_load_percent > 0);
});
