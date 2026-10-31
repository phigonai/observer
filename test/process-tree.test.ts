import { create } from "@bufbuild/protobuf";
import { timestampFromDate } from "@bufbuild/protobuf/wkt";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { randomUUID } from "node:crypto";
import { once } from "node:events";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { AgentActionExecutor, describeOutcome } from "../src/agent-action-executor.js";
import { SystemEvidenceProvider } from "../src/discovery/system-evidence.js";
import {
  UnixProcessTreeControl,
  WindowsProcessTreeControl,
  descendantsOf,
  parseTreeReport,
  parseUnixProcessTable,
  type ProcessRow,
  type TreeStopOutcome,
} from "../src/process-tree.js";
import { AgentActionCommandSchema, RemoteActionResultState, RemoteActionType } from "../src/generated/phigon/v1/action_pb.js";
import { AgentState } from "../src/generated/phigon/v1/common_pb.js";
import { AgentIdentitySchema, AgentInventorySchema } from "../src/generated/phigon/v1/identity_pb.js";

const start = Date.parse("Wed Oct 28 10:00:00 2026");
const row = (processId: number, parentId: number, offsetSeconds = 0, zombie = false): ProcessRow =>
  ({ processId, parentId, startedAt: start + offsetSeconds * 1000, zombie });
const table = (...rows: ProcessRow[]) => new Map(rows.map((entry) => [entry.processId, entry]));
const errno = (code: string) => Object.assign(new Error(code), { code });

/** A simulated OS: signals end processes unless they ignore them or are protected. */
function fakeUnix(rows: ProcessRow[], options: { ignore?: Set<number>; protect?: Set<number>; observer?: number } = {}) {
  const alive = new Map(rows.map((entry) => [entry.processId, entry]));
  const signals: string[] = [];
  let now = 0;
  const control = new UnixProcessTreeControl({
    list: async () => new Map(alive),
    observerProcessId: options.observer ?? 9999,
    clock: () => now,
    sleep: async (milliseconds) => { now += milliseconds; },
    signal: (processId, signal) => {
      if (!alive.has(processId)) throw errno("ESRCH");
      if (signal === 0) return;
      if (options.protect?.has(processId)) throw errno("EPERM");
      signals.push(`${processId}:${signal}`);
      if (!options.ignore?.has(processId)) alive.delete(processId);
    },
  });
  return { control, signals, alive };
}

test("the Unix process table parser keeps PID, parent, zombie state and start time", () => {
  const parsed = parseUnixProcessTable([
    "    1     0 Ss   Wed Oct 28 09:00:00 2026",
    "  200     1 S+   Wed Oct 28 10:00:00 2026",
    "  201   200 Z    Wed Oct 28 10:00:05 2026",
    "garbage line",
    "  abc   200 S    Wed Oct 28 10:00:05 2026",
  ].join("\n"));
  assert.deepEqual([...parsed.keys()], [1, 200, 201]);
  assert.deepEqual(parsed.get(200), { processId: 200, parentId: 1, startedAt: start, zombie: false });
  assert.equal(parsed.get(201)?.zombie, true);
});

test("descendants exclude stale parent PIDs, zombies, init and the observer's own subtree", () => {
  const processes = table(
    row(1, 0, -3600), row(100, 1), row(101, 100, 1), row(102, 101, 2),
    row(103, 100, -60), // started before the root: its parent PID was reused
    row(104, 100, 3, true), // zombie
    row(9999, 100, 4), row(10000, 9999, 5), // observer started by the agent
  );
  const found = descendantsOf(processes, processes.get(100)!, 9999).map((entry) => entry.processId);
  assert.deepEqual(found, [101, 102]);
});

test("a reused PID is never signalled", async () => {
  const { control, signals } = fakeUnix([row(100, 1, 30), row(101, 100, 31)]);
  assert.deepEqual(await control.stop({ processId: 100, startedAt: new Date(start) }, "kill"), { outcome: "stale" });
  assert.deepEqual(signals, []);
});

test("an exited or zombie target is reported as already stopped", async () => {
  assert.deepEqual(await fakeUnix([row(1, 0)]).control.stop({ processId: 100, startedAt: new Date(start) }, "kill"), { outcome: "exited" });
  assert.deepEqual(await fakeUnix([row(100, 1, 0, true)]).control.stop({ processId: 100, startedAt: new Date(start) }, "kill"), { outcome: "exited" });
});

test("force stop ends the exact root and every verified descendant", async () => {
  const { control, signals, alive } = fakeUnix([row(1, 0, -3600), row(100, 1), row(101, 100, 1), row(102, 101, 2), row(200, 1, 5), row(9999, 100, 4)]);
  const outcome = await control.stop({ processId: 100, startedAt: new Date(start) }, "kill");
  assert.deepEqual(outcome, { outcome: "dispatched", rootRunning: false, descendants: 2, descendantsRunning: 0, descendantsDenied: 0 });
  assert.deepEqual(signals, ["100:SIGKILL", "101:SIGKILL", "102:SIGKILL"]);
  assert.ok(alive.has(200) && alive.has(9999), "unrelated processes and the observer are untouched");
});

test("a protected root is reported as access denied and its children are left alone", async () => {
  const { control, signals } = fakeUnix([row(100, 1), row(101, 100, 1)], { protect: new Set([100]) });
  assert.deepEqual(await control.stop({ processId: 100, startedAt: new Date(start) }, "kill"), { outcome: "access_denied" });
  assert.deepEqual(signals, []);
});

test("graceful stop reports a root that ignores it and children the OS protects, without escalating", async () => {
  const { control, signals } = fakeUnix([row(100, 1), row(101, 100, 1), row(102, 100, 1)], { ignore: new Set([100]), protect: new Set([102]) });
  const outcome = await control.stop({ processId: 100, startedAt: new Date(start) }, "stop");
  assert.deepEqual(outcome, { outcome: "dispatched", rootRunning: true, descendants: 2, descendantsRunning: 0, descendantsDenied: 1 });
  assert.deepEqual(signals, ["100:SIGTERM", "101:SIGTERM"]);
});

test("a PID reused during the wait is not mistaken for the stopped agent", async () => {
  let listed = 0;
  let alive = true;
  const control = new UnixProcessTreeControl({
    observerProcessId: 9999,
    sleep: async () => undefined,
    list: async () => (listed++ === 0 ? table(row(100, 1)) : table(row(100, 1, 120))),
    signal: (_processId, signal) => { if (signal !== 0) alive = false; else if (!alive) throw errno("ESRCH"); },
  });
  const outcome = await control.stop({ processId: 100, startedAt: new Date(start) }, "kill");
  assert.deepEqual(outcome, { outcome: "dispatched", rootRunning: false, descendants: 0, descendantsRunning: 0, descendantsDenied: 0 });
});

test("the Windows helper is asked for the exact tree and its report is validated", async () => {
  const calls: string[][] = [];
  const control = new WindowsProcessTreeControl(async (args) => {
    calls.push([...args]);
    return '{"outcome":"dispatched","root_running":false,"descendants":2,"descendants_running":1,"descendants_denied":0}\n';
  });
  const startedAt = new Date("2026-10-28T10:00:00.123Z");
  assert.deepEqual(await control.stop({ processId: 42, startedAt }, "stop"),
    { outcome: "dispatched", rootRunning: false, descendants: 2, descendantsRunning: 1, descendantsDenied: 0 });
  await control.stop({ processId: 42, startedAt }, "kill");
  assert.deepEqual(calls, [
    ["--kill-pid", "42", "--started-at", "2026-10-28T10:00:00.123Z", "--tree", "--graceful"],
    ["--kill-pid", "42", "--started-at", "2026-10-28T10:00:00.123Z", "--tree"],
  ]);
  const timedOut = new WindowsProcessTreeControl(async () => { throw Object.assign(new Error("timeout"), { killed: true }); });
  assert.deepEqual(await timedOut.stop({ processId: 42, startedAt }, "kill"), { outcome: "failed", code: "helper_timeout" });
  assert.deepEqual(parseTreeReport('{"outcome":"graceful_unsupported"}'), { outcome: "graceful_unsupported" });
  assert.deepEqual(parseTreeReport('{"outcome":"console_shared","root_running":true}'), { outcome: "console_shared" });
  assert.deepEqual(parseTreeReport('{"outcome":"failed","error":"x"}'), { outcome: "failed", code: "helper_failed" });
  assert.deepEqual(parseTreeReport("not json"), { outcome: "failed", code: "helper_report_invalid" });
});

test("every outcome becomes an honest receipt within the journal bound", () => {
  const outcomes: TreeStopOutcome[] = [
    { outcome: "stale" }, { outcome: "exited" }, { outcome: "self_target" }, { outcome: "access_denied" },
    { outcome: "graceful_unsupported" }, { outcome: "console_shared" }, { outcome: "failed", code: "helper_timeout" },
    { outcome: "dispatched", rootRunning: true, descendants: 0, descendantsRunning: 0, descendantsDenied: 0 },
    { outcome: "dispatched", rootRunning: false, descendants: 3, descendantsRunning: 1, descendantsDenied: 1 },
    { outcome: "dispatched", rootRunning: false, descendants: 1, descendantsRunning: 0, descendantsDenied: 0 },
  ];
  const codes = outcomes.map((outcome) => {
    const [state, code, detail, running] = describeOutcome(outcome, true);
    assert.ok(detail.length <= 256 && code.length <= 64);
    return `${state}:${code}:${running}`;
  });
  assert.deepEqual(codes, [
    `${RemoteActionResultState.REJECTED}:stale_target:false`,
    `${RemoteActionResultState.REJECTED}:target_already_stopped:false`,
    `${RemoteActionResultState.REJECTED}:self_target_rejected:true`,
    `${RemoteActionResultState.FAILED}:access_denied:true`,
    `${RemoteActionResultState.REJECTED}:graceful_stop_unsupported:true`,
    `${RemoteActionResultState.REJECTED}:terminal_shared:true`,
    `${RemoteActionResultState.FAILED}:os_dispatch_failed:true`,
    `${RemoteActionResultState.FAILED}:process_still_running:true`,
    `${RemoteActionResultState.SUCCEEDED}:process_stopped_children_running:false`,
    `${RemoteActionResultState.SUCCEEDED}:process_stopped:false`,
  ]);
  assert.match(describeOutcome(outcomes[8]!, false)[2], /2 of its child processes are still running/u);
});

function isAlive(processId: number): boolean {
  try { process.kill(processId, 0); return true; } catch (error) { return (error as NodeJS.ErrnoException).code === "EPERM"; }
}

// Real OS processes, all started by this test: an "agent" and a child it spawns.
async function spawnAgentTree(t: test.TestContext) {
  const agent = spawn(process.execPath, ["-e", [
    "const child = require('node:child_process').spawn(process.execPath, ['-e', 'setInterval(() => {}, 1000)'], { stdio: 'ignore' });",
    "process.stdout.write(String(child.pid) + '\\n');",
    "setInterval(() => {}, 1000);",
  ].join("\n")], { stdio: ["ignore", "pipe", "ignore"] });
  const [line] = await once(agent.stdout, "data") as [Buffer];
  const childPid = Number(line.toString("utf8").trim());
  assert.ok(agent.pid && Number.isSafeInteger(childPid) && childPid > 0);
  t.after(() => {
    for (const processId of [childPid, agent.pid!]) { try { process.kill(processId, "SIGKILL"); } catch { /* already gone */ } }
  });
  const evidence = await new SystemEvidenceProvider().listProcesses();
  const observed = evidence.status === "ok" ? evidence.value.find((entry) => entry.processId === agent.pid) : undefined;
  assert.ok(observed, "the test agent must have an OS-observed lifetime");
  return { agentPid: agent.pid!, childPid, startedAt: observed.startedAt };
}

function executorFor(directory: string, agentPid: number, startedAt: Date) {
  return new AgentActionExecutor({ enabled: true, machineID: "68fd2b0b-7e8c-4b0d-890d-7f2d8e94dc2f", dataDirectory: directory,
    inventory: async () => create(AgentInventorySchema, { agents: [create(AgentIdentitySchema, {
      agentId: "tree-agent", processId: BigInt(agentPid), state: AgentState.RUNNING,
      startedAt: timestampFromDate(startedAt), capabilities: ["process-instance"],
    })] }),
  });
}

function commandFor(agentPid: number, startedAt: Date, action: RemoteActionType) {
  return create(AgentActionCommandSchema, {
    actionId: randomUUID(), idempotencyKey: randomUUID(), machineId: "68fd2b0b-7e8c-4b0d-890d-7f2d8e94dc2f",
    agentId: "tree-agent", processId: BigInt(agentPid), expectedStartedAt: timestampFromDate(startedAt),
    expiresAt: timestampFromDate(new Date(Date.now() + 60_000)), action,
  });
}

test("force stop on this computer ends the test agent and the child it started", async (t) => {
  const { agentPid, childPid, startedAt } = await spawnAgentTree(t);
  const directory = await mkdtemp(join(tmpdir(), "phigon-process-tree-kill-"));
  const result = await executorFor(directory, agentPid, startedAt).execute(commandFor(agentPid, startedAt, RemoteActionType.KILL_AGENT));
  assert.equal(result.resultCode, "process_stopped", result.detail);
  assert.match(result.detail, /1 child process exited/u);
  assert.equal(isAlive(agentPid), false);
  assert.equal(isAlive(childPid), false);
});

test("graceful stop on this computer is honest about what the platform can do", async (t) => {
  const { agentPid, childPid, startedAt } = await spawnAgentTree(t);
  const directory = await mkdtemp(join(tmpdir(), "phigon-process-tree-stop-"));
  const result = await executorFor(directory, agentPid, startedAt).execute(commandFor(agentPid, startedAt, RemoteActionType.STOP_AGENT));
  if (process.platform === "win32") {
    // The test agent has no window. It either has no terminal, or shares the
    // test runner's, so Ctrl+C would reach the runner too: nothing may be sent.
    assert.ok(["graceful_stop_unsupported", "terminal_shared"].includes(result.resultCode), result.detail);
    assert.equal(result.state, RemoteActionResultState.REJECTED);
    assert.equal(isAlive(agentPid), true);
    assert.equal(isAlive(childPid), true);
  } else {
    assert.equal(result.resultCode, "process_stopped", result.detail);
    assert.equal(isAlive(childPid), false);
  }
});
