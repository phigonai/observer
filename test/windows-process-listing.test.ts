import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { existsSync } from "node:fs";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { once } from "node:events";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import test from "node:test";
import { guardianRunnerPath } from "../src/guardian-native.js";
import {
  listWindowsProcesses,
  newWindowsListingState,
  runNativeProcessListing,
  runPowerShellProcessListing,
  windowsPathIdentity,
} from "../src/discovery/system-evidence.js";

const powerShellRows = JSON.stringify([
  {
    ProcessId: 4242,
    CreationDate: "/Date(1785686000123)/",
    ExecutablePath: "C:\\Tools\\agent.exe",
    Name: "agent.exe",
  },
  {
    ProcessId: 4343,
    CreationDate: "/Date(1785686000456)/",
    ExecutablePath: null,
    Name: "Service.EXE",
  },
  { ProcessId: 0, CreationDate: "/Date(1785680000000)/", ExecutablePath: null, Name: "System Idle Process" },
  // Win32_Process reports the path a process was started with.
  {
    ProcessId: 4545,
    CreationDate: "/Date(1785686000789)/",
    ExecutablePath: "C:\\windows\\Explorer.EXE",
    Name: "explorer.exe",
  },
  {
    ProcessId: 4646,
    CreationDate: "/Date(1785686000999)/",
    ExecutablePath: "C:\\Program Files\\Git\\bin\\..\\usr\\bin\\bash.exe",
    Name: "bash.exe",
  },
]);

const nativeRows = JSON.stringify([
  { pid: 4242, ppid: 1, created_ms: 1785686000123, name: "agent.exe", path: "\\\\?\\C:\\Tools\\agent.exe" },
  { pid: 4343, ppid: 4, created_ms: 1785686000456, name: "Service.EXE" },
  // The helper reports the file's own path.
  { pid: 4545, ppid: 1, created_ms: 1785686000789, name: "explorer.exe", path: "C:\\Windows\\explorer.exe" },
  { pid: 4646, ppid: 1, created_ms: 1785686000999, name: "bash.exe", path: "C:\\Program Files\\Git\\usr\\bin\\bash.exe" },
  { pid: 0, ppid: 0, created_ms: 1785680000000, name: "System Idle Process" },
  // Without a creation time a process has no lifetime identity.
  { pid: 4444, ppid: 1, name: "exiting.exe" },
  "not a process",
]);

const unused = () => Promise.reject(new Error("This listing must not run."));

test("the native and PowerShell listings give processes the same identities", async () => {
  const native = await listWindowsProcesses(async () => nativeRows, unused);
  const powerShell = await listWindowsProcesses(undefined, async () => powerShellRows);
  assert.equal(native.length, 4);
  assert.deepEqual(
    [...native].sort((left, right) => left.processId - right.processId),
    [...powerShell].sort((left, right) => left.processId - right.processId),
  );
  assert.deepEqual(native.map((entry) => [entry.processId, entry.executableName]), [
    [4242, "agent"],
    [4343, "service"],
    [4545, "explorer"],
    [4646, "bash"],
  ]);
});

test("Windows executable paths have one spelling", () => {
  for (const [spelling, identity] of [
    ["C:\\windows\\Explorer.EXE", "c:\\windows\\explorer.exe"],
    ["\\\\?\\C:\\Tools\\Agent.exe", "c:\\tools\\agent.exe"],
    ["\\\\?\\UNC\\Server\\Share\\agent.exe", "\\\\server\\share\\agent.exe"],
    ["C:\\Program Files\\Git\\bin\\..\\usr\\.\\bin\\bash.exe", "c:\\program files\\git\\usr\\bin\\bash.exe"],
    ["conhost.exe", "conhost.exe"],
  ] as const) {
    assert.equal(windowsPathIdentity(spelling), identity);
  }
});

test("a blocked helper and its PowerShell fallback back off to five minutes, and reset once the helper works", async () => {
  const state = newWindowsListingState();
  let helperWorks = false;
  let helperRuns = 0;
  let powerShellRuns = 0;
  const native = async () => {
    helperRuns++;
    if (!helperWorks) throw Object.assign(new Error("blocked by application control"), { code: "UNKNOWN" });
    return nativeRows;
  };
  const powerShell = async () => {
    powerShellRuns++;
    return powerShellRows;
  };
  const expected = await listWindowsProcesses(undefined, powerShell);
  powerShellRuns = 0;
  // Discovery every 10 seconds for an hour.
  const start = 1_000_000;
  const helperAt: number[] = [];
  const powerShellAt: number[] = [];
  for (let second = 0; second < 3_600; second += 10) {
    const helperBefore = helperRuns;
    const powerShellBefore = powerShellRuns;
    assert.deepEqual(await listWindowsProcesses(native, powerShell, state, start + second * 1_000), expected);
    if (helperRuns > helperBefore) helperAt.push(second);
    if (powerShellRuns > powerShellBefore) powerShellAt.push(second);
  }
  assert.deepEqual(helperAt.slice(0, 6), [0, 10, 30, 70, 150, 310]);
  assert.deepEqual(powerShellAt.slice(0, 6), [0, 10, 30, 70, 150, 310]);
  // At most every five minutes from then on, instead of 360 times an hour.
  for (const times of [helperAt, powerShellAt]) {
    for (let index = 1; index < times.length; index++) {
      assert.ok((times[index] ?? 0) - (times[index - 1] ?? 0) <= 300);
    }
    assert.ok(times.length < 20, `${times.length} runs in an hour`);
  }
  // The helper works again: every pass uses it, and PowerShell stops.
  helperWorks = true;
  const at = start + 3_600_000 + 300_000;
  await listWindowsProcesses(native, powerShell, state, at);
  const after = powerShellRuns;
  for (let second = 10; second <= 60; second += 10) {
    const listed = await listWindowsProcesses(native, powerShell, state, at + second * 1_000);
    assert.equal(listed.length > 0, true);
  }
  assert.equal(powerShellRuns, after);
  assert.equal(state.nativeFailures, 0);
});

test("a failed native listing falls back to PowerShell for that pass", async () => {
  const expected = await listWindowsProcesses(undefined, async () => powerShellRows);
  for (const native of [
    () => Promise.reject(Object.assign(new Error("helper crashed"), { code: 3 })),
    () => Promise.reject(Object.assign(new Error("helper timed out"), { killed: true })),
    async () => "truncated [",
    async () => JSON.stringify({ pid: 1 }),
  ]) {
    let powerShellRuns = 0;
    const listed = await listWindowsProcesses(native, async () => {
      powerShellRuns++;
      return powerShellRows;
    });
    assert.deepEqual(listed, expected);
    assert.equal(powerShellRuns, 1);
  }
});

test(
  "the bundled helper lists real processes exactly as Win32_Process does",
  { skip: process.platform !== "win32" || !existsSync(guardianRunnerPath()), timeout: 60_000 },
  async (t) => {
    const child = spawn(process.execPath, ["-e", "setInterval(() => {}, 1000)"], { stdio: "ignore" });
    t.after(() => { child.kill(); });
    await once(child, "spawn");
    const native = await listWindowsProcesses(runNativeProcessListing, unused);
    const powerShell = await listWindowsProcesses(undefined, runPowerShellProcessListing);
    for (const processId of [process.pid, child.pid]) {
      const fromNative = native.find((entry) => entry.processId === processId);
      assert.ok(fromNative, `process ${processId} is listed`);
      assert.deepEqual(fromNative, powerShell.find((entry) => entry.processId === processId));
    }
  },
);

test(
  "the bundled helper and Win32_Process report the same npm package for a real node process",
  { skip: process.platform !== "win32" || !existsSync(guardianRunnerPath()), timeout: 60_000 },
  async (t) => {
    const directory = await mkdtemp(join(tmpdir(), "phigon script package "));
    const script = join(directory, "node_modules", "@phigon-test", "agent", "cli.js");
    await mkdir(dirname(script), { recursive: true });
    await writeFile(script, "setInterval(() => {}, 1000);\n");
    const child = spawn(process.execPath, ["--max-old-space-size=256", script, "--resume"], { stdio: "ignore", windowsHide: true });
    t.after(async () => {
      if (child.exitCode === null && child.signalCode === null) {
        child.kill();
        await once(child, "exit");
      }
      await rm(directory, { recursive: true, force: true });
    });
    await once(child, "spawn");
    const native = await listWindowsProcesses(runNativeProcessListing, unused);
    const powerShell = await listWindowsProcesses(undefined, runPowerShellProcessListing);
    const fromNative = native.find((entry) => entry.processId === child.pid);
    assert.equal(fromNative?.scriptPackage, "@phigon-test/agent");
    assert.deepEqual(fromNative, powerShell.find((entry) => entry.processId === child.pid));
  },
);
