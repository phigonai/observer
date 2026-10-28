import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { existsSync } from "node:fs";
import { once } from "node:events";
import test from "node:test";
import { guardianRunnerPath } from "../src/guardian-native.js";
import {
  listWindowsProcesses,
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
