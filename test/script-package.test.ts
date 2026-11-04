import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { once } from "node:events";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import test from "node:test";
import { AgentKind, AgentState } from "../src/generated/phigon/v1/common_pb.js";
import { claudeAdapter } from "../src/discovery/adapters/claude.js";
import { codexAdapter } from "../src/discovery/adapters/codex.js";
import { genericAdapter } from "../src/discovery/adapters/generic.js";
import { DiscoveryEngine } from "../src/discovery/engine.js";
import type {
  HostEvidenceProvider,
  ProcessEvidence,
} from "../src/discovery/evidence.js";
import {
  packageFromScriptPath,
  scriptArgument,
  scriptPackageFromWindowsCommandLine,
  scriptPackagesByProcess,
  windowsCommandLineArguments,
} from "../src/discovery/script-package.js";
import {
  listWindowsProcesses,
  SystemEvidenceProvider,
  unixScriptPackages,
} from "../src/discovery/system-evidence.js";

// The same cases are in go/cmd/guardian-runner/script_package_test.go,
// so the bundled helper and the PowerShell fallback agree.
test("Windows command lines name the npm package an interpreter runs", () => {
  for (const [image, commandLine, expected] of [
    // npm's global .cmd shim, with its doubled separator.
    ["node", String.raw`"C:\Program Files\nodejs\node.exe"  "C:\Users\dev\AppData\Roaming\npm\\node_modules\@google\gemini-cli\dist\index.js" --yolo`, "@google/gemini-cli"],
    ["node", String.raw`"C:\Program Files\nodejs\node.exe" C:\Users\dev\AppData\Roaming\npm\node_modules\@google\gemini-cli\dist\index.js`, "@google/gemini-cli"],
    // npm's PowerShell shim mixes separators.
    ["node", String.raw`"C:\Program Files\nodejs\node.exe" C:\Users\dev\AppData\Roaming\npm/node_modules/@anthropic-ai/claude-code/cli.js --resume`, "@anthropic-ai/claude-code"],
    // A user folder with a space, and nvm-windows.
    ["node", String.raw`"C:\nvm4w\nodejs\node.exe" "C:\Users\Dev User\AppData\Local\nvm\v22.12.0\node_modules\@github\copilot\npm-loader.js"`, "@github/copilot"],
    // Gemini CLI relaunches itself with memory options first.
    ["node", String.raw`"C:\Program Files\nodejs\node.exe" --max-old-space-size=8192 --require C:\hooks\preload.js C:\Users\dev\AppData\Roaming\npm\node_modules\@google\gemini-cli\dist\index.js`, "@google/gemini-cli"],
    ["node", String.raw`node -r C:\x\node_modules\@google\gemini-cli\register.js C:\work\server.js`, undefined],
    // pnpm's store keeps the real package after the last node_modules.
    ["node", String.raw`node C:\Users\dev\AppData\Local\pnpm\global\5\node_modules\.pnpm\@sourcegraph+amp@0.0.1\node_modules\@sourcegraph\amp\dist\main.js`, "@sourcegraph/amp"],
    ["bun", String.raw`bun run C:\Users\dev\.bun\install\global\node_modules\@google\gemini-cli\dist\index.js`, "@google/gemini-cli"],
    ["node", String.raw`node C:\work\project\server.js --port 3000`, undefined],
    ["node", String.raw`node C:\work\build.js C:\work\node_modules\@google\gemini-cli\dist\index.js`, undefined],
    ["node", String.raw`node -e "require('C:/x/node_modules/@google/gemini-cli')"`, undefined],
    ["node", String.raw`node C:\work\node_modules\.bin\gemini`, undefined],
    ["node", String.raw`node C:\work\node_modules\@google`, undefined],
    ["node", "", undefined],
    // Only interpreters are attributed.
    ["codex", String.raw`codex.exe C:\Users\dev\AppData\Roaming\npm\node_modules\@openai\codex\bin\codex.js`, undefined],
  ] as const) {
    assert.equal(scriptPackageFromWindowsCommandLine(image, commandLine), expected, commandLine);
  }
});

test("Windows command lines split as the C runtime splits them", () => {
  for (const [commandLine, expected] of [
    [String.raw`"C:\Program Files\nodejs\node.exe" a "b c" d`, [String.raw`C:\Program Files\nodejs\node.exe`, "a", "b c", "d"]],
    [String.raw`node  "C:\a b\\node_modules\x"`, ["node", String.raw`C:\a b\\node_modules\x`]],
    [String.raw`node a\\\"b "c\\" d`, ["node", String.raw`a\"b`, "c\\", "d"]],
    [`node "say ""hi"""`, ["node", `say "hi"`]],
    ["  node\ttab", ["node", "tab"]],
    ["", [""]],
  ] as const) {
    assert.deepEqual(windowsCommandLineArguments(commandLine), expected, commandLine);
  }
});

test("package names are validated", () => {
  for (const [path, expected] of [
    ["/usr/local/lib/node_modules/@anthropic-ai/claude-code/cli.js", "@anthropic-ai/claude-code"],
    ["/x/node_modules/Left-Pad/index.js", "left-pad"],
    ["/x/node_modules/_private/index.js", undefined],
    ["/x/node_modules/@scope/.hidden/index.js", undefined],
    ["/x/node_modules/na me/index.js", undefined],
    ["/x/node_modules", undefined],
    ["/x/lib/cli.js", undefined],
  ] as const) {
    assert.equal(packageFromScriptPath(path), expected, path);
  }
  assert.equal(scriptArgument("node", ["node", "--", "/x/cli.js"]), "/x/cli.js");
  assert.equal(scriptArgument("node", ["node", "-"]), undefined);
  assert.equal(scriptArgument("deno", ["deno", "run", "-A", "/x/main.ts"]), "/x/main.ts");
});

const startA = "Wed Nov  4 09:00:00 2026";
const startB = "Wed Nov  4 09:00:01 2026";
const unixInterpreters = [
  { processId: 101, nativeStartIdentity: startA, startedAt: new Date("2026-11-04T09:00:00Z"), executableName: "node" },
  { processId: 102, nativeStartIdentity: startB, startedAt: new Date("2026-11-04T09:00:01Z"), executableName: "node" },
  { processId: 103, nativeStartIdentity: startA, startedAt: new Date("2026-11-04T09:00:00Z"), executableName: "node" },
  { processId: 104, nativeStartIdentity: startA, startedAt: new Date("2026-11-04T09:00:00Z"), executableName: "node" },
  { processId: 105, nativeStartIdentity: startA, startedAt: new Date("2026-11-04T09:00:00Z"), executableName: "node" },
  { processId: 106, nativeStartIdentity: startA, startedAt: new Date("2026-11-04T09:00:00Z"), executableName: "node" },
  { processId: 107, nativeStartIdentity: startA, startedAt: new Date("2026-11-04T09:00:00Z"), executableName: "node" },
  { processId: 108, nativeStartIdentity: startA, startedAt: new Date("2026-11-04T09:00:00Z"), executableName: "node" },
];

test("macOS and Linux arguments name the npm package, following bin links", async () => {
  const listed: number[][] = [];
  const resolved: string[] = [];
  const rows = [
    // Started directly with the package's script.
    `  101     1 ${startA} /usr/local/bin/node /usr/local/lib/node_modules/@anthropic-ai/claude-code/cli.js --resume`,
    // A CLI that relaunches itself: the child belongs to its parent's run.
    `  102   101 ${startB} /usr/local/bin/node --max-old-space-size=8192 /usr/local/lib/node_modules/@anthropic-ai/claude-code/cli.js --resume`,
    // Started through its nvm bin link, as a shell does from PATH.
    `  103     1 ${startA} node /Users/dev/.nvm/versions/node/v22.12.0/bin/gemini --yolo`,
    // Homebrew on Apple silicon.
    `  104     1 ${startA} /opt/homebrew/bin/node /opt/homebrew/lib/node_modules/@github/copilot/npm-loader.js`,
    // An ordinary script, and one given a package path as an argument.
    `  105     1 ${startA} node /home/dev/project/server.js /home/dev/project/node_modules/@sourcegraph/amp/dist/main.js`,
    // A PID reused since the process table was read.
    `  106     1 Wed Nov  4 09:30:00 2026 node /usr/local/lib/node_modules/@google/gemini-cli/dist/index.js`,
    // ps joins arguments with spaces, so a path with one is not recognized.
    `  107     1 ${startA} node /Users/Dev User/.npm-global/lib/node_modules/@google/gemini-cli/dist/index.js`,
    // Inline code has no script.
    `  108     1 ${startA} node -e setInterval(()=>{},1000)`,
    "not a row",
  ].join("\n");
  const packages = await unixScriptPackages(
    unixInterpreters,
    async (processIds) => {
      listed.push([...processIds]);
      return rows;
    },
    async (path) => {
      resolved.push(path);
      if (path === "/Users/dev/.nvm/versions/node/v22.12.0/bin/gemini") {
        return "/Users/dev/.nvm/versions/node/v22.12.0/lib/node_modules/@google/gemini-cli/dist/index.js";
      }
      throw Object.assign(new Error("missing"), { code: "ENOENT" });
    },
  );
  assert.deepEqual(listed, [[101, 102, 103, 104, 105, 106, 107, 108]]);
  assert.deepEqual([...packages].sort(([left], [right]) => left - right), [
    [101, "@anthropic-ai/claude-code"],
    [103, "@google/gemini-cli"],
    [104, "@github/copilot"],
  ]);
  // Only bin links are followed.
  assert.deepEqual(resolved, ["/Users/dev/.nvm/versions/node/v22.12.0/bin/gemini"]);
});

test("macOS and Linux need no second ps pass without interpreters", async () => {
  const packages = await unixScriptPackages([], async () => {
    throw new Error("This listing must not run.");
  }, async () => {
    throw new Error("No path must be resolved.");
  });
  assert.equal(packages.size, 0);
});

test("a relaunched child is folded into its parent only for the same package", () => {
  const startedAt = new Date("2026-11-04T09:00:00Z");
  const later = new Date("2026-11-04T09:00:05Z");
  const packages = scriptPackagesByProcess([
    { processId: 10, parentProcessId: 1, startedAt, scriptPackage: "@google/gemini-cli" },
    { processId: 11, parentProcessId: 10, startedAt: later, scriptPackage: "@google/gemini-cli" },
    // A nested agent of another package stays its own run.
    { processId: 12, parentProcessId: 10, startedAt: later, scriptPackage: "@anthropic-ai/claude-code" },
    // A parent that started after its supposed child holds a reused PID.
    { processId: 20, parentProcessId: 21, startedAt, scriptPackage: "@sourcegraph/amp" },
    { processId: 21, parentProcessId: 1, startedAt: later, scriptPackage: "@sourcegraph/amp" },
    { processId: 30, startedAt },
  ]);
  assert.deepEqual([...packages].sort(([left], [right]) => left - right), [
    [10, "@google/gemini-cli"],
    [12, "@anthropic-ai/claude-code"],
    [20, "@sourcegraph/amp"],
    [21, "@sourcegraph/amp"],
  ]);
});

test("the native and PowerShell listings report the same package and never the command line", async () => {
  const secret = ["--api", "-key=", "phigon", "-fixture"].join("");
  const gemini = String.raw`C:\Users\dev\AppData\Roaming\npm\node_modules\@google\gemini-cli\dist\index.js`;
  const node = String.raw`C:\Program Files\nodejs\node.exe`;
  const native = JSON.stringify([
    { pid: 5000, ppid: 1, created_ms: 1785686000000, name: "node.exe", path: node, script: "@google/gemini-cli" },
    { pid: 5001, ppid: 5000, created_ms: 1785686000100, name: "node.exe", path: node, script: "@google/gemini-cli" },
    { pid: 5002, ppid: 1, created_ms: 1785686000200, name: "node.exe", path: node },
    { pid: 5003, ppid: 1, created_ms: 1785686000300, name: "agent.exe", path: String.raw`C:\Tools\agent.exe` },
    // A malformed package from the helper is ignored.
    { pid: 5004, ppid: 1, created_ms: 1785686000400, name: "node.exe", path: node, script: "../x" },
  ]);
  const powerShell = JSON.stringify([
    { ProcessId: 5000, ParentProcessId: 1, CreationDate: "/Date(1785686000000)/", ExecutablePath: node, Name: "node.exe", CommandLine: `"${node}" "${gemini}" ${secret}` },
    { ProcessId: 5001, ParentProcessId: 5000, CreationDate: "/Date(1785686000100)/", ExecutablePath: node, Name: "node.exe", CommandLine: `"${node}" --max-old-space-size=8192 ${gemini} ${secret}` },
    { ProcessId: 5002, ParentProcessId: 1, CreationDate: "/Date(1785686000200)/", ExecutablePath: node, Name: "node.exe", CommandLine: String.raw`node C:\work\server.js ${secret}` },
    { ProcessId: 5003, ParentProcessId: 1, CreationDate: "/Date(1785686000300)/", ExecutablePath: String.raw`C:\Tools\agent.exe`, Name: "agent.exe", CommandLine: null },
    { ProcessId: 5004, ParentProcessId: 1, CreationDate: "/Date(1785686000400)/", ExecutablePath: node, Name: "node.exe", CommandLine: null },
  ]);
  const unused = () => Promise.reject(new Error("This listing must not run."));
  const fromNative = await listWindowsProcesses(async () => native, unused);
  const fromPowerShell = await listWindowsProcesses(undefined, async () => powerShell);
  assert.deepEqual(fromNative, fromPowerShell);
  assert.deepEqual(fromNative.map((entry) => [entry.processId, entry.scriptPackage]), [
    [5000, "@google/gemini-cli"],
    [5001, undefined],
    [5002, undefined],
    [5003, undefined],
    [5004, undefined],
  ]);
  const allowed = ["processKey", "processId", "startedAt", "executableName", "executablePathDigest", "scriptPackage"];
  for (const entry of fromPowerShell) {
    for (const key of Object.keys(entry)) assert.ok(allowed.includes(key), key);
    // Unattributed processes are exactly as before.
    if (entry.scriptPackage === undefined) assert.ok(!("scriptPackage" in entry));
  }
  const serialized = JSON.stringify(fromPowerShell);
  assert.doesNotMatch(serialized, /phigon-fixture|server\.js|index\.js|AppData/u);
});

const geminiProcess: ProcessEvidence = {
  processKey: "process-node-gemini-start-a",
  processId: 601,
  startedAt: new Date("2026-11-04T09:00:00.000Z"),
  executableName: "node",
  executablePathDigest: "node-digest-a",
  scriptPackage: "@google/gemini-cli",
};

function evidenceWith(processes: readonly ProcessEvidence[]): HostEvidenceProvider {
  return {
    listProcesses: async () => ({ status: "ok", value: processes }),
    inspectExecutable: async () => ({ status: "ok", value: null }),
    inspectConfiguration: async () => ({ status: "ok", value: [] }),
  };
}

async function discover(processes: readonly ProcessEvidence[]) {
  return (await new DiscoveryEngine({
    adapters: [claudeAdapter, codexAdapter, genericAdapter],
    evidenceFactory: () => evidenceWith(processes),
    clock: () => new Date("2026-11-04T10:00:00.000Z"),
  }).discover("machine-script-package")).inventory;
}

test("npm-installed agents running as node are discovered as running processes", async () => {
  const inventory = await discover([
    geminiProcess,
    { ...geminiProcess, processKey: "process-node-claude-start-a", processId: 602, scriptPackage: "@anthropic-ai/claude-code" },
    { ...geminiProcess, processKey: "process-node-copilot-start-a", processId: 603, scriptPackage: "@github/copilot" },
    { ...geminiProcess, processKey: "process-node-amp-start-a", processId: 604, scriptPackage: "@sourcegraph/amp" },
  ]);
  assert.equal(inventory.partial, false);
  const running = inventory.agents
    .filter((agent) => agent.state === AgentState.RUNNING && agent.capabilities.includes("process-instance"))
    .map((agent) => [agent.displayName, Number(agent.processId)])
    .sort(([, left], [, right]) => Number(left) - Number(right));
  assert.deepEqual(running, [
    ["Gemini CLI · PID 601", 601],
    ["Claude Code · PID 602", 602],
    ["GitHub Copilot CLI · PID 603", 603],
    ["Amp · PID 604", 604],
  ]);
  const claude = inventory.agents.find((agent) => agent.processId === 602n);
  assert.equal(claude?.kind, AgentKind.CLAUDE);
});

test("other node processes and Codex are discovered exactly as before", async () => {
  const codex: ProcessEvidence = {
    processKey: "process-codex-start-a",
    processId: 701,
    startedAt: new Date("2026-11-04T09:00:00.000Z"),
    executableName: "codex",
    executablePathDigest: "codex-digest",
  };
  const plainNode: ProcessEvidence = {
    processKey: "process-node-plain-start-a",
    processId: 702,
    startedAt: new Date("2026-11-04T09:00:00.000Z"),
    executableName: "node",
    executablePathDigest: "node-digest-b",
  };
  // Codex's npm launcher runs as node; its native codex child is the agent.
  const codexLauncher: ProcessEvidence = { ...plainNode, processKey: "process-node-codex-start-a", processId: 703, scriptPackage: "@openai/codex" };
  // A package name alone never makes a non-interpreter an agent.
  const python: ProcessEvidence = { ...plainNode, processKey: "process-python-start-a", processId: 704, executableName: "python", scriptPackage: "@google/gemini-cli" };
  const withoutPackages = await discover([codex, plainNode]);
  const withPackages = await discover([codex, plainNode, codexLauncher, python]);
  assert.deepEqual(withPackages, withoutPackages);
  const running = withPackages.agents.filter((agent) => agent.state === AgentState.RUNNING);
  assert.deepEqual(running.map((agent) => [agent.kind, Number(agent.processId)]), [[AgentKind.CODEX, 701]]);
});

test(
  "this computer's process listing reports the package a real node process runs",
  { timeout: 60_000 },
  async (t) => {
    const directory = await mkdtemp(join(tmpdir(), "phigon-script-package-"));
    const marker = ["--phigon", "-marker-", "4242"].join("");
    const script = join(directory, "node_modules", "@phigon-test", "agent", "cli.js");
    await mkdir(dirname(script), { recursive: true });
    await writeFile(script, "setInterval(() => {}, 1000);\n");
    const child = spawn(process.execPath, [script, marker], { stdio: "ignore", windowsHide: true });
    t.after(async () => {
      if (child.exitCode === null && child.signalCode === null) {
        child.kill("SIGKILL");
        await once(child, "exit");
      }
      await rm(directory, { recursive: true, force: true });
    });
    await once(child, "spawn");
    const listing = await new SystemEvidenceProvider().listProcesses();
    assert.equal(listing.status, "ok");
    if (listing.status !== "ok") return;
    const observed = listing.value.find((entry) => entry.processId === child.pid);
    assert.ok(observed, "the node process is listed");
    assert.equal(observed.scriptPackage, "@phigon-test/agent");
    assert.doesNotMatch(JSON.stringify(listing.value), new RegExp(`${marker}|phigon-script-package-`, "u"));
  },
);
