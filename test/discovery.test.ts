import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test, { before } from "node:test";
import { promisify } from "node:util";
import {
  AgentKind,
  AgentState,
} from "../src/generated/phigon/v1/common_pb.js";
import { claudeAdapter } from "../src/discovery/adapters/claude.js";
import { codexAdapter } from "../src/discovery/adapters/codex.js";
import { customAgentAdapter } from "../src/discovery/adapters/custom.js";
import { genericAdapter } from "../src/discovery/adapters/generic.js";
import { hermesAdapter } from "../src/discovery/adapters/hermes.js";
import { openClawAdapter } from "../src/discovery/adapters/openclaw.js";
import { run } from "../src/cli.js";
import { DiscoveryEngine, runDiscoveryLoop } from "../src/discovery/engine.js";
import { formatDetections } from "../src/discovery/explain.js";
import {
  ExecutableProbeCache,
  SystemEvidenceProvider,
} from "../src/discovery/system-evidence.js";
import {
  observedProcessKey,
  processKeyCapability,
} from "../src/discovery/process-identity.js";
import type {
  ConfigurationEvidence,
  ExecutableEvidence,
  HostEvidenceProvider,
  ProbeResult,
  ProcessEvidence,
} from "../src/discovery/evidence.js";
import {
  CustomAgentRegistry,
  customAgentRegistration,
} from "../src/custom-agent-registry.js";

const observedAt = new Date("2026-07-24T10:00:00.000Z");

// The first Windows PowerShell start on a fresh computer prepares its .NET
// and module caches and can outlast a version probe's timeout. Start it once
// so the probe tests below measure the probe, not that one-time cost.
before(async () => {
  if (process.platform !== "win32") return;
  await promisify(execFile)(
    "powershell.exe",
    ["-NoProfile", "-NonInteractive", "-Command", "exit"],
    { timeout: 120_000, windowsHide: true },
  ).catch(() => undefined);
});

test("Windows version probes close pipeline input and honor mixed-case environment keys", { skip: process.platform !== "win32" }, async () => {
  const directory = await mkdtemp(join(tmpdir(), "phigon-version-probe-"));
  try {
    await writeFile(join(directory, "phigon-test.cmd"), "@echo off\r\n");
    await writeFile(join(directory, "phigon-test.ps1"), "$input | Out-Null\r\nWrite-Output 'phigon-test 1.2.3'\r\n");
    const provider = new SystemEvidenceProvider("win32", { Path: directory, PathExt: ".CMD" });
    const result = await provider.inspectExecutable(["phigon-test"]);
    assert.equal(result.status, "ok");
    if (result.status !== "ok") return;
    assert.equal(result.value?.version, "1.2.3");
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("installed CLI probes are reused between discoveries until the executable changes or expires", async () => {
  const directory = await mkdtemp(join(tmpdir(), "phigon-probe-cache-"));
  const counter = join(directory, "invocations.txt");
  const windows = process.platform === "win32";
  // A tiny CLI that records each `--version` launch and prints a version.
  const install = async (name: string, version: string) => {
    if (windows) {
      await writeFile(join(directory, `${name}.cmd`), `@echo off\r\nrem ${version}\r\n`);
      await writeFile(
        join(directory, `${name}.ps1`),
        `Add-Content -LiteralPath '${counter}' -Value 'x'\r\nWrite-Output '${name} ${version}'\r\n`,
      );
    } else {
      await writeFile(
        join(directory, name),
        `#!/bin/sh\necho x >> '${counter}'\necho '${name} ${version}'\n`,
        { mode: 0o755 },
      );
    }
  };
  const launches = async () => {
    try {
      return (await readFile(counter, "utf8")).split(/\r?\n/u).filter(Boolean).length;
    } catch {
      return 0;
    }
  };
  let now = 1_000_000;
  const cache = new ExecutableProbeCache({ clock: () => now });
  const environment = windows
    ? { Path: directory, PathExt: ".CMD" }
    : { PATH: directory };
  const inspect = async (name: string) => {
    const result = await new SystemEvidenceProvider(
      process.platform,
      environment,
      cache,
    ).inspectExecutable([name]);
    assert.equal(result.status, "ok");
    return result.status === "ok" ? result.value : undefined;
  };
  try {
    await install("phigon-probe", "1.2.3");
    assert.equal((await inspect("phigon-probe"))?.version, "1.2.3");
    // Its first line is kept too, to tell programs that share a name apart.
    assert.equal((await inspect("phigon-probe"))?.versionBanner, "phigon-probe 1.2.3");
    assert.equal(await launches(), 1);

    await install("phigon-probe", "1.2.40");
    assert.equal((await inspect("phigon-probe"))?.version, "1.2.40");
    assert.equal(await launches(), 2);

    // A version read by running the CLI is read again after an hour.
    now += 60 * 60_000;
    assert.equal((await inspect("phigon-probe"))?.version, "1.2.40");
    assert.equal(await launches(), 3);

    assert.equal(await inspect("phigon-later"), null);
    await install("phigon-later", "2.0.0");
    assert.equal(await inspect("phigon-later"), null);
    now += 60_000;
    assert.equal((await inspect("phigon-later"))?.version, "2.0.0");
    assert.equal(await launches(), 4);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("local process keys require start evidence and resist PID reuse", () => {
  const first = observedProcessKey(
    "darwin",
    4242,
    "Fri Jul 24 09:00:00 2026",
    "executable-digest",
  );
  const same = observedProcessKey(
    "darwin",
    4242,
    "Fri Jul 24 09:00:00 2026",
    "executable-digest",
  );
  const reused = observedProcessKey(
    "darwin",
    4242,
    "Fri Jul 24 09:05:00 2026",
    "executable-digest",
  );

  assert.ok(first);
  assert.equal(same, first);
  assert.notEqual(reused, first);
  assert.equal(
    observedProcessKey("darwin", 4242, "", "executable-digest"),
    undefined,
  );
  const capability = processKeyCapability(first);
  assert.ok(capability);
  assert.doesNotMatch(capability, new RegExp(first, "u"));
});

test("independent adapters map macOS-style evidence into stable sanitized identities", async () => {
  const evidence = new FixtureEvidenceProvider({
    processes: {
      status: "ok",
      value: [
        {
          processKey: "process-claude-101-start-a",
          processId: 101,
          startedAt: new Date("2026-07-24T09:00:00.000Z"),
          executableName: "claude",
          executablePathDigest: "claude-running-digest",
        },
        {
          processKey: "process-aider-202-start-a",
          processId: 202,
          startedAt: new Date("2026-07-24T09:05:00.000Z"),
          executableName: "aider",
          executablePathDigest: "aider-running-digest",
        },
      ],
    },
    executables: new Map([
      [
        "claude",
        {
          executableName: "claude",
          executablePathDigest: "claude-installed-digest",
          version: "2.1.0",
        },
      ],
      [
        "codex",
        {
          executableName: "codex",
          executablePathDigest: "codex-installed-digest",
          version: "",
        },
      ],
    ]),
    configurations: new Map([
      ["~/.hermes/sessions", [{ identifierDigest: "hermes-config-digest" }]],
      ["~/.openclaw", [{ identifierDigest: "openclaw-config-digest" }]],
    ]),
  });
  const adapters = [
    claudeAdapter,
    codexAdapter,
    hermesAdapter,
    openClawAdapter,
    genericAdapter,
  ];
  const engine = new DiscoveryEngine({
    adapters,
    evidenceFactory: () => evidence,
    clock: () => observedAt,
  });

  const first = await engine.discover("machine-fixture");
  const second = await engine.discover("machine-fixture");
  const byKind = new Map(
    first.inventory.agents.map((agent) => [agent.kind, agent]),
  );

  assert.equal(byKind.get(AgentKind.CLAUDE)?.state, AgentState.RUNNING);
  assert.equal(byKind.get(AgentKind.CLAUDE)?.version, "2.1.0");
  assert.equal(byKind.get(AgentKind.CODEX)?.state, AgentState.STOPPED);
  assert.equal(byKind.get(AgentKind.CODEX)?.version, "");
  assert.equal(byKind.get(AgentKind.HERMES)?.state, AgentState.INSTALLED);
  assert.equal(byKind.get(AgentKind.OPENCLAW)?.state, AgentState.INSTALLED);
  assert.ok(
    first.inventory.agents.some(
      (agent) =>
        agent.kind === AgentKind.GENERIC &&
        agent.displayName.startsWith("Aider · PID ") &&
        agent.state === AgentState.RUNNING,
    ),
  );
  assert.deepEqual(
    first.inventory.agents.map((agent) => agent.agentId),
    second.inventory.agents.map((agent) => agent.agentId),
  );
  assert.equal(first.adapterHealth.length, 5);
  assert.ok(first.inventory.notices.includes("adapter=codex;status=degraded"));

  const serialized = JSON.stringify(first, (_, value: unknown) =>
    typeof value === "bigint" ? value.toString() : value,
  );
  assert.doesNotMatch(serialized, /Users\/fixture/u);
  assert.doesNotMatch(serialized, /--dangerous-argument/u);
  assert.doesNotMatch(serialized, /SECRET_TOKEN/u);
});

test("permission-denied process evidence produces explicit partial state", async () => {
  const evidence = new FixtureEvidenceProvider({
    processes: {
      status: "permission_denied",
      notice: "Process inspection was denied by the operating system.",
    },
    executables: new Map([
      [
        "claude",
        {
          executableName: "claude",
          executablePathDigest: "claude-installed-digest",
          version: "2.1.0",
        },
      ],
    ]),
  });
  const engine = new DiscoveryEngine({
    adapters: [claudeAdapter],
    evidenceFactory: () => evidence,
    clock: () => observedAt,
  });

  const snapshot = await engine.discover("machine-denied");

  assert.equal(snapshot.inventory.partial, true);
  assert.equal(
    snapshot.inventory.agents[0]?.state,
    AgentState.PERMISSION_DENIED,
  );
  assert.equal(snapshot.adapterHealth[0]?.status, "permission_denied");
});

test("runtime identity is stable only for the same process lifetime", async () => {
  const executable = new Map([
    [
      "codex",
      {
        executableName: "codex",
        executablePathDigest: "codex-installed-digest",
        version: "0.144.5",
      },
    ],
  ]);
  const running = await codexAdapter.discover(
    new FixtureEvidenceProvider({
      processes: {
        status: "ok",
        value: [{
          processKey: "process-codex-202-start-a",
          processId: 202,
          startedAt: new Date("2026-07-24T09:10:00.000Z"),
          executableName: "codex",
          executablePathDigest: "codex-running-digest",
        }],
      },
      executables: executable,
    }),
    observedAt,
  );
  const sameLifetime = await codexAdapter.discover(
    new FixtureEvidenceProvider({
      processes: {
        status: "ok",
        value: [{
          processKey: "process-codex-202-start-a",
          processId: 202,
          startedAt: new Date("2026-07-24T09:10:00.000Z"),
          executableName: "codex",
          executablePathDigest: "codex-running-digest",
        }],
      },
      executables: executable,
    }),
    observedAt,
  );
  const stopped = await codexAdapter.discover(
    new FixtureEvidenceProvider({
      processes: { status: "ok", value: [] },
      executables: executable,
    }),
    observedAt,
  );

  assert.equal(running.agents[0]?.state, AgentState.RUNNING);
  assert.equal(stopped.agents[0]?.state, AgentState.STOPPED);
  assert.equal(
    running.agents[0]?.agentId,
    sameLifetime.agents[0]?.agentId,
  );
  assert.notEqual(running.agents[0]?.agentId, stopped.agents[0]?.agentId);
});

test("concurrent processes are represented as separate agent identities", async () => {
  const result = await codexAdapter.discover(
    new FixtureEvidenceProvider({
      processes: {
        status: "ok",
        value: [
          {
            processKey: "process-codex-202-start-a",
            processId: 202,
            startedAt: new Date("2026-07-24T09:10:00.000Z"),
            executableName: "codex",
            executablePathDigest: "codex-running-digest",
          },
          {
            processKey: "process-codex-303-start-a",
            processId: 303,
            startedAt: new Date("2026-07-24T09:11:00.000Z"),
            executableName: "codex",
            executablePathDigest: "codex-running-digest",
          },
        ],
      },
      executables: new Map([
        [
          "codex",
          {
            executableName: "codex",
            executablePathDigest: "codex-installed-digest",
            version: "0.144.5",
          },
        ],
      ]),
    }),
    observedAt,
  );

  assert.equal(result.agents.length, 2);
  assert.deepEqual(
    result.agents.map((agent) => agent.processId),
    [202n, 303n],
  );
  assert.equal(new Set(result.agents.map((agent) => agent.agentId)).size, 2);
  assert.match(result.agents[0]?.displayName ?? "", /PID 202/u);
  assert.match(result.agents[1]?.displayName ?? "", /PID 303/u);
  assert.ok(
    result.agents[0]?.capabilities.some((capability) =>
      capability.startsWith("process-key-sha256:")
    ),
  );
  assert.ok(
    result.agents[1]?.capabilities.includes("process-instance"),
  );
});

test("PID reuse creates a different process-lifetime agent identity", async () => {
  const discover = (processKey: string) => codexAdapter.discover(
    new FixtureEvidenceProvider({
      processes: {
        status: "ok",
        value: [{
          processKey,
          processId: 202,
          startedAt: new Date("2026-07-24T09:10:00.000Z"),
          executableName: "codex",
          executablePathDigest: "codex-running-digest",
        }],
      },
    }),
    observedAt,
  );

  const first = await discover("process-codex-202-start-a");
  const reused = await discover("process-codex-202-start-b");

  assert.notEqual(first.agents[0]?.agentId, reused.agents[0]?.agentId);
  assert.equal(first.agents[0]?.processId, reused.agents[0]?.processId);
});

test("discovery retains stopped lifetimes and keeps PID reuse separate", async () => {
  let processes: readonly ProcessEvidence[] = [{
    processKey: "process-codex-202-start-a",
    processId: 202,
    startedAt: new Date("2026-07-24T09:10:00.000Z"),
    executableName: "codex",
    executablePathDigest: "codex-running-digest",
  }];
  const executable: ExecutableEvidence = {
    executableName: "codex",
    executablePathDigest: "codex-installed-digest",
    version: "0.144.5",
  };
  const evidence: HostEvidenceProvider = {
    async listProcesses() {
      return { status: "ok", value: processes };
    },
    async inspectExecutable() {
      return { status: "ok", value: executable };
    },
    async inspectConfiguration() {
      return { status: "ok", value: [] };
    },
  };
  const engine = new DiscoveryEngine({
    adapters: [codexAdapter],
    evidenceFactory: () => evidence,
    clock: () => observedAt,
  });

  const first = await engine.discover("machine-a");
  const firstID = first.inventory.agents[0]?.agentId;
  assert.ok(firstID);
  assert.equal(first.inventory.agents[0]?.state, AgentState.RUNNING);

  processes = [{
    processId: 202,
    executableName: "codex",
    executablePathDigest: "codex-running-digest",
  } as ProcessEvidence];
  const incomplete = await engine.discover("machine-a");
  assert.equal(incomplete.inventory.partial, true);
  assert.equal(incomplete.inventory.agents.length, 1);
  assert.equal(incomplete.inventory.agents[0]?.agentId, firstID);
  assert.equal(incomplete.inventory.agents[0]?.state, AgentState.UNKNOWN);

  processes = [];
  const stopped = await engine.discover("machine-a");
  assert.equal(stopped.inventory.agents.length, 1);
  assert.equal(stopped.inventory.agents[0]?.agentId, firstID);
  assert.equal(stopped.inventory.agents[0]?.state, AgentState.STOPPED);
  assert.equal(stopped.inventory.agents[0]?.processId, 202n);

  processes = [{
    processKey: "process-codex-202-start-b",
    processId: 202,
    startedAt: new Date("2026-07-24T09:20:00.000Z"),
    executableName: "codex",
    executablePathDigest: "codex-running-digest",
  }];
  const reused = await engine.discover("machine-a");
  assert.equal(reused.inventory.agents.length, 2);
  assert.equal(reused.inventory.agents.length <= 256, true);
  assert.equal(
    reused.inventory.agents.find((agent) => agent.agentId === firstID)
      ?.state,
    AgentState.STOPPED,
  );
  const newRuntime = reused.inventory.agents.find(
    (agent) => agent.agentId !== firstID,
  );
  assert.equal(newRuntime?.state, AgentState.RUNNING);
  assert.equal(newRuntime?.processId, 202n);

  const otherMachine = await engine.discover("machine-b");
  assert.equal(otherMachine.inventory.agents.length, 1);
  assert.equal(
    otherMachine.inventory.agents.some((agent) => agent.agentId === firstID),
    false,
  );
});

test("retained process lifetimes remain bounded to the inventory contract", async () => {
  let processes: readonly ProcessEvidence[] = Array.from(
    { length: 300 },
    (_, index): ProcessEvidence => ({
      processKey: `process-codex-${index + 1}-start-a`,
      processId: index + 1,
      startedAt: new Date("2026-07-24T09:10:00.000Z"),
      executableName: "codex",
      executablePathDigest: "codex-running-digest",
    }),
  );
  const evidence: HostEvidenceProvider = {
    async listProcesses() {
      return { status: "ok", value: processes };
    },
    async inspectExecutable() {
      return { status: "ok", value: null };
    },
    async inspectConfiguration() {
      return { status: "ok", value: [] };
    },
  };
  const engine = new DiscoveryEngine({
    adapters: [codexAdapter],
    evidenceFactory: () => evidence,
    clock: () => observedAt,
  });

  const running = await engine.discover("machine-bounded");
  assert.equal(running.inventory.agents.length, 256);
  assert.ok(
    running.inventory.agents.every(
      (agent) => agent.state === AgentState.RUNNING,
    ),
  );

  processes = [];
  const stopped = await engine.discover("machine-bounded");
  assert.equal(stopped.inventory.agents.length, 256);
  assert.ok(
    stopped.inventory.agents.every(
      (agent) => agent.state === AgentState.STOPPED,
    ),
  );
});

test("conflicting process keys fail closed instead of merging runtimes", async () => {
  const result = await codexAdapter.discover(
    new FixtureEvidenceProvider({
      processes: {
        status: "ok",
        value: [
          {
            processKey: "duplicated-process-key",
            processId: 202,
            startedAt: new Date("2026-07-24T09:10:00.000Z"),
            executableName: "codex",
            executablePathDigest: "codex-running-digest",
          },
          {
            processKey: "duplicated-process-key",
            processId: 303,
            startedAt: new Date("2026-07-24T09:11:00.000Z"),
            executableName: "codex",
            executablePathDigest: "codex-running-digest",
          },
        ],
      },
    }),
    observedAt,
  );

  assert.equal(result.agents.length, 1);
  assert.equal(result.agents[0]?.state, AgentState.UNKNOWN);
  assert.equal(result.agents[0]?.processId, 0n);
  assert.equal(result.health.status, "error");
  assert.match(result.health.notices.join("\n"), /not attributed/u);
});

test("process claims shared across dynamic and built-in adapters fail closed", async () => {
  const directory = await mkdtemp(join(tmpdir(), "phigon-adapter-conflict-"));
  try {
    const registry = new CustomAgentRegistry(directory);
    await registry.add(customAgentRegistration({
      id: "codex-wrapper",
      displayName: "Codex Wrapper",
      processNames: ["codex"],
    }));
    const evidence = new FixtureEvidenceProvider({
      processes: {
        status: "ok",
        value: [{
          processKey: "shared-codex-process-lifetime",
          processId: 202,
          startedAt: new Date("2026-07-24T09:10:00.000Z"),
          executableName: "codex",
          executablePathDigest: "codex-running-digest",
        }],
      },
    });
    const snapshot = await new DiscoveryEngine({
      adapters: [codexAdapter, customAgentAdapter(registry)],
      evidenceFactory: () => evidence,
      clock: () => observedAt,
    }).discover("machine-conflict");

    assert.equal(snapshot.inventory.agents.length, 0);
    assert.equal(snapshot.inventory.partial, true);
    assert.equal(snapshot.adapterHealth.at(-1)?.adapterId, "attribution");
    assert.equal(snapshot.adapterHealth.at(-1)?.status, "error");
    assert.match(snapshot.inventory.notices.join("\n"), /not attributed/u);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("missing process-lifetime evidence reports coverage loss", async () => {
  const incomplete = {
    processId: 202,
    executableName: "codex",
    executablePathDigest: "codex-running-digest",
  } as ProcessEvidence;
  const result = await codexAdapter.discover(
    new FixtureEvidenceProvider({
      processes: { status: "ok", value: [incomplete] },
    }),
    observedAt,
  );

  assert.equal(result.agents.length, 1);
  assert.equal(result.agents[0]?.state, AgentState.UNKNOWN);
  assert.equal(result.agents[0]?.processId, 0n);
  assert.equal(result.health.status, "error");
});

test("passive process snapshot completes before version execution", async () => {
  let processSnapshotComplete = false;
  let versionProbeOverlapped = false;
  const evidence: HostEvidenceProvider = {
    async listProcesses() {
      await new Promise<void>((resolve) => setImmediate(resolve));
      processSnapshotComplete = true;
      return { status: "ok", value: [] };
    },
    async inspectExecutable() {
      if (!processSnapshotComplete) versionProbeOverlapped = true;
      return {
        status: "ok",
        value: {
          executableName: "codex",
          executablePathDigest: "codex-installed-digest",
          version: "0.144.5",
        },
      };
    },
    async inspectConfiguration() {
      return { status: "ok", value: [] };
    },
  };

  await codexAdapter.discover(evidence, observedAt);

  assert.equal(versionProbeOverlapped, false);
});

test("a failed discovery pass is reported and the loop keeps discovering", async () => {
  const evidence = new FixtureEvidenceProvider({
    processes: { status: "ok", value: [] },
  });
  let passes = 0;
  const engine = new DiscoveryEngine({
    evidenceFactory: () => {
      passes++;
      if (passes === 1) throw new Error("process listing crashed");
      return evidence;
    },
    clock: () => observedAt,
  });
  const controller = new AbortController();
  const published: number[] = [];
  const errors: string[] = [];
  await runDiscoveryLoop(
    engine,
    "",
    1,
    controller.signal,
    () => {
      published.push(passes);
      if (published.length === 1) throw new Error("inventory could not be saved");
      controller.abort();
    },
    (error) => errors.push(error instanceof Error ? error.message : String(error)),
  );
  // The first pass failed while discovering and the second while
  // publishing; the third still ran.
  assert.deepEqual(published, [2, 3]);
  assert.deepEqual(errors, ["process listing crashed", "inventory could not be saved"]);
});

test("missing evidence yields an honest empty inventory", async () => {
  const evidence = new FixtureEvidenceProvider({
    processes: { status: "ok", value: [] },
  });
  const snapshot = await new DiscoveryEngine({
    evidenceFactory: () => evidence,
    clock: () => observedAt,
  }).discover();

  assert.equal(snapshot.inventory.agents.length, 0);
  assert.equal(snapshot.inventory.partial, false);
  assert.equal(snapshot.adapterHealth.length, 5);
});

test("desktop applications are one running product, not one agent per helper process", async () => {
  const helpers = [1, 2, 3].map((index) => ({
    processKey: `process-cursor-${index}-start-a`,
    processId: 400 + index,
    startedAt: new Date("2026-07-24T09:00:00.000Z"),
    executableName: "cursor",
    executablePathDigest: `cursor-helper-digest-${index}`,
  }));
  const discover = (configured: boolean) => new DiscoveryEngine({
    adapters: [genericAdapter],
    evidenceFactory: () => new FixtureEvidenceProvider({
      processes: { status: "ok", value: helpers },
      configurations: configured
        ? new Map([["~/AppData/Roaming/Cursor", [{ identifierDigest: "cursor-config-digest" }]]])
        : new Map(),
    }),
    clock: () => observedAt,
  }).discover();

  const running = await discover(true);
  const cursor = running.inventory.agents.filter((agent) =>
    agent.displayName === "Cursor" || agent.displayName.startsWith("Cursor · ")
  );
  assert.equal(cursor.length, 1);
  assert.equal(cursor[0]?.state, AgentState.RUNNING);
  assert.equal(cursor[0]?.processId, 0n);
  assert.equal(running.inventory.partial, false);

  // A helper process alone does not show that the application is installed.
  const unconfigured = await discover(false);
  assert.ok(!unconfigured.inventory.agents.some((agent) =>
    agent.displayName.startsWith("Cursor")
  ));
});

test("agents whose conversations are not read are still discovered", async () => {
  const agents: ReadonlyArray<Readonly<{
    displayName: string;
    configuration: string;
    process?: string;
  }>> = [
    { displayName: "Antigravity", configuration: "~/.gemini/antigravity", process: "antigravity" },
    { displayName: "Trae", configuration: "~/AppData/Roaming/Trae", process: "trae" },
    { displayName: "Zed", configuration: "~/.config/zed", process: "zed" },
    { displayName: "Factory Droid", configuration: "~/.factory" },
    {
      displayName: "Roo Code",
      configuration: "~/AppData/Roaming/Code/User/globalStorage/rooveterinaryinc.roo-cline",
    },
  ];
  for (const agent of agents) {
    const snapshot = await new DiscoveryEngine({
      adapters: [genericAdapter],
      evidenceFactory: () => new FixtureEvidenceProvider({
        processes: {
          status: "ok",
          value: agent.process === undefined ? [] : [1, 2].map((index) => ({
            processKey: `process-${agent.process}-${index}-start-a`,
            processId: 500 + index,
            startedAt: new Date("2026-07-24T09:00:00.000Z"),
            executableName: agent.process ?? "",
            executablePathDigest: `${agent.process}-digest-${index}`,
          })),
        },
        configurations: new Map([
          [agent.configuration, [{ identifierDigest: `${agent.displayName}-config` }]],
        ]),
      }),
      clock: () => observedAt,
    }).discover();
    const found = snapshot.inventory.agents.filter((identity) =>
      identity.displayName.split(" · ")[0] === agent.displayName
    );
    assert.equal(found.length, 1, agent.displayName);
    assert.equal(
      found[0]?.state,
      agent.process === undefined ? AgentState.INSTALLED : AgentState.RUNNING,
      agent.displayName,
    );
  }
});

// Anonymized samples of programs that share an agent's name: kdb+'s q
// (`q --version` prints its banner, "KDB+ 4.1 2024.10.16 ..."), the goose
// database migration tool ("goose version: v3.24.1"), the AWS Copilot CLI
// ("copilot version: v1.34.1"), the Hermes IBC relayer ("hermes 1.10.0")
// and the amp text editor.
const lookAlikeStart = new Date("2026-07-24T09:30:00.000Z");
const lookAlike = (executableName: string, processId: number): ProcessEvidence => ({
  processKey: `process-${executableName}-${processId}-start-a`,
  processId,
  startedAt: lookAlikeStart,
  executableName,
  executablePathDigest: `${executableName}-path-digest`,
});
const lookAlikeExecutables = new Map<string, ExecutableEvidence>([
  ["q", { executableName: "q", executablePathDigest: "kdb-q-digest", version: "4.1" }],
  ["goose", { executableName: "goose", executablePathDigest: "pressly-goose-digest", version: "v3.24.1" }],
  ["copilot", { executableName: "copilot", executablePathDigest: "aws-copilot-digest", version: "v1.34.1" }],
  ["hermes", { executableName: "hermes", executablePathDigest: "ibc-hermes-digest", version: "1.10.0" }],
  ["amp", { executableName: "amp", executablePathDigest: "amp-editor-digest", version: "0.7.1" }],
]);

test("programs that only share an agent's name are not reported and cannot be stopped", async () => {
  const processes = [
    lookAlike("q", 3101),
    lookAlike("goose", 3102),
    lookAlike("copilot", 3103),
    lookAlike("hermes", 3104),
    lookAlike("amp", 3105),
  ];
  const snapshot = await new DiscoveryEngine({
    adapters: [hermesAdapter, genericAdapter],
    evidenceFactory: () => new FixtureEvidenceProvider({
      processes: { status: "ok", value: processes },
      executables: lookAlikeExecutables,
      // The Hermes IBC relayer's own folder is ~/.hermes, holding config.toml.
      configurations: new Map([["~/.hermes", [{ identifierDigest: "ibc-relayer-home" }]]]),
    }),
    clock: () => observedAt,
  }).discover("machine-fixture");

  assert.deepEqual(snapshot.inventory.agents.map((agent) => agent.displayName), []);
  assert.equal(snapshot.inventory.partial, false);
  assert.ok(snapshot.adapterHealth.every((health) => health.status === "healthy"));
  // kdb+'s q is not even looked at: Amazon Q is found by its own qchat.
  const setAside = snapshot.detections.filter((detection) => !detection.reported);
  assert.deepEqual(setAside.map((detection) => detection.displayName).sort(), [
    "Amp",
    "GitHub Copilot CLI",
    "Goose",
    "Hermes Agent",
  ]);
  for (const detection of setAside) {
    assert.equal(detection.stoppable, false);
    assert.equal(detection.confidence, "low");
    assert.ok(detection.evidence.every((item) => !item.identifying));
    assert.match(detection.notes.join(" "), /other programs use the same name/u);
  }
});

test("where an agent's own configuration exists, its native processes with a shared name are that agent", async () => {
  const processes: ProcessEvidence[] = [
    // Goose desktop's agent server, and a goose CLI session.
    lookAlike("goosed", 4101),
    lookAlike("goose", 4102),
    // GitHub Copilot CLI installed with npm, and the native binary that
    // WinGet, Homebrew and the install script put on PATH.
    { ...lookAlike("node", 4201), scriptPackage: "@github/copilot" },
    lookAlike("copilot", 4202),
    // An Amazon Q chat session, and a q program: kdb+'s, or Amazon Q's
    // launcher, which never counts.
    lookAlike("qchat", 4301),
    lookAlike("q", 4302),
    // Hermes Agent, a Python console script listed by its name.
    lookAlike("hermes", 4401),
  ];
  const snapshot = await new DiscoveryEngine({
    adapters: [hermesAdapter, genericAdapter],
    evidenceFactory: () => new FixtureEvidenceProvider({
      processes: { status: "ok", value: processes },
      executables: lookAlikeExecutables,
      configurations: new Map([
        ["~/.config/goose", [{ identifierDigest: "goose-config" }]],
        ["~/.copilot", [{ identifierDigest: "copilot-config" }]],
        ["~/.aws/amazonq", [{ identifierDigest: "amazonq-config" }]],
        ["~/.hermes/sessions", [{ identifierDigest: "hermes-sessions" }]],
      ]),
    }),
    clock: () => observedAt,
  }).discover("machine-fixture");

  const stoppable = snapshot.inventory.agents
    .filter((agent) => agent.capabilities.includes("process-instance") && agent.state === AgentState.RUNNING)
    .map((agent) => [agent.displayName, Number(agent.processId)]);
  assert.deepEqual(stoppable.sort(([, left], [, right]) => Number(left) - Number(right)), [
    ["Goose · PID 4101", 4101],
    ["Goose · PID 4102", 4102],
    ["GitHub Copilot CLI · PID 4201", 4201],
    ["GitHub Copilot CLI · PID 4202", 4202],
    ["Amazon Q Developer CLI · PID 4301", 4301],
    ["Hermes Agent · PID 4401", 4401],
  ]);
  // A q process is never Amazon Q, even where Amazon Q is installed.
  assert.ok(!snapshot.inventory.agents.some((agent) => agent.processId === 4302n));
  assert.equal(snapshot.inventory.partial, false);
  assert.ok(!snapshot.inventory.notices.some((notice) => /other programs use the same name/u.test(notice)));
  // Only the amp editor's command, with no Amp settings here, is set aside.
  assert.deepEqual(snapshot.detections.filter((detection) => !detection.reported).map((detection) => detection.displayName), ["Amp"]);

  // The WinGet copilot: a native process, its command on PATH and ~/.copilot.
  const copilot = snapshot.detections.find((detection) => detection.displayName === "GitHub Copilot CLI · PID 4202");
  assert.equal(copilot?.confidence, "high");
  assert.equal(copilot?.stoppable, true);
  assert.deepEqual(copilot?.evidence.map((item) => [item.detail, item.identifying]), [
    ['running process "copilot" (PID 4202)', true],
    ['"copilot" command on PATH, version v1.34.1', true],
    ["~/.copilot exists", true],
  ]);
  const npmCopilot = snapshot.detections.find((detection) => detection.displayName === "GitHub Copilot CLI · PID 4201");
  assert.equal(npmCopilot?.evidence[0]?.detail, "node process running the npm package @github/copilot (PID 4201)");
  assert.equal(npmCopilot?.evidence[0]?.kind, "package");
  // The copilot on PATH may be AWS's, so its version is not Copilot's.
  for (const agent of snapshot.inventory.agents.filter((identity) => identity.displayName.startsWith("GitHub Copilot CLI"))) {
    assert.equal(agent.version, "", agent.displayName);
  }
  assert.match(copilot?.notes.join(" ") ?? "", /Other programs are also called "copilot", so the version of that command is not given as GitHub Copilot CLI's\./u);
  // goose on PATH may be the migration tool; no qchat is on PATH here.
  assert.equal(snapshot.inventory.agents.find((agent) => agent.displayName === "Goose · PID 4101")?.version, "");
  assert.equal(snapshot.inventory.agents.find((agent) => agent.displayName === "Amazon Q Developer CLI · PID 4301")?.version, "");
});

test("an npm agent's runtime never takes the version of a same-named command on PATH", async () => {
  // GitHub Copilot CLI runs from npm, without ~/.copilot, while AWS's
  // copilot is the copilot command on PATH.
  const snapshot = await new DiscoveryEngine({
    adapters: [genericAdapter],
    evidenceFactory: () => new FixtureEvidenceProvider({
      processes: { status: "ok", value: [{ ...lookAlike("node", 4601), scriptPackage: "@github/copilot" }] },
      executables: new Map([
        ["copilot", lookAlikeExecutables.get("copilot")!],
        ["gemini", { executableName: "gemini", executablePathDigest: "gemini-digest", version: "0.12.0" }],
      ]),
    }),
    clock: () => observedAt,
  }).discover("machine-fixture");
  const copilot = snapshot.inventory.agents.find((agent) => agent.displayName === "GitHub Copilot CLI · PID 4601");
  assert.ok(copilot?.capabilities.includes("process-instance"));
  assert.equal(copilot?.version, "");
  assert.ok(!snapshot.inventory.notices.some((notice) => /GitHub Copilot CLI version is unknown/u.test(notice)));
  // A command with the agent's own name still gives its version.
  assert.equal(snapshot.inventory.agents.find((agent) => agent.displayName === "Gemini CLI")?.version, "0.12.0");
});

test("a shared-name command gives the agent's version when it shows it is the agent", async () => {
  const versionOf = async (copilot: ExecutableEvidence) => (await new DiscoveryEngine({
    adapters: [genericAdapter],
    evidenceFactory: () => new FixtureEvidenceProvider({
      processes: { status: "ok", value: [] },
      executables: new Map([["copilot", copilot]]),
      configurations: new Map([["~/.copilot", [{ identifierDigest: "copilot-config" }]]]),
    }),
    clock: () => observedAt,
  }).discover("machine-fixture")).inventory.agents.find((agent) => agent.displayName === "GitHub Copilot CLI")?.version;
  // WinGet's native copilot.exe names itself.
  assert.equal(await versionOf({
    executableName: "copilot", executablePathDigest: "winget-copilot", version: "1.0.41", versionBanner: "GitHub Copilot CLI 1.0.41.",
  }), "1.0.41");
  // npm's copilot shim, whose version came from @github/copilot's package.json.
  assert.equal(await versionOf({
    executableName: "copilot", executablePathDigest: "npm-copilot", version: "1.0.40", packageName: "@github/copilot",
  }), "1.0.40");
  // AWS's copilot on PATH where GitHub's configuration is.
  assert.equal(await versionOf({
    executableName: "copilot", executablePathDigest: "aws-copilot", version: "v1.34.1", versionBanner: "copilot version: v1.34.1",
  }), "");
  assert.equal(await versionOf({
    executableName: "copilot", executablePathDigest: "other-copilot", version: "2.0.0", packageName: "@someone/copilot",
  }), "");
});

test("without the agent's configuration, a shared name is set aside even next to the agent's own process", async () => {
  // No ~/.config/goose: the goose desktop server identifies Goose, while a
  // goose program may be the migration tool and is not attributed.
  const snapshot = await new DiscoveryEngine({
    adapters: [genericAdapter],
    evidenceFactory: () => new FixtureEvidenceProvider({
      processes: { status: "ok", value: [lookAlike("goosed", 4501), lookAlike("goose", 4502), lookAlike("copilot", 4503)] },
      executables: lookAlikeExecutables,
    }),
    clock: () => observedAt,
  }).discover("machine-fixture");
  const stoppable = snapshot.inventory.agents
    .filter((agent) => agent.capabilities.includes("process-instance"))
    .map((agent) => Number(agent.processId));
  assert.deepEqual(stoppable, [4501]);
  assert.ok(!snapshot.inventory.agents.some((agent) => agent.displayName.startsWith("GitHub Copilot CLI")));
  const goose = snapshot.detections.find((detection) => detection.displayName === "Goose · PID 4501");
  assert.match(goose?.notes.join(" ") ?? "", /1 other running program\(s\) with a name other programs also use were set aside/u);
  assert.ok(snapshot.inventory.notices.some((notice) => /Goose were not attributed to it: other programs use the same name/u.test(notice)));
  const copilot = snapshot.detections.find((detection) => detection.displayName === "GitHub Copilot CLI");
  assert.equal(copilot?.reported, false);
  assert.equal(copilot?.stoppable, false);
});

test("a q command or process never stands for Amazon Q; qchat, its configuration or data folder do", async () => {
  const qchat: ExecutableEvidence = { executableName: "qchat", executablePathDigest: "amazon-qchat-digest", version: "1.19.3" };
  const explain = async (executables: ReadonlyMap<string, ExecutableEvidence>, configurations = new Map<string, readonly ConfigurationEvidence[]>()) =>
    formatDetections((await new DiscoveryEngine({
      adapters: [genericAdapter],
      evidenceFactory: () => new FixtureEvidenceProvider({ processes: { status: "ok", value: [] }, executables, configurations }),
      clock: () => observedAt,
    }).discover("machine-fixture")).detections);
  const kdb = new Map([["q", lookAlikeExecutables.get("q")!]]);

  // kdb+'s q alone: nothing, not even a look at it.
  assert.equal(await explain(kdb), "Why each agent was detected:\n  Nothing was detected.\n");

  // Amazon Q's qchat beside kdb+'s q: Amazon Q, with qchat's own version.
  assert.equal(await explain(new Map([...kdb, ["qchat", qchat]])), [
    "Why each agent was detected:",
    "Amazon Q Developer CLI (adapter generic:amazon-q)",
    "  Confidence: medium. Can be stopped from Phigon: no.",
    '  Evidence: "qchat" command on PATH, version 1.19.3',
    "  Note: Installed; no process of its own is running.",
    "",
  ].join("\n"));

  // Amazon Q's data folder beside kdb+'s q: installed, without q's version.
  assert.equal(await explain(kdb, new Map([["~/.local/share/amazon-q", [{ identifierDigest: "amazon-q-data" }]]])), [
    "Why each agent was detected:",
    "Amazon Q Developer CLI (adapter generic:amazon-q)",
    "  Confidence: medium. Can be stopped from Phigon: no.",
    "  Evidence: ~/.local/share/amazon-q exists",
    "  Note: Installed; no process of its own is running.",
    "",
  ].join("\n"));
});

test("discover --explain says which evidence identified each agent and what was set aside", async () => {
  const snapshot = await new DiscoveryEngine({
    adapters: [claudeAdapter, hermesAdapter, genericAdapter],
    evidenceFactory: () => new FixtureEvidenceProvider({
      processes: { status: "ok", value: [lookAlike("claude", 5101), lookAlike("goose", 5102)] },
      executables: new Map([
        ["claude", { executableName: "claude", executablePathDigest: "claude-digest", version: "2.1.0" }],
        ["goose", lookAlikeExecutables.get("goose")!],
      ]),
      configurations: new Map([["~/.claude", [{ identifierDigest: "claude-config" }]]]),
    }),
    clock: () => observedAt,
  }).discover("machine-fixture");
  const text = formatDetections(snapshot.detections);
  assert.equal(text, [
    "Why each agent was detected:",
    "Claude Code · PID 5101 (adapter claude)",
    "  Confidence: high. Can be stopped from Phigon: yes, when this computer allows remote actions.",
    '  Evidence: running process "claude" (PID 5101); "claude" command on PATH, version 2.1.0; ~/.claude exists',
    "",
    "Set aside, not reported:",
    "Goose (adapter generic:goose)",
    '  Name only, not proof: running process "goose" (PID 5102); "goose" command on PATH, version v3.24.1',
    "  Note: Not reported: other programs use the same name, and nothing on this computer identifies one as Goose (its configuration was not found).",
    "",
  ].join("\n"));
  assert.equal(formatDetections([]), "Why each agent was detected:\n  Nothing was detected.\n");
});

test("discover --explain --json adds the detections to the inventory", async () => {
  const directory = await mkdtemp(join(tmpdir(), "phigon-discover-explain-"));
  try {
    let stdout = "";
    const code = await run(
      ["discover", "--explain", "--json"],
      { PHIGON_CONTROL_PLANE_URL: "https://control.example.test", PHIGON_DATA_DIR: directory, PATH: directory },
      { stdout: (value) => { stdout += value; }, stderr: () => undefined },
    );
    assert.equal(code, 0);
    const report = JSON.parse(stdout) as { inventory: unknown; detections: Array<{ reported: boolean; confidence: string; evidence: unknown[] }> };
    assert.ok(Array.isArray(report.detections));
    for (const detection of report.detections) {
      assert.ok(["high", "medium", "low"].includes(detection.confidence));
      assert.ok(Array.isArray(detection.evidence));
    }
    stdout = "";
    await run(["discover", "--json"], { PHIGON_CONTROL_PLANE_URL: "https://control.example.test", PHIGON_DATA_DIR: directory, PATH: directory }, { stdout: (value) => { stdout += value; }, stderr: () => undefined });
    assert.equal("detections" in (JSON.parse(stdout) as object), false);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

type FixtureOptions = Readonly<{
  processes: ProbeResult<readonly ProcessEvidence[]>;
  executables?: ReadonlyMap<string, ExecutableEvidence>;
  configurations?: ReadonlyMap<
    string,
    readonly ConfigurationEvidence[]
  >;
}>;

class FixtureEvidenceProvider implements HostEvidenceProvider {
  readonly #options: FixtureOptions;

  constructor(options: FixtureOptions) {
    this.#options = options;
  }

  async listProcesses(): Promise<
    ProbeResult<readonly ProcessEvidence[]>
  > {
    return this.#options.processes;
  }

  async inspectExecutable(
    candidates: readonly string[],
  ): Promise<ProbeResult<ExecutableEvidence | null>> {
    for (const candidate of candidates) {
      const executable = this.#options.executables?.get(candidate);
      if (executable !== undefined) {
        return { status: "ok", value: executable };
      }
    }
    return { status: "ok", value: null };
  }

  async inspectConfiguration(
    candidates: readonly string[],
  ): Promise<ProbeResult<readonly ConfigurationEvidence[]>> {
    return {
      status: "ok",
      value: candidates.flatMap(
        (candidate) => this.#options.configurations?.get(candidate) ?? [],
      ),
    };
  }
}
