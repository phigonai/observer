import assert from "node:assert/strict";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
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
import { DiscoveryEngine } from "../src/discovery/engine.js";
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
    assert.equal((await inspect("phigon-probe"))?.version, "1.2.3");
    assert.equal(await launches(), 1);

    await install("phigon-probe", "1.2.40");
    assert.equal((await inspect("phigon-probe"))?.version, "1.2.40");
    assert.equal(await launches(), 2);

    now += 5 * 60_000;
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
      ["~/.hermes", [{ identifierDigest: "hermes-config-digest" }]],
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
