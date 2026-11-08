import assert from "node:assert/strict";
import { mkdtemp, rm, stat, writeFile } from "node:fs/promises";
import { homedir, tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { registeredAgentActivitySources } from "../src/activity/collector.js";
import { run } from "../src/cli.js";
import {
  CustomAgentRegistry,
  customAgentRegistration,
} from "../src/custom-agent-registry.js";
import { claudeAdapter } from "../src/discovery/adapters/claude.js";
import { customAgentAdapter, customAgentProblemNotice } from "../src/discovery/adapters/custom.js";
import { DiscoveryEngine } from "../src/discovery/engine.js";
import type { HostEvidenceProvider } from "../src/discovery/evidence.js";
import { AgentState } from "../src/generated/phigon/v1/common_pb.js";

test("custom agent definitions drive discovery and activity sources dynamically", async () => {
  const directory = await mkdtemp(join(tmpdir(), "phigon-custom-agents-"));
  try {
    const registry = new CustomAgentRegistry(directory);
    const registered = await registry.add(customAgentRegistration({
      id: "release-bot",
      displayName: "Release Bot",
      executableNames: ["release-bot"],
      processNames: ["release-bot-worker"],
      configurationPaths: ["~/.release-bot"],
      activityDirectories: ["~/.release-bot/sessions"],
      capabilities: ["activity", "filesystem", "git", "terminal"],
    }));
    assert.equal(registered.id, "release-bot");
    assert.deepEqual(await registry.list(), [registered]);
    assert.deepEqual(registeredAgentActivitySources(await registry.list()), [{
      adapterId: "generic",
      roots: ["~/.release-bot/sessions"],
      sourceDisplayName: "Release Bot",
    }]);

    const evidence: HostEvidenceProvider = {
      listProcesses: async () => ({
        status: "ok",
        value: [{
          processKey: "release-bot-process-lifetime",
          processId: 7331,
          startedAt: new Date("2026-08-09T00:00:00.000Z"),
          executableName: "release-bot-worker",
          executablePathDigest: "a".repeat(64),
        }],
      }),
      inspectExecutable: async (candidates) => ({
        status: "ok",
        value: candidates.includes("release-bot")
          ? {
              executableName: "release-bot",
              executablePathDigest: "b".repeat(64),
              version: "2.4.0",
            }
          : null,
      }),
      inspectConfiguration: async () => ({ status: "ok", value: [] }),
    };
    const adapter = customAgentAdapter(registry);
    const discovered = await adapter.discover(
      evidence,
      new Date("2026-08-09T00:01:00.000Z"),
    );
    assert.equal(discovered.agents.length, 1);
    assert.match(discovered.agents[0]?.displayName ?? "", /^Release Bot · PID /u);
    assert.equal(discovered.agents[0]?.state, AgentState.RUNNING);
    assert.ok(discovered.agents[0]?.capabilities.includes("git"));

    assert.equal((await registry.remove("release-bot"))?.id, "release-bot");
    assert.deepEqual(await registry.list(), []);
    const afterRemoval = await adapter.discover(
      evidence,
      new Date("2026-08-09T00:02:00.000Z"),
    );
    assert.deepEqual(afterRemoval.agents, []);
    assert.deepEqual(registeredAgentActivitySources(await registry.list()), []);

    if (process.platform !== "win32") {
      const registryFile = await stat(join(directory, "custom-agents.json"));
      assert.equal(registryFile.mode & 0o777, 0o600);
    }
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("custom agent definitions reject unsafe or signal-free monitoring", () => {
  assert.throws(
    () => customAgentRegistration({ id: "release-bot", displayName: "Release Bot" }),
    /at least one executable, process, configuration path, or activity directory/u,
  );
  assert.throws(
    () => customAgentRegistration({
      id: "Release Bot",
      displayName: "Release Bot",
      processNames: ["release-bot"],
    }),
    /lowercase letters/u,
  );
  assert.throws(
    () => customAgentRegistration({
      id: "release-bot",
      displayName: "Release Bot",
      activityDirectories: ["bad\npath"],
    }),
    /activity directory is invalid/u,
  );
  assert.throws(
    () => customAgentRegistration({
      id: "release-bot",
      displayName: "Release Bot",
      activityDirectories: ["relative/sessions"],
    }),
    /must be absolute or begin with ~\//u,
  );
  assert.throws(
    () => customAgentRegistration({
      id: "release-bot",
      displayName: "Release Bot",
      activityDirectories: ["~"],
    }),
    /must be scoped below/u,
  );
  assert.throws(
    () => customAgentRegistration({
      id: "release-bot",
      displayName: "Release Bot",
      processNames: ["release-bot"],
      capabilities: ["activity", "process-instance"],
    }),
    /cannot claim Phigon-managed identity or evidence properties/u,
  );
  assert.throws(
    () => customAgentRegistration({
      id: "release-bot",
      displayName: "Release Bot",
      processNames: ["release-bot"],
      capabilities: ["agent-product:codex"],
    }),
    /cannot claim Phigon-managed identity or evidence properties/u,
  );
  // Only Guardian's own decision journal is Phigon's; an agent cannot hide as it.
  assert.throws(
    () => customAgentRegistration({
      id: "release-bot",
      displayName: "Release Bot",
      processNames: ["release-bot"],
      capabilities: ["activity", "phigon-guardian"],
    }),
    /cannot claim Phigon-managed identity or evidence properties/u,
  );
});

test("custom agent definitions reject ambiguous evidence claims", async () => {
  const directory = await mkdtemp(join(tmpdir(), "phigon-custom-conflict-"));
  try {
    const registry = new CustomAgentRegistry(directory);
    await registry.add(customAgentRegistration({
      id: "release-bot",
      displayName: "Release Bot",
      executableNames: ["release-bot"],
      processNames: ["release-worker"],
      configurationPaths: ["~/.release-bot/config.json"],
      activityDirectories: ["~/.release-bot/sessions"],
    }));
    await assert.rejects(
      registry.add(customAgentRegistration({
        id: "deploy-bot",
        displayName: "Deploy Bot",
        processNames: ["RELEASE-WORKER.exe"],
      })),
      /process name.*ambiguous between release-bot and deploy-bot/u,
    );
    await assert.rejects(
      registry.add(customAgentRegistration({
        id: "deploy-bot",
        displayName: "Deploy Bot",
        activityDirectories: ["~/.release-bot/sessions/deploy"],
      })),
      /activity directory.*ambiguous between release-bot and deploy-bot/u,
    );
    await assert.rejects(
      registry.add(customAgentRegistration({
        id: "deploy-bot",
        displayName: "Deploy Bot",
        configurationPaths: [join(homedir(), ".release-bot", "config.json")],
      })),
      /configuration path.*ambiguous between release-bot and deploy-bot/u,
    );

    await writeFile(
      join(directory, "custom-agents.json"),
      JSON.stringify({
        version: 1,
        agents: [
          customAgentRegistration({
            id: "alpha",
            displayName: "Alpha",
            executableNames: ["shared-agent"],
          }),
          customAgentRegistration({
            id: "beta",
            displayName: "Beta",
            executableNames: ["SHARED-AGENT"],
          }),
        ],
      }),
      "utf8",
    );
    // A hand-edited conflict skips the later definition, not discovery.
    const read = await registry.read();
    assert.deepEqual(read.agents.map((agent) => agent.id), ["alpha"]);
    assert.match(read.problem ?? "", /1 of 2 custom agent definitions .* were skipped \(Custom agent executable name "SHARED-AGENT" is ambiguous between alpha and beta/u);
    await assert.rejects(
      registry.add(customAgentRegistration({ id: "gamma", displayName: "Gamma", processNames: ["gamma"] })),
      /is damaged \(Custom agent executable name.*ambiguous between alpha and beta.*\), so it was not changed/u,
    );
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("a damaged custom agent file is skipped with one warning and never stops discovery", async () => {
  const directory = await mkdtemp(join(tmpdir(), "phigon-custom-damaged-"));
  const path = join(directory, "custom-agents.json");
  const warnings: string[] = [];
  const registry = new CustomAgentRegistry(directory, { onProblem: (message) => warnings.push(message) });
  const evidence: HostEvidenceProvider = {
    listProcesses: async () => ({
      status: "ok",
      value: [{
        processKey: "process-claude-101-start-a",
        processId: 101,
        startedAt: new Date("2026-07-24T09:00:00.000Z"),
        executableName: "claude",
        executablePathDigest: "claude-digest",
      }, {
        processKey: "process-release-202-start-a",
        processId: 202,
        startedAt: new Date("2026-07-24T09:00:00.000Z"),
        executableName: "release-bot-worker",
        executablePathDigest: "release-digest",
      }],
    }),
    inspectExecutable: async () => ({ status: "ok", value: null }),
    inspectConfiguration: async () => ({ status: "ok", value: [] }),
  };
  const discover = () => new DiscoveryEngine({
    adapters: [claudeAdapter, customAgentAdapter(registry)],
    evidenceFactory: () => evidence,
    clock: () => new Date("2026-07-24T10:00:00.000Z"),
  }).discover("machine-fixture");
  try {
    // Cut off half-way through a write.
    await writeFile(path, '{"version":1,"agents":[{"id":"release-bot","displayName":"Rel', "utf8");
    for (let scan = 0; scan < 3; scan++) {
      const snapshot = await discover();
      assert.ok(snapshot.inventory.agents.some((agent) => agent.displayName.startsWith("Claude Code · PID 101")));
      assert.ok(!snapshot.inventory.agents.some((agent) => agent.displayName.startsWith("Release Bot")));
      assert.equal(snapshot.inventory.partial, true);
      assert.ok(snapshot.inventory.notices.includes(customAgentProblemNotice));
      // The notice sent to Phigon names no local path.
      assert.ok(!snapshot.inventory.notices.some((notice) => notice.includes(directory)));
    }
    assert.equal(warnings.length, 1, "warned once, not on every scan");
    assert.match(warnings[0] ?? "", /custom-agents\.json is damaged \(Custom agent registry is not valid JSON\), so custom agents are not discovered until it is fixed\. Built-in agents are still discovered\./u);
    await assert.rejects(
      registry.remove("release-bot"),
      /is damaged \(Custom agent registry is not valid JSON\), so it was not changed/u,
    );

    // One bad definition among good ones: only it is skipped.
    await writeFile(path, JSON.stringify({
      version: 1,
      agents: [
        customAgentRegistration({ id: "release-bot", displayName: "Release Bot", processNames: ["release-bot-worker"] }),
        { id: "Not An ID", displayName: "Broken", processNames: ["broken"] },
      ],
    }), "utf8");
    const partly = await discover();
    assert.ok(partly.inventory.agents.some((agent) => agent.displayName.startsWith("Release Bot · PID 202")));
    assert.equal(warnings.length, 2);
    assert.match(warnings[1] ?? "", /1 of 2 custom agent definitions .* were skipped \(Custom agent ID must use/u);

    // Fixed: no warning, complete coverage. Damaged again: warned again.
    await rm(path);
    assert.equal((await discover()).inventory.partial, false);
    await writeFile(path, "not json", "utf8");
    await discover();
    assert.equal(warnings.length, 3);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("doctor names a damaged custom agent file", async () => {
  const directory = await mkdtemp(join(tmpdir(), "phigon-custom-doctor-"));
  try {
    await writeFile(join(directory, "custom-agents.json"), "{", "utf8");
    const environment = { PHIGON_CONTROL_PLANE_URL: "https://control.example.test", PHIGON_DATA_DIR: directory };
    let stdout = "";
    assert.equal(await run(["doctor", "--json"], environment, { stdout: (value) => { stdout += value; }, stderr: () => undefined }), 0);
    const report = JSON.parse(stdout) as { customAgents: { definitions: number; problem?: string } };
    assert.equal(report.customAgents.definitions, 0);
    assert.match(report.customAgents.problem ?? "", /is damaged \(Custom agent registry is not valid JSON\)/u);

    stdout = "";
    assert.equal(await run(["doctor"], environment, { stdout: (value) => { stdout += value; }, stderr: () => undefined }), 0);
    assert.match(stdout, /^Custom agents: The custom agent file .* is damaged/mu);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("an adapter that fails is skipped and the others still discover", async () => {
  const snapshot = await new DiscoveryEngine({
    adapters: [
      { id: "broken", discover: () => Promise.reject(new Error("boom")) },
      claudeAdapter,
    ],
    evidenceFactory: () => ({
      listProcesses: async () => ({ status: "ok", value: [] }),
      inspectExecutable: async () => ({ status: "ok", value: null }),
      inspectConfiguration: async (candidates) => ({
        status: "ok",
        value: candidates.includes("~/.claude") ? [{ identifierDigest: "claude-config" }] : [],
      }),
    }),
  }).discover();
  assert.ok(snapshot.inventory.agents.some((agent) => agent.displayName === "Claude Code"));
  assert.equal(snapshot.inventory.partial, true);
  assert.ok(snapshot.adapterHealth.some((health) => health.adapterId === "broken" && health.status === "error"));
});
