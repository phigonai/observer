import assert from "node:assert/strict";
import { mkdtemp, rm, stat, writeFile } from "node:fs/promises";
import { homedir, tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { registeredAgentActivitySources } from "../src/activity/collector.js";
import {
  CustomAgentRegistry,
  customAgentRegistration,
} from "../src/custom-agent-registry.js";
import { customAgentAdapter } from "../src/discovery/adapters/custom.js";
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
    await assert.rejects(
      registry.list(),
      /executable name.*ambiguous between alpha and beta/u,
    );
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});
