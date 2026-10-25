import assert from "node:assert/strict";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { createExecutionManifest, executionEnvironment, verifyExecutionManifest } from "../src/guardian-execution-manifest.js";

test("execution review binds file content, arguments, cwd, and environment", async () => {
  const directory = await mkdtemp(join(tmpdir(), "guardian-manifest-"));
  try {
    const script = join(directory, "agent.js"); await writeFile(script, "process.exit(0)");
    const environment = executionEnvironment(process.env);
    const manifest = await createExecutionManifest({ executable: process.execPath, arguments: [script], agentId: "test", environment, cwd: directory });
    await verifyExecutionManifest(manifest, environment);
    await assert.rejects(verifyExecutionManifest(manifest, { ...environment, GUARDIAN_TEST_VALUE: "changed" }), /changed after review/u);
    await writeFile(script, "process.exit(9)");
    await assert.rejects(verifyExecutionManifest(manifest, environment), /changed after review/u);
  } finally { await rm(directory, { recursive: true, force: true }); }
});

test("workload environment strips management secrets and interpreter injection", () => {
  const environment = executionEnvironment({ PHIGON_MACHINE_TOKEN: "secret", phigon_data_dir: "private", NODE_OPTIONS: "--require attacker", LD_PRELOAD: "attacker", PATH: "safe", NORMAL: "kept" });
  assert.deepEqual(environment, { NORMAL: "kept", PATH: "safe" });
});
