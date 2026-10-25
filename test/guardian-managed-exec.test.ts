import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { createServer } from "node:http";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { setTimeout as delay } from "node:timers/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { executeManagedCommand } from "../src/guardian-managed-exec.js";
import { createExecutionManifest, executionEnvironment } from "../src/guardian-execution-manifest.js";

test("company runtime limit stops a managed workload and its child", { skip: process.platform === "linux", timeout: 15_000 }, async () => {
  const directory = await mkdtemp(join(tmpdir(), "phigon-runtime-limit-"));
  const marker = join(directory, "child.pid");
  let childPID: number | undefined;
  try {
    const environment = executionEnvironment(process.env);
    const arguments_ = ["-e", "const c=require('node:child_process').spawn(process.execPath,['-e','setInterval(()=>{},1000)'],{stdio:'ignore'});require('node:fs').writeFileSync(process.argv[1],String(c.pid));setInterval(()=>{},1000)", marker];
    const manifest = await createExecutionManifest({ executable: process.execPath, arguments: arguments_, agentId: "test", environment,
      sandbox: JSON.stringify([{ name: "Time budget", platform: process.platform === "win32" ? "windows" : "darwin", network: "inherit", limits: { max_runtime_seconds: 2 } }]) });
    const safety = AbortSignal.timeout(10_000);
    const result = await executeManagedCommand({ executable: manifest.executable, arguments: manifest.arguments, agentId: "test", sessionId: "runtime-limit", dataDirectory: directory, manifest, environment, signal: safety });
    assert.equal(safety.aborted, false);
    assert.equal(result.exitCode, 77);
    childPID = Number(await readFile(marker, "utf8"));
    assert.ok(childPID > 0);
    let alive = true;
    for (let attempt = 0; attempt < 30; attempt++) {
      try { process.kill(childPID, 0); } catch { alive = false; break; }
      await delay(100);
    }
    assert.equal(alive, false, "runtime expiry must stop descendants");
  } finally {
    if (childPID !== undefined) { try { process.kill(childPID, "SIGKILL"); } catch { /* already contained */ } }
    await rm(directory, { recursive: true, force: true });
  }
});

test("native lease revocation stops the process tree without an observer stop signal", { timeout: 30_000 }, async () => {
  const directory = await mkdtemp(join(tmpdir(), "phigon-native-lease-"));
  const marker = join(directory, "child.pid");
  const script = join(directory, "worker.cjs");
  let childPID: number | undefined;
  let calls = 0;
  const credential = `phg_m_${"x".repeat(43)}`;
  const policy = "a".repeat(64);
  let digest = "";
  const server = createServer((request, response) => {
    assert.equal(request.url, "/v1/machine/guardian/executions/renew");
    assert.equal(request.headers.authorization, `Bearer ${credential}`);
    request.resume(); calls++;
    response.setHeader("Content-Type", "application/json");
    if (calls > 1) { response.statusCode = 409; response.end("{}"); return; }
    response.end(JSON.stringify({ authorized: true, manifest_digest: digest, policy_digest: policy, lease_seconds: 30 }));
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  try {
    const address = server.address(); assert.ok(address && typeof address === "object");
    await writeFile(script, `const fs=require('node:fs'),path=require('node:path');if(fs.readdirSync(path.dirname(process.argv[2])).some(x=>x.startsWith('guardian-lease-')))throw Error('bootstrap exposed');const c=require('node:child_process').spawn(process.execPath,['-e','setInterval(()=>{},1000)'],{stdio:'ignore'});fs.writeFileSync(process.argv[2],String(c.pid));setInterval(()=>{},1000);`);
    const environment = executionEnvironment(process.env);
    const manifest = await createExecutionManifest({ executable: process.execPath, arguments: [script, marker], agentId: "test", environment });
    const serialized = JSON.stringify(manifest);
    digest = createHash("sha256").update(serialized).digest("hex");
    const safety = AbortSignal.timeout(25_000);
    const result = await executeManagedCommand({ executable: manifest.executable, arguments: manifest.arguments, agentId: "test", sessionId: "native-lease", dataDirectory: directory, manifest, environment, signal: safety,
      lease: { origin: `http://127.0.0.1:${address.port}`, credential, request: { manifest: serialized, policy_digest: policy, token: "b".repeat(64) } } });
    assert.equal(safety.aborted, false, "native supervisor must act before the test cleanup deadline");
    assert.equal(result.exitCode, 77);
    assert.equal(calls, 2, "native runner must renew independently after its initial check");
    childPID = Number(await readFile(marker, "utf8"));
    assert.ok(childPID > 0);
    let alive = true;
    for (let attempt = 0; attempt < 50; attempt++) {
      try { process.kill(childPID, 0); } catch { alive = false; break; }
      if (process.platform === "linux") {
        try { if (/\) Z /u.test(await readFile(`/proc/${childPID}/stat`, "utf8"))) { alive = false; break; } } catch { alive = false; break; }
      }
      await delay(100);
    }
    assert.equal(alive, false, "native revocation must contain descendants");
    const journal = await readFile(join(directory, "bridges", "generic", "guardian-managed-commands.jsonl"), "utf8");
    assert.ok(!journal.includes(credential), "machine credentials must not enter activity telemetry");
  } finally {
    server.closeAllConnections(); await new Promise<void>((resolve) => server.close(() => resolve()));
    if (childPID !== undefined) { try { process.kill(childPID, "SIGKILL"); } catch { /* already contained */ } }
    await rm(directory, { recursive: true, force: true });
  }
});

test("managed command executes directly and journals input, output, and exit", async () => {
  const directory = await mkdtemp(join(tmpdir(), "phigon-managed-exec-"));
  try {
    const environment = executionEnvironment(process.env);
    const manifest = await createExecutionManifest({ executable: process.execPath, arguments: ["-e", "process.stdout.write('managed-output')"], agentId: "codex:test", environment });
    const result = await executeManagedCommand({
      executable: process.execPath,
      arguments: ["-e", "process.stdout.write('managed-output')"],
      agentId: "codex:test",
      sessionId: "task:test",
      dataDirectory: directory,
      manifest, environment,
    });
    assert.equal(result.exitCode, 0);
    const lines = (await readFile(
      join(directory, "bridges", "generic", "guardian-managed-commands.jsonl"),
      "utf8",
    )).trim().split("\n").map((line) => JSON.parse(line) as Record<string, unknown>);
    assert.equal(lines[0]?.["phase"], "requested");
    assert.equal(lines.at(-1)?.["phase"], "succeeded");
    assert.ok(lines.some((line) => line["output"] === "managed-output"));
    assert.ok(lines.every((line) => line["invocation_id"] === result.invocationId));
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("an expired authorization never starts a managed executable", async () => {
  const directory = await mkdtemp(join(tmpdir(), "phigon-expired-exec-"));
  const marker = join(directory, "unexpected.txt");
  try {
    const environment = executionEnvironment(process.env);
    const manifest = await createExecutionManifest({ executable: process.execPath, arguments: ["-e", "require('fs').writeFileSync(process.argv[1], 'started')", marker], agentId: "test", environment });
    await assert.rejects(executeManagedCommand({ executable: manifest.executable, arguments: manifest.arguments, agentId: "test", sessionId: "expired", dataDirectory: directory, manifest, environment, signal: AbortSignal.abort() }), /authorization expired/u);
    await assert.rejects(readFile(marker), { code: "ENOENT" });
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("revoking a managed lifetime stops the agent and its child processes", { timeout: 30_000 }, async () => {
  const directory = await mkdtemp(join(tmpdir(), "phigon-contained-tree-"));
  const marker = join(directory, "child.pid");
  const script = join(directory, "agent.cjs");
  const controller = new AbortController();
  let childPID: number | undefined;
  try {
    await writeFile(script, `const {spawn}=require('node:child_process');const fs=require('node:fs');const c=spawn(process.execPath,['-e','setInterval(()=>{},1000)'],{stdio:'ignore'});fs.writeFileSync(process.argv[2],String(c.pid));setInterval(()=>{},1000);`);
    const environment = executionEnvironment(process.env);
    const manifest = await createExecutionManifest({ executable: process.execPath, arguments: [script, marker], agentId: "test", environment });
    const execution = executeManagedCommand({ executable: manifest.executable, arguments: manifest.arguments, agentId: "test", sessionId: "tree", dataDirectory: directory, manifest, environment, signal: controller.signal });
    let completed = false; void execution.finally(() => { completed = true; });
    for (let attempt = 0; attempt < 150; attempt++) {
      try { childPID = Number(await readFile(marker, "utf8")); break; } catch { if (completed) break; await delay(100); }
    }
    controller.abort();
    const result = await execution;
    assert.ok(childPID !== undefined && childPID > 0, "managed agent must start inside containment");
    assert.equal(result.exitCode, 77);
    let alive = true;
    for (let attempt = 0; attempt < 50; attempt++) {
      try { process.kill(childPID, 0); } catch { alive = false; break; }
      if (process.platform === "linux") {
        try { if (/\) Z /u.test(await readFile(`/proc/${childPID}/stat`, "utf8"))) { alive = false; break; } } catch { alive = false; break; }
      }
      await delay(100);
    }
    assert.equal(alive, false, "child process must not survive lifetime revocation");
  } finally {
    controller.abort(); if (childPID !== undefined) { try { process.kill(childPID, "SIGKILL"); } catch { /* already contained */ } }
    await rm(directory, { recursive: true, force: true });
  }
});
