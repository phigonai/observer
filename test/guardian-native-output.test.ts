import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { once } from "node:events";
import { mkdtemp, readFile, rm, stat, writeFile } from "node:fs/promises";
import { createServer, type ServerResponse } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { setTimeout as delay } from "node:timers/promises";
import { guardianRunnerPath } from "../src/guardian-native.js";
import { createExecutionManifest, executionEnvironment } from "../src/guardian-execution-manifest.js";

test("Windows runtime enforcement cannot be stalled by an unread stderr pipe", { skip: process.platform !== "win32", timeout: 15_000 }, async () => {
  const directory = await mkdtemp(join(tmpdir(), "phigon-blocked-stderr-"));
  const marker = join(directory, "child.pid");
  const environment = executionEnvironment(process.env);
  const manifest = await createExecutionManifest({ executable: process.execPath, cwd: directory, agentId: "test", environment,
    arguments: ["-e", "const fs=require('node:fs');const c=require('node:child_process').spawn(process.execPath,['-e','setInterval(()=>{},1000)'],{stdio:'ignore'});fs.writeFileSync(process.argv[1],String(c.pid));const b=Buffer.alloc(65536,120);while(true)fs.writeSync(2,b)", marker],
    sandbox: JSON.stringify([{ name: "Runtime deadline", platform: "windows", network: "inherit", limits: { max_runtime_seconds: 2 } }]) });
  const child = spawn(guardianRunnerPath(), ["--sha256", manifest.executable_digest, "--cwd", directory, "--sandbox", manifest.sandbox, "--", manifest.executable, ...manifest.arguments], { env: environment, windowsHide: true, stdio: ["ignore", "ignore", "pipe"] });
  let childPID: number | undefined;
  const exited = new Promise<number | null>((resolve, reject) => { child.once("exit", resolve); child.once("error", reject); });
  try {
    const timeout = AbortSignal.timeout(6_000);
    const result = await Promise.race([exited, new Promise<"timeout">((resolve) => timeout.addEventListener("abort", () => resolve("timeout"), { once: true }))]);
    childPID = Number(await readFile(marker, "utf8"));
    assert.ok(childPID > 0);
    assert.equal(result, 77, "full output buffers must not delay native termination");
    let alive = true;
    for (let attempt = 0; attempt < 30; attempt++) {
      try { process.kill(childPID, 0); } catch { alive = false; break; }
      await delay(50);
    }
    assert.equal(alive, false, "deadline must also terminate descendants");
  } finally {
    child.kill("SIGKILL"); child.stderr?.resume();
    await exited;
    if (childPID !== undefined) { try { process.kill(childPID, "SIGKILL"); } catch { /* already contained */ } }
    await rm(directory, { recursive: true, force: true });
  }
});

test("managed output stays bounded when the terminal stops reading", { skip: process.platform !== "win32", timeout: 15_000 }, async (t) => {
  const directory = await mkdtemp(join(tmpdir(), "phigon-output-backpressure-"));
  const resultPath = join(directory, "result.json");
  const script = join(directory, "observer.mjs");
  const dataDirectory = join(directory, "data");
  await writeFile(script, [
    `import {executeManagedCommand} from ${JSON.stringify(new URL("../src/guardian-managed-exec.js", import.meta.url).href)};`,
    `import {createExecutionManifest,executionEnvironment} from ${JSON.stringify(new URL("../src/guardian-execution-manifest.js", import.meta.url).href)};`,
    "import {writeFileSync} from 'node:fs';",
    "import cp from 'node:child_process';import {syncBuiltinESMExports} from 'node:module';const original=cp.spawn,children=[];cp.spawn=(...args)=>{const child=original(...args);children.push(child.pid);return child;};syncBuiltinESMExports();",
    "const environment=executionEnvironment(process.env);",
    `const options=${JSON.stringify({ executable: process.execPath, cwd: directory, agentId: "test", arguments: ["-e", "const fs=require('node:fs'),b=Buffer.alloc(8192,120);while(true)fs.writeSync(1,b)"], sandbox: JSON.stringify([{ name: "Budget", platform: "windows", network: "inherit", limits: { max_runtime_seconds: 2 } }]) })};`,
    "const manifest=await createExecutionManifest({...options,environment});",
    `const result=await executeManagedCommand({executable:manifest.executable,arguments:manifest.arguments,agentId:'test',sessionId:'output-budget',dataDirectory:${JSON.stringify(dataDirectory)},manifest,environment});`,
    `writeFileSync(${JSON.stringify(resultPath)},JSON.stringify({...result,buffered:process.stdout.writableLength,children}));process.exit(0);`,
  ].join("\n"));
  const observer = spawn(process.execPath, [script], { windowsHide: true, stdio: ["ignore", "pipe", "ignore"] });
  const exited = once(observer, "exit", { signal: t.signal });
  t.after(async () => { observer.kill("SIGKILL"); observer.stdout?.resume(); await exited.catch(() => {}); await rm(directory, { recursive: true, force: true }); });
  const [code] = await exited; assert.equal(code, 0);
  const result = JSON.parse(await readFile(resultPath, "utf8")) as { exitCode: number; buffered: number; children: number[] };
  assert.equal(result.exitCode, 77);
  assert.ok(result.buffered <= 128 << 10, `terminal buffered ${result.buffered} bytes`);
  assert.ok((await stat(join(dataDirectory, "bridges", "generic", "guardian-managed-commands.jsonl"))).size <= 2 << 20, "blocked terminal must backpressure the workload and journal queue");
  assert.ok(result.children.length >= 2);
  for (const pid of result.children) assert.throws(() => process.kill(pid, 0), "output relay or native supervisor survived cleanup");
});

test("native runner refuses launch if its observer exits during authorization", { timeout: 15_000 }, async (t) => {
  const directory = await mkdtemp(join(tmpdir(), "phigon-parent-lifetime-"));
  const marker = join(directory, "unexpected-launch");
  const environment = executionEnvironment(process.env);
  const manifest = await createExecutionManifest({ executable: process.execPath, cwd: directory, agentId: "test", environment,
    arguments: ["-e", "require('node:fs').writeFileSync(process.argv[1],'started')", marker] });
  const serialized = JSON.stringify(manifest);
  const digest = createHash("sha256").update(serialized).digest("hex");
  let pending: ServerResponse | undefined;
  let onReview = () => {};
  const reviewing = new Promise<void>((resolve) => { onReview = resolve; });
  const server = createServer((request, response) => { request.resume(); pending = response; onReview(); });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address(); assert.ok(address && typeof address === "object");
  const bootstrap = join(directory, "lease.json");
  await writeFile(bootstrap, JSON.stringify({ origin: `http://127.0.0.1:${address.port}`, credential: "test-credential-for-native-parent", request: { policy_digest: "a".repeat(64), token: "b".repeat(64), manifest: serialized } }), { mode: 0o600 });
  const script = join(directory, "observer.cjs");
  await writeFile(script, "const c=require('node:child_process').spawn(process.argv[2],process.argv.slice(3),{stdio:'ignore',windowsHide:true});c.on('error',()=>process.exit(1));process.send(c.pid);setInterval(()=>{},1000)");
  const observer = spawn(process.execPath, [script, guardianRunnerPath(), "--sha256", manifest.executable_digest, "--cwd", manifest.working_directory, "--lease-config", bootstrap, "--", manifest.executable, ...manifest.arguments], { env: environment, windowsHide: true, stdio: ["ignore", "ignore", "ignore", "ipc"] });
  const observerExited = once(observer, "exit");
  let nativePID: number | undefined = undefined;
  let nativeStopped = false;
  t.after(async () => {
    observer.kill("SIGKILL"); await observerExited;
    server.closeAllConnections(); await new Promise<void>((resolve) => server.close(() => resolve()));
    if (nativePID !== undefined && !nativeStopped) { try { process.kill(nativePID, "SIGKILL"); } catch { /* already exited */ } }
    await rm(directory, { recursive: true, force: true });
  });
  const [pid] = await once(observer, "message", { signal: t.signal });
  assert.equal(typeof pid, "number"); nativePID = pid as number;
  await reviewing;
  observer.kill("SIGKILL"); await observerExited;
  assert.ok(pending);
  pending.end(JSON.stringify({ authorized: true, manifest_digest: digest, policy_digest: "a".repeat(64), lease_seconds: 30 }));
  for (let attempt = 0; attempt < 50; attempt++) {
    try { process.kill(nativePID, 0); } catch { nativeStopped = true; break; }
    if (process.platform === "linux") {
      try { if (/\) Z /u.test(await readFile(`/proc/${nativePID}/stat`, "utf8"))) { nativeStopped = true; break; } } catch { nativeStopped = true; break; }
    }
    await delay(50);
  }
  assert.equal(nativeStopped, true, "native runner must exit after the original observer disappears");
  await assert.rejects(readFile(marker), { code: "ENOENT" });
});
