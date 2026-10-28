import assert from "node:assert/strict";
import test from "node:test";
import { randomUUID } from "node:crypto";
import { mkdtemp, mkdir, readFile, writeFile, rm, utimes, readdir, rename } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve, sep } from "node:path";
import { create } from "@bufbuild/protobuf";
import { timestampFromDate } from "@bufbuild/protobuf/wkt";
import { AgentActionCommandSchema, RemoteActionType as Action, RemoteActionResultState as State } from "../src/generated/phigon/v1/action_pb.js";
import { MachineCommandExecutor, parseCommand, powerCommand, redactCommandOutput, runCommand, pruneCommandReceipts } from "../src/machine-command-executor.js";

test("receipt cleanup removes only expired recognized records and preserves unrelated files", async (t) => {
  const directory = await mkdtemp(join(tmpdir(), "phigon-receipt-retention-"));
  t.after(async () => { if (!resolve(directory).startsWith(resolve(tmpdir()) + sep)) throw new Error("Unsafe test cleanup path"); await rm(directory, { recursive: true, force: true }); });
  const old = `${randomUUID()}.json`, claim = `${randomUUID()}.claim`, current = `${randomUUID()}.json`;
  const oldAt = new Date(Date.now() - 31 * 86_400_000);
  for (const name of [old, claim, current, "keep.txt"]) {
    await writeFile(join(directory, name), "synthetic");
    if (name !== current) await utimes(join(directory, name), oldAt, oldAt);
  }
  await pruneCommandReceipts(directory);
  assert.deepEqual((await readdir(directory)).sort(), [current, "keep.txt"].sort());
});

test("remote command enrollment, exact request binding, and durable replay", async (t) => {
  const directory = await mkdtemp(join(tmpdir(), "phigon-command-test-"));
  t.after(async () => { if (!resolve(directory).startsWith(resolve(tmpdir()) + sep)) throw new Error("Unsafe test cleanup path"); await rm(directory, { recursive: true, force: true }); });
  const machineID = randomUUID(); const marker = join(directory, "count.txt");
  const command = create(AgentActionCommandSchema, { actionId: randomUUID(), idempotencyKey: randomUUID(), machineId: machineID, agentId: "__machine__", processId: 0n, action: Action.RUN_COMMAND, expiresAt: timestampFromDate(new Date(Date.now() + 60_000)), reason: "Test harmless command", commandJson: JSON.stringify({ executable: process.execPath, arguments: ["-e", "require('node:fs').appendFileSync(process.argv[1], 'x'); console.log('verified: 42')", marker], timeout_seconds: 5 }) });
  const disabled = new MachineCommandExecutor({ enabled: false, machineID, dataDirectory: directory });
  assert.equal((await disabled.execute(command)).state, State.REJECTED);
  const executor = new MachineCommandExecutor({ enabled: true, machineID, dataDirectory: directory });
  const [first, repeated] = await Promise.all([executor.execute(command), executor.execute(command)]);
  assert.equal(first.state, State.SUCCEEDED); assert.equal(first.exitCode, 0); assert.match(first.output, /verified: 42/u);
  assert.deepEqual(repeated, first); assert.equal(await readFile(marker, "utf8"), "x");
  const restarted = new MachineCommandExecutor({ enabled: true, machineID, dataDirectory: directory });
  assert.deepEqual(await restarted.execute(command), first);
  const conflict = await restarted.execute({ ...command, commandJson: command.commandJson.replace("verified: 42", "changed") });
  assert.equal(conflict.resultCode, "idempotency_conflict");
  assert.equal(await readFile(marker, "utf8"), "x");
  assert.equal((await restarted.execute({ ...command, machineId: randomUUID() })).resultCode, "invalid_command");
  assert.equal((await restarted.execute({ ...command, actionId: randomUUID(), idempotencyKey: randomUUID(), expiresAt: timestampFromDate(new Date(0)) })).state, State.EXPIRED);
});

test("output is readable, bounded, and redacted; stdin closes and nonzero exits remain failures", async () => {
  const result = await runCommand({ executable: process.execPath, arguments: ["-e", "console.log('password=syntheticsecret123'); process.stdout.write('a'.repeat(40000)); process.exitCode=7"], timeout_seconds: 5 });
  assert.equal(result.exitCode, 7); assert.equal(result.truncated, true);
  assert.ok(Buffer.byteLength(result.output) <= 32768); assert.doesNotMatch(result.output, /syntheticsecret123/u); assert.match(result.output, /REDACTED/u);
  const stdin = await runCommand({ executable: process.execPath, arguments: ["-e", "process.stdin.resume(); process.stdin.on('end',()=>console.log('stdin closed'))"], timeout_seconds: 5 });
  assert.match(stdin.output, /stdin closed/u);
});

test("unreadable command journal returns a failure receipt without disconnecting telemetry", async () => {
  const directory = await mkdtemp(join(tmpdir(), "phigon-command-corrupt-"));
  const machineID = randomUUID();
  const command = create(AgentActionCommandSchema, { actionId: randomUUID(), idempotencyKey: randomUUID(), machineId: machineID,
    agentId: "__machine__", processId: 0n, action: Action.INSPECT_SYSTEM, expiresAt: timestampFromDate(new Date(Date.now() + 60000)) });
  await mkdir(join(directory, "machine-operation-receipts"));
  await writeFile(join(directory, "machine-operation-receipts", `${command.idempotencyKey}.json`), "corrupt");
  const executor = new MachineCommandExecutor({ enabled: true, machineID, dataDirectory: directory });
  const failed = await executor.execute(command);
  assert.equal(failed.state, State.FAILED); assert.equal(failed.resultCode, "execution_journal_unavailable");
  assert.equal((await executor.execute({ ...command, actionId: randomUUID(), idempotencyKey: randomUUID() })).state, State.SUCCEEDED);
});

test("long-running commands time out; malformed requests never become shell text", async () => {
  const started = Date.now();
  const result = await runCommand({ executable: process.execPath, arguments: ["-e", "setInterval(()=>{},1000)"], timeout_seconds: 1 });
  assert.equal(result.timedOut, true); assert.ok(Date.now() - started < 6000);
  assert.equal(parseCommand(JSON.stringify({ executable: "node", arguments: "-e anything", timeout_seconds: 5 })), null);
  assert.equal(parseCommand(JSON.stringify({ executable: "node", arguments: ["\0"], timeout_seconds: 5 })), null);
  assert.equal(parseCommand(JSON.stringify({ executable: "node", arguments: [], timeout_seconds: 999 })), null);
});

test("an executable the OS refuses to start gets a durable failure receipt, not a lost result", async (t) => {
  const directory = await mkdtemp(join(tmpdir(), "phigon-command-launch-"));
  t.after(async () => { if (!resolve(directory).startsWith(resolve(tmpdir()) + sep)) throw new Error("Unsafe test cleanup path"); await rm(directory, { recursive: true, force: true }); });
  // Windows refuses batch files without a shell; elsewhere a missing binary fails to start.
  const executable = process.platform === "win32" ? join(directory, "hello.cmd") : join(directory, "missing-binary");
  if (process.platform === "win32") await writeFile(executable, "@echo hello\r\n");
  const launched = await runCommand({ executable, arguments: [], timeout_seconds: 5 });
  assert.equal(launched.exitCode, null); assert.equal(launched.timedOut, false); assert.equal(launched.launched, false);
  assert.match(launched.output, /could not start/u);
  const machineID = randomUUID();
  const command = create(AgentActionCommandSchema, { actionId: randomUUID(), idempotencyKey: randomUUID(), machineId: machineID, agentId: "__machine__", processId: 0n,
    action: Action.RUN_COMMAND, expiresAt: timestampFromDate(new Date(Date.now() + 60_000)), commandJson: JSON.stringify({ executable, arguments: [], timeout_seconds: 5 }) });
  const executor = new MachineCommandExecutor({ enabled: true, machineID, dataDirectory: directory });
  const first = await executor.execute(command);
  assert.equal(first.state, State.FAILED); assert.equal(first.resultCode, "command_not_started");
  assert.deepEqual(await new MachineCommandExecutor({ enabled: true, machineID, dataDirectory: directory }).execute(command), first);
});

test("a command that exits is not reported as timed out when its background child keeps the output open", async () => {
  const started = Date.now();
  // The background child exits by itself after four seconds.
  const result = await runCommand({ executable: process.execPath, arguments: ["-e",
    "require('node:child_process').spawn(process.execPath, ['-e', 'setTimeout(() => {}, 4000)'], { stdio: 'inherit', detached: true }).unref(); console.log('parent done')",
  ], timeout_seconds: 3 });
  assert.equal(result.timedOut, false);
  assert.equal(result.exitCode, 0);
  assert.match(result.output, /parent done/u);
  assert.ok(Date.now() - started < 2_500, "the receipt must not wait for the background child");
});

test("command output hides credentials by name, by known format, and by the observer's own secret values", (t) => {
  // Values are assembled at runtime so the source holds nothing token-shaped.
  const filler = (letter: string, length: number) => letter.repeat(length);
  const envName = ["EXAMPLE", "SIGNING", "KEY"].join("_");
  const envValue = `value-${filler("v", 16)}`;
  process.env[envName] = envValue;
  t.after(() => { delete process.env[envName]; });
  const secrets = [
    `OPENAI_KEY=${filler("q", 20)}`, `MYSQL_PWD=${filler("w", 12)}`, `"passphrase": "${filler("e", 14)}"`,
    `Cookie: session=${filler("r", 18)}`, `DefaultEndpointsProtocol=https;AccountKey=${filler("t", 30)}==;EndpointSuffix=core`,
    `glpat-${filler("a", 20)}`, `hf_${filler("b", 34)}`, `ya29.${filler("c", 30)}`, `xapp-1-${filler("d", 20)}`, `rk_live_${filler("f", 24)}`,
    `the observer value ${envValue} printed alone`,
  ];
  const redacted = redactCommandOutput(secrets.join("\n"));
  for (const hidden of [filler("q", 20), filler("w", 12), filler("e", 14), filler("r", 18), filler("t", 30), filler("a", 20), filler("b", 34), filler("c", 30), filler("d", 20), filler("f", 24), envValue]) {
    assert.doesNotMatch(redacted, new RegExp(hidden.replace(/[.*+?^${}()|[\]\\]/gu, "\\$&"), "u"), `leaked: ${hidden.slice(0, 6)}`);
  }
  // Ordinary output stays readable.
  const ordinary = "PWD=/home/example\nOLDPWD=/tmp\nkey: display-name\nprimary_key=id\nSSH_AUTH_SOCK=/tmp/agent.sock";
  assert.equal(redactCommandOutput(ordinary), ordinary);
  const started = performance.now();
  for (const adversarial of ["a-".repeat(16_384), "x".repeat(32_768), "k=".repeat(16_384), `${"token".repeat(6_000)}=`]) redactCommandOutput(adversarial);
  assert.ok(performance.now() - started < 1_000, "redaction must stay linear on bounded output");
});

test("a timed-out command is stopped together with the child it started", async () => {
  const result = await runCommand({ executable: process.execPath, arguments: ["-e", [
    "const child = require('node:child_process').spawn(process.execPath, ['-e', 'setInterval(() => {}, 1000)'], { stdio: 'ignore' });",
    "console.log('child ' + child.pid);",
    "setInterval(() => {}, 1000);",
  ].join("\n")], timeout_seconds: 1 });
  assert.equal(result.timedOut, true);
  const childPid = Number(/child (\d+)/u.exec(result.output)?.[1]);
  assert.ok(Number.isSafeInteger(childPid) && childPid > 0, result.output);
  const alive = () => { try { process.kill(childPid, 0); return true; } catch { return false; } };
  for (let attempt = 0; attempt < 30 && alive(); attempt++) await new Promise((done) => setTimeout(done, 100));
  try { assert.equal(alive(), false, "the command's child must not outlive its timeout"); }
  finally { if (alive()) process.kill(childPid, "SIGKILL"); }
});

test("a briefly locked receipt on Windows still records the completed command", { skip: process.platform !== "win32" }, async (t) => {
  const directory = await mkdtemp(join(tmpdir(), "phigon-command-locked-"));
  t.after(async () => { if (!resolve(directory).startsWith(resolve(tmpdir()) + sep)) throw new Error("Unsafe test cleanup path"); await rm(directory, { recursive: true, force: true }); });
  const machineID = randomUUID();
  let attempts = 0;
  const executor = new MachineCommandExecutor({ enabled: true, machineID, dataDirectory: directory,
    replace: async (from, to) => { if (attempts++ === 0) throw Object.assign(new Error("locked by a scanner"), { code: "EBUSY" }); await rename(from, to); } });
  const command = create(AgentActionCommandSchema, { actionId: randomUUID(), idempotencyKey: randomUUID(), machineId: machineID, agentId: "__machine__", processId: 0n,
    action: Action.RUN_COMMAND, expiresAt: timestampFromDate(new Date(Date.now() + 60_000)), commandJson: JSON.stringify({ executable: process.execPath, arguments: ["-e", "console.log('done')"], timeout_seconds: 5 }) });
  const result = await executor.execute(command);
  assert.equal(result.resultCode, "command_completed");
  assert.deepEqual(await new MachineCommandExecutor({ enabled: true, machineID, dataDirectory: directory }).execute(command), result);
});

test("power commands use the reviewed one-minute operating-system schedule", () => {
  for (const restart of [false, true]) {
    const command = powerCommand(restart);
    assert.equal(command.timeout_seconds, 10);
    assert.ok(command.arguments.includes(process.platform === "win32" ? "60" : "+1"));
    // Windows implies force-close for /t > 0, even without an explicit /f.
  }
});
