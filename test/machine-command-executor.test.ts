import assert from "node:assert/strict";
import test from "node:test";
import { randomUUID } from "node:crypto";
import { mkdtemp, mkdir, readFile, writeFile, rm, utimes, readdir } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve, sep } from "node:path";
import { create } from "@bufbuild/protobuf";
import { timestampFromDate } from "@bufbuild/protobuf/wkt";
import { AgentActionCommandSchema, RemoteActionType as Action, RemoteActionResultState as State } from "../src/generated/phigon/v1/action_pb.js";
import { MachineCommandExecutor, parseCommand, powerCommand, runCommand, pruneCommandReceipts } from "../src/machine-command-executor.js";

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

test("power commands use the reviewed one-minute operating-system schedule", () => {
  for (const restart of [false, true]) {
    const command = powerCommand(restart);
    assert.equal(command.timeout_seconds, 10);
    assert.ok(command.arguments.includes(process.platform === "win32" ? "60" : "+1"));
    // Windows implies force-close for /t > 0, even without an explicit /f.
  }
});
