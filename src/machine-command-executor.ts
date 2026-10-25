import { redactSecrets } from "./content-redaction.js";
import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdir, readFile, readdir, lstat, unlink, rename, writeFile } from "node:fs/promises";
import { cpus, freemem, hostname, platform, release, totalmem, uptime } from "node:os";
import { join } from "node:path";
import { create, fromJsonString, toJsonString } from "@bufbuild/protobuf";
import { timestampDate, timestampFromDate } from "@bufbuild/protobuf/wkt";
import { AgentActionResultSchema, RemoteActionResultState as State, RemoteActionType as Action, type AgentActionCommand, type AgentActionResult } from "./generated/phigon/v1/action_pb.js";

export const machineActionTypes: readonly Action[] = [Action.RUN_COMMAND, Action.INSPECT_SYSTEM, Action.SHUTDOWN_MACHINE, Action.RESTART_MACHINE];
export type CommandSpec = { executable: string; arguments: string[]; working_directory?: string; timeout_seconds: number };
const outputLimit = 32768;
const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu;

export function parseCommand(value: string): CommandSpec | null {
  let input: unknown;
  try { input = JSON.parse(value); } catch { return null; }
  if (!input || typeof input !== "object" || Array.isArray(input)) return null;
  const item = input as Record<string, unknown>;
  if (Object.keys(item).some((key) => !["executable", "arguments", "working_directory", "timeout_seconds"].includes(key))) return null;
  const bounded = (v: unknown, max: number): v is string => typeof v === "string" && Buffer.byteLength(v) <= max && !v.includes("\0");
  if (!bounded(item["executable"], 2048) || !item["executable"].trim() || !Array.isArray(item["arguments"]) || item["arguments"].length > 64 ||
    !item["arguments"].every((arg) => bounded(arg, 4096)) ||
    (item["working_directory"] !== undefined && !bounded(item["working_directory"], 2048)) ||
    !Number.isInteger(item["timeout_seconds"]) || Number(item["timeout_seconds"]) < 1 || Number(item["timeout_seconds"]) > 120) return null;
  if (Buffer.byteLength(item["executable"] + String(item["working_directory"] ?? "") + item["arguments"].join("")) > 12288) return null;
  return item as CommandSpec;
}

/** Separate machine-owner enrollment; durable claims prevent crash/retry execution. */
export class MachineCommandExecutor {
  readonly #options: { enabled: boolean; machineID: string; dataDirectory: string };
  #queue: Promise<unknown> = Promise.resolve();
  constructor(options: { enabled: boolean; machineID: string; dataDirectory: string }) {
    this.#options = options;
    this.#queue = pruneCommandReceipts(join(options.dataDirectory, "machine-operation-receipts"));
  }
  execute(command: AgentActionCommand): Promise<AgentActionResult> {
    const task = this.#queue.then(() => this.#execute(command)).catch(() => create(AgentActionResultSchema, {
      actionId: command.actionId, idempotencyKey: command.idempotencyKey, machineId: this.#options.machineID,
      observedAt: timestampFromDate(new Date()), state: State.FAILED,
      resultCode: "execution_journal_unavailable", detail: "Execution could not be confirmed from its durable record. Check the system before issuing another request.",
    }));
    this.#queue = task.catch(() => undefined);
    return task;
  }
  prune(): Promise<void> {
    const task = this.#queue.then(() => pruneCommandReceipts(join(this.#options.dataDirectory, "machine-operation-receipts")));
    this.#queue = task.catch(() => undefined);
    return task;
  }
  async #execute(command: AgentActionCommand): Promise<AgentActionResult> {
    const receipt = (state: State, resultCode: string, detail: string, extra: Partial<Pick<AgentActionResult, "output" | "outputTruncated" | "exitCode">> = {}) => create(AgentActionResultSchema, {
      actionId: command.actionId, idempotencyKey: command.idempotencyKey, machineId: this.#options.machineID,
      observedAt: timestampFromDate(new Date()), state, resultCode, detail, ...extra,
    });
    if (!this.#options.enabled) return receipt(State.REJECTED, "executor_disabled", "Machine owner has not enabled remote commands.");
    if (command.machineId !== this.#options.machineID || !uuid.test(command.actionId) || !uuid.test(command.idempotencyKey) ||
      !machineActionTypes.includes(command.action) || command.agentId !== "__machine__" || command.processId !== 0n || !command.expiresAt) {
      return receipt(State.REJECTED, "invalid_command", "Machine command identity or capability is invalid.");
    }
    const expires = timestampDate(command.expiresAt).getTime();
    if (!Number.isFinite(expires) || expires > Date.now() + 330_000) return receipt(State.EXPIRED, "command_expired", "Command is outside its approved execution window.");
    const spec = command.action === Action.RUN_COMMAND ? parseCommand(command.commandJson) : null;
    if ((command.action === Action.RUN_COMMAND && !spec) || (command.action !== Action.RUN_COMMAND && !["", "null"].includes(command.commandJson))) return receipt(State.REJECTED, "invalid_command", "Executable, arguments, or limits are invalid.");
    const digest = createHash("sha256").update(JSON.stringify([command.actionId, command.machineId, command.action, command.commandJson, command.reason, expires])).digest("hex");
    const directory = join(this.#options.dataDirectory, "machine-operation-receipts");
    const path = join(directory, `${command.idempotencyKey}.json`);
    try {
      const stored = JSON.parse(await readFile(path, "utf8")) as { digest: string; receipt: string };
      return stored.digest === digest ? fromJsonString(AgentActionResultSchema, stored.receipt) : receipt(State.REJECTED, "idempotency_conflict", "This request key belongs to a different command.");
    } catch (error) { if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error; }
    if (expires <= Date.now()) return receipt(State.EXPIRED, "command_expired", "Command expired before execution.");
    await mkdir(directory, { recursive: true, mode: 0o700 });
    const uncertain = receipt(State.FAILED, "execution_interrupted", "Execution was claimed but no completion receipt is available. It will not be repeated automatically.");
    try {
      await writeFile(path, JSON.stringify({ digest, receipt: toJsonString(AgentActionResultSchema, uncertain) }), { flag: "wx", mode: 0o600, flush: true });
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error;
      const stored = JSON.parse(await readFile(path, "utf8")) as { digest: string; receipt: string };
      return stored.digest === digest ? fromJsonString(AgentActionResultSchema, stored.receipt) : receipt(State.REJECTED, "idempotency_conflict", "This request key belongs to a different command.");
    }
    let result: AgentActionResult;
    if (command.action === Action.INSPECT_SYSTEM) {
      result = receipt(State.SUCCEEDED, "inspection_complete", "Current operating-system information collected.", { output: JSON.stringify({ hostname: hostname(), platform: platform(), release: release(), logical_cpus: cpus().length, memory_bytes: totalmem(), free_memory_bytes: freemem(), uptime_seconds: Math.floor(uptime()), observed_at: new Date().toISOString() }, null, 2), exitCode: 0 });
    } else {
      const power = command.action === Action.SHUTDOWN_MACHINE || command.action === Action.RESTART_MACHINE;
      const operation = power ? powerCommand(command.action === Action.RESTART_MACHINE) : spec!;
      const execution = await runCommand(operation);
      const succeeded = execution.exitCode === 0 && !execution.timedOut;
      result = receipt(succeeded ? State.SUCCEEDED : State.FAILED,
        execution.timedOut ? "command_timeout" : succeeded ? (power ? "power_change_scheduled" : "command_completed") : "command_failed",
        execution.timedOut ? "Command exceeded its time limit; termination was requested." : power && succeeded ? "Operating system accepted the power change scheduled for one minute from now." : succeeded ? "Command completed." : "Command did not complete successfully.",
        { output: execution.output, outputTruncated: execution.truncated, ...(execution.exitCode === null ? {} : { exitCode: execution.exitCode }) });
    }
    const temporary = `${path}.tmp`;
    await writeFile(temporary, JSON.stringify({ digest, receipt: toJsonString(AgentActionResultSchema, result) }), { mode: 0o600, flush: true });
    await rename(temporary, path);
    return result;
  }
}

/** Commands expire within minutes. Thirty days of receipts allows local
 * troubleshooting; an expired command is still rejected after its receipt ages out. */
export async function pruneCommandReceipts(directory: string, now = Date.now()): Promise<void> {
  let entries;
  try { entries = await readdir(directory, { withFileTypes: true }); }
  catch (error) { if ((error as NodeJS.ErrnoException).code === "ENOENT") return; throw error; }
  for (const entry of entries) {
    if (!entry.isFile() || !/^[0-9a-f-]{36}\.(?:json(?:\.tmp)?|claim)$/iu.test(entry.name)) continue;
    const path = join(directory, entry.name);
    const stat = await lstat(path).catch(() => null);
    if (stat?.isFile() && stat.mtimeMs < now - 30 * 86_400_000) await unlink(path).catch(() => undefined);
  }
}

export function powerCommand(restart: boolean): CommandSpec {
  return process.platform === "win32"
    ? { executable: join(process.env["SystemRoot"] ?? "C:\\Windows", "System32", "shutdown.exe"), arguments: [restart ? "/r" : "/s", "/t", "60"], timeout_seconds: 10 }
    : { executable: "/sbin/shutdown", arguments: [restart ? "-r" : "-h", "+1"], timeout_seconds: 10 };
}

export function redactCommandOutput(value: string): string {
  let safe = redactSecrets(value, "[REDACTED]");
  for (const [key, secret] of Object.entries(process.env)) if (/TOKEN|SECRET|PASSWORD|API_KEY/iu.test(key) && secret && secret.length >= 8) safe = safe.split(secret).join("[REDACTED]");
  return safe;
}

export async function runCommand(spec: CommandSpec): Promise<{ output: string; exitCode: number | null; truncated: boolean; timedOut: boolean }> {
  return new Promise((resolve) => {
    const env = Object.fromEntries(Object.entries(process.env).filter(([key]) => !/^PHIGON_|TOKEN|SECRET|PASSWORD|API_KEY/iu.test(key)));
    const child = spawn(spec.executable, spec.arguments, { shell: false, windowsHide: true, detached: process.platform !== "win32", stdio: ["ignore", "pipe", "pipe"], env, ...(spec.working_directory ? { cwd: spec.working_directory } : {}) });
    let collected = Buffer.alloc(0); let truncated = false; let timedOut = false; let done = false;
    const consume = (chunk: Buffer) => { const remaining = outputLimit - collected.length; if (chunk.length > remaining) truncated = true; if (remaining > 0) collected = Buffer.concat([collected, chunk.subarray(0, remaining)]); };
    const finish = (exitCode: number | null) => {
      if (done) return; done = true; clearTimeout(timeout); clearTimeout(hardDeadline);
      const safe = Buffer.from(redactCommandOutput(truncated ? collected.toString("utf8").replace(/[^\n]*$/u, "[TRUNCATED]") : collected.toString("utf8")));
      // Leave room for a final UTF-8 replacement character after a byte boundary.
      const output = safe.subarray(0, outputLimit - 4).toString("utf8");
      resolve({ output, exitCode, truncated: truncated || safe.length > outputLimit - 4, timedOut });
    };
    child.stdout.on("data", consume); child.stderr.on("data", consume);
    child.once("error", () => { consume(Buffer.from("Operating system could not launch the requested executable.")); finish(null); });
    child.once("close", (code) => finish(code));
    const timeout = setTimeout(() => {
      timedOut = true;
      if (process.platform === "win32" && child.pid) {
        const killer = spawn(join(process.env["SystemRoot"] ?? "C:\\Windows", "System32", "taskkill.exe"), ["/PID", String(child.pid), "/T", "/F"], { windowsHide: true, stdio: "ignore" });
        killer.on("error", () => child.kill());
      } else { try { if (child.pid) process.kill(-child.pid, "SIGKILL"); } catch { child.kill("SIGKILL"); } }
    }, spec.timeout_seconds * 1000);
    const hardDeadline = setTimeout(() => { child.stdout.destroy(); child.stderr.destroy(); child.unref(); finish(null); }, spec.timeout_seconds * 1000 + 3000);
  });
}
