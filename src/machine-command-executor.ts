import { atomicReplace } from "./atomic-replace.js";
import { redactSecrets } from "./content-redaction.js";
import { execFile, spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { guardianRunnerPath } from "./guardian-native.js";
import { parseTreeReport } from "./process-tree.js";
import { mkdir, readFile, readdir, lstat, unlink, writeFile, type rename } from "node:fs/promises";
import { formatInspection, inspectSystem, type RunningAgents } from "./system-inspection.js";
import { join } from "node:path";
import { create, fromJsonString, toJsonString } from "@bufbuild/protobuf";
import { timestampDate, timestampFromDate } from "@bufbuild/protobuf/wkt";
import { AgentActionResultSchema, RemoteActionResultState as State, RemoteActionType as Action, type AgentActionCommand, type AgentActionResult } from "./generated/phigon/v1/action_pb.js";

export const machineActionTypes: readonly Action[] = [Action.RUN_COMMAND, Action.INSPECT_SYSTEM, Action.SHUTDOWN_MACHINE, Action.RESTART_MACHINE];
export type CommandSpec = { executable: string; arguments: string[]; working_directory?: string; timeout_seconds: number };
const outputLimit = 32768;
const outputDrainMs = 500;
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

export type MachineCommandOptions = {
  enabled: boolean;
  machineID: string;
  dataDirectory: string;
  replace?: typeof rename;
  /** Running agent processes for inspect_system; omitted means none are listed. */
  agents?: () => Promise<RunningAgents>;
};

/** Separate machine-owner enrollment; durable claims prevent crash/retry execution. */
export class MachineCommandExecutor {
  readonly #options: MachineCommandOptions;
  #queue: Promise<unknown> = Promise.resolve();
  constructor(options: MachineCommandOptions) {
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
      const report = await inspectSystem(this.#options.agents === undefined ? {} : { agents: this.#options.agents });
      result = receipt(State.SUCCEEDED, "inspection_complete", report.agents_complete
        ? "Current operating-system, disk and agent process information collected."
        : "Current operating-system and disk information collected; the agent process list is incomplete.",
      { output: formatInspection(report), exitCode: 0 });
    } else {
      const power = command.action === Action.SHUTDOWN_MACHINE || command.action === Action.RESTART_MACHINE;
      const operation = power ? powerCommand(command.action === Action.RESTART_MACHINE) : spec!;
      const execution = await runCommand(operation);
      const succeeded = execution.exitCode === 0 && !execution.timedOut;
      result = !execution.launched
        ? receipt(State.FAILED, "command_not_started", "The operating system could not start the executable. Nothing ran.", { output: execution.output })
        : receipt(succeeded ? State.SUCCEEDED : State.FAILED,
          execution.timedOut ? "command_timeout" : succeeded ? (power ? "power_change_scheduled" : "command_completed") : "command_failed",
          execution.timedOut ? "Command exceeded its time limit; termination was requested." : power && succeeded ? "Operating system accepted the power change scheduled for one minute from now." : succeeded ? "Command completed." : "Command did not complete successfully.",
          { output: execution.output, outputTruncated: execution.truncated, ...(execution.exitCode === null ? {} : { exitCode: execution.exitCode }) });
    }
    const temporary = `${path}.tmp`;
    await writeFile(temporary, JSON.stringify({ digest, receipt: toJsonString(AgentActionResultSchema, result) }), { mode: 0o600, flush: true });
    // A scanner briefly holding the receipt on Windows must not turn a
    // completed command into "journal unavailable" with its output lost.
    await atomicReplace(temporary, path, this.#options.replace);
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

/** Names whose values are credentials, in environment variables and in NAME=value output. */
export function credentialName(name: string): boolean {
  const lower = name.toLowerCase();
  if (lower === "key" || lower === "pwd" || lower === "oldpwd") return false;
  return /token|secret|passw(?:or)?d|api[_-]?key|passphrase|credential|cookie|(?:key|pwd)$|(?:^|[_.-])auth$|dsn$|connection[_-]?string/u.test(lower);
}

// Command output only: well-known credential formats beyond the shared set.
const commandTokenFormats = /\b(?:glpat-[A-Za-z0-9_-]{20,}|xapp-[A-Za-z0-9-]{10,}|hf_[A-Za-z0-9]{30,}|ya29\.[A-Za-z0-9_-]{20,}|rk_(?:live|test)_[A-Za-z0-9]{10,}|shpat_[a-fA-F0-9]{32}|dop_v1_[a-f0-9]{64}|pypi-[A-Za-z0-9_-]{50,})/gu;
const assignment = /(^|[\s;,{(&?-])(["']?)([A-Za-z_][A-Za-z0-9_.-]{0,127})\2([ \t]*[:=][ \t]*)("[^"\n]*"|'[^'\n]*'|[^\s,;}&]+)/gmu;

export function redactCommandOutput(value: string): string {
  let safe = redactSecrets(value, "[REDACTED]").replace(commandTokenFormats, "[REDACTED]");
  // Short values such as ids and booleans stay readable.
  safe = safe.replace(assignment, (match: string, lead: string, quote: string, name: string, separator: string, item: string) =>
    credentialName(name) && item.replace(/^["']|["']$/gu, "").length >= 6 && !item.includes("[REDACTED")
      ? `${lead}${quote}${name}${quote}${separator}[REDACTED]`
      : match);
  for (const [key, secret] of Object.entries(process.env)) if (credentialName(key) && secret && secret.length >= 8) safe = safe.split(secret).join("[REDACTED]");
  // The paired credential lives in the data directory, not the environment;
  // redactSecrets masks its phg_m_ prefix wherever it is printed.
  return safe;
}

export type CommandExecution = { output: string; exitCode: number | null; truncated: boolean; timedOut: boolean; launched: boolean };

function launchFailure(executable: string): CommandExecution {
  const batch = process.platform === "win32" && /\.(?:cmd|bat)$/iu.test(executable)
    ? " Windows runs .cmd and .bat files only through cmd.exe; use cmd.exe with the arguments /d /c and the script path."
    : "";
  return { output: `The operating system could not start the requested executable.${batch}`, exitCode: null, truncated: false, timedOut: false, launched: false };
}

export async function runCommand(spec: CommandSpec): Promise<CommandExecution> {
  return new Promise((resolve) => {
    const env = Object.fromEntries(Object.entries(process.env).filter(([key]) => !/^PHIGON_/iu.test(key) && !credentialName(key)));
    let child: ReturnType<typeof spawn>;
    try {
      child = spawn(spec.executable, spec.arguments, { shell: false, windowsHide: true, detached: process.platform !== "win32", stdio: ["ignore", "pipe", "pipe"], env, ...(spec.working_directory ? { cwd: spec.working_directory } : {}) });
    } catch {
      // Node refuses some launches synchronously (for example a Windows batch
      // file without a shell). That must still produce a receipt.
      resolve(launchFailure(spec.executable));
      return;
    }
    const stdout = child.stdout!; const stderr = child.stderr!;
    let collected = Buffer.alloc(0); let truncated = false; let timedOut = false; let done = false;
    const consume = (chunk: Buffer) => { const remaining = outputLimit - collected.length; if (chunk.length > remaining) truncated = true; if (remaining > 0) collected = Buffer.concat([collected, chunk.subarray(0, remaining)]); };
    const finish = (exitCode: number | null) => {
      if (done) return; done = true; clearTimeout(timeout); clearTimeout(hardDeadline); clearTimeout(drain);
      const safe = Buffer.from(redactCommandOutput(truncated ? collected.toString("utf8").replace(/[^\n]*$/u, "[TRUNCATED]") : collected.toString("utf8")));
      // Leave room for a final UTF-8 replacement character after a byte boundary.
      const output = safe.subarray(0, outputLimit - 4).toString("utf8");
      resolve({ output, exitCode, truncated: truncated || safe.length > outputLimit - 4, timedOut, launched: true });
    };
    stdout.on("data", consume); stderr.on("data", consume);
    child.once("error", () => {
      // After a successful start, "error" only reports a failed kill; "close" follows.
      if (child.pid !== undefined || done) return;
      done = true; clearTimeout(timeout); clearTimeout(hardDeadline);
      resolve(launchFailure(spec.executable));
    });
    child.once("close", (code) => finish(code));
    // "close" waits for every holder of the output pipes. A background process
    // the command started can hold them long after the command exited, so
    // report the command's own exit after a short drain instead of a timeout.
    let drain: NodeJS.Timeout | undefined;
    child.once("exit", (code) => {
      drain = setTimeout(() => { stdout.destroy(); stderr.destroy(); finish(code); }, outputDrainMs);
    });
    const timeout = setTimeout(() => {
      timedOut = true;
      if (process.platform === "win32" && child.pid) {
        // taskkill /T trusts recorded parent PIDs, so it can also end an
        // unrelated process whose dead parent's PID our command reused. The
        // helper accepts only our direct child and descendants created after
        // their parent. Our own child is still held, so killing it is safe.
        execFile(guardianRunnerPath(), ["--kill-pid", String(child.pid), "--own-child", "--tree"], { windowsHide: true, timeout: 15_000, maxBuffer: 16 << 10, encoding: "utf8" },
          (error, stdout) => { if (error !== null || parseTreeReport(stdout).outcome !== "dispatched") child.kill(); });
      } else { try { if (child.pid) process.kill(-child.pid, "SIGKILL"); } catch { child.kill("SIGKILL"); } }
    }, spec.timeout_seconds * 1000);
    const hardDeadline = setTimeout(() => { stdout.destroy(); stderr.destroy(); child.unref(); finish(null); }, spec.timeout_seconds * 1000 + 3000);
  });
}
