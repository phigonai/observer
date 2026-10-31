import { execFile } from "node:child_process";
import { guardianRunnerPath } from "./guardian-native.js";

/** One exact process lifetime: a PID alone is never an identity. */
export type ExactProcess = Readonly<{ processId: number; startedAt: Date }>;
export type TreeStopMode = "stop" | "kill";

export type TreeStopOutcome =
  | Readonly<{ outcome: "stale" | "exited" | "access_denied" | "graceful_unsupported" | "console_shared" | "self_target" }>
  | Readonly<{ outcome: "failed"; code: string }>
  | Readonly<{
    outcome: "dispatched";
    rootRunning: boolean;
    /** Verified descendants that were signalled. */
    descendants: number;
    /** Signalled descendants still running at the end of the wait. */
    descendantsRunning: number;
    /** Running descendants the OS would not let the observer stop. */
    descendantsDenied: number;
  }>;

/** Stops one exact process and the descendants it started. */
export interface ProcessTreeControl {
  stop(target: ExactProcess, mode: TreeStopMode): Promise<TreeStopOutcome>;
}

export type TreeStopReceipt = Readonly<{
  state: "succeeded" | "failed" | "rejected";
  code: string;
  detail: string;
  targetStillRunning: boolean;
}>;

/** Plain-language receipts; detail stays within the 256-character journal bound. */
export function describeTreeOutcome(outcome: TreeStopOutcome, graceful: boolean): TreeStopReceipt {
  const receipt = (state: TreeStopReceipt["state"], code: string, detail: string, targetStillRunning: boolean) =>
    ({ state, code, detail, targetStillRunning });
  switch (outcome.outcome) {
    case "stale":
      return receipt("rejected", "stale_target", "The process ID now belongs to a different process. Nothing was signalled.", false);
    case "exited":
      return receipt("rejected", "target_already_stopped", "The agent process had already exited. Nothing was signalled.", false);
    case "self_target":
      return receipt("rejected", "self_target_rejected", "Observer refuses to terminate its own process.", true);
    case "access_denied":
      return receipt("failed", "access_denied", "The operating system denied permission to stop this process. It may run as another user or as administrator. It is still running.", true);
    case "graceful_unsupported":
      return receipt("rejected", "graceful_stop_unsupported", "This agent has no window to close and no terminal to press Ctrl+C in, so a graceful stop is not possible. Nothing was sent. Use force stop instead.", true);
    case "console_shared":
      return receipt("rejected", "terminal_shared", "Other programs share this agent's terminal, and Ctrl+C would reach them too. Nothing was sent. Use force stop instead.", true);
    case "failed":
      return receipt("failed", "os_dispatch_failed", `The operating system could not complete the request (${outcome.code}). The agent may still be running.`, true);
    case "dispatched": {
      if (outcome.rootRunning) {
        return receipt("failed", "process_still_running", graceful
          ? "The stop request was sent, but the agent is still running after 5 seconds. It was not escalated; use force stop if needed."
          : "Force stop was sent, but the agent still reports running.", true);
      }
      const remaining = outcome.descendantsRunning + outcome.descendantsDenied;
      if (remaining > 0) {
        return receipt("succeeded", "process_stopped_children_running",
          `The agent process exited, but ${remaining} of its child processes ${remaining === 1 ? "is" : "are"} still running.`, false);
      }
      return receipt("succeeded", "process_stopped", outcome.descendants > 0
        ? `The agent process and its ${outcome.descendants} child ${outcome.descendants === 1 ? "process" : "processes"} exited.`
        : "The agent process exited.", false);
    }
  }
}

export function defaultProcessTreeControl(platform: NodeJS.Platform = process.platform): ProcessTreeControl {
  return platform === "win32" ? new WindowsProcessTreeControl() : new UnixProcessTreeControl();
}

const maxDescendants = 1024;
// Graceful stop gives the agent time to save state; force stop is immediate.
const exitWait: Record<TreeStopMode, number> = { stop: 5_000, kill: 3_000 };

export type ProcessRow = Readonly<{ processId: number; parentId: number; startedAt: number; zombie: boolean }>;
type Signal = "SIGTERM" | "SIGKILL" | 0;

/**
 * Linux and macOS: one process-table snapshot verifies the root's start time
 * immediately before signalling, and finds descendants whose start is not
 * earlier than their parent's (a stale parent PID cannot adopt them). The
 * observer and everything it started are never members.
 */
export class UnixProcessTreeControl implements ProcessTreeControl {
  readonly #list: () => Promise<ReadonlyMap<number, ProcessRow>>;
  readonly #signal: (processId: number, signal: Signal) => void;
  readonly #sleep: (milliseconds: number) => Promise<void>;
  readonly #observerProcessId: number;
  readonly #clock: () => number;

  constructor(options: Readonly<{
    list?: () => Promise<ReadonlyMap<number, ProcessRow>>;
    signal?: (processId: number, signal: Signal) => void;
    sleep?: (milliseconds: number) => Promise<void>;
    observerProcessId?: number;
    clock?: () => number;
  }> = {}) {
    this.#list = options.list ?? readUnixProcessTable;
    this.#signal = options.signal ?? ((processId, signal) => { process.kill(processId, signal); });
    this.#sleep = options.sleep ?? ((milliseconds) => new Promise((resolve) => setTimeout(resolve, milliseconds)));
    this.#observerProcessId = options.observerProcessId ?? process.pid;
    this.#clock = options.clock ?? Date.now;
  }

  async stop(target: ExactProcess, mode: TreeStopMode): Promise<TreeStopOutcome> {
    if (target.processId === this.#observerProcessId) return { outcome: "self_target" };
    let table: ReadonlyMap<number, ProcessRow>;
    try { table = await this.#list(); }
    catch { return { outcome: "failed", code: "process_table_unavailable" }; }
    const root = table.get(target.processId);
    if (root === undefined || root.zombie) return { outcome: "exited" };
    if (!sameStart(root.startedAt, target.startedAt.getTime())) return { outcome: "stale" };
    const descendants = descendantsOf(table, root, this.#observerProcessId);
    const signal = mode === "stop" ? "SIGTERM" : "SIGKILL";
    try {
      this.#signal(root.processId, signal);
    } catch (error) {
      const code = (error as NodeJS.ErrnoException).code;
      if (code === "ESRCH") return { outcome: "exited" };
      if (code === "EPERM") return { outcome: "access_denied" };
      return { outcome: "failed", code: String(code ?? "unknown").slice(0, 32) };
    }
    const denied = new Set<number>();
    for (const descendant of descendants) {
      try { this.#signal(descendant.processId, signal); }
      catch (error) { if ((error as NodeJS.ErrnoException).code === "EPERM") denied.add(descendant.processId); }
    }
    const members = [root, ...descendants];
    const deadline = this.#clock() + exitWait[mode];
    while (this.#clock() < deadline && members.some((member) => this.#alive(member.processId))) {
      await this.#sleep(100);
    }
    // A final snapshot tells an exited process from a zombie or a reused PID.
    let after: ReadonlyMap<number, ProcessRow> | undefined;
    try { after = await this.#list(); } catch { after = undefined; }
    const running = (member: ProcessRow) => {
      if (after === undefined) return this.#alive(member.processId);
      const current = after.get(member.processId);
      return current !== undefined && !current.zombie && sameStart(current.startedAt, member.startedAt);
    };
    const stillRunning = descendants.filter(running);
    return {
      outcome: "dispatched",
      rootRunning: running(root),
      descendants: descendants.length,
      // Counted separately so a receipt can say why a child survived.
      descendantsRunning: stillRunning.filter((member) => !denied.has(member.processId)).length,
      descendantsDenied: stillRunning.filter((member) => denied.has(member.processId)).length,
    };
  }

  #alive(processId: number): boolean {
    try {
      this.#signal(processId, 0);
      return true;
    } catch (error) {
      return (error as NodeJS.ErrnoException).code === "EPERM";
    }
  }
}

export function descendantsOf(table: ReadonlyMap<number, ProcessRow>, root: ProcessRow, observerProcessId: number): ProcessRow[] {
  const children = new Map<number, ProcessRow[]>();
  for (const row of table.values()) {
    if (row.processId === row.parentId) continue;
    const siblings = children.get(row.parentId) ?? [];
    siblings.push(row);
    children.set(row.parentId, siblings);
  }
  const found: ProcessRow[] = [];
  const seen = new Set([root.processId]);
  const queue = [root];
  for (let index = 0; index < queue.length && found.length < maxDescendants; index++) {
    const parent = queue[index]!;
    for (const child of children.get(parent.processId) ?? []) {
      if (seen.has(child.processId) || child.processId <= 1 || child.processId === observerProcessId) continue;
      seen.add(child.processId);
      // ps start times have one-second resolution.
      if (child.zombie || child.startedAt < parent.startedAt - 999) continue;
      found.push(child);
      queue.push(child);
      if (found.length >= maxDescendants) break;
    }
  }
  return found;
}

function sameStart(observed: number, expected: number): boolean {
  return Math.abs(observed - expected) < 1_000;
}

export async function readUnixProcessTable(): Promise<ReadonlyMap<number, ProcessRow>> {
  const stdout = await new Promise<string>((resolve, reject) => execFile(
    "ps",
    ["-A", "-o", "pid=,ppid=,stat=,lstart="],
    { timeout: 3_000, maxBuffer: 8 << 20, encoding: "utf8", env: { ...process.env, LANG: "C", LC_ALL: "C" } },
    (error, output) => error ? reject(error) : resolve(output),
  ));
  return parseUnixProcessTable(stdout);
}

export function parseUnixProcessTable(stdout: string): ReadonlyMap<number, ProcessRow> {
  const table = new Map<number, ProcessRow>();
  for (const line of stdout.split(/\r?\n/u)) {
    const match = /^\s*(\d+)\s+(\d+)\s+(\S+)\s+(\S+\s+\S+\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+\d{4})\s*$/u.exec(line);
    if (match === null) continue;
    const processId = Number(match[1]);
    const startedAt = Date.parse(match[4]!);
    if (!Number.isSafeInteger(processId) || processId < 1 || !Number.isFinite(startedAt)) continue;
    table.set(processId, { processId, parentId: Number(match[2]), startedAt, zombie: match[3]!.startsWith("Z") });
  }
  return table;
}

/**
 * Windows: the native helper holds a handle to every member while it works,
 * so no member's PID can be recycled before the report is written.
 */
export class WindowsProcessTreeControl implements ProcessTreeControl {
  readonly #run: (args: readonly string[]) => Promise<string>;

  constructor(run?: (args: readonly string[]) => Promise<string>) {
    this.#run = run ?? runGuardianHelper;
  }

  async stop(target: ExactProcess, mode: TreeStopMode): Promise<TreeStopOutcome> {
    let stdout: string;
    try {
      stdout = await this.#run([
        "--kill-pid", String(target.processId),
        "--started-at", target.startedAt.toISOString(),
        "--tree", ...(mode === "stop" ? ["--graceful"] : []),
      ]);
    } catch (error) {
      const code = (error as { code?: unknown; killed?: boolean }).killed === true
        ? "helper_timeout"
        : `helper_${String((error as { code?: unknown }).code ?? "failed")}`;
      return { outcome: "failed", code: code.slice(0, 32) };
    }
    return parseTreeReport(stdout);
  }
}

function runGuardianHelper(args: readonly string[]): Promise<string> {
  return new Promise((resolve, reject) => execFile(guardianRunnerPath(), args, {
    windowsHide: true, timeout: 20_000, maxBuffer: 16 << 10, encoding: "utf8",
  }, (error, stdout) => error ? reject(error) : resolve(stdout)));
}

export function parseTreeReport(stdout: string): TreeStopOutcome {
  let value: unknown;
  try { value = JSON.parse(stdout.trim()); } catch { return { outcome: "failed", code: "helper_report_invalid" }; }
  if (value === null || typeof value !== "object") return { outcome: "failed", code: "helper_report_invalid" };
  const report = value as Record<string, unknown>;
  const count = (key: string) => {
    const item = report[key];
    return typeof item === "number" && Number.isSafeInteger(item) && item >= 0 ? item : 0;
  };
  switch (report["outcome"]) {
    case "stale": case "exited": case "access_denied": case "graceful_unsupported": case "console_shared": case "self_target":
      return { outcome: report["outcome"] };
    case "dispatched":
      return {
        outcome: "dispatched",
        rootRunning: report["root_running"] === true,
        descendants: count("descendants"),
        descendantsRunning: count("descendants_running"),
        descendantsDenied: count("descendants_denied"),
      };
    default:
      return { outcome: "failed", code: `helper_${String(report["outcome"] ?? "invalid")}`.slice(0, 32) };
  }
}
