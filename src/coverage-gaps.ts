import { randomUUID } from "node:crypto";
import { mkdir, readdir, readFile, unlink, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { atomicReplace } from "./atomic-replace.js";
import { serverFetch } from "./server-fetch.js";

/**
 * When collection was not running on this computer, and why, as far as this
 * computer can tell. A run record in the data directory says when this
 * observer started, when it was last alive and how it stopped; the next
 * start compares it with when the computer started. What is found waits, one
 * small file per gap, until the company's server has it, so an administrator learns
 * that Phigon was turned off on a computer, not only that it went quiet.
 *
 * Never guessed: a gap the record cannot explain is "ended_unexpectedly"
 * only when the computer has been running since before it, and nothing here
 * names the person at the computer.
 */
export type CoverageGapKind =
  /** The observer was stopped: Ctrl+C, or its service manager stopped it. */
  | "stopped"
  /** On Windows, the background service's task ended: signed out, or ended by someone. */
  | "service_stopped"
  /** The computer started again after the observer last ran: it was off or restarted. */
  | "computer_off"
  /** It ended without stopping while the computer stayed on: ended from Task Manager or crashed. */
  | "ended_unexpectedly"
  /** The observer ran but the computer was asleep. */
  | "asleep"
  /** Someone removed the background service on this computer. */
  | "service_removed";

export type CoverageGap = Readonly<{
  id: string;
  kind: CoverageGapKind;
  /** When collection stopped. */
  from: string;
  /** When it started again; missing while it is still stopped. */
  to?: string;
}>;

/** How this run is ending, as the next start reads it. */
export type StopReason = "stopped" | "service_stopped";

type RunRecord = {
  version: 1;
  pid: number;
  startedAt: string;
  aliveAt: string;
  stoppedAt?: string;
  stopReason?: StopReason;
};

const runFileName = "observer-run.json";
// One file per gap, so the running observer delivering them and another
// command adding one (service uninstall) never write the same file.
const gapsDirectoryName = "coverage-gaps";
/** At most this many gaps wait for the server; the oldest go first. */
export const maxPendingGaps = 64;
const maxFileBytes = 64 << 10;
/** A gap shorter than this between two runs is a restart, not worth an alert. */
const restartGraceMs = 2 * 60_000;
/** Time that passes between two signs of life in one run means the computer slept. */
export const asleepAfterMs = 3 * 60_000;

/**
 * Starts this run's record, after queueing the gap since the previous run
 * when there was one worth reporting, and returns that gap. `bootedAt` is
 * when the computer started. The previous record is replaced only once its
 * gap is saved, so a failed write leaves it for the next start to report.
 */
export async function beginRun(
  dataDirectory: string,
  options: Readonly<{ now: Date; bootedAt: Date; pid: number }>,
): Promise<CoverageGap | undefined> {
  const previous = await readRecord(dataDirectory);
  const gap = previous === undefined ? undefined : gapSince(previous, options.now, options.bootedAt);
  if (gap !== undefined) await queueGaps(dataDirectory, [gap]);
  await writeRecord(dataDirectory, {
    version: 1, pid: options.pid, startedAt: options.now.toISOString(), aliveAt: options.now.toISOString(),
  });
  return gap;
}

/** What happened between the previous run's record and now. */
export function gapSince(previous: RunRecord, now: Date, bootedAt: Date): CoverageGap | undefined {
  const lastAlive = Date.parse(previous.aliveAt);
  const stopped = previous.stoppedAt === undefined ? Number.NaN : Date.parse(previous.stoppedAt);
  const from = Number.isFinite(stopped) ? stopped : lastAlive;
  if (!Number.isFinite(from) || now.getTime() - from < restartGraceMs) return undefined;
  const gap = (kind: CoverageGapKind): CoverageGap => ({
    id: randomUUID(), kind, from: new Date(from).toISOString(), to: now.toISOString(),
  });
  // The computer started after the observer was last alive: whatever ended
  // it, the computer was off or restarting for part of the gap.
  if (bootedAt.getTime() > from) return gap("computer_off");
  if (Number.isFinite(stopped)) return gap(previous.stopReason === "service_stopped" ? "service_stopped" : "stopped");
  return gap("ended_unexpectedly");
}

/**
 * Notes that this run is alive. Returns a gap when the time since the last
 * note shows the process was not running for a while: the computer slept.
 */
export async function markAlive(dataDirectory: string, now: Date): Promise<CoverageGap | undefined> {
  const record = await readRecord(dataDirectory);
  if (record === undefined || record.pid !== process.pid) return undefined;
  const last = Date.parse(record.aliveAt);
  await writeRecord(dataDirectory, { ...record, aliveAt: now.toISOString() });
  if (!Number.isFinite(last) || now.getTime() - last < asleepAfterMs) return undefined;
  return { id: randomUUID(), kind: "asleep", from: new Date(last).toISOString(), to: now.toISOString() };
}

/** Records how this run ends, for the next start to read. */
export async function endRun(dataDirectory: string, reason: StopReason, now: Date = new Date()): Promise<void> {
  const record = await readRecord(dataDirectory);
  if (record === undefined || record.pid !== process.pid) return;
  await writeRecord(dataDirectory, { ...record, aliveAt: now.toISOString(), stoppedAt: now.toISOString(), stopReason: reason });
}

/** Adds gaps to those waiting for the server, keeping the newest. */
export async function queueGaps(dataDirectory: string, gaps: readonly CoverageGap[]): Promise<void> {
  if (gaps.length === 0) return;
  const directory = join(dataDirectory, gapsDirectoryName);
  await mkdir(directory, { recursive: true, mode: 0o700 });
  for (const gap of gaps) await writeJSON(join(directory, `${gap.id}.json`), gap);
  const pending = await pendingGaps(dataDirectory);
  for (const old of pending.slice(0, Math.max(0, pending.length - maxPendingGaps))) await forget(dataDirectory, old.id);
}

/** The gaps waiting for the server, oldest first. */
export async function pendingGaps(dataDirectory: string): Promise<CoverageGap[]> {
  let names: string[];
  try {
    names = await readdir(join(dataDirectory, gapsDirectoryName));
  } catch {
    return [];
  }
  const gaps: CoverageGap[] = [];
  for (const name of names) {
    if (!/^[0-9a-f-]{36}\.json$/u.test(name)) continue;
    const value = await readJSON(join(dataDirectory, gapsDirectoryName, name));
    if (validGap(value) && `${value.id}.json` === name) gaps.push(value);
  }
  return gaps.sort((left, right) => Date.parse(left.from) - Date.parse(right.from));
}

async function forget(dataDirectory: string, id: string): Promise<void> {
  await unlink(join(dataDirectory, gapsDirectoryName, `${id}.json`)).catch(() => undefined);
}

/**
 * Sends the waiting gaps with `post`, which answers with the HTTP status.
 * Accepted gaps are forgotten; so are gaps a server too old to know them
 * refuses (404), since it never will. Anything else keeps them for later.
 */
export async function sendPendingGaps(
  dataDirectory: string,
  post: (body: unknown) => Promise<number>,
): Promise<"sent" | "none" | "unsupported" | "later"> {
  const gaps = await pendingGaps(dataDirectory);
  if (gaps.length === 0) return "none";
  let status: number;
  try {
    status = await post({ gaps });
  } catch {
    return "later";
  }
  if (status !== 200 && status !== 404) return "later";
  // Only what was sent goes; a gap another command added meanwhile stays.
  for (const gap of gaps) await forget(dataDirectory, gap.id);
  return status === 200 ? "sent" : "unsupported";
}

/**
 * Posts gaps to the company's server with this computer's key, answering
 * with the HTTP status. Nothing of the response is read.
 */
export function gapPoster(
  controlPlaneURL: URL,
  credential: string,
  fetcher: typeof fetch = serverFetch,
): (body: unknown) => Promise<number> {
  return async (body) => {
    const response = await fetcher(new URL("/v1/machine/coverage-gaps", controlPlaneURL), {
      method: "POST", redirect: "error",
      headers: { Authorization: `Bearer ${credential}`, "Content-Type": "application/json" },
      body: JSON.stringify(body), signal: AbortSignal.timeout(10_000),
    });
    await response.body?.cancel().catch(() => undefined);
    return response.status;
  };
}

const kinds: ReadonlySet<string> = new Set<CoverageGapKind>([
  "stopped", "service_stopped", "computer_off", "ended_unexpectedly", "asleep", "service_removed",
]);

function validGap(value: unknown): value is CoverageGap {
  if (typeof value !== "object" || value === null) return false;
  const gap = value as Record<string, unknown>;
  return typeof gap["id"] === "string" && /^[0-9a-f-]{36}$/u.test(gap["id"]) &&
    typeof gap["kind"] === "string" && kinds.has(gap["kind"]) &&
    typeof gap["from"] === "string" && Number.isFinite(Date.parse(gap["from"])) &&
    (gap["to"] === undefined || (typeof gap["to"] === "string" && Number.isFinite(Date.parse(gap["to"]))));
}

async function readRecord(dataDirectory: string): Promise<RunRecord | undefined> {
  const value = await readJSON(join(dataDirectory, runFileName));
  if (typeof value !== "object" || value === null) return undefined;
  const record = value as Record<string, unknown>;
  if (record["version"] !== 1 || typeof record["pid"] !== "number" || typeof record["startedAt"] !== "string" ||
    typeof record["aliveAt"] !== "string") return undefined;
  return {
    version: 1, pid: record["pid"], startedAt: record["startedAt"], aliveAt: record["aliveAt"],
    ...(typeof record["stoppedAt"] === "string" ? { stoppedAt: record["stoppedAt"] } : {}),
    ...(record["stopReason"] === "stopped" || record["stopReason"] === "service_stopped" ? { stopReason: record["stopReason"] } : {}),
  };
}

async function writeRecord(dataDirectory: string, record: RunRecord): Promise<void> {
  await writeJSON(join(dataDirectory, runFileName), record);
}

async function readJSON(path: string): Promise<unknown> {
  try {
    const raw = await readFile(path, "utf8");
    return raw.length > maxFileBytes ? undefined : JSON.parse(raw) as unknown;
  } catch {
    return undefined;
  }
}

async function writeJSON(path: string, value: unknown): Promise<void> {
  const temporary = `${path}.${process.pid}.${randomUUID()}.tmp`;
  try {
    await writeFile(temporary, `${JSON.stringify(value)}\n`, { encoding: "utf8", flag: "wx", mode: 0o600 });
    await atomicReplace(temporary, path);
  } catch (error) {
    await unlink(temporary).catch(() => undefined);
    throw error;
  }
}
