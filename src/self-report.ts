import { randomUUID } from "node:crypto";
import { readFile, unlink, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { monitorEventLoopDelay } from "node:perf_hooks";
import { atomicReplace } from "./atomic-replace.js";
import type { QueueMetrics } from "./event-queue.js";

const statusFileName = "observer-status.json";
const statusVersion = 1;
/** How often a running observer measures itself and writes its status. */
export const selfReportIntervalMs = 60_000;
// A status older than this was left by an observer that stopped.
const staleAfterMs = 3 * selfReportIntervalMs;
const maxStatusBytes = 16 << 10;

/**
 * What a running observer reports about itself in `doctor`: its own cost
 * and how far behind delivery is. Numbers only, never activity content.
 */
export type ObserverRuntimeHealth = Readonly<{
  pid: number;
  observerVersion: string;
  /** When the running observer wrote this. */
  writtenAt: string;
  /** Whether it is older than three report intervals: that observer stopped. */
  stale: boolean;
  /** CPU used over the last interval, as a percentage of one core. */
  cpuPercent: number;
  rssBytes: number;
  eventLoopDelayMs: Readonly<{ mean: number; p99: number; max: number }>;
  lastScanAt?: string;
  lastScanDurationMs?: number;
  /** Whether collection is resting between scans after a quiet spell. */
  collectionResting?: boolean;
  queuedEvents: number;
  queuedBytes?: number;
  /** When the oldest event not yet acknowledged by the server was queued. */
  oldestUndeliveredAt?: string;
  oldestUndeliveredAgeSeconds?: number;
}>;

export type SelfReportSources = Readonly<{
  dataDirectory: string;
  observerVersion: string;
  queue: () => QueueMetrics;
  scan: () => Readonly<{ lastScanAt?: Date; lastScanDurationMs: number; idle: boolean }> | undefined;
  signal: AbortSignal;
  intervalMs?: number;
  now?: () => number;
}>;

/**
 * Measures this observer once a minute (CPU, memory, event-loop delay,
 * last scan, delivery queue) and writes the result to the data directory,
 * where `doctor` reads it. The write is small and not flushed: losing it
 * only shows an older measurement. Stops, and clears its timer and
 * histogram, when `signal` aborts.
 */
export function startSelfReport(sources: SelfReportSources): Readonly<{ measure: () => ObserverRuntimeHealth }> {
  const now = sources.now ?? Date.now;
  const histogram = monitorEventLoopDelay({ resolution: 20 });
  histogram.enable();
  let cpuBefore = process.cpuUsage();
  let measuredAt = performance.now();
  const measure = (): ObserverRuntimeHealth => {
    const cpu = process.cpuUsage(cpuBefore);
    const elapsedMs = Math.max(1, performance.now() - measuredAt);
    cpuBefore = process.cpuUsage();
    measuredAt = performance.now();
    const loop = {
      mean: round(histogram.count > 0 ? histogram.mean / 1e6 : 0),
      p99: round(histogram.count > 0 ? histogram.percentile(99) / 1e6 : 0),
      max: round(histogram.count > 0 ? histogram.max / 1e6 : 0),
    };
    histogram.reset();
    const queue = sources.queue();
    const scan = sources.scan();
    const at = now();
    return Object.freeze({
      pid: process.pid,
      observerVersion: sources.observerVersion,
      writtenAt: new Date(at).toISOString(),
      stale: false,
      cpuPercent: round((cpu.user + cpu.system) / 1_000 / elapsedMs * 100),
      rssBytes: process.memoryUsage.rss(),
      eventLoopDelayMs: Object.freeze(loop),
      ...(scan?.lastScanAt === undefined ? {} : {
        lastScanAt: scan.lastScanAt.toISOString(),
        lastScanDurationMs: round(scan.lastScanDurationMs),
        collectionResting: scan.idle,
      }),
      queuedEvents: queue.depth,
      ...(queue.bytes === undefined ? {} : { queuedBytes: queue.bytes }),
      ...(queue.oldestQueuedAt === undefined ? {} : {
        oldestUndeliveredAt: new Date(queue.oldestQueuedAt).toISOString(),
        oldestUndeliveredAgeSeconds: Math.max(0, Math.floor((at - queue.oldestQueuedAt) / 1_000)),
      }),
    });
  };
  let writing = Promise.resolve();
  const report = () => {
    writing = writing
      .then(() => writeStatus(sources.dataDirectory, measure()))
      .catch(() => undefined);
  };
  const timer = setInterval(report, sources.intervalMs ?? selfReportIntervalMs);
  timer.unref();
  const stop = () => {
    clearInterval(timer);
    histogram.disable();
  };
  if (sources.signal.aborted) stop();
  else sources.signal.addEventListener("abort", stop, { once: true });
  return { measure };
}

async function writeStatus(dataDirectory: string, health: ObserverRuntimeHealth): Promise<void> {
  const path = join(dataDirectory, statusFileName);
  const temporary = `${path}.${process.pid}.${randomUUID()}.tmp`;
  // Whether it is stale is decided by whoever reads it.
  const stored: Record<string, unknown> = { version: statusVersion, ...health };
  delete stored["stale"];
  try {
    await writeFile(temporary, `${JSON.stringify(stored)}\n`, {
      encoding: "utf8", flag: "wx", mode: 0o600,
    });
    await atomicReplace(temporary, path);
  } catch (error) {
    await unlink(temporary).catch(() => undefined);
    throw error;
  }
}

/** What the running observer last reported, or undefined when it has not. */
export async function readObserverStatus(
  dataDirectory: string,
  now: number = Date.now(),
): Promise<ObserverRuntimeHealth | undefined> {
  let value: unknown;
  try {
    const raw = await readFile(join(dataDirectory, statusFileName), "utf8");
    if (raw.length > maxStatusBytes) return undefined;
    value = JSON.parse(raw);
  } catch {
    return undefined;
  }
  if (typeof value !== "object" || value === null) return undefined;
  const status = value as Record<string, unknown>;
  const number = (key: string) => typeof status[key] === "number" && Number.isFinite(status[key]) ? status[key] : undefined;
  const text = (key: string) => typeof status[key] === "string" && status[key].length <= 64 ? status[key] : undefined;
  const loop = typeof status["eventLoopDelayMs"] === "object" && status["eventLoopDelayMs"] !== null
    ? status["eventLoopDelayMs"] as Record<string, unknown>
    : {};
  const loopNumber = (key: string) => typeof loop[key] === "number" && Number.isFinite(loop[key]) ? loop[key] : 0;
  const writtenAt = text("writtenAt");
  const pid = number("pid");
  const cpuPercent = number("cpuPercent");
  const rssBytes = number("rssBytes");
  const queuedEvents = number("queuedEvents");
  if (
    status["version"] !== statusVersion || writtenAt === undefined || !Number.isFinite(Date.parse(writtenAt)) ||
    pid === undefined || cpuPercent === undefined || rssBytes === undefined || queuedEvents === undefined
  ) {
    return undefined;
  }
  const optionalNumber = (key: string) => {
    const found = number(key);
    return found === undefined ? {} : { [key]: found };
  };
  const optionalText = (key: string) => {
    const found = text(key);
    return found === undefined ? {} : { [key]: found };
  };
  return Object.freeze({
    pid,
    observerVersion: text("observerVersion") ?? "",
    writtenAt,
    stale: now - Date.parse(writtenAt) > staleAfterMs,
    cpuPercent,
    rssBytes,
    eventLoopDelayMs: Object.freeze({ mean: loopNumber("mean"), p99: loopNumber("p99"), max: loopNumber("max") }),
    ...optionalText("lastScanAt"),
    ...optionalNumber("lastScanDurationMs"),
    ...(typeof status["collectionResting"] === "boolean" ? { collectionResting: status["collectionResting"] } : {}),
    queuedEvents,
    ...optionalNumber("queuedBytes"),
    ...optionalText("oldestUndeliveredAt"),
    ...optionalNumber("oldestUndeliveredAgeSeconds"),
  }) as ObserverRuntimeHealth;
}

/** One line for `doctor`. */
export function describeRuntime(runtime: ObserverRuntimeHealth): string {
  const parts = [
    `${runtime.cpuPercent}% CPU`,
    `${Math.round(runtime.rssBytes / (1 << 20))} MiB memory`,
    `event-loop delay p99 ${runtime.eventLoopDelayMs.p99} ms`,
    runtime.lastScanAt === undefined
      ? "no activity scan yet"
      : `last scan ${runtime.lastScanAt}${runtime.collectionResting === true ? " (resting while agents are quiet)" : ""}`,
    `${runtime.queuedEvents} events waiting for the server${
      runtime.oldestUndeliveredAgeSeconds === undefined ? "" : `, oldest ${runtime.oldestUndeliveredAgeSeconds} s`
    }`,
  ];
  return `${parts.join(", ")} (measured ${runtime.writtenAt}${runtime.stale ? "; that observer is no longer reporting" : ""})`;
}

function round(value: number): number {
  return Math.round(value * 100) / 100;
}
