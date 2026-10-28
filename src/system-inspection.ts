import { execFile } from "node:child_process";
import { readFile, statfs } from "node:fs/promises";
import { arch, cpus, freemem, hostname, loadavg, platform, release, totalmem, uptime, type CpuInfo } from "node:os";

/**
 * inspect_system report. Every field from the first version keeps its name
 * and meaning (the desktop parses them). New facts are bounded and contain no
 * file contents, environment values, command lines or user names.
 */
export type SystemInspection = {
  hostname: string;
  platform: string;
  release: string;
  logical_cpus: number;
  memory_bytes: number;
  free_memory_bytes: number;
  uptime_seconds: number;
  observed_at: string;
  observer_version: string;
  architecture: string;
  cpu_model: string | null;
  /** Share of all logical processors busy during the sample window, 0-100. */
  cpu_load_percent: number | null;
  /** 1, 5 and 15 minute run-queue averages; Windows has none. */
  load_average: [number, number, number] | null;
  sample_window_ms: number;
  disk_path: string;
  disk_total_bytes: number | null;
  /** Space the observer's account can still use. */
  disk_free_bytes: number | null;
  agents: InspectedAgent[];
  /** False when discovery or measurement was partial, timed out or unavailable. */
  agents_complete: boolean;
  /** Running agents left out to keep the report short (busiest are kept). */
  agents_omitted: number;
};

export type InspectedAgent = {
  name: string;
  process_id: number;
  /** Share of the whole machine's CPU during the sample window, 0-100. */
  cpu_percent: number | null;
  /** Resident memory (Windows working set). */
  memory_bytes: number | null;
  run_time_seconds: number;
};

export type RunningAgent = Readonly<{ name: string; processId: number; startedAt: Date }>;
export type RunningAgents = Readonly<{ agents: readonly RunningAgent[]; complete: boolean }>;

/** One reading of cumulative CPU time and memory for a process. */
export type ProcessReading = Readonly<{ startedAt: number | null; cpuMs: number | null; memoryBytes: number | null }>;
export type ProcessSample = Readonly<{
  before: ReadonlyMap<number, ProcessReading>;
  after: ReadonlyMap<number, ProcessReading>;
  elapsedMs: number;
}>;
export type ProcessSampler = (processIds: readonly number[], windowMs: number) => Promise<ProcessSample>;

const maxAgents = 20;
const sampleWindowMs = 500;
const agentListTimeoutMs = 15_000;
const sampleTimeoutMs = 10_000;
const diskTimeoutMs = 2_000;

export async function inspectSystem(options: Readonly<{
  agents?: () => Promise<RunningAgents>;
  sampler?: ProcessSampler;
  observerVersion?: string;
  windowMs?: number;
  now?: () => number;
}> = {}): Promise<SystemInspection> {
  const now = options.now ?? Date.now;
  const windowMs = options.windowMs ?? sampleWindowMs;
  const logicalCpus = Math.max(1, cpus().length);
  const diskPath = mainDiskPath();
  // The machine-wide CPU window runs before discovery or sampling starts, so
  // the observer's own work does not inflate it.
  const [cpuLoad, disk, version] = await Promise.all([
    machineCpuLoad(windowMs),
    withTimeout(statfs(diskPath), diskTimeoutMs).then(
      (stats) => ({ total: stats.blocks * stats.bsize, free: stats.bavail * stats.bsize }),
      () => null,
    ),
    options.observerVersion === undefined ? readObserverVersion() : Promise.resolve(options.observerVersion),
  ]);
  const measured = await measureAgents(options.agents, options.sampler ?? defaultProcessSampler(), windowMs, logicalCpus, now);
  const model = cpus()[0]?.model.trim().replace(/\s+/gu, " ").slice(0, 128);
  return {
    hostname: hostname(),
    platform: platform(),
    release: release(),
    logical_cpus: cpus().length,
    memory_bytes: totalmem(),
    free_memory_bytes: freemem(),
    uptime_seconds: Math.floor(uptime()),
    observed_at: new Date(now()).toISOString(),
    observer_version: version,
    architecture: arch(),
    cpu_model: model ? model : null,
    cpu_load_percent: cpuLoad,
    load_average: platform() === "win32" ? null : loadavg().map((value) => round(value, 2)) as [number, number, number],
    sample_window_ms: windowMs,
    disk_path: diskPath,
    disk_total_bytes: disk?.total ?? null,
    disk_free_bytes: disk?.free ?? null,
    agents: measured.agents,
    agents_complete: measured.complete,
    agents_omitted: measured.omitted,
  };
}

/** Compact enough for the 4,000 characters Cortex reads, still readable as JSON. */
export function formatInspection(report: SystemInspection): string {
  const lines = Object.entries(report).map(([key, value]) => key === "agents" && Array.isArray(value) && value.length > 0
    ? `  ${JSON.stringify(key)}: [\n${value.map((agent) => `    ${JSON.stringify(agent)}`).join(",\n")}\n  ]`
    : `  ${JSON.stringify(key)}: ${JSON.stringify(value)}`);
  return `{\n${lines.join(",\n")}\n}`;
}

async function measureAgents(
  list: (() => Promise<RunningAgents>) | undefined,
  sampler: ProcessSampler,
  windowMs: number,
  logicalCpus: number,
  now: () => number,
): Promise<{ agents: InspectedAgent[]; complete: boolean; omitted: number }> {
  if (list === undefined) return { agents: [], complete: false, omitted: 0 };
  let running: RunningAgents;
  try { running = await withTimeout(list(), agentListTimeoutMs); }
  catch { return { agents: [], complete: false, omitted: 0 }; }
  const candidates = running.agents.filter((agent) => Number.isSafeInteger(agent.processId) && agent.processId > 0).slice(0, 256);
  if (candidates.length === 0) return { agents: [], complete: running.complete, omitted: 0 };
  let sample: ProcessSample | undefined;
  try { sample = await withTimeout(sampler(candidates.map((agent) => agent.processId), windowMs), sampleTimeoutMs); }
  catch { sample = undefined; }
  const measured: InspectedAgent[] = [];
  let complete = running.complete && sample !== undefined;
  for (const agent of candidates) {
    const before = sample?.before.get(agent.processId);
    const after = sample?.after.get(agent.processId);
    const startedAt = agent.startedAt.getTime();
    if (sample !== undefined) {
      // Gone, or the PID now belongs to another process: not a running agent.
      if (after === undefined) continue;
      if (after.startedAt !== null && Math.abs(after.startedAt - startedAt) >= 1_000) continue;
    }
    const cpuDelta = before?.cpuMs != null && after?.cpuMs != null && sample !== undefined && sample.elapsedMs > 0
      ? Math.max(0, after.cpuMs - before.cpuMs) / (sample.elapsedMs * logicalCpus) * 100
      : null;
    if (sample !== undefined && (cpuDelta === null || after?.memoryBytes == null)) complete = false;
    measured.push({
      name: agent.name.replace(/[\u0000-\u001f\u007f]/gu, " ").trim().slice(0, 64) || "Unnamed agent",
      process_id: agent.processId,
      cpu_percent: cpuDelta === null ? null : round(Math.min(100, cpuDelta), 1),
      memory_bytes: after?.memoryBytes ?? null,
      run_time_seconds: Math.max(0, Math.floor((now() - startedAt) / 1_000)),
    });
  }
  measured.sort((left, right) => (right.cpu_percent ?? -1) - (left.cpu_percent ?? -1) ||
    (right.memory_bytes ?? -1) - (left.memory_bytes ?? -1) || left.process_id - right.process_id);
  return { agents: measured.slice(0, maxAgents), complete, omitted: Math.max(0, measured.length - maxAgents) };
}

async function machineCpuLoad(windowMs: number): Promise<number | null> {
  const before = cpuTotals(cpus());
  await new Promise((resolve) => setTimeout(resolve, windowMs));
  const after = cpuTotals(cpus());
  const total = after.total - before.total;
  if (!(total > 0)) return null;
  return round(Math.min(100, Math.max(0, (total - (after.idle - before.idle)) / total * 100)), 1);
}

function cpuTotals(processors: readonly CpuInfo[]): { total: number; idle: number } {
  let total = 0; let idle = 0;
  for (const { times } of processors) {
    total += times.user + times.nice + times.sys + times.idle + times.irq;
    idle += times.idle;
  }
  return { total, idle };
}

function mainDiskPath(): string {
  if (platform() !== "win32") return "/";
  const drive = process.env["SystemDrive"] ?? "C:";
  return /^[A-Za-z]:$/u.test(drive) ? `${drive.toUpperCase()}\\` : "C:\\";
}

async function readObserverVersion(): Promise<string> {
  try {
    const value: unknown = JSON.parse(await readFile(new URL("../../package.json", import.meta.url), "utf8"));
    const version = value !== null && typeof value === "object" && "version" in value ? value.version : undefined;
    return typeof version === "string" && /^[0-9A-Za-z.+-]{1,64}$/u.test(version) ? version : "unknown";
  } catch {
    return "unknown";
  }
}

function round(value: number, digits: number): number {
  const scale = 10 ** digits;
  return Math.round(value * scale) / scale;
}

function withTimeout<T>(work: Promise<T>, milliseconds: number): Promise<T> {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error("timeout")), milliseconds);
    work.then((value) => { clearTimeout(timer); resolve(value); }, (error: unknown) => { clearTimeout(timer); reject(error instanceof Error ? error : new Error("failed")); });
  });
}

export function defaultProcessSampler(target: NodeJS.Platform = process.platform): ProcessSampler {
  if (target === "win32") return sampleWindowsProcesses;
  if (target === "linux") return sampleLinuxProcesses;
  return samplePsProcesses;
}

// Windows: one PowerShell call takes both readings, so its own start-up cost
// falls outside the measured window.
async function sampleWindowsProcesses(processIds: readonly number[], windowMs: number): Promise<ProcessSample> {
  const ids = processIds.filter((id) => Number.isSafeInteger(id) && id > 0).join(",");
  const script = [
    `$ids = @(${ids})`,
    "function Read-Agents { foreach ($p in @(Get-Process -Id $ids -ErrorAction SilentlyContinue)) {",
    "  $s = $null; $c = $null",
    "  try { $s = $p.StartTime.ToUniversalTime().ToString('o') } catch {}",
    "  try { $c = $p.TotalProcessorTime.TotalMilliseconds } catch {}",
    "  [pscustomobject]@{ i = $p.Id; s = $s; c = $c; m = $p.WorkingSet64 } } }",
    "$w = [Diagnostics.Stopwatch]::StartNew(); $a = @(Read-Agents)",
    `Start-Sleep -Milliseconds ${Math.max(50, Math.min(5_000, Math.floor(windowMs)))}`,
    "$e = $w.Elapsed.TotalMilliseconds; $b = @(Read-Agents)",
    "ConvertTo-Json -Compress -Depth 3 -InputObject @{ a = $a; b = $b; e = $e }",
  ].join("\n");
  const stdout = await run("powershell.exe", ["-NoProfile", "-NonInteractive", "-Command", script], {});
  return parseWindowsSample(stdout);
}

export function parseWindowsSample(stdout: string): ProcessSample {
  const value = JSON.parse(stdout) as { a?: unknown; b?: unknown; e?: unknown };
  const readings = (entries: unknown) => {
    const map = new Map<number, ProcessReading>();
    for (const entry of Array.isArray(entries) ? entries : entries === undefined || entries === null ? [] : [entries]) {
      if (entry === null || typeof entry !== "object") continue;
      const item = entry as Record<string, unknown>;
      if (typeof item["i"] !== "number" || !Number.isSafeInteger(item["i"])) continue;
      const startedAt = typeof item["s"] === "string" ? Date.parse(item["s"]) : Number.NaN;
      map.set(item["i"], {
        startedAt: Number.isFinite(startedAt) ? startedAt : null,
        cpuMs: finiteOrNull(item["c"]),
        memoryBytes: finiteOrNull(item["m"]),
      });
    }
    return map;
  };
  return { before: readings(value.a), after: readings(value.b), elapsedMs: finiteOrNull(value.e) ?? 0 };
}

// Linux: /proc gives CPU time in clock ticks (USER_HZ, 100 on Linux) and
// the start time relative to boot.
async function sampleLinuxProcesses(processIds: readonly number[], windowMs: number): Promise<ProcessSample> {
  const bootSeconds = Number(/^btime\s+(\d+)$/mu.exec(await readFile("/proc/stat", "utf8"))?.[1]);
  const read = async () => {
    const readings = new Map<number, ProcessReading>();
    await Promise.all(processIds.map(async (processId) => {
      try {
        const [stat, status] = await Promise.all([
          readFile(`/proc/${processId}/stat`, "utf8"),
          readFile(`/proc/${processId}/status`, "utf8"),
        ]);
        const reading = parseLinuxProcess(stat, status, bootSeconds);
        if (reading !== null) readings.set(processId, reading);
      } catch { /* exited or not visible */ }
    }));
    return readings;
  };
  const started = performance.now();
  const before = await read();
  await new Promise((resolve) => setTimeout(resolve, windowMs));
  const elapsedMs = performance.now() - started;
  return { before, after: await read(), elapsedMs };
}

export function parseLinuxProcess(stat: string, status: string, bootSeconds: number): ProcessReading | null {
  // The command name may contain spaces and parentheses; fields follow the last ")".
  const fields = stat.slice(stat.lastIndexOf(")") + 2).split(" ");
  if (fields.length < 20 || fields[0] === "Z") return null;
  const ticks = Number(fields[11]) + Number(fields[12]);
  const startTicks = Number(fields[19]);
  const rssKiB = Number(/^VmRSS:\s+(\d+)\s+kB$/mu.exec(status)?.[1]);
  return {
    startedAt: Number.isFinite(bootSeconds) && Number.isFinite(startTicks) ? bootSeconds * 1_000 + startTicks * 10 : null,
    cpuMs: Number.isFinite(ticks) ? ticks * 10 : null,
    memoryBytes: Number.isFinite(rssKiB) ? rssKiB * 1_024 : null,
  };
}

// macOS and other Unix systems: two ps readings.
async function samplePsProcesses(processIds: readonly number[], windowMs: number): Promise<ProcessSample> {
  const read = async () => parsePsSample(await run("ps", ["-o", "pid=,rss=,time=,lstart=", "-p", processIds.join(",")], { LANG: "C", LC_ALL: "C" }, true));
  const started = performance.now();
  const before = await read();
  await new Promise((resolve) => setTimeout(resolve, windowMs));
  const elapsedMs = performance.now() - started;
  return { before, after: await read(), elapsedMs };
}

export function parsePsSample(stdout: string): Map<number, ProcessReading> {
  const readings = new Map<number, ProcessReading>();
  for (const line of stdout.split(/\r?\n/u)) {
    const match = /^\s*(\d+)\s+(\d+)\s+(\S+)\s+(\S+\s+\S+\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+\d{4})\s*$/u.exec(line);
    if (match === null) continue;
    const startedAt = Date.parse(match[4]!);
    readings.set(Number(match[1]), {
      startedAt: Number.isFinite(startedAt) ? startedAt : null,
      cpuMs: parseCpuTime(match[3]!),
      memoryBytes: Number(match[2]) * 1_024,
    });
  }
  return readings;
}

/** "[[dd-]hh:]mm:ss[.cc]" as printed by ps. */
export function parseCpuTime(value: string): number | null {
  const match = /^(?:(\d+)-)?(?:(\d+):)?(\d+):(\d+(?:\.\d+)?)$/u.exec(value);
  if (match === null) return null;
  const [days, hours, minutes, seconds] = [match[1], match[2], match[3], match[4]].map((part) => Number(part ?? 0)) as [number, number, number, number];
  return Math.round((((days * 24 + hours) * 60 + minutes) * 60 + seconds) * 1_000);
}

function run(file: string, args: readonly string[], environment: NodeJS.ProcessEnv, allowExitOne = false): Promise<string> {
  return new Promise((resolve, reject) => execFile(file, args, {
    timeout: sampleTimeoutMs, maxBuffer: 1 << 20, encoding: "utf8", windowsHide: true,
    env: { ...process.env, ...environment },
  }, (error, stdout) => {
    // ps exits 1 when some of the listed processes have already exited.
    if (error === null || (allowExitOne && error.code === 1)) resolve(stdout);
    else reject(error);
  }));
}

function finiteOrNull(value: unknown): number | null {
  return typeof value === "number" && Number.isFinite(value) ? value : null;
}
