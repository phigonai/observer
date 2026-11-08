#!/usr/bin/env node
// Measures what the observer's activity collection costs on this computer:
// CPU time, file-system calls and bytes written to the data directory, while
// every agent is idle and, with --writer, while one agent writes five lines a
// second. It runs the real collector and telemetry spool against a fake home
// directory of agent session files; nothing leaves the computer.
//
// Build first (`npm run build`, or `npx tsc -p tsconfig.json`), then:
//
//   node scripts/bench-idle.mjs                     # 3,000 files, 20 s idle
//   node scripts/bench-idle.mjs --files 385 --seconds 30 --writer
//   node scripts/bench-idle.mjs --json              # one JSON line, for scripts
//
// Options:
//   --files N      session files to create, split across Codex, Claude Code
//                  and Gemini CLI folders (default 3000)
//   --seconds N    length of each measured phase (default 20)
//   --writer       also measure a phase where one Codex session grows by five
//                  lines a second, with simulated server acknowledgements
//   --passes N     back-to-back collection passes timed on their own (default 20)
//   --dist PATH    the compiled observer to measure (default ../dist), for
//                  comparing two builds on the same computer
//   --keep         keep the fake home and data directory afterwards
//   --json         print the summary as JSON
import fs from "node:fs";
import fsp from "node:fs/promises";
import { syncBuiltinESMExports } from "node:module";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { monitorEventLoopDelay, performance } from "node:perf_hooks";
import { randomUUID } from "node:crypto";
import { fileURLToPath, pathToFileURL } from "node:url";
import { parseArgs } from "node:util";

const { values: options } = parseArgs({
  options: {
    files: { type: "string", default: "3000" },
    seconds: { type: "string", default: "20" },
    passes: { type: "string", default: "20" },
    writer: { type: "boolean", default: false },
    dist: { type: "string", default: fileURLToPath(new URL("../dist/", import.meta.url)) },
    keep: { type: "boolean", default: false },
    json: { type: "boolean", default: false },
  },
});
const fileCount = positive(options.files, "--files");
const phaseSeconds = positive(options.seconds, "--seconds");
const passCount = positive(options.passes, "--passes");

// Count file-system calls and bytes written. Every module imported below sees
// the wrapped functions: syncBuiltinESMExports updates the ESM named exports.
const calls = new Map();
let bytesWritten = 0;
let flushedWrites = 0;
const countCall = (name) => calls.set(name, (calls.get(name) ?? 0) + 1);
// fs.appendFileSync calls fs.writeFileSync; count only the outer call.
let depth = 0;
const writtenBytes = (data) => typeof data === "string"
  ? Buffer.byteLength(data)
  : ArrayBuffer.isView(data) ? data.byteLength : 0;
function wrap(target, name, prefix, onWrite) {
  const original = target[name];
  if (typeof original !== "function") return;
  target[name] = function counted(...args) {
    if (depth === 0) {
      countCall(`${prefix}${name}`);
      if (onWrite) {
        bytesWritten += writtenBytes(args[1]);
        const flags = args[2];
        if (typeof flags === "object" && flags !== null && flags.flush === true) flushedWrites++;
      }
    }
    depth++;
    try {
      return original.apply(this, args);
    } finally {
      depth--;
    }
  };
}
for (const name of ["stat", "lstat", "readdir", "realpath", "open", "readFile", "access", "rename", "unlink", "mkdir", "chmod"]) {
  wrap(fsp, name, "");
}
for (const name of ["writeFile", "appendFile"]) wrap(fsp, name, "", true);
for (const name of ["statSync", "readdirSync", "readFileSync", "renameSync", "existsSync"]) wrap(fs, name, "");
// The benchmark's own agent writes uncounted.
const originalAppend = fs.appendFileSync;
const appendUncounted = (path, data) => {
  depth++;
  try {
    return originalAppend(path, data);
  } finally {
    depth--;
  }
};
for (const name of ["writeFileSync", "appendFileSync"]) wrap(fs, name, "", true);
let watchers = 0;
const originalWatch = fs.watch;
fs.watch = /** @type {typeof fs.watch} */ (function countedWatch(...args) {
  watchers++;
  return Reflect.apply(originalWatch, fs, args);
});
syncBuiltinESMExports();

const workspace = fs.mkdtempSync(join(tmpdir(), "phigon-bench-"));
const home = join(workspace, "home");
const dataDirectory = join(workspace, "data");
const environment = {
  ...process.env,
  HOME: home,
  USERPROFILE: home,
  APPDATA: join(home, "AppData", "Roaming"),
  LOCALAPPDATA: join(home, "AppData", "Local"),
  XDG_CONFIG_HOME: join(home, ".config"),
  XDG_DATA_HOME: join(home, ".local", "share"),
  PHIGON_DATA_DIR: dataDirectory,
  PHIGON_ACTIVITY_SCAN_INTERVAL_MS: "1000",
  PHIGON_OBSERVABILITY_PROFILE: "full",
};
for (const [key, value] of Object.entries(environment)) process.env[key] = value;

const now = Date.now();
const day = 86_400_000;
const created = createSessions(home, fileCount, now);

const [{ loadConfig }, { ActivityCollector }, { FileBackedEventQueue }, { sanitizeEventForPolicy }, protobuf, observerService] =
  await Promise.all([
    import(compiled("src/config.js")),
    import(compiled("src/activity/collector.js")),
    import(compiled("src/event-spool.js")),
    import(compiled("src/stream-client.js")),
    import("@bufbuild/protobuf"),
    import(compiled("src/generated/phigon/v1/observer_service_pb.js")),
  ]);
const config = loadConfig(environment);
const credential = Object.freeze({
  tenantId: "tenant-bench",
  machineId: "machine-bench",
  credential: `phg_m_${"b".repeat(43)}`,
  controlPlaneOrigin: "https://127.0.0.1",
  createdAt: new Date(now).toISOString(),
  consentProfile: "full",
});
const queue = new FileBackedEventQueue(dataDirectory, config.activityQueueCapacity);
queue.restore(credential.tenantId, credential.machineId, credential.credential);
const emitted = [];
const collector = new ActivityCollector({
  config,
  credential,
  initialSequence: 0n,
  durableDelivery: true,
  flushDelivery: () => queue.flush(),
  emit: (event) => {
    queue.enqueue(event, event.sequence);
    emitted.push(performance.now());
  },
});

// What the stream client does with each queued event before the server
// acknowledges it: apply the workspace policy and serialize the request.
let sentThrough = 0n;
async function deliver() {
  for (const event of queue.pendingAfter(sentThrough, config.activityMaxInFlightEvents)) {
    const sanitized = sanitizeEventForPolicy(event, config.policy);
    protobuf.toBinary(
      observerService.StreamTelemetryRequestSchema,
      protobuf.create(observerService.StreamTelemetryRequestSchema, { payload: { case: "event", value: sanitized } }),
    );
    sentThrough = event.sequence;
  }
  const latest = queue.latestSequence();
  if (latest !== undefined && latest > queue.metrics().acknowledged) {
    queue.acknowledge(latest);
    await collector.acknowledge(latest);
  }
}

// The first pass baselines every file; it is reported on its own.
const startup = await measure(async () => {
  await collector.scanOnce();
});

const passes = await measure(async () => {
  for (let pass = 0; pass < passCount; pass++) await collector.scanOnce();
});

// One collector runs through both phases, as in the observer: the first
// phase starts after a pause that lets its startup work settle.
const controller = new AbortController();
const delivering = setInterval(() => {
  void deliver();
}, 50);
const running = collector.run(controller.signal);
await new Promise((resolve) => setTimeout(resolve, 2_000));
const idle = await runPhase(false);
const writing = options.writer ? await runPhase(true) : undefined;
controller.abort();
await running;
clearInterval(delivering);
await deliver();

const summary = {
  platform: `${process.platform} ${process.arch}`,
  node: process.version,
  files: created.files,
  folders: created.folders,
  watches: watchers,
  startupPass: describe(startup, 1),
  backToBackPass: describe(passes, passCount),
  idle,
  ...(writing === undefined ? {} : { writing }),
};
if (options.json) {
  process.stdout.write(`${JSON.stringify(summary)}\n`);
} else {
  print(summary);
}
collector.close();
queue.flush();
if (!options.keep) fs.rmSync(workspace, { recursive: true, force: true });
else process.stdout.write(`Kept ${workspace}\n`);
// Watchers and timers the collector left would keep the process alive.
process.exit(0);

async function runPhase(withWriter) {
  const active = withWriter ? created.active : undefined;
  const appended = [];
  let line = 0;
  const writer = active === undefined ? undefined : setInterval(() => {
    for (let index = 0; index < 1; index++) {
      appendUncounted(active, `${codexLine(Date.now(), line++)}\n`);
      appended.push(performance.now());
    }
  }, 200);
  const emittedBefore = emitted.length;
  const result = await measure(async () => {
    await new Promise((resolve) => setTimeout(resolve, phaseSeconds * 1_000));
    if (writer !== undefined) clearInterval(writer);
  });
  const phase = describe(result, phaseSeconds);
  phase.cpuPercent = round(result.cpuMs / result.wallMs * 100, 2);
  phase.eventsEmitted = emitted.length - emittedBefore;
  if (withWriter) {
    phase.linesAppended = appended.length;
    phase.deliveryDelayMs = delays(appended, emitted.slice(emittedBefore));
  }
  return phase;
}

async function measure(work) {
  const callsBefore = new Map(calls);
  const bytesBefore = bytesWritten;
  const flushedBefore = flushedWrites;
  const histogram = monitorEventLoopDelay({ resolution: 10 });
  histogram.enable();
  const cpuBefore = process.cpuUsage();
  const wallBefore = performance.now();
  await work();
  const cpu = process.cpuUsage(cpuBefore);
  const wallMs = performance.now() - wallBefore;
  histogram.disable();
  const callDelta = {};
  for (const [name, count] of calls) {
    const delta = count - (callsBefore.get(name) ?? 0);
    if (delta > 0) callDelta[name] = delta;
  }
  return {
    cpuMs: (cpu.user + cpu.system) / 1_000,
    wallMs,
    calls: callDelta,
    bytesWritten: bytesWritten - bytesBefore,
    flushedWrites: flushedWrites - flushedBefore,
    loopDelayP99Ms: histogram.percentile(99) / 1e6,
  };
}

function describe(result, per) {
  const fsCalls = Object.values(result.calls).reduce((total, count) => total + count, 0);
  return {
    cpuMs: round(result.cpuMs, 1),
    cpuMsPer: round(result.cpuMs / per, 2),
    wallMs: round(result.wallMs, 0),
    fsCalls,
    fsCallsPer: round(fsCalls / per, 1),
    calls: result.calls,
    bytesWritten: result.bytesWritten,
    flushedWrites: result.flushedWrites,
    loopDelayP99Ms: round(result.loopDelayP99Ms, 1),
  };
}

// For each appended line, the time until the next event was emitted.
function delays(appendedAt, emittedAt) {
  const values = [];
  let next = 0;
  for (const at of appendedAt) {
    while (next < emittedAt.length && emittedAt[next] < at) next++;
    if (next < emittedAt.length) values.push(emittedAt[next] - at);
  }
  if (values.length === 0) return { samples: 0 };
  values.sort((left, right) => left - right);
  const at = (share) => round(values[Math.min(values.length - 1, Math.floor(values.length * share))], 0);
  return { samples: values.length, p50: at(0.5), p95: at(0.95), max: round(values.at(-1), 0) };
}

function print(result) {
  const line = (label, phase, unit) =>
    `${label.padEnd(22)} CPU ${String(phase.cpuMsPer).padStart(8)} ms/${unit}` +
    `${phase.cpuPercent === undefined ? "" : ` (${phase.cpuPercent}% of a core)`}` +
    `  fs calls ${String(phase.fsCallsPer).padStart(8)}/${unit}` +
    `  written ${phase.bytesWritten} B in ${phase.flushedWrites} flushed writes` +
    `  loop p99 ${phase.loopDelayP99Ms} ms`;
  process.stdout.write([
    `Observer activity benchmark on ${result.platform}, Node ${result.node}`,
    `${result.files} session files in ${result.folders} folders; ${result.watches} folder watches`,
    line("first pass", result.startupPass, "pass"),
    line("back-to-back passes", result.backToBackPass, "pass"),
    line("idle, 1 s ticks", result.idle, "s"),
    ...(result.writing === undefined ? [] : [
      line("one agent writing", result.writing, "s"),
      `  ${result.writing.linesAppended} lines appended, ${result.writing.eventsEmitted} events emitted, delay to first event ` +
        JSON.stringify(result.writing.deliveryDelayMs),
    ]),
    `idle calls: ${JSON.stringify(result.idle.calls)}`,
    ...(result.writing === undefined ? [] : [`writing calls: ${JSON.stringify(result.writing.calls)}`]),
    "",
  ].join("\n"));
}

/**
 * Codex (`sessions/YYYY/MM/DD/rollout-*.jsonl`), Claude Code
 * (`projects/<project>/<id>.jsonl`) and Gemini CLI
 * (`tmp/<project hash>/chats/session-*.jsonl`) sessions, a third each, all
 * last written between one hour and ninety days ago. One recent Codex
 * session is the one the writer grows.
 */
function createSessions(root, count, at) {
  const folders = new Set();
  let files = 0;
  const write = (folder, name, modifiedMs, lines) => {
    fs.mkdirSync(folder, { recursive: true });
    folders.add(folder);
    const path = join(folder, name);
    fs.writeFileSync(path, lines.join("\n") + "\n");
    const time = new Date(modifiedMs);
    fs.utimesSync(path, time, time);
    files++;
    return path;
  };
  const age = (index) => at - 3_600_000 - Math.floor((index / count) * 90 * day);
  for (let index = 0; index < count; index++) {
    const modifiedMs = age(index);
    const date = new Date(modifiedMs);
    const lines = Array.from({ length: 8 }, (_, line) => codexLine(modifiedMs, line));
    switch (index % 3) {
      case 0: {
        const folder = join(root, ".codex", "sessions", String(date.getUTCFullYear()),
          String(date.getUTCMonth() + 1).padStart(2, "0"), String(date.getUTCDate()).padStart(2, "0"));
        write(folder, `rollout-${date.toISOString().replace(/[:.]/gu, "-")}-${randomUUID()}.jsonl`, modifiedMs, lines);
        break;
      }
      case 1:
        write(join(root, ".claude", "projects", `-home-dev-project-${index % 40}`), `${randomUUID()}.jsonl`, modifiedMs,
          lines.map((_, line) => JSON.stringify({ type: "assistant", uuid: randomUUID(), timestamp: date.toISOString(), message: { role: "assistant", content: [{ type: "text", text: `reply ${line}` }] } })));
        break;
      default:
        write(join(root, ".gemini", "tmp", `${String(index % 25).padStart(8, "0")}`, "chats"), `session-${index}.jsonl`, modifiedMs,
          lines.map((_, line) => JSON.stringify({ type: "gemini", id: randomUUID(), timestamp: date.toISOString(), content: `reply ${line}` })));
    }
  }
  const today = new Date(at - 3_600_000);
  const activeFolder = join(root, ".codex", "sessions", String(today.getUTCFullYear()),
    String(today.getUTCMonth() + 1).padStart(2, "0"), String(today.getUTCDate()).padStart(2, "0"));
  const active = write(activeFolder, `rollout-active-${randomUUID()}.jsonl`, at - 3_600_000, [codexLine(at - 3_600_000, 0)]);
  // A folder's modified time is when an entry was last added to it, as on
  // a real computer: deepest folders first, each from its newest entry.
  const newest = new Map();
  for (const folder of folders) {
    for (const name of fs.readdirSync(folder)) {
      const modifiedMs = fs.statSync(join(folder, name)).mtimeMs;
      newest.set(folder, Math.max(newest.get(folder) ?? 0, modifiedMs));
    }
  }
  const ancestors = (folder) => {
    const result = [];
    for (let current = dirname(folder); current.startsWith(root) && current !== root; current = dirname(current)) {
      result.push(current);
    }
    return result;
  };
  for (const [folder, modifiedMs] of [...newest]) {
    for (const ancestor of ancestors(folder)) newest.set(ancestor, Math.max(newest.get(ancestor) ?? 0, modifiedMs));
  }
  for (const [folder, modifiedMs] of newest) fs.utimesSync(folder, new Date(modifiedMs), new Date(modifiedMs));
  return { files, folders: folders.size, active };
}

function codexLine(atMs, index) {
  return JSON.stringify({
    timestamp: new Date(atMs).toISOString(),
    type: "event_msg",
    payload: { type: index % 2 === 0 ? "agent_message" : "user_message", message: `Line ${index}: ${"x".repeat(160)}` },
  });
}

function compiled(path) {
  return pathToFileURL(join(options.dist, path)).href;
}

function positive(value, name) {
  const number = Number(value);
  if (!Number.isSafeInteger(number) || number < 1) throw new Error(`${name} must be a positive whole number.`);
  return number;
}

function round(value, digits) {
  const factor = 10 ** digits;
  return Math.round(value * factor) / factor;
}
