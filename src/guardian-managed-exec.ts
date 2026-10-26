import { makeDirectoryPrivate } from "./private-directory.js";
import { randomUUID } from "node:crypto";
import { constants } from "node:fs";
import { chmod, mkdir, open, unlink } from "node:fs/promises";
import { join, resolve as resolvePath } from "node:path";
import { guardianRunnerPath } from "./guardian-native.js";
import { access } from "node:fs/promises";
import { verifyExecutionManifest, type ExecutionManifest } from "./guardian-execution-manifest.js";
import { StringDecoder } from "node:string_decoder";
import { spawn, type ChildProcess } from "node:child_process";

export type ManagedExecutionResult = Readonly<{
  exitCode: number;
  invocationId: string;
}>;

export async function executeManagedCommand(options: Readonly<{
  executable: string;
  arguments: readonly string[];
  agentId: string;
  sessionId: string;
  dataDirectory: string;
  manifest: ExecutionManifest;
  environment: NodeJS.ProcessEnv;
  lease?: Readonly<{ origin: string; credential: string; request: Readonly<Record<string, unknown>> }>;
  signal?: AbortSignal;
}>): Promise<ManagedExecutionResult> {
  const runner = guardianRunnerPath();
  await access(runner, constants.X_OK);
  await verifyExecutionManifest(options.manifest, options.environment);
  if (options.signal?.aborted) throw new Error("Guardian execution authorization expired before start.");
  const invocationId = randomUUID();
  const journal = new ManagedCommandJournal(options.dataDirectory);
  await journal.append({
    invocationId,
    agentId: options.agentId,
    sessionId: options.sessionId,
    phase: "requested",
    executable: options.executable,
    arguments: options.arguments,
  });
  if (options.signal?.aborted) throw new Error("Guardian execution authorization expired before start.");

  const leaseFile = options.lease === undefined ? undefined : resolvePath(options.dataDirectory, `guardian-lease-${randomUUID()}.json`);
  const relays = new Map<"stdout" | "stderr", OutputRelay>();
  let leaseCreated = false;
  try {
    if (leaseFile !== undefined) {
      const bootstrap = JSON.stringify(options.lease);
      if (Buffer.byteLength(bootstrap) > 128 << 10) throw new Error("Guardian native lease bootstrap exceeds its limit.");
      const file = await open(leaseFile, "wx", 0o600);
      leaseCreated = true;
      try { await file.writeFile(bootstrap); } finally { await file.close(); }
    }
    return await new Promise<ManagedExecutionResult>((resolve, reject) => {
      const child = spawn(runner, ["--sha256", options.manifest.executable_digest, "--cwd", options.manifest.working_directory, "--cgroup-root", options.manifest.cgroup_root, "--sandbox", options.manifest.sandbox, "--lease-config", leaseFile ?? "",
        "--", options.manifest.executable, ...options.manifest.arguments], {
        shell: false,
        windowsHide: true,
        cwd: options.manifest.working_directory,
        env: options.environment,
        stdio: ["inherit", "pipe", "pipe"],
      });
      const terminate = () => { child.kill("SIGTERM"); };
      options.signal?.addEventListener("abort", terminate, { once: true });
      if (options.signal?.aborted) terminate();
      process.once("SIGINT", terminate);
      process.once("SIGTERM", terminate);
      const detach = () => {
        options.signal?.removeEventListener("abort", terminate);
        process.removeListener("SIGINT", terminate);
        process.removeListener("SIGTERM", terminate);
      };
      const stdoutDecoder = new StringDecoder("utf8");
      const stderrDecoder = new StringDecoder("utf8");
      let writes = Promise.resolve();
      let closed = false;
      const mirrorAbort = new AbortController();
      let mirrorDeadline: NodeJS.Timeout | undefined;
      child.once("exit", () => {
        // Preserve normal output, but a stalled terminal cannot prevent final
        // audit/exit handling after the native process has already stopped.
        mirrorDeadline = setTimeout(() => mirrorAbort.abort(), 1_000);
      });
      const record = (stream: "stdout" | "stderr", output: string, raw?: Buffer) => {
        if (output === "" && raw === undefined) return;
        child.stdout?.pause(); child.stderr?.pause();
        const batch: Promise<void> = writes.then(async () => {
          for (let offset = 0; offset < output.length; offset += 8_192) {
            await journal.append({
              invocationId,
              agentId: options.agentId,
              sessionId: options.sessionId,
              phase: "running",
              executable: options.executable,
              arguments: options.arguments,
              stream,
              output: output.slice(offset, offset + 8_192),
            });
          }
          if (raw !== undefined && !mirrorAbort.signal.aborted) {
            let relay = relays.get(stream);
            if (!relay) {
              relay = outputRelay(runner, stream === "stdout" ? process.stdout.fd : process.stderr.fd, options.dataDirectory, options.environment);
              relays.set(stream, relay);
            }
            await relay.write(raw, mirrorAbort.signal);
          }
        }).then(() => {
          // Resume only after the whole current queue, not its first 8 KiB.
          if (writes === batch) { child.stdout?.resume(); child.stderr?.resume(); }
        });
        writes = batch;
        void batch.catch(() => { terminate(); mirrorAbort.abort(); child.stdout?.resume(); child.stderr?.resume(); });
      };
      child.stdout?.on("data", (chunk: Buffer) => {
        record("stdout", stdoutDecoder.write(chunk), chunk);
      });
      child.stderr?.on("data", (chunk: Buffer) => {
        record("stderr", stderrDecoder.write(chunk), chunk);
      });
      child.once("error", (error) => {
        if (closed) return;
        closed = true;
        detach();
        mirrorAbort.abort();
        writes.then(() => journal.append({
          invocationId,
          agentId: options.agentId,
          sessionId: options.sessionId,
          phase: "failed",
          executable: options.executable,
          arguments: options.arguments,
          output: safeExecutionError(error),
          exitCode: 1,
        })).then(() => reject(error), reject).finally(() => clearTimeout(mirrorDeadline));
      });
      child.once("close", (code, signal) => {
        if (closed) return;
        closed = true;
        detach();
        record("stdout", stdoutDecoder.end());
        record("stderr", stderrDecoder.end());
        const exitCode = options.signal?.aborted ? 77 : code ?? 1;
        writes.then(() => journal.append({
          invocationId,
          agentId: options.agentId,
          sessionId: options.sessionId,
          phase: exitCode === 0 ? "succeeded" : "failed",
          executable: options.executable,
          arguments: options.arguments,
          ...(signal === null ? {} : { output: `Process exited after ${signal}.` }),
          exitCode,
        })).then(() => resolve({ exitCode, invocationId }), reject).finally(() => clearTimeout(mirrorDeadline));
      });
    });
  } finally {
    for (const relay of relays.values()) relay.process.stdin?.end();
    const deadline = setTimeout(() => { for (const relay of relays.values()) relay.process.kill("SIGKILL"); }, 1_000);
    try { await Promise.all([...relays.values()].map((relay) => relay.closed)); }
    finally { clearTimeout(deadline); }
    if (leaseFile !== undefined && leaseCreated) {
      await unlink(leaseFile).catch((error: NodeJS.ErrnoException) => { if (error.code !== "ENOENT") throw error; });
    }
  }
}

type OutputRelay = { process: ChildProcess; closed: Promise<void>; write: (data: Buffer, signal: AbortSignal) => Promise<void> };

// Native relays isolate blocking console IO. Child stdin is an asynchronous
// IPC stream, so its backpressure can be cancelled without blocking Node or
// occupying its shared filesystem/DNS thread pool.
function outputRelay(runner: string, fd: number, cwd: string, environment: NodeJS.ProcessEnv): OutputRelay {
  const child = spawn(runner, ["__relay"], { cwd, env: environment, windowsHide: true, stdio: ["pipe", fd, "ignore"] });
  child.stdin?.on("error", () => { /* pending write callbacks receive this error */ });
  const closed = new Promise<void>((resolve) => { child.once("exit", () => resolve()); child.once("error", () => resolve()); });
  return { process: child, closed, write: async (data, signal) => {
    if (signal.aborted) return;
    const pending = new Promise<void>((resolve, reject) => {
      if (!child.stdin) { reject(new Error("Guardian output relay unavailable.")); return; }
      child.stdin.write(data, (error) => error ? reject(error) : resolve());
    });
    await waitForTerminal(pending, signal);
  } };
}

async function waitForTerminal(pending: Promise<void>, signal: AbortSignal): Promise<void> {
  if (signal.aborted) return;
  let abort = () => {};
  const cancelled = new Promise<void>((resolve) => { abort = resolve; signal.addEventListener("abort", abort, { once: true }); });
  try { await Promise.race([pending, cancelled]); }
  finally { signal.removeEventListener("abort", abort); }
}

type ManagedCommandRecord = Readonly<{
  invocationId: string;
  agentId: string;
  sessionId: string;
  phase: "requested" | "running" | "succeeded" | "failed";
  executable: string;
  arguments: readonly string[];
  stream?: "stdout" | "stderr";
  output?: string;
  exitCode?: number;
}>;

class ManagedCommandJournal {
  readonly #dataDirectory: string;

  constructor(dataDirectory: string) {
    this.#dataDirectory = dataDirectory;
  }

  async append(record: ManagedCommandRecord): Promise<void> {
    const directory = join(this.#dataDirectory, "bridges", "generic");
    await mkdir(directory, { recursive: true, mode: 0o700 });
    await makeDirectoryPrivate(this.#dataDirectory);
    await chmod(join(this.#dataDirectory, "bridges"), 0o700);
    await chmod(directory, 0o700);
    const path = join(directory, "guardian-managed-commands.jsonl");
    const encoded = JSON.stringify({
      type: "phigon_managed_command",
      timestamp: new Date().toISOString(),
      session_id: record.sessionId,
      agent_id: record.agentId,
      invocation_id: record.invocationId,
      phase: record.phase,
      executable: record.executable,
      arguments: record.arguments,
      stream: record.stream ?? "",
      output: record.output ?? "",
      exit_code: record.exitCode ?? null,
    });
    if (Buffer.byteLength(encoded, "utf8") > 96 << 10) {
      throw new Error("Managed command telemetry chunk exceeded 96 KiB.");
    }
    const handle = await open(path, "a", 0o600);
    try {
      await handle.write(`${encoded}\n`);
    } finally {
      await handle.close();
    }
    await chmod(path, 0o600);
  }
}

function safeExecutionError(error: unknown): string {
  const code = error instanceof Error && "code" in error
    ? String((error as NodeJS.ErrnoException).code ?? "unknown")
    : "unknown";
  return `Managed executable could not start (${code.slice(0, 32)}).`;
}
