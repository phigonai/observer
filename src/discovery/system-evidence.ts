import { createHash } from "node:crypto";
import { execFile } from "node:child_process";
import { constants } from "node:fs";
import { access, stat } from "node:fs/promises";
import { homedir } from "node:os";
import { basename, delimiter, join, win32 } from "node:path";
import { promisify } from "node:util";
import type {
  ConfigurationEvidence,
  ExecutableEvidence,
  HostEvidenceProvider,
  ProbeResult,
  ProcessEvidence,
} from "./evidence.js";
import { observedProcessKey } from "./process-identity.js";
import { guardianRunnerPath } from "../guardian-native.js";

const execFileAsync = promisify(execFile);
const executableNamePattern = /^[a-zA-Z0-9._+-]{1,128}$/;
const versionPattern =
  /\bv?\d+\.\d+(?:\.\d+)?(?:[-+][0-9A-Za-z.-]+)?\b/;
const maxCachedExecutableProbes = 64;

type CachedExecutableProbe = Readonly<{
  checkedAt: number;
  ttlMs: number;
  value: ExecutableEvidence | null;
  executablePath?: string;
  size?: number;
  modifiedMs?: number;
}>;

/**
 * Remembers which agent CLIs are installed between discovery passes.
 * Finding one walks PATH and runs its `--version`, which starts the agent's
 * own runtime; discovery runs every few seconds, while installs change
 * rarely. A found CLI is probed again when its file changes or after
 * `foundTtlMs` (npm shims stay unchanged across upgrades); an absent one, or
 * one whose version could not be read, is probed again after `missingTtlMs`.
 */
export class ExecutableProbeCache {
  readonly #entries = new Map<string, CachedExecutableProbe>();
  readonly #foundTtlMs: number;
  readonly #missingTtlMs: number;
  readonly #clock: () => number;

  constructor(
    options: Readonly<{
      foundTtlMs?: number;
      missingTtlMs?: number;
      clock?: () => number;
    }> = {},
  ) {
    this.#foundTtlMs = options.foundTtlMs ?? 5 * 60_000;
    this.#missingTtlMs = options.missingTtlMs ?? 60_000;
    this.#clock = options.clock ?? Date.now;
  }

  async lookup(key: string): Promise<
    Readonly<{ value: ExecutableEvidence | null }> | undefined
  > {
    const cached = this.#entries.get(key);
    if (cached === undefined) return undefined;
    const age = this.#clock() - cached.checkedAt;
    if (age < 0 || age >= cached.ttlMs) return undefined;
    if (cached.executablePath === undefined) return { value: cached.value };
    try {
      const metadata = await stat(cached.executablePath);
      if (
        metadata.size !== cached.size ||
        metadata.mtimeMs !== cached.modifiedMs
      ) {
        return undefined;
      }
    } catch {
      return undefined;
    }
    return { value: cached.value };
  }

  async remember(
    key: string,
    value: ExecutableEvidence | null,
    executablePath: string | null,
  ): Promise<void> {
    const checkedAt = this.#clock();
    const ttlMs = value === null || value.version === ""
      ? this.#missingTtlMs
      : this.#foundTtlMs;
    let entry: CachedExecutableProbe = { checkedAt, ttlMs, value };
    if (executablePath !== null) {
      try {
        const metadata = await stat(executablePath);
        entry = {
          ...entry,
          executablePath,
          size: metadata.size,
          modifiedMs: metadata.mtimeMs,
        };
      } catch {
        return;
      }
    }
    this.#entries.delete(key);
    this.#entries.set(key, entry);
    if (this.#entries.size > maxCachedExecutableProbes) {
      const oldest = this.#entries.keys().next().value;
      if (oldest !== undefined) this.#entries.delete(oldest);
    }
  }
}

export class SystemEvidenceProvider implements HostEvidenceProvider {
  readonly #platform: NodeJS.Platform;
  readonly #environment: NodeJS.ProcessEnv;
  readonly #executableCache: ExecutableProbeCache | undefined;
  #processes:
    | Promise<ProbeResult<readonly ProcessEvidence[]>>
    | undefined;

  constructor(
    platform: NodeJS.Platform = process.platform,
    environment: NodeJS.ProcessEnv = process.env,
    executableCache?: ExecutableProbeCache,
  ) {
    this.#platform = platform;
    this.#environment = environment;
    this.#executableCache = executableCache;
  }

  listProcesses(): Promise<ProbeResult<readonly ProcessEvidence[]>> {
    this.#processes ??= this.#readProcesses();
    return this.#processes;
  }

  async inspectExecutable(
    candidates: readonly string[],
  ): Promise<ProbeResult<ExecutableEvidence | null>> {
    for (const candidate of candidates) {
      if (!executableNamePattern.test(candidate)) {
        return {
          status: "unknown",
          notice: "Executable probe configuration was invalid.",
        };
      }
    }
    const cacheKey = JSON.stringify([
      this.#platform,
      this.#environmentValue("PATH") ?? "",
      this.#environmentValue("PATHEXT") ?? "",
      candidates,
    ]);
    try {
      const cached = await this.#executableCache?.lookup(cacheKey);
      if (cached !== undefined) return { status: "ok", value: cached.value };
      for (const candidate of candidates) {
        const executablePath = await this.#findExecutable(candidate);
        if (executablePath === null) continue;
        const value = {
          executableName: normalizedExecutableName(candidate),
          executablePathDigest: digest(executablePath),
          version: await readVersion(executablePath),
        };
        await this.#executableCache?.remember(cacheKey, value, executablePath);
        return { status: "ok", value };
      }
      await this.#executableCache?.remember(cacheKey, null, null);
      return { status: "ok", value: null };
    } catch (error) {
      return probeFailure(error, "Executable inspection");
    }
  }

  async inspectConfiguration(
    candidates: readonly string[],
  ): Promise<ProbeResult<readonly ConfigurationEvidence[]>> {
    const found: ConfigurationEvidence[] = [];
    try {
      for (const candidate of candidates) {
        const expanded = expandHome(candidate);
        try {
          await stat(expanded);
          found.push({ identifierDigest: digest(expanded) });
        } catch (error) {
          if (isNodeError(error) && error.code === "ENOENT") continue;
          throw error;
        }
      }
      return { status: "ok", value: found };
    } catch (error) {
      return probeFailure(error, "Configuration inspection");
    }
  }

  async #readProcesses(): Promise<
    ProbeResult<readonly ProcessEvidence[]>
  > {
    try {
      if (this.#platform === "win32") {
        return {
          status: "ok",
          value: await readWindowsProcesses(),
        };
      }
      const { stdout } = await execFileAsync(
        "ps",
        ["-axo", "pid=,lstart=,comm="],
        {
          timeout: 3_000,
          maxBuffer: 1 << 20,
          encoding: "utf8",
          env: {
            ...this.#environment,
            LANG: "C",
            LC_ALL: "C",
          },
        },
      );
      const processes: ProcessEvidence[] = [];
      for (const line of stdout.split(/\r?\n/u)) {
        const match =
          /^\s*(\d+)\s+(\S+\s+\S+\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+\d{4})\s+(.+?)\s*$/u.exec(
            line,
          );
        if (match === null) continue;
        const processId = Number(match[1]);
        const nativeStartIdentity = match[2];
        const executablePath = match[3];
        const startedAt = processStartDate(nativeStartIdentity);
        if (
          nativeStartIdentity === undefined ||
          executablePath === undefined ||
          startedAt === undefined ||
          !Number.isSafeInteger(processId) ||
          processId < 1
        ) {
          continue;
        }
        const executablePathDigest = digest(executablePath);
        const processKey = observedProcessKey(
          this.#platform,
          processId,
          nativeStartIdentity,
          executablePathDigest,
        );
        if (processKey === undefined) continue;
        processes.push({
          processKey,
          processId,
          startedAt,
          executableName: normalizedExecutableName(
            basename(executablePath),
          ),
          executablePathDigest,
        });
      }
      return { status: "ok", value: processes };
    } catch (error) {
      return probeFailure(error, "Process inspection");
    }
  }

  #environmentValue(name: string): string | undefined {
    return this.#environment[name] ?? (
      this.#platform === "win32"
        ? Object.entries(this.#environment).find(([key]) => key.toUpperCase() === name)?.[1]
        : undefined
    );
  }

  async #findExecutable(candidate: string): Promise<string | null> {
    const pathValue = this.#environmentValue("PATH") ?? "";
    const extensions =
      this.#platform === "win32"
        ? (this.#environmentValue("PATHEXT") ?? ".EXE;.CMD;.BAT")
            .split(";")
            .filter(Boolean)
        : [""];
    for (const directory of pathValue.split(delimiter)) {
      if (directory.length === 0) continue;
      for (const extension of extensions) {
        const executablePath = join(directory, `${candidate}${extension}`);
        try {
          await access(
            executablePath,
            this.#platform === "win32" ? constants.F_OK : constants.X_OK,
          );
          return executablePath;
        } catch (error) {
          if (isNodeError(error) && error.code === "ENOENT") continue;
          if (isNodeError(error) && error.code === "EACCES") continue;
          throw error;
        }
      }
    }
    return null;
  }
}

// Set once the native helper is found missing (for example, a source
// checkout built without Go); PowerShell is used from then on.
let nativeProcessListingMissing = false;

/**
 * Windows processes, listed by the bundled native helper in tens of
 * milliseconds. PowerShell's Win32_Process query, which costs 0.3-1 s (most
 * of it PowerShell start-up), is the fallback when the helper is missing or
 * fails. Both report the same IDs, names and start times, and paths are
 * normalized (see windowsPathIdentity) before identities are derived. Each
 * listing is one short-lived process with a timeout, so nothing outlives
 * the observer.
 */
async function readWindowsProcesses(): Promise<readonly ProcessEvidence[]> {
  return listWindowsProcesses(
    nativeProcessListingMissing ? undefined : runNativeProcessListing,
    runPowerShellProcessListing,
  );
}

export async function listWindowsProcesses(
  native: (() => Promise<string>) | undefined,
  powerShell: () => Promise<string>,
): Promise<readonly ProcessEvidence[]> {
  if (native !== undefined) {
    try {
      return windowsProcessEvidence(nativeProcessValues(await native()));
    } catch {
      // A crashed, timed-out or unreadable helper is retried next pass.
    }
  }
  const parsed: unknown = JSON.parse(await powerShell());
  return windowsProcessEvidence(Array.isArray(parsed) ? parsed : [parsed]);
}

export async function runNativeProcessListing(): Promise<string> {
  try {
    const { stdout } = await execFileAsync(guardianRunnerPath(), ["__processes"], {
      timeout: 5_000,
      maxBuffer: 8 << 20,
      encoding: "utf8",
      windowsHide: true,
    });
    return stdout;
  } catch (error) {
    if (isNodeError(error) && error.code === "ENOENT") {
      nativeProcessListingMissing = true;
    }
    throw error;
  }
}

export async function runPowerShellProcessListing(): Promise<string> {
  const script = [
    "Get-CimInstance Win32_Process",
    "Select-Object ProcessId,CreationDate,ExecutablePath,Name",
    "ConvertTo-Json -Compress",
  ].join(" | ");
  const { stdout } = await execFileAsync(
    "powershell.exe",
    ["-NoProfile", "-NonInteractive", "-Command", script],
    {
      timeout: 15_000,
      maxBuffer: 1 << 20,
      encoding: "utf8",
      windowsHide: true,
    },
  );
  return stdout;
}

/**
 * The native listing in Win32_Process's shape. PowerShell serializes
 * CreationDate as `/Date(<Unix ms>)/`; the helper reports those milliseconds,
 * so rebuilding the string keeps process identities unchanged.
 */
export function nativeProcessValues(stdout: string): unknown[] {
  const parsed: unknown = JSON.parse(stdout);
  if (!Array.isArray(parsed)) {
    throw new Error("Native process listing is invalid.");
  }
  return parsed.map((value: unknown) => {
    if (typeof value !== "object" || value === null) return undefined;
    const entry = value as Record<string, unknown>;
    const created = entry["created_ms"];
    return {
      ProcessId: entry["pid"],
      Name: entry["name"],
      CreationDate: typeof created === "number" && Number.isSafeInteger(created) && created > 0
        ? `/Date(${created})/`
        : undefined,
      ExecutablePath: entry["path"],
    };
  });
}

function windowsProcessEvidence(values: readonly unknown[]): ProcessEvidence[] {
  const processes: ProcessEvidence[] = [];
  for (const value of values) {
    if (
      typeof value !== "object" ||
      value === null ||
      !("ProcessId" in value) ||
      typeof value.ProcessId !== "number" ||
      !("Name" in value) ||
      typeof value.Name !== "string" ||
      !("CreationDate" in value) ||
      typeof value.CreationDate !== "string"
    ) {
      continue;
    }
    const rawPath =
      "ExecutablePath" in value &&
      typeof value.ExecutablePath === "string"
        ? value.ExecutablePath
        : value.Name;
    const startedAt = processStartDate(value.CreationDate);
    const executablePathDigest = digest(windowsPathIdentity(rawPath));
    const processKey = observedProcessKey(
      "win32",
      value.ProcessId,
      value.CreationDate,
      executablePathDigest,
    );
    if (startedAt === undefined || processKey === undefined) continue;
    processes.push({
      processKey,
      processId: value.ProcessId,
      startedAt,
      executableName: normalizedExecutableName(value.Name),
      executablePathDigest,
    });
  }
  return processes;
}

/**
 * One spelling of a Windows executable path, so a process has the same
 * identity whichever listing found it. Win32_Process reports the path the
 * process was started with (`C:\windows\Explorer.EXE`,
 * `C:\Program Files\Git\bin\..\usr\bin\bash.exe`); the native helper reports
 * the file's own path (`C:\Windows\explorer.exe`). Windows paths are
 * case-insensitive, so case, `.` and `..` segments and a `\\?\` prefix are
 * removed. A path reached through a junction still differs from its target.
 */
export function windowsPathIdentity(path: string): string {
  let value = path;
  if (/^\\\\\?\\UNC\\/iu.test(value)) value = `\\\\${value.slice(8)}`;
  else if (value.startsWith("\\\\?\\")) value = value.slice(4);
  return win32.normalize(value).toLowerCase();
}

async function readVersion(executablePath: string): Promise<string> {
  try {
    // npm exposes .cmd shims on Windows, which execFile cannot launch.
    // Its sibling PowerShell shim accepts a literal file argument, avoiding
    // shell interpolation of paths (including spaces and metacharacters).
    const script = process.platform === "win32" && /\.(cmd|bat)$/iu.test(executablePath)
      ? executablePath.replace(/\.(cmd|bat)$/iu, ".ps1")
      : undefined;
    if (script !== undefined) await access(script, constants.F_OK);
    const execution = execFileAsync(
      script === undefined ? executablePath : "powershell.exe",
      script === undefined ? ["--version"] : ["-NoProfile", "-NonInteractive", "-File", script, "--version"],
      {
        // Starting PowerShell alone can take several seconds on a busy or
        // closely monitored computer, as for the PowerShell process listing.
        // A probe result is cached, so a slow start is paid once per CLI.
        timeout: script === undefined ? 5_000 : 15_000,
        maxBuffer: 4_096,
        encoding: "utf8",
        windowsHide: true,
      },
    );
    // npm's PowerShell shims forward pipeline input before exiting. Version
    // probes have no input; leaving this pipe open can make a healthy CLI
    // wait until the timeout instead of returning its version.
    execution.child.stdin?.end();
    const { stdout, stderr } = await execution;
    const match = versionPattern.exec(`${stdout}\n${stderr}`.slice(0, 4_096));
    return match?.[0]?.slice(0, 64) ?? "";
  } catch {
    return "";
  }
}

function probeFailure<T>(
  error: unknown,
  label: string,
): ProbeResult<T> {
  if (
    isNodeError(error) &&
    (error.code === "EACCES" || error.code === "EPERM")
  ) {
    return {
      status: "permission_denied",
      notice: `${label} was denied by the operating system.`,
    };
  }
  return {
    status: "unknown",
    notice: `${label} could not be completed.`,
  };
}

function expandHome(value: string): string {
  if (value === "~") return homedir();
  if (value.startsWith("~/") || value.startsWith("~\\")) {
    return join(homedir(), value.slice(2));
  }
  return value;
}

function normalizedExecutableName(value: string): string {
  return value.toLowerCase().replace(/\.exe$/u, "").slice(0, 128);
}

function processStartDate(value: string | undefined): Date | undefined {
  if (value === undefined || value.trim().length === 0) return undefined;
  const dotNet = /^\/Date\((\d+)(?:[+-]\d{4})?\)\/$/u.exec(value);
  const milliseconds = dotNet === null ? Date.parse(value) : Number(dotNet[1]);
  if (!Number.isFinite(milliseconds)) return undefined;
  const startedAt = new Date(milliseconds);
  return Number.isNaN(startedAt.getTime()) ? undefined : startedAt;
}

function digest(value: string): string {
  return createHash("sha256").update(value).digest("hex");
}

function isNodeError(error: unknown): error is NodeJS.ErrnoException {
  return error instanceof Error && "code" in error;
}
