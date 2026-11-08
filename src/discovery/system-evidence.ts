import { createHash } from "node:crypto";
import { execFile } from "node:child_process";
import { constants } from "node:fs";
import { access, realpath, stat } from "node:fs/promises";
import { homedir } from "node:os";
import { basename, delimiter, join, posix, win32 } from "node:path";
import { promisify } from "node:util";
import type {
  ConfigurationEvidence,
  ExecutableEvidence,
  HostEvidenceProvider,
  ProbeResult,
  ProcessEvidence,
} from "./evidence.js";
import { observedProcessKey } from "./process-identity.js";
import {
  isInterpreterName,
  mayBeInterpreterName,
  packageFromScriptPath,
  scriptArgument,
  scriptPackageFromWindowsCommandLine,
  scriptPackagesByProcess,
  validScriptPackage,
  type ScriptProcess,
} from "./script-package.js";
import { guardianRunnerPath } from "../guardian-native.js";
import { windowsPowerShell } from "../system-tools.js";

const execFileAsync = promisify(execFile);
const executableNamePattern = /^[a-zA-Z0-9._+-]{1,128}$/;
const versionPattern =
  /\bv?\d+\.\d+(?:\.\d+)?(?:[-+][0-9A-Za-z.-]+)?\b/;
const maxCachedExecutableProbes = 64;
// Bounds the work of learning which npm package interpreter processes run,
// so it never delays a discovery pass for long.
const maxInterpreterProcesses = 256;
const maxBinLinkResolutions = 32;
const scriptPackageDeadlineMs = 3_000;

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
      const interpreters: UnixInterpreterProcess[] = [];
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
        const executableName = normalizedExecutableName(
          basename(executablePath),
        );
        processes.push({
          processKey,
          processId,
          startedAt,
          executableName,
          executablePathDigest,
        });
        // Linux reports a process's name, which Node.js may set to its main
        // thread's ("MainThread"); its command line then says which program
        // it is.
        if (isInterpreterName(executableName) || (this.#platform === "linux" && mayBeInterpreterName(executableName))) {
          interpreters.push({
            processId,
            nativeStartIdentity,
            startedAt,
            executableName,
          });
        }
      }
      const packages = interpreters.length === 0
        ? new Map<number, string>()
        : await withinDeadline(
            unixScriptPackages(
              interpreters,
              (processIds) => this.#listArguments(processIds),
              (path) => realpath(path),
            ),
            scriptPackageDeadlineMs,
          ).catch(() => new Map<number, string>());
      return { status: "ok", value: withScriptPackages(processes, packages) };
    } catch (error) {
      return probeFailure(error, "Process inspection");
    }
  }

  /**
   * One `ps` pass over the given interpreter processes only. Its output holds
   * their arguments and is parsed and dropped by unixScriptPackages.
   */
  #listArguments(processIds: readonly number[]): Promise<string> {
    return new Promise((resolve, reject) => {
      execFile(
        "ps",
        ["-ww", "-o", "pid=,ppid=,lstart=,args=", "-p", processIds.join(",")],
        {
          timeout: 3_000,
          maxBuffer: 4 << 20,
          encoding: "utf8",
          env: {
            ...this.#environment,
            LANG: "C",
            LC_ALL: "C",
          },
        },
        (error, stdout) => {
          // ps exits 1 when some of the listed processes have already exited.
          if (error === null || error.code === 1) resolve(stdout);
          else reject(error);
        },
      );
    });
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

type UnixInterpreterProcess = Readonly<{
  processId: number;
  nativeStartIdentity: string;
  startedAt: Date;
  executableName: string;
}>;

/**
 * Which npm package each macOS or Linux interpreter process runs, by process
 * ID (see script-package.ts). listArguments reads the arguments of those
 * processes only. A row counts only when its start time matches the process
 * table, so a reused PID is never attributed. A CLI started through its bin
 * link (`/usr/local/bin/gemini`, a link into
 * `node_modules/@google/gemini-cli`) is followed on this computer. Arguments
 * are dropped once parsed.
 *
 * `ps` joins arguments with spaces, so a script path that contains a space
 * is not recognized; that process is still listed, by its image name.
 */
export async function unixScriptPackages(
  interpreters: readonly UnixInterpreterProcess[],
  listArguments: (processIds: readonly number[]) => Promise<string>,
  resolvePath: (path: string) => Promise<string>,
): Promise<ReadonlyMap<number, string>> {
  const byID = new Map(
    interpreters
      .slice(0, maxInterpreterProcesses)
      .map((entry) => [entry.processId, entry]),
  );
  if (byID.size === 0) return new Map();
  const output = await listArguments([...byID.keys()]);
  const rows: ScriptProcess[] = [];
  let resolutions = 0;
  for (const line of output.split(/\r?\n/u)) {
    const match =
      /^\s*(\d+)\s+(\d+)\s+(\S+\s+\S+\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+\d{4})(?:\s+(.*))?$/u.exec(
        line,
      );
    const interpreter = match === null ? undefined : byID.get(Number(match[1]));
    if (
      match === null ||
      interpreter === undefined ||
      singleSpaced(match[3] ?? "") !==
        singleSpaced(interpreter.nativeStartIdentity)
    ) {
      continue;
    }
    const values = (match[4] ?? "").split(/\s+/u).filter((value) => value.length > 0);
    // The listed name, or for a renamed process the program it started as.
    const program = isInterpreterName(interpreter.executableName)
      ? interpreter.executableName
      : normalizedExecutableName(posix.basename(values[0] ?? ""));
    if (!isInterpreterName(program)) continue;
    const script = scriptArgument(program, values);
    let scriptPackage =
      script === undefined ? undefined : packageFromScriptPath(script);
    if (
      scriptPackage === undefined &&
      script !== undefined &&
      isBinLink(script) &&
      resolutions < maxBinLinkResolutions
    ) {
      resolutions++;
      scriptPackage = await resolvePath(script).then(
        packageFromScriptPath,
        () => undefined,
      );
    }
    rows.push({
      processId: interpreter.processId,
      parentProcessId: Number(match[2]),
      startedAt: interpreter.startedAt,
      scriptPackage,
    });
  }
  return scriptPackagesByProcess(rows);
}

// An absolute path in a `bin` or `node_modules/.bin` folder, where npm,
// Homebrew, nvm and others link the command of an installed package.
function isBinLink(path: string): boolean {
  if (!path.startsWith("/")) return false;
  const folder = posix.basename(posix.dirname(path));
  return folder === "bin" || folder === ".bin";
}

function singleSpaced(value: string): string {
  return value.trim().replace(/\s+/gu, " ");
}

function withScriptPackages(
  processes: readonly ProcessEvidence[],
  packages: ReadonlyMap<number, string>,
): ProcessEvidence[] {
  return processes.map((entry) => {
    const scriptPackage = packages.get(entry.processId);
    return scriptPackage === undefined ? entry : { ...entry, scriptPackage };
  });
}

function withinDeadline<T>(work: Promise<T>, milliseconds: number): Promise<T> {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(
      () => reject(new Error("deadline_exceeded")),
      milliseconds,
    );
    work.then(
      (value) => {
        clearTimeout(timer);
        resolve(value);
      },
      (error: unknown) => {
        clearTimeout(timer);
        reject(error instanceof Error ? error : new Error("failed"));
      },
    );
  });
}

// Set once the native helper is found missing (for example, a source
// checkout built without Go); PowerShell is used from then on.
let nativeProcessListingMissing = false;

/**
 * Windows processes, listed by the bundled native helper in tens of
 * milliseconds. PowerShell's Win32_Process query, which costs 0.3-1 s (most
 * of it PowerShell start-up), is the fallback when the helper is missing or
 * fails. Both report the same IDs, names and start times, and paths are
 * normalized (see windowsPathIdentity) before identities are derived. For
 * interpreter processes (node, bun, deno) both also give the npm package of
 * the script they run (see script-package.ts): the helper reports only the
 * package, and PowerShell's command line is reduced to it here. Each
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
  // The command line is selected for interpreter processes only; it is
  // reduced to a package name by windowsProcessEvidence and dropped.
  const script = [
    "Get-CimInstance Win32_Process",
    "Select-Object ProcessId,ParentProcessId,CreationDate,ExecutablePath,Name," +
      "@{Name='CommandLine';Expression={if ($_.Name -match '^(node|bun|deno)(\\.exe)?$') { $_.CommandLine }}}",
    "ConvertTo-Json -Compress",
  ].join(" | ");
  const { stdout } = await execFileAsync(
    windowsPowerShell(),
    ["-NoProfile", "-NonInteractive", "-Command", script],
    {
      timeout: 15_000,
      maxBuffer: 4 << 20,
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
      ParentProcessId: entry["ppid"],
      Name: entry["name"],
      CreationDate: typeof created === "number" && Number.isSafeInteger(created) && created > 0
        ? `/Date(${created})/`
        : undefined,
      ExecutablePath: entry["path"],
      ScriptPackage: entry["script"],
    };
  });
}

function windowsProcessEvidence(values: readonly unknown[]): ProcessEvidence[] {
  const processes: ProcessEvidence[] = [];
  const scripts: ScriptProcess[] = [];
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
    const executableName = normalizedExecutableName(value.Name);
    processes.push({
      processKey,
      processId: value.ProcessId,
      startedAt,
      executableName,
      executablePathDigest,
    });
    if (isInterpreterName(executableName)) {
      scripts.push({
        processId: value.ProcessId,
        parentProcessId:
          "ParentProcessId" in value && typeof value.ParentProcessId === "number"
            ? value.ParentProcessId
            : undefined,
        startedAt,
        scriptPackage: windowsScriptPackage(executableName, value),
      });
    }
  }
  return withScriptPackages(processes, scriptPackagesByProcess(scripts));
}

/**
 * The package the helper reported, or the one PowerShell's command line
 * names. The command line goes out of scope here.
 */
function windowsScriptPackage(
  executableName: string,
  value: object,
): string | undefined {
  if ("ScriptPackage" in value && value.ScriptPackage !== undefined) {
    return validScriptPackage(value.ScriptPackage);
  }
  return "CommandLine" in value && typeof value.CommandLine === "string"
    ? scriptPackageFromWindowsCommandLine(executableName, value.CommandLine)
    : undefined;
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
      script === undefined ? executablePath : windowsPowerShell(),
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
