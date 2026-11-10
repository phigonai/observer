import { createHash } from "node:crypto";
import { execFile } from "node:child_process";
import { constants } from "node:fs";
import { access, readFile, readdir, realpath, stat } from "node:fs/promises";
import { homedir } from "node:os";
import { basename, delimiter, dirname, isAbsolute, join, posix, resolve, win32 } from "node:path";
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

// A PATH folder with more entries than this is not kept in memory; its
// candidates are checked one by one instead.
const maxListedPathEntries = 20_000;
const maxCachedPathFolders = 256;
// PATH folders are looked at once for all the probes of a discovery pass.
const pathFolderTrustMs = 5_000;
// A folder changed this recently is listed again: a coarse clock could hide
// a second change.
const pathFolderSettleMs = 2_000;
const maxShimBytes = 64 << 10;
const versionProbeTimeoutMs = 15_000;
const maxPackageJsonBytes = 256 << 10;
const packageVersionPattern = /^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$/u;

type CachedFile = Readonly<{ path: string; size: number; modifiedMs: number }>;

type CachedExecutableProbe = Readonly<{
  checkedAt: number;
  ttlMs: number;
  value: ExecutableEvidence | null;
  /** The executable, and the package.json its version came from. */
  files: readonly CachedFile[];
}>;

type PathFolder = Readonly<{
  modifiedMs: number;
  listedAt: number;
  checkedAt: number;
  /** null: missing or unreadable; undefined: too large to keep. */
  names: ReadonlySet<string> | null | undefined;
}>;

/**
 * Remembers which agent CLIs are installed between discovery passes.
 * Discovery runs every ten seconds, while installs change rarely.
 *
 * - An npm-installed CLI's version comes from its package's package.json,
 *   found from the executable or its npm shim, with no process started.
 *   It is read again when the executable or package.json changes (an
 *   upgrade rewrites package.json; npm shims stay unchanged).
 * - Otherwise the CLI's `--version` runs, which starts its runtime (for
 *   an npm `.cmd` shim, PowerShell): again when the executable changes, or
 *   after `foundTtlMs` (an hour).
 * - A version that could not be read is tried again after
 *   `unreadableTtlMs` (ten minutes), and a CLI not found after
 *   `missingTtlMs` (a minute).
 *
 * PATH folders are listed and kept while their modified time stays the
 * same, so looking for absent CLIs no longer checks every folder and
 * extension one by one (thousands of checks a minute on Windows).
 */
export class ExecutableProbeCache {
  readonly #entries = new Map<string, CachedExecutableProbe>();
  readonly #folders = new Map<string, PathFolder>();
  readonly #folderChecks = new Map<string, Promise<ReadonlySet<string> | null | undefined>>();
  readonly #foundTtlMs: number;
  readonly #missingTtlMs: number;
  readonly #unreadableTtlMs: number;
  readonly #clock: () => number;

  constructor(
    options: Readonly<{
      foundTtlMs?: number;
      missingTtlMs?: number;
      unreadableTtlMs?: number;
      clock?: () => number;
    }> = {},
  ) {
    this.#foundTtlMs = options.foundTtlMs ?? 60 * 60_000;
    this.#missingTtlMs = options.missingTtlMs ?? 60_000;
    this.#unreadableTtlMs = options.unreadableTtlMs ?? 10 * 60_000;
    this.#clock = options.clock ?? Date.now;
  }

  async lookup(key: string): Promise<
    Readonly<{ value: ExecutableEvidence | null }> | undefined
  > {
    const cached = this.#entries.get(key);
    if (cached === undefined) return undefined;
    const age = this.#clock() - cached.checkedAt;
    if (age < 0 || age >= cached.ttlMs) return undefined;
    for (const file of cached.files) {
      try {
        const metadata = await stat(file.path);
        if (metadata.size !== file.size || metadata.mtimeMs !== file.modifiedMs) return undefined;
      } catch {
        return undefined;
      }
    }
    return { value: cached.value };
  }

  async remember(
    key: string,
    value: ExecutableEvidence | null,
    executablePath: string | null,
    versionFile: string | null = null,
  ): Promise<void> {
    const checkedAt = this.#clock();
    const ttlMs = value === null
      ? this.#missingTtlMs
      : value.version === "" ? this.#unreadableTtlMs : this.#foundTtlMs;
    const files: CachedFile[] = [];
    for (const path of [executablePath, versionFile]) {
      if (path === null) continue;
      try {
        const metadata = await stat(path);
        files.push({ path, size: metadata.size, modifiedMs: metadata.mtimeMs });
      } catch {
        return;
      }
    }
    this.#entries.delete(key);
    this.#entries.set(key, { checkedAt, ttlMs, value, files });
    if (this.#entries.size > maxCachedExecutableProbes) {
      const oldest = this.#entries.keys().next().value;
      if (oldest !== undefined) this.#entries.delete(oldest);
    }
  }

  /**
   * The entry names of a PATH folder (lower-cased when `caseInsensitive`),
   * null when it is missing or unreadable, or undefined when it should be
   * checked name by name instead.
   */
  async pathFolderNames(
    directory: string,
    caseInsensitive: boolean,
  ): Promise<ReadonlySet<string> | null | undefined> {
    const key = `${caseInsensitive ? "i" : "s"}\u0000${directory}`;
    const now = this.#clock();
    const cached = this.#folders.get(key);
    if (cached !== undefined && now >= cached.checkedAt && now - cached.checkedAt < pathFolderTrustMs) {
      return cached.names;
    }
    const pending = this.#folderChecks.get(key);
    if (pending !== undefined) return pending;
    const check = this.#checkPathFolder(key, directory, caseInsensitive, now, cached)
      .finally(() => this.#folderChecks.delete(key));
    this.#folderChecks.set(key, check);
    return check;
  }

  async #checkPathFolder(
    key: string,
    directory: string,
    caseInsensitive: boolean,
    now: number,
    cached: PathFolder | undefined,
  ): Promise<ReadonlySet<string> | null | undefined> {
    const keep = (folder: PathFolder) => {
      this.#folders.delete(key);
      this.#folders.set(key, folder);
      if (this.#folders.size > maxCachedPathFolders) {
        const oldest = this.#folders.keys().next().value;
        if (oldest !== undefined) this.#folders.delete(oldest);
      }
      return folder.names;
    };
    let modifiedMs: number;
    try {
      const metadata = await stat(directory);
      if (!metadata.isDirectory()) {
        return keep({ modifiedMs: Number.NaN, listedAt: now, checkedAt: now, names: null });
      }
      modifiedMs = metadata.mtimeMs;
    } catch (error) {
      if (isNodeError(error) && ["ENOENT", "ENOTDIR", "EACCES", "EPERM"].includes(String(error.code))) {
        return keep({ modifiedMs: Number.NaN, listedAt: now, checkedAt: now, names: null });
      }
      return undefined;
    }
    if (
      cached !== undefined && cached.names !== null && cached.modifiedMs === modifiedMs &&
      cached.listedAt - modifiedMs >= pathFolderSettleMs
    ) {
      return keep({ ...cached, checkedAt: now });
    }
    let entries: string[];
    try {
      entries = await readdir(directory);
    } catch {
      return undefined;
    }
    const names = entries.length > maxListedPathEntries
      ? undefined
      : new Set(caseInsensitive ? entries.map((name) => name.toLowerCase()) : entries);
    return keep({ modifiedMs, listedAt: now, checkedAt: now, names });
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
        const installed = await packageVersion(executablePath, this.#platform);
        const probed = installed === undefined ? await readVersion(executablePath) : undefined;
        const value: ExecutableEvidence = {
          executableName: normalizedExecutableName(candidate),
          executablePathDigest: digest(executablePath),
          version: installed?.version ?? probed?.version ?? "",
          // Which program it is, for a name other programs share.
          ...(installed === undefined ? {} : { packageName: installed.name }),
          ...(probed?.banner ? { versionBanner: probed.banner } : {}),
        };
        await this.#executableCache?.remember(cacheKey, value, executablePath, installed?.file ?? null);
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
        const expanded = this.#expandSetting(candidate);
        if (expanded === undefined) continue;
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

  /**
   * A configuration path: `~` is the home folder, and `$NAME` is the folder
   * an agent's own setting names, such as $CODEX_HOME. A setting that is
   * not set, or not an absolute path, names nothing.
   */
  #expandSetting(candidate: string): string | undefined {
    const setting = /^\$([A-Z][A-Z0-9_]*)(?:[\\/](.*))?$/u.exec(candidate);
    if (setting === null) return expandHome(candidate);
    const folder = this.#environmentValue(setting[1]!)?.trim();
    if (!folder || !isAbsolute(folder)) return undefined;
    return setting[2] ? join(folder, setting[2]) : folder;
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
    // Windows and macOS file systems ignore case, as access() does there.
    const caseInsensitive = this.#platform === "win32" || this.#platform === "darwin";
    for (const directory of pathValue.split(delimiter)) {
      if (directory.length === 0) continue;
      const names = await this.#executableCache?.pathFolderNames(directory, caseInsensitive);
      if (names === null) continue;
      for (const extension of extensions) {
        const name = `${candidate}${extension}`;
        // A name the folder does not hold is not checked on disk.
        if (names !== undefined && !names.has(caseInsensitive ? name.toLowerCase() : name)) continue;
        const executablePath = join(directory, name);
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
 * How Windows process listing has been going, kept between discovery
 * passes. When the native helper fails (blocked by application control,
 * crashing), it is tried again after 10 s, then 20 s, 40 s... up to five
 * minutes, and PowerShell lists the processes instead. PowerShell costs
 * 0.3-1 s of CPU each time, so its listing is reused for a while too:
 * after the first one, for 20 s, 40 s... up to five minutes. A stopped
 * agent can then look running for that long; nothing acts on it without
 * checking the process again (see process-tree.ts). All of this resets
 * as soon as the helper works again.
 */
export type WindowsListingState = {
  nativeFailures: number;
  nativeRetryAt: number;
  powerShellRuns: number;
  powerShell: Readonly<{ processes: readonly ProcessEvidence[]; reuseUntil: number }> | undefined;
};

export function newWindowsListingState(): WindowsListingState {
  return { nativeFailures: 0, nativeRetryAt: 0, powerShellRuns: 0, powerShell: undefined };
}

const windowsListingState = newWindowsListingState();
const listingBackoffBaseMs = 10_000;
const listingBackoffMaxMs = 5 * 60_000;

function listingBackoff(attempt: number): number {
  return Math.min(listingBackoffMaxMs, listingBackoffBaseMs * 2 ** Math.min(Math.max(0, attempt - 1), 16));
}

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
    windowsListingState,
  );
}

/**
 * The processes from the native helper, or else from PowerShell. With
 * `state`, failures back off as WindowsListingState says; without it,
 * every call tries both.
 */
export async function listWindowsProcesses(
  native: (() => Promise<string>) | undefined,
  powerShell: () => Promise<string>,
  state?: WindowsListingState,
  now: number = Date.now(),
): Promise<readonly ProcessEvidence[]> {
  if (native !== undefined && (state === undefined || now >= state.nativeRetryAt)) {
    try {
      const processes = windowsProcessEvidence(nativeProcessValues(await native()));
      if (state !== undefined) Object.assign(state, newWindowsListingState());
      return processes;
    } catch {
      // A crashed, timed-out, blocked or unreadable helper is tried again
      // later.
      if (state !== undefined) {
        state.nativeFailures++;
        state.nativeRetryAt = now + listingBackoff(state.nativeFailures);
      }
    }
  }
  if (state?.powerShell !== undefined && now < state.powerShell.reuseUntil) {
    return state.powerShell.processes;
  }
  const parsed: unknown = JSON.parse(await powerShell());
  const processes = windowsProcessEvidence(Array.isArray(parsed) ? parsed : [parsed]);
  if (state !== undefined) {
    state.powerShellRuns++;
    state.powerShell = {
      processes,
      reuseUntil: state.powerShellRuns <= 1 ? now : now + listingBackoff(state.powerShellRuns),
    };
  }
  return processes;
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

/**
 * The version of the npm package an installed CLI runs, from its
 * package.json, and that file. Found from the npm shim that starts it
 * (`%dp0%\\node_modules\\<package>\\...` in a `.cmd`, `$basedir/...` in a
 * PowerShell or shell shim), or from the executable's own path once links
 * are resolved (`/usr/local/bin/codex` links into
 * `lib/node_modules/@openai/codex`). Undefined when it is not an npm
 * package, so `--version` is run instead.
 */
export async function packageVersion(
  executablePath: string,
  platform: NodeJS.Platform = process.platform,
): Promise<Readonly<{ version: string; file: string; name: string }> | undefined> {
  const candidates: string[] = [];
  try {
    const metadata = await stat(executablePath);
    if (metadata.isFile() && metadata.size <= maxShimBytes) {
      const shim = platform === "win32" && /\.(cmd|bat|ps1)$/iu.test(executablePath);
      const text = await readFile(executablePath, "utf8");
      if (shim || text.startsWith("#!")) {
        const base = dirname(executablePath);
        for (const match of text.matchAll(/(?:%~?dp0%?|\$\{?basedir\}?)[\\/]*([^"'\s*?<>|%$]+)/gu)) {
          const relative = match[1];
          if (relative !== undefined) candidates.push(resolve(base, relative));
        }
      }
    }
    candidates.push(await realpath(executablePath));
  } catch {
    // Unreadable: the version comes from running it, if anything.
  }
  for (const candidate of candidates) {
    const installed = npmPackageOf(candidate);
    if (installed === undefined) continue;
    const file = join(installed.directory, "package.json");
    try {
      const metadata = await stat(file);
      if (!metadata.isFile() || metadata.size > maxPackageJsonBytes) continue;
      const manifest: unknown = JSON.parse(await readFile(file, "utf8"));
      if (typeof manifest !== "object" || manifest === null) continue;
      const { name, version } = manifest as Record<string, unknown>;
      if (
        name === installed.name && typeof version === "string" &&
        version.length <= 64 && packageVersionPattern.test(version)
      ) {
        return { version, file, name: installed.name };
      }
    } catch {
      // Not this one.
    }
  }
  return undefined;
}

/** The npm package folder and name a path lies in, from its last node_modules. */
function npmPackageOf(path: string): Readonly<{ directory: string; name: string }> | undefined {
  const parts = path.split(/[\\/]/u);
  const at = parts.lastIndexOf("node_modules");
  if (at < 0) return undefined;
  const first = parts[at + 1];
  if (first === undefined || first === "" || first.startsWith(".")) return undefined;
  const scoped = first.startsWith("@");
  const second = scoped ? parts[at + 2] : undefined;
  if (scoped && (second === undefined || second === "" || second.startsWith("."))) return undefined;
  const length = at + (scoped ? 3 : 2);
  const separator = path.includes("\\") && !path.includes("/") ? "\\" : "/";
  return {
    directory: parts.slice(0, length).join(separator),
    name: scoped ? `${first}/${second}` : first,
  };
}

/** The version `--version` prints, and its first line (see ExecutableEvidence). */
async function readVersion(executablePath: string): Promise<Readonly<{ version: string; banner: string }>> {
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
        // closely monitored computer, as for the PowerShell process listing,
        // and some native CLIs are as slow to answer (GitHub Copilot's
        // copilot.exe from WinGet takes 6-10 s). A probe result is cached
        // until the executable changes or for an hour, so a slow answer is
        // paid that rarely.
        timeout: versionProbeTimeoutMs,
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
    const output = `${stdout}\n${stderr}`.slice(0, 4_096);
    const match = versionPattern.exec(output);
    const banner = output.split(/\r?\n/u).map((line) => line.replace(/[\u0000-\u001f\u007f]/gu, "").trim())
      .find((line) => line.length > 0) ?? "";
    return { version: match?.[0]?.slice(0, 64) ?? "", banner: banner.slice(0, 128) };
  } catch {
    return { version: "", banner: "" };
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
