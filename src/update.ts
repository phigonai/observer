import { spawn } from "node:child_process";
import { existsSync, realpathSync } from "node:fs";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { join, posix, win32 } from "node:path";
import { fileURLToPath } from "node:url";

const versionPattern = /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/u;
const cacheTTLms = 24 * 60 * 60 * 1000;
const failureRetryMs = 15 * 60 * 1000;
const registryURL = "https://registry.npmjs.org/@phigon%2fobserver/latest";
export function newerVersion(current: string, latest: string): boolean {
  if (!versionPattern.test(current) || !versionPattern.test(latest)) return false;
  const before = current.split(".").map(Number);
  const after = latest.split(".").map(Number);
  for (let index = 0; index < 3; index++) {
    if (after[index] !== before[index]) return after[index]! > before[index]!;
  }
  return false;
}

export async function latestObserverVersion(directory: string, options: {
  force?: boolean; fetcher?: typeof fetch; now?: number;
} = {}): Promise<string | null> {
  const now = options.now ?? Date.now();
  const cachePath = join(directory, "update-check.json");
  if (!options.force) {
    try {
      const cache = JSON.parse(await readFile(cachePath, "utf8")) as { checkedAt?: number; version?: string | null };
      if (typeof cache.checkedAt === "number" && now >= cache.checkedAt && now - cache.checkedAt < cacheTTLms &&
          (cache.version === null || (typeof cache.version === "string" && versionPattern.test(cache.version)))) return cache.version;
    } catch { /* Missing or malformed cache is safe to replace. */ }
  }
  let version: string | null = null;
  let checked = false;
  try {
    const response = await (options.fetcher ?? fetch)(registryURL, { signal: AbortSignal.timeout(1500), redirect: "error", headers: { Accept: "application/json" } });
    if (!response.ok || !response.body) throw new Error("Registry unavailable.");
    const reader = response.body.getReader();
    const chunks: Uint8Array[] = [];
    let size = 0;
    try {
      while (true) {
        const next = await reader.read();
        if (next.done) break;
        size += next.value.byteLength;
        if (size > 128 * 1024) throw new Error("Registry metadata exceeds limit.");
        chunks.push(next.value);
      }
      const value = JSON.parse(Buffer.concat(chunks).toString("utf8")) as { name?: unknown; version?: unknown };
      if (value.name === "@phigon/observer" && typeof value.version === "string" && versionPattern.test(value.version)) { version = value.version; checked = true; }
    } finally { await reader.cancel().catch(() => undefined); }
  } catch { /* Offline update checks must not block monitoring or pairing. */ }
  try {
    await mkdir(directory, { recursive: true, mode: 0o700 });
    // A failed lookup is retried soon; only a real answer is cached for a day.
    await writeFile(cachePath, JSON.stringify({ checkedAt: checked ? now : now - cacheTTLms + failureRetryMs, version }), { mode: 0o600 });
  } catch { /* A cache is optional. */ }
  return version;
}

/**
 * npm's own script, `npm-cli.js`, of the npm that came with the Node.js at
 * `execPath`, by absolute path; never the first `npm` on PATH, which can
 * belong to another Node.js and install somewhere else. Windows keeps it in
 * node_modules next to node.exe; elsewhere `bin/npm` beside node links to
 * it under lib (or Homebrew's libexec/lib).
 */
export function bundledNpmCli(
  execPath: string = process.execPath,
  platform: NodeJS.Platform = process.platform,
  exists: (path: string) => boolean = existsSync,
  real: (path: string) => string = realpathSync.native,
): string | undefined {
  const paths = platform === "win32" ? win32 : posix;
  const directory = paths.dirname(execPath);
  const script = ["node_modules", "npm", "bin", "npm-cli.js"];
  const candidates: string[] = [];
  if (platform === "win32") {
    candidates.push(paths.join(directory, ...script));
  } else {
    try {
      const linked = real(paths.join(directory, "npm"));
      if (paths.basename(linked) === "npm-cli.js") candidates.push(linked);
    } catch { /* No npm link beside this Node.js. */ }
    candidates.push(
      paths.join(directory, "..", "lib", ...script),
      paths.join(directory, "..", "libexec", "lib", ...script),
    );
  }
  return candidates.find((candidate) => exists(candidate));
}

/** The folder of the observer package that is running: dist/src/update.js is two levels below it. */
export const runningPackageRoot = fileURLToPath(new URL("../../", import.meta.url));

/** The version in a package's package.json, or undefined when it cannot be read. */
export async function packageVersion(packageRoot: string): Promise<string | undefined> {
  try {
    const value = JSON.parse(await readFile(join(packageRoot, "package.json"), "utf8")) as { version?: unknown };
    return typeof value.version === "string" ? value.version : undefined;
  } catch {
    return undefined;
  }
}

export type InstallUpdateOptions = Readonly<{
  /** The Node.js running the observer; its own npm installs the update. */
  execPath?: string;
  platform?: NodeJS.Platform;
  /** This installation, which must have the new version afterwards. */
  packageRoot?: string;
  /** Runs a program without a shell and resolves with its exit code; tests replace it. */
  run?: (command: string, args: readonly string[]) => Promise<number>;
  npmCli?: string | undefined;
}>;

/**
 * Installs `version` with the npm of the Node.js running the observer, then
 * checks that this installation, the one the background service runs, now
 * has it. npm installing into another folder (another Node.js, another
 * prefix, a Volta or source install) is reported as a failure, not success.
 */
export async function installObserverUpdate(version: string, options: InstallUpdateOptions = {}): Promise<void> {
  if (!versionPattern.test(version)) throw new Error("Invalid observer version.");
  const execPath = options.execPath ?? process.execPath;
  const packageRoot = options.packageRoot ?? runningPackageRoot;
  const npmCli = "npmCli" in options ? options.npmCli : bundledNpmCli(execPath, options.platform);
  if (npmCli === undefined) {
    throw new Error(
      `The npm that came with this Node.js (${execPath}) was not found, so the observer was not updated. ` +
        `Update it with the tool that installed it, for example: npm install --global @phigon/observer@${version}`,
    );
  }
  const run = options.run ?? runWithoutShell;
  // Every argument is fixed or a validated numeric version, and no shell runs.
  const code = await run(execPath, [npmCli, "install", "--global", `@phigon/observer@${version}`, "--registry=https://registry.npmjs.org"])
    .catch(() => -1);
  if (code !== 0) {
    throw new Error(
      code === -1
        ? `Could not start npm (${npmCli}). Run npm install --global @phigon/observer@${version} manually. Your pairing data was not removed.`
        : "Update failed. Check npm permissions and network access, then run npm install --global @phigon/observer. Your pairing data was not removed.",
    );
  }
  const installed = await packageVersion(packageRoot);
  if (installed !== version) {
    throw new Error(
      `npm finished, but the observer in ${packageRoot} is still ${installed ?? "unreadable"}, not ${version}: ` +
        "npm installed the update into another folder. Update this observer with the tool that installed it " +
        "(npm, Volta, mise or a package manager), then run phigon-observer service install. Your pairing data was not removed.",
    );
  }
}

function runWithoutShell(command: string, args: readonly string[]): Promise<number> {
  return new Promise<number>((resolve, reject) => {
    const child = spawn(command, [...args], { stdio: "inherit", windowsHide: true, shell: false });
    child.once("error", reject);
    child.once("exit", (code) => resolve(code ?? 1));
  });
}

export async function offerObserverUpdate(options: {
  current: string; latest: string | null;
  /** Asks the person at the computer; without it, `update --yes` approved the update already. */
  confirm?: (() => Promise<string>) | undefined;
  write: (message: string) => void; install?: (version: string) => Promise<void>;
}): Promise<boolean> {
  if (!options.latest || !newerVersion(options.current, options.latest)) return false;
  if (options.confirm === undefined) {
    options.write(`Updating the Phigon observer from ${options.current} to ${options.latest}.\n`);
  } else {
    options.write(`A new Phigon observer version is available: ${options.current} → ${options.latest}.\nType "yes" to update, or press Enter to continue: `);
    if ((await options.confirm()).trim().toLowerCase() !== "yes") return false;
  }
  await (options.install ?? installObserverUpdate)(options.latest);
  options.write("Observer updated. Your pairing and queued activity are preserved. Run your command again.\n");
  return true;
}
