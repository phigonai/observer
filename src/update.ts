import { spawn } from "node:child_process";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";

const versionPattern = /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/u;
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
      if (typeof cache.checkedAt === "number" && now >= cache.checkedAt && now - cache.checkedAt < 24 * 60 * 60 * 1000 &&
          (cache.version === null || (typeof cache.version === "string" && versionPattern.test(cache.version)))) return cache.version;
    } catch { /* Missing or malformed cache is safe to replace. */ }
  }
  let version: string | null = null;
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
      if (value.name === "@phigon/observer" && typeof value.version === "string" && versionPattern.test(value.version)) version = value.version;
    } finally { await reader.cancel().catch(() => undefined); }
  } catch { /* Offline update checks must not block monitoring or pairing. */ }
  try {
    await mkdir(directory, { recursive: true, mode: 0o700 });
    await writeFile(cachePath, JSON.stringify({ checkedAt: now, version }), { mode: 0o600 });
  } catch { /* A cache is optional. */ }
  return version;
}

export async function installObserverUpdate(version: string): Promise<void> {
  if (!versionPattern.test(version)) throw new Error("Invalid observer version.");
  const args = ["install", "--global", `@phigon/observer@${version}`, "--registry=https://registry.npmjs.org"];
  // cmd is needed for npm.cmd on Windows; every argument above is fixed or a
  // validated numeric version. No caller-controlled shell syntax is accepted.
  const command = process.platform === "win32" ? "cmd.exe" : "npm";
  const commandArgs = process.platform === "win32" ? ["/d", "/s", "/c", `npm ${args.join(" ")}`] : args;
  await new Promise<void>((resolve, reject) => {
    const child = spawn(command, commandArgs, { stdio: "inherit", windowsHide: true, shell: false });
    child.once("error", () => reject(new Error("Could not start npm. Run npm install --global @phigon/observer manually.")));
    child.once("exit", (code) => code === 0 ? resolve() : reject(new Error("Update failed. Check npm permissions and network access, then run npm install --global @phigon/observer. Your pairing data was not removed.")));
  });
}

export async function offerObserverUpdate(options: {
  current: string; latest: string | null; confirm: () => Promise<string>;
  write: (message: string) => void; install?: (version: string) => Promise<void>;
}): Promise<boolean> {
  if (!options.latest || !newerVersion(options.current, options.latest)) return false;
  options.write(`A new Phigon observer version is available: ${options.current} → ${options.latest}.\nType "yes" to update, or press Enter to continue: `);
  if ((await options.confirm()).trim().toLowerCase() !== "yes") return false;
  await (options.install ?? installObserverUpdate)(options.latest);
  options.write("Observer updated. Run your command again. Restart the observer service if it is running; your pairing and queued activity are preserved.\n");
  return true;
}
