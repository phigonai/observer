import { createHash } from "node:crypto";
import { readFileSync, statSync } from "node:fs";
import { basename, dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

/**
 * The SHA-256 of every Guardian runner built with this package, written
 * beside them when the package is built (scripts/build-guardian-runner.mjs)
 * and checked before release (scripts/verify-guardian-release.mjs).
 */
export const guardianManifestName = "guardian-runner.sha256.json";

export const guardianRunnerUnverifiedMessage =
  "The Guardian runner that came with the observer does not match the checksum it was built with, so it was not started. " +
  "Reinstall the observer: npm install --global @phigon/observer.";

/** Where this platform's Guardian runner is, checked or not. */
export function guardianRunnerFile(): string {
  const os = process.platform === "win32" ? "windows" : process.platform;
  const arch = process.arch === "x64" ? "amd64" : process.arch;
  return fileURLToPath(new URL(`../bin/guardian-runner-${os}-${arch}${os === "windows" ? ".exe" : ""}`, import.meta.url));
}

/**
 * This platform's Guardian runner, once it matches the checksum it was built
 * with. A runner that is not there is returned as is, so starting it fails
 * with ENOENT as before (a development build without Go, for example); one
 * that does not match, or has no checksum, throws.
 */
export function guardianRunnerPath(): string {
  const path = guardianRunnerFile();
  verifyGuardianRunner(path);
  return path;
}

// Checked once for each file identity: a changed file is checked again.
const checked = new Map<string, Readonly<{ identity: string; matches: boolean }>>();

/** Throws unless `path` matches its SHA-256 in `manifestPath`; a missing file passes. */
export function verifyGuardianRunner(path: string, manifestPath = join(dirname(path), guardianManifestName)): void {
  let identity: string;
  try {
    const stats = statSync(path, { bigint: true });
    identity = `${stats.dev}:${stats.ino}:${stats.size}:${stats.mtimeNs}:${stats.ctimeNs}`;
  } catch {
    return;
  }
  let result = checked.get(path);
  if (result?.identity !== identity) {
    result = { identity, matches: matchesManifest(path, manifestPath) };
    if (checked.size >= 16) checked.clear();
    checked.set(path, result);
  }
  if (!result.matches) throw new Error(guardianRunnerUnverifiedMessage);
}

function matchesManifest(path: string, manifestPath: string): boolean {
  try {
    const manifest = JSON.parse(readFileSync(manifestPath, "utf8")) as { files?: Record<string, unknown> };
    const expected = manifest.files?.[basename(path)];
    if (typeof expected !== "string" || !/^[0-9a-f]{64}$/u.test(expected)) return false;
    return createHash("sha256").update(readFileSync(path)).digest("hex") === expected;
  } catch {
    return false;
  }
}
