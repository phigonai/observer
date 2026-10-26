import { execFileSync } from "node:child_process";
import { chmodSync } from "node:fs";
import { chmod } from "node:fs/promises";
import { resolve } from "node:path";

// chmod only changes the read-only flag on Windows, so the credential store and
// event spool would otherwise rely on the profile folder's default ACL. Owner
// and SYSTEM keep access; files created inside inherit the restriction.
const restricted = new Set<string>();

function restrictWindowsDirectory(path: string): void {
  const key = resolve(path).toLowerCase();
  if (restricted.has(key)) return;
  const owner = `${process.env["USERDOMAIN"] ?? ""}\\${process.env["USERNAME"] ?? ""}`;
  try {
    execFileSync(
      "icacls",
      [resolve(path), "/inheritance:r", "/grant:r", `${owner}:(OI)(CI)F`, "/grant:r", "*S-1-5-18:(OI)(CI)F"],
      { windowsHide: true, stdio: "ignore", timeout: 15_000 },
    );
  } catch {
    // Storing a credential or activity under an open ACL would defeat the
    // point of this directory, so refuse instead of continuing silently.
    throw new Error("Could not restrict the Phigon data directory to the current user. Choose a data directory on an NTFS drive that you own.");
  }
  restricted.add(key);
}

/** Restrict an existing directory to its owner on every platform. */
export async function makeDirectoryPrivate(path: string): Promise<void> {
  await chmod(path, 0o700);
  if (process.platform === "win32") restrictWindowsDirectory(path);
}

export function makeDirectoryPrivateSync(path: string): void {
  chmodSync(path, 0o700);
  if (process.platform === "win32") restrictWindowsDirectory(path);
}
