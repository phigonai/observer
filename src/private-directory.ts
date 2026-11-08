import { execFileSync } from "node:child_process";
import { chmodSync } from "node:fs";
import { chmod } from "node:fs/promises";
import { resolve } from "node:path";
import { windowsSystemTool } from "./system-tools.js";

// chmod only changes the read-only flag on Windows, so the credential store and
// event spool would otherwise rely on the profile folder's default ACL. Owner
// and SYSTEM keep access; files created inside inherit the restriction.
const restricted = new Set<string>();
// The account this process runs as, by security identifier: null when
// Windows would not say.
let processUserSID: string | null | undefined;

/**
 * The current account's SID from whoami. A name built from USERDOMAIN and
 * USERNAME does not resolve for every account: services that run as
 * LocalSystem or a virtual account see names icacls cannot look up.
 */
export function currentUserSID(): string | undefined {
  if (processUserSID === undefined) {
    processUserSID = null;
    try {
      // By full path: Git for Windows puts another whoami on PATH.
      const output = execFileSync(windowsSystemTool("whoami.exe"), ["/user", "/fo", "csv", "/nh"], {
        encoding: "utf8",
        windowsHide: true,
        stdio: ["ignore", "pipe", "ignore"],
        timeout: 15_000,
      });
      processUserSID = /"(S-1-[0-9]+(?:-[0-9]+){1,15})"\s*$/u.exec(output.trim())?.[1] ?? null;
    } catch {
      // Fall back to the account name below.
    }
  }
  return processUserSID ?? undefined;
}

/**
 * The icacls command that leaves `path` to `owner` and SYSTEM. icacls goes
 * by its full path, never found in the current folder.
 */
export function restrictCommand(path: string, owner: string): Readonly<{ file: string; args: readonly string[] }> {
  return {
    file: windowsSystemTool("icacls.exe"),
    args: [resolve(path), "/inheritance:r", "/grant:r", `${owner}:(OI)(CI)F`, "/grant:r", "*S-1-5-18:(OI)(CI)F"],
  };
}

function restrictWindowsDirectory(path: string): void {
  const key = resolve(path).toLowerCase();
  if (restricted.has(key)) return;
  const sid = currentUserSID();
  const owner = sid === undefined
    ? `${process.env["USERDOMAIN"] ?? ""}\\${process.env["USERNAME"] ?? ""}`
    : `*${sid}`;
  try {
    const command = restrictCommand(path, owner);
    execFileSync(command.file, command.args, { windowsHide: true, stdio: "ignore", timeout: 15_000 });
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
