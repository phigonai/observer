import { execFile } from "node:child_process";
import { fileURLToPath } from "node:url";

export function guardianRunnerPath(): string {
  const os = process.platform === "win32" ? "windows" : process.platform;
  const arch = process.arch === "x64" ? "amd64" : process.arch;
  return fileURLToPath(new URL(`../bin/guardian-runner-${os}-${arch}${os === "windows" ? ".exe" : ""}`, import.meta.url));
}
export async function killVerifiedWindowsProcess(processId: number, startedAt: string): Promise<void> {
  await new Promise<void>((resolve, reject) => execFile(guardianRunnerPath(), ["--kill-pid", String(processId), "--started-at", startedAt], {
    windowsHide: true, timeout: 8_000, maxBuffer: 4096,
  }, (error) => error ? reject(error) : resolve()));
}
