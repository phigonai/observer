import { fileURLToPath } from "node:url";

export function guardianRunnerPath(): string {
  const os = process.platform === "win32" ? "windows" : process.platform;
  const arch = process.arch === "x64" ? "amd64" : process.arch;
  return fileURLToPath(new URL(`../bin/guardian-runner-${os}-${arch}${os === "windows" ? ".exe" : ""}`, import.meta.url));
}
