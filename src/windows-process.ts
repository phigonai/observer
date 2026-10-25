import { execFile } from "node:child_process";
import { guardianRunnerPath } from "./guardian-native.js";

const taskkillTimeoutMs = 5_000;

/**
 * Requests Windows to close one exact PID without the /F force flag. This is a
 * graceful attempt, not a guarantee: applications that do not accept a normal
 * close request return an OS error and are never silently escalated.
 */
export function requestWindowsGracefulStop(processID: number, startedAt: string): Promise<void> {
  return new Promise((resolve, reject) => {
    execFile(
      guardianRunnerPath(),
      ["--kill-pid", String(processID), "--started-at", startedAt, "--graceful"],
      {
        windowsHide: true,
        timeout: taskkillTimeoutMs,
        maxBuffer: 16 << 10,
      },
      (error) => error === null ? resolve() : reject(error),
    );
  });
}
