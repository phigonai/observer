import { renameSync } from "node:fs";
import { rename } from "node:fs/promises";
import { setTimeout as delay } from "node:timers/promises";

/** Preserve both files while Windows readers or scanners briefly hold a lock. */
export async function atomicReplace(
  temporary: string,
  destination: string,
  replace: typeof rename = rename,
): Promise<void> {
  for (let attempt = 0; ; attempt++) {
    try {
      await replace(temporary, destination);
      return;
    } catch (error) {
      if (!retryable(error, attempt)) throw error;
      await delay(retryDelayMs(attempt));
    }
  }
}

/**
 * The same for synchronous writers such as the telemetry spool. The wait
 * blocks, like the synchronous write around it, and only after Windows
 * refused the rename: at most about 0.6 seconds in all.
 */
export function atomicReplaceSync(
  temporary: string,
  destination: string,
  replace: typeof renameSync = renameSync,
): void {
  for (let attempt = 0; ; attempt++) {
    try {
      replace(temporary, destination);
      return;
    } catch (error) {
      if (!retryable(error, attempt)) throw error;
      Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, retryDelayMs(attempt));
    }
  }
}

function retryable(error: unknown, attempt: number): boolean {
  const code = (error as NodeJS.ErrnoException | undefined)?.code;
  return process.platform === "win32" && attempt < 5 && ["EPERM", "EACCES", "EBUSY"].includes(code ?? "");
}

function retryDelayMs(attempt: number): number {
  return 20 * 2 ** attempt;
}
