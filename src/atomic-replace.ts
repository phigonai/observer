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
      const code = (error as NodeJS.ErrnoException).code;
      if (process.platform !== "win32" || attempt >= 5 || !["EPERM", "EACCES", "EBUSY"].includes(code ?? "")) throw error;
      await delay(20 * 2 ** attempt);
    }
  }
}
