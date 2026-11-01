import { setTimeout as delay } from "node:timers/promises";

/**
 * Wait `milliseconds`, or less once `signal` aborts. An abort ends the wait
 * quietly; it never rejects.
 *
 * The observer's loops wait here for their whole lifetime, some every 100 ms,
 * on one long-lived signal. The promise timer removes its abort listener when
 * it fires, so finished waits leave nothing attached to that signal.
 */
export async function abortableDelay(
  milliseconds: number,
  signal?: AbortSignal,
): Promise<void> {
  if (signal?.aborted === true) return;
  try {
    await delay(milliseconds, undefined, signal === undefined ? {} : { signal });
  } catch (error) {
    if (!(error instanceof Error && error.name === "AbortError")) throw error;
  }
}
