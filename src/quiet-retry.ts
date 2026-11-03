/**
 * Spacing for a call that keeps failing: the first retry waits `initialMs`,
 * each failure after that doubles the wait up to `maxMs`, and a success
 * starts over.
 */
export class RetryBackoff {
  #delayMs = 0;
  #retryAt = 0;

  constructor(
    private readonly initialMs: number,
    private readonly maxMs: number,
  ) {}

  /** Whether a call may be made at `now`. */
  ready(now: number): boolean {
    return now >= this.#retryAt;
  }

  /**
   * Records a failure at `now`. Calls made together fail together: a
   * failure while a wait is already set does not lengthen it.
   */
  failed(now: number): void {
    if (now < this.#retryAt) return;
    this.#delayMs = this.#delayMs === 0
      ? this.initialMs
      : Math.min(this.#delayMs * 2, this.maxMs);
    this.#retryAt = now + this.#delayMs;
  }

  succeeded(): void {
    this.#delayMs = 0;
    this.#retryAt = 0;
  }
}

/**
 * Writes what a long-running loop reports when it changes, not on every
 * pass: a message is written when it differs from the last one on its
 * topic, and again after `repeatMs` so the log still shows a problem that
 * lasts. A caller clears a topic when its problem ends; past `maxTopics`
 * the topic reported longest ago is forgotten.
 */
export class StatusChanges {
  readonly #last = new Map<string, Readonly<{ message: string; at: number }>>();

  constructor(
    private readonly write: (message: string) => void,
    private readonly repeatMs: number,
    private readonly now: () => number = Date.now,
    private readonly maxTopics = 256,
  ) {}

  report(topic: string, message: string): void {
    const now = this.now();
    const last = this.#last.get(topic);
    if (last?.message === message && now - last.at < this.repeatMs) return;
    this.#last.delete(topic);
    this.#last.set(topic, { message, at: now });
    while (this.#last.size > this.maxTopics) {
      const oldest = this.#last.keys().next().value;
      if (oldest === undefined) break;
      this.#last.delete(oldest);
    }
    this.write(message);
  }

  /** Ends what `topic` reported, writing `message` when it had reported something. */
  clear(topic: string, message?: string): void {
    if (!this.#last.delete(topic)) return;
    if (message !== undefined) this.write(message);
  }
}

/** A short, single-line reason from an error, to put in brackets in a log line. */
export function errorSummary(error: unknown): string {
  const text = (error instanceof Error ? error.message : String(error))
    .replace(/\s+/gu, " ")
    .trim()
    .replace(/\.$/u, "");
  if (text === "") return "no detail";
  return text.length <= 200 ? text : `${text.slice(0, 197)}...`;
}
