/**
 * The server's idea of the time, estimated from the times it stamps on the
 * stream (acknowledgements and policies). Remote commands carry an expiry in
 * server time, so judging it by a computer clock that is a few minutes off
 * would reject or extend every command.
 *
 * Each sample is the server's stamp minus the local time it arrived, which
 * is the true offset less the one-way network delay: well under a second,
 * against command windows of minutes. The estimate is the median of recent
 * samples, so one odd stamp does not move it, and it is bounded so a broken
 * stamp cannot move the clock arbitrarily far.
 */
export class ServerClock {
  readonly #now: () => number;
  readonly #maxCorrectionMs: number;
  readonly #largeSkewMs: number;
  readonly #onLargeSkew: (offsetMs: number) => void;
  readonly #samples: number[] = [];
  #offsetMs = 0;
  // The offset last reported as large, so a steady skew is reported once.
  #reportedOffsetMs: number | undefined;

  constructor(options: Readonly<{
    now?: () => number;
    /** The largest correction applied; larger offsets are clamped to it. */
    maxCorrectionMs?: number;
    /** Skews at least this large are reported. */
    largeSkewMs?: number;
    onLargeSkew?: (offsetMs: number) => void;
  }> = {}) {
    this.#now = options.now ?? Date.now;
    this.#maxCorrectionMs = options.maxCorrectionMs ?? maxCorrectionMs;
    this.#largeSkewMs = options.largeSkewMs ?? largeSkewMs;
    this.#onLargeSkew = options.onLargeSkew ?? (() => undefined);
  }

  /** Records a server timestamp that arrived just now. */
  observe(serverTime: Date): void {
    const sample = serverTime.getTime() - this.#now();
    if (!Number.isFinite(sample)) return;
    this.#samples.push(sample);
    if (this.#samples.length > retainedSamples) this.#samples.shift();
    const sorted = [...this.#samples].sort((left, right) => left - right);
    const median = sorted[Math.floor(sorted.length / 2)] ?? 0;
    this.#offsetMs = Math.max(
      -this.#maxCorrectionMs,
      Math.min(this.#maxCorrectionMs, median),
    );
    const large = Math.abs(median) >= this.#largeSkewMs;
    if (!large) {
      this.#reportedOffsetMs = undefined;
    } else if (
      this.#reportedOffsetMs === undefined ||
      Math.abs(median - this.#reportedOffsetMs) >= this.#largeSkewMs
    ) {
      this.#reportedOffsetMs = median;
      this.#onLargeSkew(median);
    }
  }

  /** How far the server's clock is ahead of this computer's, as applied. */
  offsetMs(): number {
    return this.#offsetMs;
  }

  /** The current time on the server's clock, in epoch milliseconds. */
  now(): number {
    return this.#now() + this.#offsetMs;
  }
}

/** A plain-English description of a clock skew, for status messages. */
export function describeClockSkew(offsetMs: number): string {
  const seconds = Math.round(Math.abs(offsetMs) / 1_000);
  const amount = seconds >= 120
    ? `${Math.round(seconds / 60)} minutes`
    : `${seconds} seconds`;
  return `This computer's clock is ${amount} ${offsetMs > 0 ? "behind" : "ahead of"} the workspace server. ` +
    "Remote commands are timed by the server's clock; correct the computer's clock to keep other tools accurate.";
}

const retainedSamples = 9;
// Covers a clock set to the wrong time zone, as on a computer that also
// starts another operating system, without trusting a wildly wrong stamp.
const maxCorrectionMs = 24 * 3_600_000;
const largeSkewMs = 60_000;
