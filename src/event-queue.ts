export type QueueMetrics = Readonly<{
  capacity: number;
  depth: number;
  utilization: number;
  dropped: number;
  coalesced: number;
  acknowledged: bigint;
  oldestSequence?: bigint;
  latestSequence?: bigint;
}>;

export type QueuedEvent<T> = Readonly<{
  value: T;
  sequence: bigint;
  coalesceKey?: string;
}>;

export class BoundedEventQueue<T> {
  readonly #capacity: number;
  #events: Array<QueuedEvent<T>> = [];
  #dropped = 0;
  #coalesced = 0;
  #acknowledged = 0n;

  constructor(capacity = 2048) {
    if (!Number.isSafeInteger(capacity) || capacity < 1) {
      throw new Error("Event queue capacity must be a positive integer.");
    }
    this.#capacity = capacity;
  }

  enqueue(
    value: T,
    sequence: bigint,
    coalesceKey?: string,
  ): void {
    if (sequence <= this.#acknowledged) return;
    if (coalesceKey !== undefined) {
      const index = this.#events.findIndex(
        (event) => event.coalesceKey === coalesceKey,
      );
      if (index >= 0) {
        this.#events[index] = { value, sequence, coalesceKey };
        this.#events.sort((left, right) =>
          left.sequence < right.sequence ? -1 : 1,
        );
        this.#coalesced++;
        return;
      }
    }
    if (this.#events.length >= this.#capacity) {
      this.#events.shift();
      this.#dropped++;
    }
    this.#events.push({
      value,
      sequence,
      ...(coalesceKey === undefined ? {} : { coalesceKey }),
    });
  }

  canEnqueue(coalesceKey?: string): boolean {
    return (
      this.#events.length < this.#capacity ||
      (coalesceKey !== undefined &&
        this.#events.some((event) => event.coalesceKey === coalesceKey))
    );
  }

  acknowledge(throughSequence: bigint): void {
    if (throughSequence <= this.#acknowledged) return;
    this.#acknowledged = throughSequence;
    this.#events = this.#events.filter(
      (event) => event.sequence > throughSequence,
    );
  }

  discard(sequence: bigint): boolean {
    const index = this.#events.findIndex(
      (event) => event.sequence === sequence,
    );
    if (index < 0) return false;
    this.#events.splice(index, 1);
    this.#dropped++;
    return true;
  }

  reconcileAcknowledged(throughSequence: bigint): void {
    if (throughSequence < 0n) {
      throw new Error("Acknowledged sequence must not be negative.");
    }
    this.#acknowledged = throughSequence;
    this.#events = this.#events.filter(
      (event) => event.sequence > throughSequence,
    );
  }

  pending(): readonly T[] {
    return this.#events.map((event) => event.value);
  }

  entries(): readonly QueuedEvent<T>[] {
    return this.#events.map((event) => Object.freeze({ ...event }));
  }

  replacePending(replace: (value: T) => T): void {
    this.#events = this.#events.map((event) => ({
      ...event,
      value: replace(event.value),
    }));
  }

  protected replaceState(source: BoundedEventQueue<T>): void {
    if (source.#capacity !== this.#capacity) {
      throw new Error("Event queue replacement capacity does not match.");
    }
    this.#events = source.#events.map((event) => ({ ...event }));
    this.#dropped = source.#dropped;
    this.#coalesced = source.#coalesced;
    this.#acknowledged = source.#acknowledged;
  }

  latestSequence(): bigint | undefined {
    let latest: bigint | undefined;
    for (const event of this.#events) {
      if (latest === undefined || event.sequence > latest) {
        latest = event.sequence;
      }
    }
    return latest;
  }

  pendingAfter(
    sequence: bigint,
    limit = this.#capacity,
  ): readonly T[] {
    if (!Number.isSafeInteger(limit) || limit < 1) {
      return [];
    }
    return this.#events
      .filter((event) => event.sequence > sequence)
      .slice(0, limit)
      .map((event) => event.value);
  }

  metrics(): QueueMetrics {
    let oldestSequence: bigint | undefined;
    let latestSequence: bigint | undefined;
    for (const event of this.#events) {
      if (
        oldestSequence === undefined ||
        event.sequence < oldestSequence
      ) {
        oldestSequence = event.sequence;
      }
      if (
        latestSequence === undefined ||
        event.sequence > latestSequence
      ) {
        latestSequence = event.sequence;
      }
    }
    return Object.freeze({
      capacity: this.#capacity,
      depth: this.#events.length,
      utilization: this.#events.length / this.#capacity,
      dropped: this.#dropped,
      coalesced: this.#coalesced,
      acknowledged: this.#acknowledged,
      ...(oldestSequence === undefined ? {} : { oldestSequence }),
      ...(latestSequence === undefined ? {} : { latestSequence }),
    });
  }
}
