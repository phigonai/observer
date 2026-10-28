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
  // Queued events are #events[#head..], ordered by sequence. The stream
  // acknowledges every event and pumps after each acknowledgement, so
  // acknowledge, metrics and pendingAfter work from the ends of the queue
  // and acknowledged events are released by advancing #head; a full queue
  // drains in linear rather than quadratic time.
  #events: Array<QueuedEvent<T>> = [];
  #head = 0;
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
    const event = {
      value,
      sequence,
      ...(coalesceKey === undefined ? {} : { coalesceKey }),
    };
    if (coalesceKey === undefined && this.#size() < this.#capacity) {
      const last = this.#last();
      if (last === undefined || last.sequence <= sequence) {
        this.#events.push(event);
        return;
      }
    }
    this.#compact();
    if (coalesceKey !== undefined) {
      const index = this.#events.findIndex(
        (candidate) => candidate.coalesceKey === coalesceKey,
      );
      if (index >= 0) {
        this.#events[index] = { value, sequence, coalesceKey };
        this.#events.sort((left, right) =>
          left.sequence < right.sequence ? -1 : left.sequence > right.sequence ? 1 : 0,
        );
        this.#coalesced++;
        return;
      }
    }
    if (this.#events.length >= this.#capacity) {
      this.#events.shift();
      this.#dropped++;
    }
    this.#events.splice(this.#firstAfter(sequence), 0, event);
  }

  canEnqueue(coalesceKey?: string): boolean {
    if (this.#size() < this.#capacity) return true;
    if (coalesceKey === undefined) return false;
    for (let index = this.#head; index < this.#events.length; index++) {
      if (this.#events[index]?.coalesceKey === coalesceKey) return true;
    }
    return false;
  }

  acknowledge(throughSequence: bigint): void {
    if (throughSequence <= this.#acknowledged) return;
    this.#acknowledged = throughSequence;
    this.#removeThrough(throughSequence);
  }

  discard(sequence: bigint): boolean {
    this.#compact();
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
    this.#removeThrough(throughSequence);
  }

  pending(): readonly T[] {
    return this.#events.slice(this.#head).map((event) => event.value);
  }

  entries(): readonly QueuedEvent<T>[] {
    return this.#events
      .slice(this.#head)
      .map((event) => Object.freeze({ ...event }));
  }

  replacePending(replace: (value: T) => T): void {
    this.#compact();
    this.#events = this.#events.map((event) => ({
      ...event,
      value: replace(event.value),
    }));
  }

  protected replaceState(source: BoundedEventQueue<T>): void {
    if (source.#capacity !== this.#capacity) {
      throw new Error("Event queue replacement capacity does not match.");
    }
    this.#events = source.#events
      .slice(source.#head)
      .map((event) => ({ ...event }));
    this.#head = 0;
    this.#dropped = source.#dropped;
    this.#coalesced = source.#coalesced;
    this.#acknowledged = source.#acknowledged;
  }

  latestSequence(): bigint | undefined {
    return this.#last()?.sequence;
  }

  pendingAfter(
    sequence: bigint,
    limit = this.#capacity,
  ): readonly T[] {
    if (!Number.isSafeInteger(limit) || limit < 1) {
      return [];
    }
    const start = this.#firstAfter(sequence);
    return this.#events
      .slice(start, start + limit)
      .map((event) => event.value);
  }

  metrics(): QueueMetrics {
    const depth = this.#size();
    const oldestSequence = depth === 0
      ? undefined
      : this.#events[this.#head]?.sequence;
    const latestSequence = this.#last()?.sequence;
    return Object.freeze({
      capacity: this.#capacity,
      depth,
      utilization: depth / this.#capacity,
      dropped: this.#dropped,
      coalesced: this.#coalesced,
      acknowledged: this.#acknowledged,
      ...(oldestSequence === undefined ? {} : { oldestSequence }),
      ...(latestSequence === undefined ? {} : { latestSequence }),
    });
  }

  #size(): number {
    return this.#events.length - this.#head;
  }

  #last(): QueuedEvent<T> | undefined {
    return this.#size() === 0 ? undefined : this.#events.at(-1);
  }

  /** Index of the first queued event with a sequence above `sequence`. */
  #firstAfter(sequence: bigint): number {
    let low = this.#head;
    let high = this.#events.length;
    while (low < high) {
      const middle = (low + high) >>> 1;
      if ((this.#events[middle]?.sequence ?? 0n) <= sequence) {
        low = middle + 1;
      } else {
        high = middle;
      }
    }
    return low;
  }

  #removeThrough(sequence: bigint): void {
    this.#head = this.#firstAfter(sequence);
    // Release acknowledged events once they are half of the backing array,
    // which keeps the copy amortized to constant work per event.
    if (this.#head > 0 && this.#head * 2 >= this.#events.length) {
      this.#compact();
    }
  }

  #compact(): void {
    if (this.#head === 0) return;
    this.#events = this.#events.slice(this.#head);
    this.#head = 0;
  }
}
