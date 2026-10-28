import assert from "node:assert/strict";
import test from "node:test";
import { BoundedEventQueue } from "../src/event-queue.js";

test("bounded queue reports empty backpressure metrics without sequence bounds", () => {
  const queue = new BoundedEventQueue<string>(4);

  assert.deepEqual(queue.metrics(), {
    capacity: 4,
    depth: 0,
    utilization: 0,
    dropped: 0,
    coalesced: 0,
    acknowledged: 0n,
  });
});

test("bounded queue drops oldest events and never exceeds capacity", () => {
  const queue = new BoundedEventQueue<string>(2);
  queue.enqueue("one", 1n);
  queue.enqueue("two", 2n);
  assert.equal(queue.canEnqueue(), false);
  queue.enqueue("three", 3n);

  assert.deepEqual(queue.pending(), ["two", "three"]);
  assert.deepEqual(queue.metrics(), {
    capacity: 2,
    depth: 2,
    utilization: 1,
    dropped: 1,
    coalesced: 0,
    acknowledged: 0n,
    oldestSequence: 2n,
    latestSequence: 3n,
  });
});

test("bounded queue coalesces snapshots and removes acknowledgements", () => {
  const queue = new BoundedEventQueue<string>(3);
  queue.enqueue("old status", 1n, "agent-status");
  queue.enqueue("tool", 2n);
  assert.equal(queue.canEnqueue("agent-status"), true);
  queue.enqueue("new status", 3n, "agent-status");

  assert.deepEqual(queue.pending(), ["tool", "new status"]);
  assert.equal(queue.latestSequence(), 3n);
  queue.acknowledge(2n);
  assert.deepEqual(queue.pending(), ["new status"]);
  assert.equal(queue.metrics().coalesced, 1);
  assert.equal(queue.metrics().acknowledged, 2n);
  assert.equal(queue.metrics().utilization, 1 / 3);
  assert.equal(queue.metrics().oldestSequence, 3n);
  assert.equal(queue.metrics().latestSequence, 3n);
});

test("bounded queue selects a limited window after a sequence", () => {
  const queue = new BoundedEventQueue<string>(4);
  queue.enqueue("one", 1n);
  queue.enqueue("two", 2n);
  queue.enqueue("three", 3n);

  assert.deepEqual(queue.pendingAfter(1n, 1), ["two"]);
  assert.deepEqual(queue.pendingAfter(2n), ["three"]);
  assert.deepEqual(queue.pendingAfter(3n), []);
  assert.equal(queue.latestSequence(), 3n);
});

test("bounded queue keeps sequence order for late inserts and prefix acknowledgements", () => {
  const queue = new BoundedEventQueue<string>(8);
  queue.enqueue("five", 5n);
  queue.enqueue("two", 2n);
  queue.enqueue("seven", 7n);
  queue.enqueue("three", 3n);
  queue.enqueue("status", 4n, "status");
  queue.enqueue("status again", 8n, "status");

  assert.deepEqual(queue.pending(), ["two", "three", "five", "seven", "status again"]);
  assert.deepEqual(queue.pendingAfter(2n, 2), ["three", "five"]);
  assert.deepEqual(queue.pendingAfter(4n), ["five", "seven", "status again"]);
  assert.deepEqual(queue.pendingAfter(8n), []);
  assert.equal(queue.latestSequence(), 8n);
  assert.equal(queue.metrics().oldestSequence, 2n);

  queue.acknowledge(5n);
  assert.deepEqual(queue.pending(), ["seven", "status again"]);
  assert.equal(queue.metrics().oldestSequence, 7n);
  queue.acknowledge(7n);
  assert.deepEqual(queue.pending(), ["status again"]);
  queue.reconcileAcknowledged(1n);
  assert.deepEqual(queue.pending(), ["status again"]);
  assert.equal(queue.metrics().acknowledged, 1n);
  queue.acknowledge(8n);
  assert.deepEqual(queue.pending(), []);
  assert.equal(queue.latestSequence(), undefined);
});

test("a full queue drains with per-event acknowledgements in linear time", () => {
  const capacity = 65_536;
  const queue = new BoundedEventQueue<number>(capacity);
  for (let index = 1; index <= capacity; index++) {
    queue.enqueue(index, BigInt(index));
  }
  const started = performance.now();
  // The stream's per-acknowledgement work: acknowledge, read metrics for
  // backpressure and heartbeats, then pump the next window.
  for (let index = 1; index <= capacity; index++) {
    const sequence = BigInt(index);
    queue.acknowledge(sequence);
    queue.metrics();
    assert.equal(queue.pendingAfter(sequence, 64)[0], index < capacity ? index + 1 : undefined);
  }
  assert.equal(queue.metrics().depth, 0);
  // Quadratic scans took over a minute here; linear work takes well under.
  assert.ok(performance.now() - started < 10_000);
});

test("bounded queue replaces pending values without changing delivery order", () => {
  const queue = new BoundedEventQueue<string>(4);
  queue.enqueue("private one", 1n);
  queue.enqueue("private two", 2n, "status");

  queue.replacePending(() => "redacted");

  assert.deepEqual(queue.pending(), ["redacted", "redacted"]);
  assert.deepEqual(
    queue.entries().map((entry) => [entry.sequence, entry.coalesceKey]),
    [[1n, undefined], [2n, "status"]],
  );
});
