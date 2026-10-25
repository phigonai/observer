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
