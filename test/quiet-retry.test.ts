import assert from "node:assert/strict";
import test from "node:test";
import { errorSummary, RetryBackoff, StatusChanges } from "../src/quiet-retry.js";

test("a retry waits longer after each failure, up to the maximum, and a success starts over", () => {
  const backoff = new RetryBackoff(10, 50);
  const waits: number[] = [];
  let now = 0;
  for (let failure = 0; failure < 5; failure++) {
    backoff.failed(now);
    const from = now;
    while (!backoff.ready(now)) now++;
    waits.push(now - from);
  }
  assert.deepEqual(waits, [10, 20, 40, 50, 50]);
  backoff.succeeded();
  assert.equal(backoff.ready(now), true);
  backoff.failed(now);
  assert.equal(backoff.ready(now + 9), false);
  assert.equal(backoff.ready(now + 10), true);
});

test("failures while a wait is set do not lengthen it", () => {
  const backoff = new RetryBackoff(10, 1_000);
  backoff.failed(0);
  backoff.failed(1);
  backoff.failed(5);
  assert.equal(backoff.ready(10), true);
});

test("a status is written when it changes or after the repeat interval, and its end once", () => {
  let now = 0;
  const written: string[] = [];
  const changes = new StatusChanges((message) => written.push(message), 100, () => now);
  changes.report("stream", "down: refused");
  now = 50;
  changes.report("stream", "down: refused");
  changes.report("stream", "down: timed out");
  changes.report("policy", "waiting");
  now = 149;
  changes.report("stream", "down: timed out");
  now = 150;
  changes.report("stream", "down: timed out");
  changes.clear("stream", "up again");
  changes.clear("stream", "up again");
  changes.clear("unused", "never written");
  assert.deepEqual(written, ["down: refused", "down: timed out", "waiting", "down: timed out", "up again"]);
});

test("only the most recently reported topics are kept", () => {
  const written: string[] = [];
  const changes = new StatusChanges((message) => written.push(message), 60_000, () => 0, 2);
  changes.report("a", "first");
  changes.report("b", "second");
  changes.report("c", "third");
  // "a" was written longest ago, so it was forgotten and is written again,
  // which in turn forgets "b"; "c" is still kept.
  changes.report("a", "first");
  changes.report("c", "third");
  changes.report("b", "second");
  assert.deepEqual(written, ["first", "second", "third", "first", "second"]);
});

test("an error summary is one short line without its final period", () => {
  assert.equal(errorSummary(new Error("Service returned\n409.")), "Service returned 409");
  assert.equal(errorSummary("x".repeat(300)).length, 200);
  assert.equal(errorSummary(new Error("   ")), "no detail");
});
