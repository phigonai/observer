import assert from "node:assert/strict";
import test from "node:test";
import { ServerClock, describeClockSkew } from "../src/server-clock.js";

const localNow = Date.parse("2026-11-02T12:00:00.000Z");

test("the server clock follows the median of the server's timestamps", () => {
  const clock = new ServerClock({ now: () => localNow });
  assert.equal(clock.now(), localNow);
  for (const offset of [5_000, 5_200, 900_000, 4_900, 5_100]) {
    clock.observe(new Date(localNow + offset));
  }
  // One stamp far off does not move the estimate.
  assert.equal(clock.offsetMs(), 5_100);
  assert.equal(clock.now(), localNow + 5_100);
});

test("the correction is bounded and a large skew is reported once", () => {
  const reported: number[] = [];
  const clock = new ServerClock({
    now: () => localNow,
    maxCorrectionMs: 3_600_000,
    onLargeSkew: (offset) => reported.push(offset),
  });
  clock.observe(new Date(localNow + 30_000));
  assert.deepEqual(reported, []);
  for (let sample = 0; sample < 9; sample++) {
    clock.observe(new Date(localNow - 600_000));
  }
  assert.equal(clock.offsetMs(), -600_000);
  assert.deepEqual(reported, [-600_000]);

  for (let sample = 0; sample < 9; sample++) {
    clock.observe(new Date(localNow + 5 * 3_600_000));
  }
  // Applied up to the bound, and reported as it really is.
  assert.equal(clock.offsetMs(), 3_600_000);
  assert.deepEqual(reported, [-600_000, 5 * 3_600_000]);
});

test("the skew message says which way the computer's clock is off", () => {
  assert.match(describeClockSkew(600_000), /10 minutes behind the workspace server/u);
  assert.match(describeClockSkew(-90_000), /90 seconds ahead of the workspace server/u);
});
