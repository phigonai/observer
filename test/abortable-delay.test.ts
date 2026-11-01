import assert from "node:assert/strict";
import { getEventListeners } from "node:events";
import test from "node:test";
import { create } from "@bufbuild/protobuf";
import { abortableDelay } from "../src/abortable-delay.js";
import { type DiscoveryEngine, runDiscoveryLoop } from "../src/discovery/engine.js";
import { AgentInventorySchema } from "../src/generated/phigon/v1/identity_pb.js";

test("many finished waits leave no abort listeners on the shared signal", async () => {
  const controller = new AbortController();
  for (let index = 0; index < 500; index++) {
    await abortableDelay(0, controller.signal);
  }
  assert.equal(getEventListeners(controller.signal, "abort").length, 0);
});

test("an abort ends a wait early without rejecting", async () => {
  const controller = new AbortController();
  const started = performance.now();
  const waiting = abortableDelay(60_000, controller.signal);
  controller.abort();
  await waiting;
  assert.ok(performance.now() - started < 1_000);
  assert.equal(getEventListeners(controller.signal, "abort").length, 0);
  // An already aborted signal returns at once.
  await abortableDelay(60_000, controller.signal);
});

test("a long-running loop keeps at most one listener on its signal", async () => {
  const controller = new AbortController();
  const inventory = create(AgentInventorySchema, {});
  const engine = {
    discover: async () => ({ inventory }),
  } as unknown as DiscoveryEngine;
  let passes = 0;
  let most = 0;
  await runDiscoveryLoop(engine, "", 1, controller.signal, () => {
    most = Math.max(most, getEventListeners(controller.signal, "abort").length);
    if (++passes === 100) controller.abort();
  });
  assert.equal(passes, 100);
  assert.equal(most, 0);
});
