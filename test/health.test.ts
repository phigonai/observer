import assert from "node:assert/strict";
import test from "node:test";
import { loadConfig } from "../src/config.js";
import { createHealthSnapshot } from "../src/health.js";

test("createHealthSnapshot reports pairing without exposing token values", () => {
  const config = loadConfig({
    PHIGON_CONTROL_PLANE_URL: "https://control.example.test",
    PHIGON_MACHINE_TOKEN: "sensitive-machine-token",
    PHIGON_DATA_DIR: "/tmp/phigon-test",
  });
  const health = createHealthSnapshot(
    config,
    "0.1.0",
    new Date("2026-07-24T00:00:00.000Z"),
    {
      machineId: "machine-health-1",
      acknowledgedSequence: "42",
      updatedAt: "2026-07-23T23:59:00.000Z",
    },
  );

  assert.equal(health.status, "ready");
  assert.equal(health.machineTokenConfigured, true);
  assert.equal(health.controlPlaneOrigin, "https://control.example.test");
  assert.equal(health.checkedAt, "2026-07-24T00:00:00.000Z");
  assert.deepEqual(health.streamCursor, {
    machineId: "machine-health-1",
    acknowledgedSequence: "42",
    updatedAt: "2026-07-23T23:59:00.000Z",
  });
  assert.equal(health.streamCursorIssue, undefined);
  assert.doesNotMatch(JSON.stringify(health), /sensitive-machine-token/);
});

test("createHealthSnapshot can report stream cursor diagnostics", () => {
  const config = loadConfig({
    PHIGON_CONTROL_PLANE_URL: "https://control.example.test",
    PHIGON_DATA_DIR: "/tmp/phigon-test",
  });
  const health = createHealthSnapshot(
    config,
    "0.1.0",
    new Date("2026-07-24T00:00:00.000Z"),
    undefined,
    "Stored stream cursor could not be read.",
  );

  assert.equal(health.status, "needs-pairing");
  assert.equal(health.streamCursor, undefined);
  assert.equal(
    health.streamCursorIssue,
    "Stored stream cursor could not be read.",
  );
});

test("createHealthSnapshot identifies the default profile as metadata only", () => {
  const health = createHealthSnapshot(loadConfig({}), "0.1.0");

  assert.equal(health.observabilityProfile, "metadata");
  assert.equal(health.safeCollectionDefaults, true);
  assert.deepEqual(health.enabledCollectionCategories, [
    "processMetadata",
    "fileMetadata",
    "networkMetadata",
    "browserMetadata",
  ]);
});

test("createHealthSnapshot reports explicit content collection", () => {
  const health = createHealthSnapshot(
    loadConfig({ PHIGON_COLLECT_PROMPT_CONTENT: "true" }),
    "0.1.0",
  );

  assert.equal(health.safeCollectionDefaults, false);
  assert.equal(
    health.enabledCollectionCategories.includes("promptContent"),
    true,
  );
});
