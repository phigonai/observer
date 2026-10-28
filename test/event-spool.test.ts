import assert from "node:assert/strict";
import { create } from "@bufbuild/protobuf";
import { timestampFromDate } from "@bufbuild/protobuf/wkt";
import {
  appendFile,
  mkdtemp,
  open,
  readFile,
  rm,
  stat,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { FileBackedEventQueue } from "../src/event-spool.js";
import { PrivacyClass } from "../src/generated/phigon/v1/common_pb.js";
import {
  EventEnvelopeSchema,
  LifecycleEventSchema,
  LifecyclePhase,
  type EventEnvelope,
} from "../src/generated/phigon/v1/telemetry_pb.js";

const tenantID = "7d1b4cb4-a77d-4f53-af66-197e184683f4";
const machineID = "5f1b4cb4-a77d-4f53-af66-197e184683f4";
const credential = `phg_m_${"a".repeat(43)}`;

test("encrypted event spool survives restart without storing plaintext", async () => {
  const directory = await mkdtemp(join(tmpdir(), "phigon-event-spool-"));
  try {
    const first = new FileBackedEventQueue(directory, 4);
    first.restore(tenantID, machineID, credential);
    first.enqueue(lifecycleEvent(1n, "private restart evidence"), 1n);

    const raw = await readFile(join(directory, "telemetry-spool.jsonl"), "utf8");
    assert.doesNotMatch(raw, /private restart evidence/u);

    const restarted = new FileBackedEventQueue(directory, 4);
    restarted.restore(tenantID, machineID, credential);
    assert.deepEqual(
      restarted.pending().map((event) => event.sequence),
      [1n],
    );
    assert.equal(eventReason(restarted.pending()[0]), "private restart evidence");

    restarted.acknowledge(1n);
    restarted.reconcileAcknowledged(0n);
    const afterAck = new FileBackedEventQueue(directory, 4);
    afterAck.restore(tenantID, machineID, credential);
    assert.equal(afterAck.metrics().depth, 0);
    assert.equal(afterAck.metrics().acknowledged, 0n);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("event spool keeps appending across compaction and a removed data directory", async () => {
  const root = await mkdtemp(join(tmpdir(), "phigon-event-spool-append-"));
  const directory = join(root, "data");
  try {
    const queue = new FileBackedEventQueue(directory, 2048);
    queue.restore(tenantID, machineID, credential);
    // 1,101 appends cross the 1,024-operation compaction threshold.
    for (let sequence = 1n; sequence <= 600n; sequence++) {
      queue.enqueue(lifecycleEvent(sequence, "batch"), sequence);
    }
    queue.acknowledge(500n);
    for (let sequence = 601n; sequence <= 1_100n; sequence++) {
      queue.enqueue(lifecycleEvent(sequence, "batch"), sequence);
    }
    const restarted = new FileBackedEventQueue(directory, 2048);
    restarted.restore(tenantID, machineID, credential);
    assert.equal(restarted.metrics().acknowledged, 500n);
    assert.deepEqual(
      restarted.pending().map((event) => event.sequence),
      Array.from({ length: 600 }, (_, index) => BigInt(index + 501)),
    );

    await rm(directory, { recursive: true, force: true });
    queue.enqueue(lifecycleEvent(1_101n, "after removal"), 1_101n);
    const recreated = new FileBackedEventQueue(directory, 2048);
    recreated.restore(tenantID, machineID, credential);
    assert.deepEqual(recreated.pending().map((event) => event.sequence), [1_101n]);
    if (process.platform !== "win32") {
      const metadata = await stat(join(directory, "telemetry-spool.jsonl"));
      assert.equal(metadata.mode & 0o777, 0o600);
    }
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("event spool persists policy replacement and rejects scope mismatch", async () => {
  const directory = await mkdtemp(join(tmpdir(), "phigon-event-spool-policy-"));
  try {
    const first = new FileBackedEventQueue(directory, 4);
    first.restore(tenantID, machineID, credential);
    first.enqueue(lifecycleEvent(1n, "private value"), 1n);
    first.replacePending((event) =>
      lifecycleEvent(event.sequence, "redacted")
    );

    const restarted = new FileBackedEventQueue(directory, 4);
    restarted.restore(tenantID, machineID, credential);
    assert.equal(eventReason(restarted.pending()[0]), "redacted");

    const wrongTenant = new FileBackedEventQueue(directory, 4);
    assert.throws(
      () => wrongTenant.restore(
        "8d1b4cb4-a77d-4f53-af66-197e184683f4",
        machineID,
        credential,
      ),
      /scope/u,
    );
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("event spool restore commits only after every durable record verifies", async () => {
  const directory = await mkdtemp(join(tmpdir(), "phigon-event-spool-atomic-"));
  const path = join(directory, "telemetry-spool.jsonl");
  try {
    const writer = new FileBackedEventQueue(directory, 4);
    writer.restore(tenantID, machineID, credential);
    writer.enqueue(lifecycleEvent(1n, "verified evidence"), 1n);
    const verified = await readFile(path, "utf8");
    await appendFile(path, "{\"corrupt\":true}\n", "utf8");

    const restored = new FileBackedEventQueue(directory, 4);
    assert.throws(
      () => restored.restore(tenantID, machineID, credential),
      /scope or record shape/u,
    );
    assert.equal(restored.metrics().depth, 0);

    await writeFile(path, verified, "utf8");
    restored.restore(tenantID, machineID, credential);
    assert.deepEqual(restored.pending().map((event) => event.sequence), [1n]);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("event spool rejects oversized files before reading them", async () => {
  const directory = await mkdtemp(join(tmpdir(), "phigon-event-spool-bound-"));
  const path = join(directory, "telemetry-spool.jsonl");
  try {
    const handle = await open(path, "w");
    await handle.truncate((64 << 20) + 1);
    await handle.close();
    const restored = new FileBackedEventQueue(directory, 4);
    assert.throws(
      () => restored.restore(tenantID, machineID, credential),
      /safe storage bound/u,
    );
    assert.equal(restored.metrics().depth, 0);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

function lifecycleEvent(sequence: bigint, reason: string): EventEnvelope {
  return create(EventEnvelopeSchema, {
    tenantId: tenantID,
    machineId: machineID,
    agentId: "agent-test",
    sessionId: "session-test",
    sequence,
    observedAt: timestampFromDate(new Date()),
    schemaVersion: 1,
    privacyClass: PrivacyClass.SYSTEM_METADATA,
    payload: {
      case: "lifecycle",
      value: create(LifecycleEventSchema, {
        phase: LifecyclePhase.STARTED,
        reason,
      }),
    },
  });
}

function eventReason(event: EventEnvelope | undefined): string {
  return event?.payload.case === "lifecycle"
    ? event.payload.value.reason
    : "";
}
