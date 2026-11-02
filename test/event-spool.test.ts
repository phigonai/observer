import assert from "node:assert/strict";
import { create } from "@bufbuild/protobuf";
import { timestampFromDate } from "@bufbuild/protobuf/wkt";
import {
  appendFile,
  mkdtemp,
  open,
  readFile,
  readdir,
  rm,
  stat,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { basename, dirname, join } from "node:path";
import test from "node:test";
import { hasByteHeadroom } from "../src/event-queue.js";
import {
  FileBackedEventQueue,
  retirePairingState,
} from "../src/event-spool.js";
import { PrivacyClass } from "../src/generated/phigon/v1/common_pb.js";
import { describeSpoolRestore } from "../src/stream-client.js";
import {
  EventEnvelopeSchema,
  LifecycleEventSchema,
  LifecyclePhase,
  type EventEnvelope,
} from "../src/generated/phigon/v1/telemetry_pb.js";

const tenantID = "7d1b4cb4-a77d-4f53-af66-197e184683f4";
const machineID = "5f1b4cb4-a77d-4f53-af66-197e184683f4";
const otherMachineID = "9a2c4cb4-a77d-4f53-af66-197e184683f4";
const credential = `phg_m_${"a".repeat(43)}`;

test("encrypted event spool survives restart without storing plaintext", async () => {
  const directory = await mkdtemp(join(tmpdir(), "phigon-event-spool-"));
  try {
    const first = new FileBackedEventQueue(directory, 4);
    first.restore(tenantID, machineID, credential);
    first.enqueue(lifecycleEvent(1n, "private restart evidence"), 1n);
    first.flush();

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
    // A small budget makes the acknowledged records worth compacting.
    const queue = new FileBackedEventQueue(directory, 2048, 1 << 20);
    queue.restore(tenantID, machineID, credential);
    for (let sequence = 1n; sequence <= 600n; sequence++) {
      queue.enqueue(lifecycleEvent(sequence, "batch"), sequence);
    }
    queue.acknowledge(500n);
    for (let sequence = 601n; sequence <= 1_100n; sequence++) {
      queue.enqueue(lifecycleEvent(sequence, "batch"), sequence);
    }
    queue.flush();
    const restarted = new FileBackedEventQueue(directory, 2048);
    restarted.restore(tenantID, machineID, credential);
    assert.equal(restarted.metrics().acknowledged, 500n);
    assert.deepEqual(
      restarted.pending().map((event) => event.sequence),
      Array.from({ length: 600 }, (_, index) => BigInt(index + 501)),
    );

    await rm(directory, { recursive: true, force: true });
    queue.enqueue(lifecycleEvent(1_101n, "after removal"), 1_101n);
    queue.flush();
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

test("event spool persists policy replacement", async () => {
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
    assert.throws(
      () => restarted.restore(tenantID, otherMachineID, credential),
      /scope changed while the observer was running/u,
    );
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("a spool left for another machine is moved aside instead of stopping the observer", async () => {
  const directory = await mkdtemp(join(tmpdir(), "phigon-event-spool-retire-"));
  const path = join(directory, "telemetry-spool.jsonl");
  try {
    const previous = new FileBackedEventQueue(directory, 4);
    previous.restore(tenantID, machineID, credential);
    previous.enqueue(lifecycleEvent(1n, "earlier pairing"), 1n);
    previous.flush();
    const previousSpool = await readFile(path, "utf8");
    await writeFile(join(directory, "stream-state.json"), "{}\n", "utf8");

    // The data directory was paired again as a new machine.
    const repaired = new FileBackedEventQueue(directory, 4);
    const notice = repaired.restore(
      tenantID,
      otherMachineID,
      `phg_m_${"b".repeat(43)}`,
    );
    assert.ok(notice?.reason === "other_machine");
    const retired = notice.directory;
    assert.equal(dirname(retired), join(directory, "retired-pairings"));
    assert.match(basename(retired), new RegExp(`-${machineID}-`, "u"));
    assert.equal(await readFile(join(retired, "telemetry-spool.jsonl"), "utf8"), previousSpool);
    assert.equal(await readFile(join(retired, "stream-state.json"), "utf8"), "{}\n");
    await assert.rejects(stat(path), { code: "ENOENT" });
    assert.equal(repaired.metrics().depth, 0);

    // The new machine's queue works and survives a restart.
    repaired.enqueue(lifecycleEvent(1n, "new pairing", otherMachineID), 1n);
    repaired.flush();
    const restarted = new FileBackedEventQueue(directory, 4);
    assert.equal(
      restarted.restore(tenantID, otherMachineID, `phg_m_${"b".repeat(43)}`),
      undefined,
    );
    assert.equal(eventReason(restarted.pending()[0]), "new pairing");
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("only the newest retired pairings are kept", async () => {
  const directory = await mkdtemp(join(tmpdir(), "phigon-event-spool-retired-"));
  try {
    const kept: string[] = [];
    for (let pairing = 0; pairing < 5; pairing++) {
      await writeFile(join(directory, "telemetry-spool.jsonl"), "{}\n", "utf8");
      const retired = retirePairingState(directory, `machine-${pairing}`);
      assert.ok(retired !== undefined);
      kept.push(basename(retired));
    }
    assert.deepEqual(
      (await readdir(join(directory, "retired-pairings"))).sort(),
      kept.slice(-3).sort(),
    );
    assert.equal(retirePairingState(directory, "machine-5"), undefined);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("a spool with a record that does not verify is moved aside and the queue starts empty", async () => {
  const directory = await mkdtemp(join(tmpdir(), "phigon-event-spool-damaged-"));
  const path = join(directory, "telemetry-spool.jsonl");
  try {
    const writer = new FileBackedEventQueue(directory, 4);
    writer.restore(tenantID, machineID, credential);
    writer.enqueue(lifecycleEvent(1n, "verified evidence"), 1n);
    writer.flush();
    const verified = await readFile(path, "utf8");
    // A damaged record in the middle, with a good one after it.
    await appendFile(path, "{\"corrupt\":true}\n", "utf8");
    writer.enqueue(lifecycleEvent(2n, "later evidence"), 2n);
    writer.flush();
    const damaged = await readFile(path, "utf8");
    assert.ok(damaged.startsWith(verified));
    await writeFile(join(directory, "stream-state.json"), "{}\n", "utf8");

    const restored = new FileBackedEventQueue(directory, 4);
    const notice = restored.restore(tenantID, machineID, credential);
    assert.ok(notice?.reason === "damaged");
    assert.equal(dirname(notice.directory), join(directory, "damaged-spools"));
    assert.equal(await readFile(join(notice.directory, "telemetry-spool.jsonl"), "utf8"), damaged);
    await assert.rejects(stat(path), { code: "ENOENT" });
    // The stream cursor still belongs to this machine and stays.
    assert.equal(await readFile(join(directory, "stream-state.json"), "utf8"), "{}\n");
    assert.equal(restored.metrics().depth, 0);
    const message = describeSpoolRestore(notice);
    assert.match(message, /damaged and could not be read/u);
    assert.match(message, /continues with an empty queue/u);
    assert.doesNotMatch(message, /evidence/u);

    // Collection continues with a fresh spool that survives a restart.
    restored.enqueue(lifecycleEvent(3n, "after the damage"), 3n);
    restored.flush();
    const restarted = new FileBackedEventQueue(directory, 4);
    assert.equal(restarted.restore(tenantID, machineID, credential), undefined);
    assert.equal(eventReason(restarted.pending()[0]), "after the damage");

    // A spool written with another key does not verify either.
    const otherKey = new FileBackedEventQueue(directory, 4);
    assert.equal(
      otherKey.restore(tenantID, machineID, `phg_m_${"c".repeat(43)}`)?.reason,
      "damaged",
    );

    // Only the newest few damaged spools are kept.
    for (let attempt = 0; attempt < 4; attempt++) {
      await writeFile(path, "{\"corrupt\":true}\n", "utf8");
      const again = new FileBackedEventQueue(directory, 4);
      assert.equal(again.restore(tenantID, machineID, credential)?.reason, "damaged");
    }
    assert.equal((await readdir(join(directory, "damaged-spools"))).length, 3);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("an oversized spool is moved aside without being read", async () => {
  const directory = await mkdtemp(join(tmpdir(), "phigon-event-spool-bound-"));
  const path = join(directory, "telemetry-spool.jsonl");
  try {
    const handle = await open(path, "w");
    await handle.truncate((64 << 20) + 1);
    await handle.close();
    const restored = new FileBackedEventQueue(directory, 4);
    const notice = restored.restore(tenantID, machineID, credential);
    assert.ok(notice?.reason === "damaged");
    assert.equal(
      (await stat(join(notice.directory, "telemetry-spool.jsonl"))).size,
      (64 << 20) + 1,
    );
    await assert.rejects(stat(path), { code: "ENOENT" });
    assert.equal(restored.metrics().depth, 0);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("a spool with more events than the queue holds keeps the newest", async () => {
  const directory = await mkdtemp(join(tmpdir(), "phigon-event-spool-capacity-"));
  try {
    const writer = new FileBackedEventQueue(directory, 8);
    writer.restore(tenantID, machineID, credential);
    for (let sequence = 1n; sequence <= 6n; sequence++) {
      writer.enqueue(lifecycleEvent(sequence, `event ${sequence}`), sequence);
    }
    writer.acknowledge(1n);
    writer.flush();

    // The queue capacity was lowered below the backlog of five events.
    const smaller = new FileBackedEventQueue(directory, 3);
    const notice = smaller.restore(tenantID, machineID, credential);
    assert.deepEqual(notice, { reason: "over_capacity", dropped: 2 });
    assert.deepEqual(smaller.pending().map((event) => event.sequence), [4n, 5n, 6n]);
    assert.match(describeSpoolRestore(notice), /^2 queued events did not fit/u);
    assert.doesNotMatch(describeSpoolRestore(notice), /event \d/u);

    // The spool was rewritten to what was kept.
    const restarted = new FileBackedEventQueue(directory, 3);
    assert.equal(restarted.restore(tenantID, machineID, credential), undefined);
    assert.deepEqual(restarted.pending().map((event) => event.sequence), [4n, 5n, 6n]);
    assert.equal(restarted.metrics().acknowledged, 1n);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("event spool reports its stored bytes across acknowledgement, compaction and restart", async () => {
  const directory = await mkdtemp(join(tmpdir(), "phigon-event-spool-bytes-"));
  const path = join(directory, "telemetry-spool.jsonl");
  try {
    const queue = new FileBackedEventQueue(directory, 16, 64 << 10);
    queue.restore(tenantID, machineID, credential);
    assert.equal(queue.metrics().bytes, 0);
    assert.equal(queue.metrics().byteCapacity, 64 << 10);
    for (let sequence = 1n; sequence <= 3n; sequence++) {
      queue.enqueue(lifecycleEvent(sequence, "x".repeat(200)), sequence);
    }
    // Before any acknowledgement the spool holds exactly the queued events.
    queue.flush();
    const queued = queue.metrics().bytes ?? 0;
    assert.equal(queued, (await stat(path)).size);
    const lines = (await readFile(path, "utf8")).split("\n");
    queue.acknowledge(1n);
    const unacknowledged = queued - Buffer.byteLength(lines[0] ?? "") - 1;
    assert.equal(queue.metrics().bytes, unacknowledged);
    // Rewriting the spool keeps the same stored size for the same events.
    queue.replacePending((event) => event);
    assert.equal(queue.metrics().bytes, unacknowledged);
    queue.discard(3n);
    const kept = queue.metrics().bytes;
    assert.equal(kept, Buffer.byteLength(lines[1] ?? "") + 1);
    queue.flush();

    const restarted = new FileBackedEventQueue(directory, 16, 64 << 10);
    restarted.restore(tenantID, machineID, credential);
    assert.equal(restarted.metrics().bytes, kept);
    restarted.acknowledge(2n);
    assert.equal(restarted.metrics().bytes, 0);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("collection stops by bytes before the spool budget, and a full spool still drains", async () => {
  const root = await mkdtemp(join(tmpdir(), "phigon-event-spool-budget-"));
  // A fixed time keeps every event, and so the spool, the same size.
  const large = (sequence: bigint) => create(EventEnvelopeSchema, {
    ...lifecycleEvent(sequence, "y".repeat(1_000)),
    observedAt: timestampFromDate(new Date("2026-11-01T00:00:00.000Z")),
  });
  try {
    const measured = new FileBackedEventQueue(join(root, "measure"), 1_024);
    measured.restore(tenantID, machineID, credential);
    for (let sequence = 1n; sequence <= 8n; sequence++) {
      measured.enqueue(large(sequence), sequence);
    }
    measured.flush();
    const budget = (await stat(join(root, "measure", "telemetry-spool.jsonl"))).size;

    // Eight large events fill the budget exactly, far below the event count.
    const queue = new FileBackedEventQueue(join(root, "spool"), 1_024, budget);
    queue.restore(tenantID, machineID, credential);
    let pausedAt: bigint | undefined;
    for (let sequence = 1n; sequence <= 8n; sequence++) {
      queue.enqueue(large(sequence), sequence);
      if (pausedAt === undefined && !hasByteHeadroom(queue.metrics())) {
        pausedAt = sequence;
      }
    }
    assert.equal(queue.metrics().bytes, budget);
    // Collection paused at three quarters of the budget, with room left.
    assert.equal(pausedAt, 6n);
    // Past the budget the spool refuses rather than dropping an event.
    assert.throws(() => queue.enqueue(large(9n), 9n), /spool is full/u);
    // The acknowledgement record does not fit either, yet it is accepted.
    queue.acknowledge(4n);
    assert.equal(queue.metrics().depth, 4);
    assert.equal(hasByteHeadroom(queue.metrics()), true);
    queue.flush();
    const restarted = new FileBackedEventQueue(join(root, "spool"), 1_024, budget);
    restarted.restore(tenantID, machineID, credential);
    assert.deepEqual(restarted.pending().map((event) => event.sequence), [5n, 6n, 7n, 8n]);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("spool records are written together by flush or within 100 ms", async () => {
  const directory = await mkdtemp(join(tmpdir(), "phigon-event-spool-group-"));
  const path = join(directory, "telemetry-spool.jsonl");
  try {
    const queue = new FileBackedEventQueue(directory, 16);
    queue.restore(tenantID, machineID, credential);
    queue.enqueue(lifecycleEvent(1n, "first"), 1n);
    queue.enqueue(lifecycleEvent(2n, "second"), 2n);
    queue.acknowledge(1n);
    // Nothing is written yet: no event is durable before a flush.
    await assert.rejects(stat(path), { code: "ENOENT" });

    await new Promise((resolve) => setTimeout(resolve, 300));
    const restarted = new FileBackedEventQueue(directory, 16);
    restarted.restore(tenantID, machineID, credential);
    assert.equal(restarted.metrics().acknowledged, 1n);
    assert.deepEqual(restarted.pending().map((event) => event.sequence), [2n]);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("a torn write at the end of the spool is ignored on restore", async () => {
  const directory = await mkdtemp(join(tmpdir(), "phigon-event-spool-torn-"));
  const path = join(directory, "telemetry-spool.jsonl");
  try {
    const queue = new FileBackedEventQueue(directory, 16);
    queue.restore(tenantID, machineID, credential);
    queue.enqueue(lifecycleEvent(1n, "durable"), 1n);
    queue.enqueue(lifecycleEvent(2n, "durable"), 2n);
    queue.flush();
    const durable = await readFile(path, "utf8");
    // A crash in the middle of the next group write leaves part of a record.
    const lastRecord = durable.trimEnd().split("\n").at(-1) ?? "";
    await appendFile(path, lastRecord.slice(0, 40), "utf8");

    const restarted = new FileBackedEventQueue(directory, 16);
    restarted.restore(tenantID, machineID, credential);
    assert.deepEqual(restarted.pending().map((event) => event.sequence), [1n, 2n]);
    assert.ok((await readFile(path, "utf8")).endsWith("\n"));
    restarted.enqueue(lifecycleEvent(3n, "after the crash"), 3n);
    restarted.flush();
    const again = new FileBackedEventQueue(directory, 16);
    again.restore(tenantID, machineID, credential);
    assert.deepEqual(again.pending().map((event) => event.sequence), [1n, 2n, 3n]);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("the spool is compacted once dead records outweigh the queued events", async () => {
  const directory = await mkdtemp(join(tmpdir(), "phigon-event-spool-dead-"));
  const path = join(directory, "telemetry-spool.jsonl");
  try {
    // A 64 KiB budget compacts after 16 KiB of dead records.
    const queue = new FileBackedEventQueue(directory, 16, 64 << 10);
    queue.restore(tenantID, machineID, credential);
    let largest = 0;
    for (let sequence = 1n; sequence <= 400n; sequence++) {
      queue.enqueue(lifecycleEvent(sequence, "z".repeat(200)), sequence);
      queue.acknowledge(sequence);
      if (sequence % 10n === 0n) {
        queue.flush();
        largest = Math.max(largest, (await stat(path)).size);
      }
    }
    // About 230 KB was appended, but the file never held much more than
    // the dead-record threshold.
    assert.ok(largest < 24 << 10, `spool reached ${largest} bytes`);
    const restarted = new FileBackedEventQueue(directory, 16, 64 << 10);
    restarted.restore(tenantID, machineID, credential);
    assert.equal(restarted.metrics().acknowledged, 400n);
    assert.equal(restarted.metrics().depth, 0);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("a failed spool write refuses new events until the whole spool can be rewritten", async () => {
  const root = await mkdtemp(join(tmpdir(), "phigon-event-spool-failure-"));
  const directory = join(root, "data");
  try {
    const queue = new FileBackedEventQueue(directory, 16);
    queue.restore(tenantID, machineID, credential);
    queue.enqueue(lifecycleEvent(1n, "buffered"), 1n);
    // Something else now occupies the data directory's path.
    await rm(directory, { recursive: true, force: true });
    await writeFile(directory, "not a directory", "utf8");

    assert.throws(() => queue.flush());
    assert.throws(() => queue.enqueue(lifecycleEvent(2n, "refused"), 2n));
    assert.deepEqual(queue.pending().map((event) => event.sequence), [1n]);

    await rm(directory, { force: true });
    queue.enqueue(lifecycleEvent(2n, "accepted"), 2n);
    queue.flush();
    const restarted = new FileBackedEventQueue(directory, 16);
    restarted.restore(tenantID, machineID, credential);
    assert.deepEqual(restarted.pending().map((event) => event.sequence), [1n, 2n]);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("a queue without a byte budget always has byte headroom", () => {
  const base = { capacity: 4, depth: 0, utilization: 0, dropped: 0, coalesced: 0, acknowledged: 0n };
  assert.equal(hasByteHeadroom(base), true);
  assert.equal(hasByteHeadroom({ ...base, bytes: 74, byteCapacity: 100 }), true);
  assert.equal(hasByteHeadroom({ ...base, bytes: 75, byteCapacity: 100 }), false);
});

function lifecycleEvent(
  sequence: bigint,
  reason: string,
  machine = machineID,
): EventEnvelope {
  return create(EventEnvelopeSchema, {
    tenantId: tenantID,
    machineId: machine,
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
