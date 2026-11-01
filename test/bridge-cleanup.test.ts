import assert from "node:assert/strict";
import { mkdir, mkdtemp, readFile, readdir, rm, utimes, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Readable } from "node:stream";
import test from "node:test";
import { ActivityCollector } from "../src/activity/collector.js";
import { ingestActivityJSONL } from "../src/activity/ingest.js";
import {
  SegmentedJournal,
  closedJournalSegments,
  guardianDecisionJournal,
} from "../src/bridge-journal.js";
import { loadConfig } from "../src/config.js";
import type { EventEnvelope } from "../src/generated/phigon/v1/telemetry_pb.js";

const credential = {
  machineId: "5f1b4cb4-a77d-4f53-af66-197e184683f4",
  tenantId: "7d1b4cb4-a77d-4f53-af66-197e184683f4",
  credential: `phg_m_${"0".repeat(43)}`,
  controlPlaneOrigin: "http://127.0.0.1:8080",
  createdAt: "2026-07-24T00:00:00.000Z",
};

const reply = (text: string) => `${JSON.stringify({
  type: "assistant",
  message: { role: "assistant", content: text },
})}\n`;

test("bridge files are deleted once read and acknowledged, or after seven days", async () => {
  const dataDirectory = await mkdtemp(join(tmpdir(), "phigon-bridge-cleanup-"));
  const bridges = join(dataDirectory, "bridges");
  try {
    await ingestActivityJSONL({ agent: "cursor", dataDirectory, input: Readable.from([reply("Delivered.")]) });
    const [delivered] = await readdir(join(bridges, "cursor"));
    assert.ok(delivered !== undefined);
    // An ingest run that is still writing.
    const writing = "1700000000000-0b9f4c4e-2f7b-4c39-9a51-6f0f3f1f2a10.jsonl";
    await writeFile(join(bridges, "cursor", writing), reply("Still arriving."));
    await writeFile(join(bridges, "cursor", `${writing}.writing`), "");
    // A closed journal segment, quiet for two minutes, and the current one.
    await mkdir(join(bridges, "generic"), { recursive: true });
    const closed = join(bridges, "generic", "guardian-decisions.jsonl");
    await writeFile(closed, reply("Closed segment."));
    const twoMinutesAgo = new Date(Date.now() - 120_000);
    await utimes(closed, twoMinutesAgo, twoMinutesAgo);
    await writeFile(join(bridges, "generic", "guardian-decisions-1800000000000.jsonl"), reply("Current segment."));
    // Never read: one eight days old, one recent.
    await mkdir(join(bridges, "aider"), { recursive: true });
    const old = join(bridges, "aider", "1600000000000-1c2d3e4f-5a6b-4c7d-8e9f-0a1b2c3d4e5f.jsonl");
    const recent = "1700000000001-2c2d3e4f-5a6b-4c7d-8e9f-0a1b2c3d4e5f.jsonl";
    await writeFile(old, reply("Old."));
    await writeFile(join(bridges, "aider", recent), reply("Recent."));
    const eightDaysAgo = new Date(Date.now() - 8 * 86_400_000);
    await utimes(old, eightDaysAgo, eightDaysAgo);

    const events: EventEnvelope[] = [];
    const collector = new ActivityCollector({
      config: loadConfig({
        PHIGON_DATA_DIR: dataDirectory,
        PHIGON_ACTIVITY_REPLAY_ON_FIRST_START: "true",
        PHIGON_ACTIVITY_RATE_LIMIT_PER_MINUTE: "100",
      }),
      credential,
      initialSequence: 0n,
      emit: (event) => events.push(event),
      sources: [
        { adapterId: "cursor", roots: [join(bridges, "cursor")] },
        { adapterId: "generic", roots: [join(bridges, "generic")] },
      ],
    });
    await collector.scanOnce();
    assert.ok(events.length > 0);

    // Read, but not yet acknowledged by the server: only the old file goes.
    await collector.pruneBridgeFiles();
    assert.deepEqual((await readdir(join(bridges, "aider"))).sort(), [recent]);
    assert.ok((await readdir(join(bridges, "cursor"))).includes(delivered));

    await collector.acknowledge(collector.metrics().lastSequence);
    await collector.pruneBridgeFiles();
    assert.deepEqual((await readdir(join(bridges, "cursor"))).sort(), [writing, `${writing}.writing`].sort());
    assert.deepEqual(await readdir(join(bridges, "generic")), ["guardian-decisions-1800000000000.jsonl"]);
    assert.deepEqual(await readdir(join(bridges, "aider")), [recent]);
  } finally {
    await rm(dataDirectory, { recursive: true, force: true });
  }
});

test("an ingest run removes its writing marker when it finishes", async () => {
  const dataDirectory = await mkdtemp(join(tmpdir(), "phigon-bridge-marker-"));
  try {
    await ingestActivityJSONL({ agent: "cursor", dataDirectory, input: Readable.from([reply("Done.")]) });
    const names = await readdir(join(dataDirectory, "bridges", "cursor"));
    assert.equal(names.length, 1);
    assert.match(names[0] ?? "", /\.jsonl$/u);
  } finally {
    await rm(dataDirectory, { recursive: true, force: true });
  }
});

test("the Guardian journal starts a new segment when full and keeps about its bound", async () => {
  const dataDirectory = await mkdtemp(join(tmpdir(), "phigon-journal-segments-"));
  const directory = join(dataDirectory, "bridges", "generic");
  try {
    const journal = new SegmentedJournal(dataDirectory, guardianDecisionJournal, {
      segmentBytes: 1_000,
      maxBytes: 2_500,
    });
    const record = JSON.stringify({ value: "x".repeat(180) });
    await journal.append(record);
    assert.deepEqual(await readdir(directory), ["guardian-decisions.jsonl"]);
    for (let index = 1; index < 40; index++) await journal.append(record);
    const names = await readdir(directory);
    assert.ok(names.length > 1);
    assert.ok(names.every((name) => /^guardian-decisions-\d+\.jsonl$/u.test(name)), names.join());
    let total = 0;
    for (const name of names) {
      const size = Buffer.byteLength(await readFile(join(directory, name), "utf8"));
      total += size;
      assert.ok(size <= 1_000, `${name} grew past its segment size`);
    }
    assert.ok(total <= 2_500, `journal kept ${total} bytes`);
    assert.equal(closedJournalSegments(names).length, names.length - 1);
  } finally {
    await rm(dataDirectory, { recursive: true, force: true });
  }
});
