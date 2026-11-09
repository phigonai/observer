import assert from "node:assert/strict";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import {
  asleepAfterMs, beginRun, endRun, gapPoster, markAlive, maxPendingGaps, pendingGaps, queueGaps, sendPendingGaps,
  type CoverageGap,
} from "../src/coverage-gaps.js";

const minutes = (count: number) => count * 60_000;

async function directory(): Promise<string> {
  return await mkdtemp(join(tmpdir(), "phigon-coverage-"));
}

/** A previous run's record, as an earlier observer process left it. */
async function previousRun(data: string, record: Record<string, unknown>): Promise<void> {
  await writeFile(join(data, "observer-run.json"), JSON.stringify({ version: 1, pid: 1, ...record }));
}

test("the first run on a computer reports nothing", async () => {
  const data = await directory();
  try {
    const now = new Date("2026-11-10T09:00:00Z");
    assert.equal(await beginRun(data, { now, bootedAt: new Date(now.getTime() - minutes(60)), pid: process.pid }), undefined);
    const record = JSON.parse(await readFile(join(data, "observer-run.json"), "utf8")) as Record<string, unknown>;
    assert.equal(record["pid"], process.pid);
    assert.equal(record["startedAt"], now.toISOString());
  } finally {
    await rm(data, { recursive: true, force: true });
  }
});

test("a gap is explained by what the computer can tell, never guessed", async () => {
  const data = await directory();
  try {
    const now = new Date("2026-11-10T10:00:00Z");
    const lastAlive = new Date(now.getTime() - minutes(22)).toISOString();
    const upSinceMorning = new Date("2026-11-10T08:00:00Z");

    // Ended from outside (Task Manager) or crashed: no stop was recorded and
    // the computer has been on since before.
    await previousRun(data, { startedAt: "2026-11-10T08:05:00Z", aliveAt: lastAlive });
    const killed = await beginRun(data, { now, bootedAt: upSinceMorning, pid: process.pid });
    assert.deepEqual({ kind: killed?.kind, from: killed?.from, to: killed?.to }, { kind: "ended_unexpectedly", from: lastAlive, to: now.toISOString() });
    // Saved to send before the record that explains it was replaced.
    assert.deepEqual((await pendingGaps(data)).map((gap) => gap.id), [killed?.id]);

    // The computer started after the observer was last alive.
    await previousRun(data, { startedAt: "2026-11-09T08:05:00Z", aliveAt: "2026-11-09T18:00:00Z" });
    assert.equal((await beginRun(data, { now, bootedAt: upSinceMorning, pid: process.pid }))?.kind, "computer_off");

    // Stopped on purpose, by a command or the service manager.
    await previousRun(data, { startedAt: "2026-11-10T08:05:00Z", aliveAt: lastAlive, stoppedAt: lastAlive, stopReason: "stopped" });
    assert.equal((await beginRun(data, { now, bootedAt: upSinceMorning, pid: process.pid }))?.kind, "stopped");
    await previousRun(data, { startedAt: "2026-11-10T08:05:00Z", aliveAt: lastAlive, stoppedAt: lastAlive, stopReason: "service_stopped" });
    assert.equal((await beginRun(data, { now, bootedAt: upSinceMorning, pid: process.pid }))?.kind, "service_stopped");

    // A restart within a couple of minutes is not a gap.
    await previousRun(data, { startedAt: "2026-11-10T08:05:00Z", aliveAt: new Date(now.getTime() - 60_000).toISOString() });
    assert.equal(await beginRun(data, { now, bootedAt: upSinceMorning, pid: process.pid }), undefined);

    // An unreadable record is no evidence.
    await writeFile(join(data, "observer-run.json"), "{not json");
    assert.equal(await beginRun(data, { now, bootedAt: upSinceMorning, pid: process.pid }), undefined);
  } finally {
    await rm(data, { recursive: true, force: true });
  }
});

test("a run that was not running for a while was asleep, and its end is recorded", async () => {
  const data = await directory();
  try {
    const start = new Date("2026-11-10T09:00:00Z");
    await beginRun(data, { now: start, bootedAt: new Date("2026-11-10T08:00:00Z"), pid: process.pid });
    assert.equal(await markAlive(data, new Date(start.getTime() + 60_000)), undefined);
    const woke = new Date(start.getTime() + 60_000 + asleepAfterMs + 1);
    const asleep = await markAlive(data, woke);
    assert.equal(asleep?.kind, "asleep");
    assert.equal(asleep?.to, woke.toISOString());

    await endRun(data, "service_stopped", new Date(woke.getTime() + 1_000));
    const record = JSON.parse(await readFile(join(data, "observer-run.json"), "utf8")) as Record<string, unknown>;
    assert.equal(record["stopReason"], "service_stopped");
    // Another process's record is never written over by this one.
    await previousRun(data, { startedAt: "x", aliveAt: "y" });
    await endRun(data, "stopped");
    assert.equal((JSON.parse(await readFile(join(data, "observer-run.json"), "utf8")) as Record<string, unknown>)["stoppedAt"], undefined);
  } finally {
    await rm(data, { recursive: true, force: true });
  }
});

test("gaps wait for the server, bounded, and leave once it has them", async () => {
  const data = await directory();
  try {
    const gap = (index: number): CoverageGap => ({
      id: `00000000-0000-4000-8000-${index.toString().padStart(12, "0")}`, kind: "stopped",
      from: new Date(Date.UTC(2026, 10, 10, 0, index)).toISOString(),
    });
    await queueGaps(data, Array.from({ length: maxPendingGaps + 5 }, (_, index) => gap(index)));
    const waiting = await pendingGaps(data);
    assert.equal(waiting.length, maxPendingGaps);
    assert.equal(waiting[0]?.id, gap(5).id, "the oldest go first");

    // Unreachable or refusing: kept for later.
    assert.equal(await sendPendingGaps(data, async () => { throw new Error("offline"); }), "later");
    assert.equal(await sendPendingGaps(data, async () => 503), "later");
    assert.equal((await pendingGaps(data)).length, maxPendingGaps);

    let sent: unknown;
    assert.equal(await sendPendingGaps(data, async (body) => { sent = body; return 200; }), "sent");
    assert.equal((sent as { gaps: unknown[] }).gaps.length, maxPendingGaps);
    assert.deepEqual(await pendingGaps(data), []);
    assert.equal(await sendPendingGaps(data, async () => 200), "none");

    // A server too old to know gaps never will: they are dropped, not kept forever.
    await queueGaps(data, [gap(1)]);
    assert.equal(await sendPendingGaps(data, async () => 404), "unsupported");
    assert.deepEqual(await pendingGaps(data), []);

    // A broken or misnamed file holds nothing.
    await queueGaps(data, [gap(2)]);
    await writeFile(join(data, "coverage-gaps", `${gap(3).id}.json`), JSON.stringify({ ...gap(3), kind: "wiped" }));
    await writeFile(join(data, "coverage-gaps", `${gap(4).id}.json`), JSON.stringify(gap(5)));
    await writeFile(join(data, "coverage-gaps", "notes.txt"), "x");
    assert.deepEqual((await pendingGaps(data)).map((item) => item.id), [gap(2).id]);
  } finally {
    await rm(data, { recursive: true, force: true });
  }
});

test("a gap another command adds while gaps are being sent is kept", async () => {
  const data = await directory();
  try {
    const first: CoverageGap = { id: "00000000-0000-4000-8000-0000000000a1", kind: "stopped", from: "2026-11-10T09:00:00Z" };
    const removal: CoverageGap = { id: "00000000-0000-4000-8000-0000000000a2", kind: "service_removed", from: "2026-11-10T09:30:00Z" };
    await queueGaps(data, [first]);
    // service uninstall queues its report while the running observer's delivery is under way.
    assert.equal(await sendPendingGaps(data, async () => {
      await queueGaps(data, [removal]);
      return 200;
    }), "sent");
    assert.deepEqual((await pendingGaps(data)).map((gap) => gap.id), [removal.id]);
  } finally {
    await rm(data, { recursive: true, force: true });
  }
});

test("a run record is kept when its gap cannot be saved, so the next start reports it", async () => {
  const data = await directory();
  try {
    await previousRun(data, { startedAt: "2026-11-10T08:05:00Z", aliveAt: "2026-11-10T09:00:00Z" });
    // The gaps folder cannot be made: a file stands in its place.
    await writeFile(join(data, "coverage-gaps"), "not a folder");
    await assert.rejects(beginRun(data, { now: new Date("2026-11-10T10:00:00Z"), bootedAt: new Date("2026-11-10T07:00:00Z"), pid: process.pid }));
    const record = JSON.parse(await readFile(join(data, "observer-run.json"), "utf8")) as Record<string, unknown>;
    assert.equal(record["aliveAt"], "2026-11-10T09:00:00Z");
    await rm(join(data, "coverage-gaps"));
    await mkdir(join(data, "coverage-gaps"));
    assert.equal((await beginRun(data, { now: new Date("2026-11-10T10:05:00Z"), bootedAt: new Date("2026-11-10T07:00:00Z"), pid: process.pid }))?.kind, "ended_unexpectedly");
  } finally {
    await rm(data, { recursive: true, force: true });
  }
});

test("gaps go to the company's server with this computer's key", async () => {
  const calls: { url: string; init: RequestInit }[] = [];
  const fetcher = (async (url: URL, init: RequestInit) => {
    calls.push({ url: url.toString(), init });
    return new Response("{}", { status: 200 });
  }) as unknown as typeof fetch;
  const credential = ["machine", "-", "key"].join("");
  const status = await gapPoster(new URL("https://phigon.example:8443"), credential, fetcher)({ gaps: [] });
  assert.equal(status, 200);
  assert.equal(calls[0]?.url, "https://phigon.example:8443/v1/machine/coverage-gaps");
  assert.equal((calls[0]?.init.headers as Record<string, string>)["Authorization"], `Bearer ${credential}`);
  assert.equal(calls[0]?.init.redirect, "error");
});
