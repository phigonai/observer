import assert from "node:assert/strict";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { BoundedEventQueue } from "../src/event-queue.js";
import { describeRuntime, readObserverStatus, startSelfReport } from "../src/self-report.js";

test("a running observer reports its own cost and delivery backlog, which doctor reads", async () => {
  const directory = await mkdtemp(join(tmpdir(), "phigon-self-report-"));
  const controller = new AbortController();
  try {
    const queue = new BoundedEventQueue<string>(16);
    queue.enqueue("waiting", 1n);
    const lastScanAt = new Date();
    const { measure } = startSelfReport({
      dataDirectory: directory,
      observerVersion: "9.9.9",
      queue: () => queue.metrics(),
      scan: () => ({ lastScanAt, lastScanDurationMs: 3.21, idle: true }),
      signal: controller.signal,
      intervalMs: 50,
    });
    // Some work, so CPU and the event loop have something to show.
    const until = Date.now() + 30;
    while (Date.now() < until) { /* busy */ }
    const measured = measure();
    assert.ok(measured.cpuPercent > 0);
    assert.ok(measured.rssBytes > 1 << 20);
    assert.equal(measured.queuedEvents, 1);
    assert.equal(measured.lastScanAt, lastScanAt.toISOString());
    assert.equal(measured.collectionResting, true);
    assert.ok((measured.oldestUndeliveredAgeSeconds ?? -1) >= 0);

    // Written once a minute (here every 50 ms) to the data directory.
    let status;
    for (let waited = 0; status === undefined && waited < 5_000; waited += 25) {
      await new Promise((resolve) => setTimeout(resolve, 25));
      status = await readObserverStatus(directory);
    }
    assert.ok(status !== undefined, "the status was written");
    assert.equal(status.observerVersion, "9.9.9");
    assert.equal(status.pid, process.pid);
    assert.equal(status.queuedEvents, 1);
    assert.equal(status.stale, false);
    assert.match(describeRuntime(status), /% CPU, \d+ MiB memory, event-loop delay p99 [\d.]+ ms, last scan .* \(resting while agents are quiet\), 1 events waiting for the server, oldest \d+ s/u);
    // Numbers only: no activity, no paths beyond what doctor already shows.
    assert.doesNotMatch(await readFile(join(directory, "observer-status.json"), "utf8"), /waiting/u);

    // An observer that stopped reporting is said to have stopped.
    controller.abort();
    const later = Date.parse(status.writtenAt) + 10 * 60_000;
    const old = await readObserverStatus(directory, later);
    assert.equal(old?.stale, true);
    assert.match(describeRuntime(old!), /no longer reporting/u);
  } finally {
    controller.abort();
    await rm(directory, { recursive: true, force: true });
  }
});

test("an unreadable or foreign status is not reported", async () => {
  const directory = await mkdtemp(join(tmpdir(), "phigon-self-report-bad-"));
  try {
    assert.equal(await readObserverStatus(directory), undefined);
    await writeFile(join(directory, "observer-status.json"), "{not json");
    assert.equal(await readObserverStatus(directory), undefined);
    await writeFile(join(directory, "observer-status.json"), JSON.stringify({ version: 2, pid: 1 }));
    assert.equal(await readObserverStatus(directory), undefined);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});
