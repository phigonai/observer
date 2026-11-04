import assert from "node:assert/strict";
import { execFile, spawn } from "node:child_process";
import { once } from "node:events";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { promisify } from "node:util";
import { InstanceLock, ObserverAlreadyRunningError } from "../src/instance-lock.js";

const lockModule = new URL("../src/instance-lock.js", import.meta.url).href;

test("one observer holds a data directory; a second is refused until it releases", async () => {
  const directory = await mkdtemp(join(tmpdir(), "phigon-instance-lock-"));
  const path = join(directory, "observer.lock");
  try {
    const first = await InstanceLock.acquire(directory);
    const held = JSON.parse(await readFile(path, "utf8")) as Record<string, unknown>;
    assert.equal(held["pid"], process.pid);
    assert.ok(Number.isFinite(Date.parse(String(held["started_at"]))));

    await assert.rejects(
      InstanceLock.acquire(directory),
      (error: unknown) =>
        error instanceof ObserverAlreadyRunningError &&
        error.message.includes(`process ${process.pid}`) &&
        error.message.includes(path),
    );
    await first.release();
    await assert.rejects(readFile(path, "utf8"), { code: "ENOENT" });

    const second = await InstanceLock.acquire(directory);
    await second.release();
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("a lock left by a stopped process or before a restart is taken over", async () => {
  const directory = await mkdtemp(join(tmpdir(), "phigon-instance-lock-stale-"));
  const path = join(directory, "observer.lock");
  const now = Date.parse("2026-11-01T12:00:00.000Z");
  try {
    // The holder's process is gone.
    await writeFile(path, JSON.stringify({ pid: 424_242, started_at: new Date(now - 60_000).toISOString() }));
    const afterCrash = await InstanceLock.acquire(directory, {
      isAlive: () => false,
      bootedAt: () => now - 3_600_000,
    });
    assert.equal(JSON.parse(await readFile(path, "utf8")).pid, process.pid);
    await afterCrash.release();

    // The process ID is in use again, its start time cannot be read, and the
    // lock predates the last boot.
    await writeFile(path, JSON.stringify({ pid: 424_242, started_at: new Date(now - 7_200_000).toISOString() }));
    const afterReboot = await InstanceLock.acquire(directory, {
      isAlive: () => true,
      bootedAt: () => now - 3_600_000,
      processStartedAt: () => Promise.resolve(null),
    });
    await afterReboot.release();

    // A lock that is still being written belongs to a starting observer;
    // one that stayed unreadable was left by a crash.
    await writeFile(path, "");
    await assert.rejects(InstanceLock.acquire(directory), ObserverAlreadyRunningError);
    const later = await InstanceLock.acquire(directory, { now: () => Date.now() + 60_000 });
    await later.release();
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("a lock whose process ID now belongs to another program is taken over", async () => {
  const directory = await mkdtemp(join(tmpdir(), "phigon-instance-lock-reused-"));
  const path = join(directory, "observer.lock");
  const now = Date.now();
  const bootedAt = () => now - 86_400_000;
  try {
    // This test's own process ID, alive, but recorded with a start time an
    // hour before this process really started: an observer killed an hour
    // ago whose ID was handed to another program.
    await writeFile(path, JSON.stringify({
      pid: process.pid,
      started_at: new Date(now - process.uptime() * 1_000 - 3_600_000).toISOString(),
    }));
    const lock = await InstanceLock.acquire(directory, { bootedAt });
    assert.equal(JSON.parse(await readFile(path, "utf8")).pid, process.pid);
    await lock.release();

    // A start time that matches, or one the system will not give, keeps
    // the holder.
    const startedAt = new Date(now - 60_000).toISOString();
    await writeFile(path, JSON.stringify({ pid: 424_242, started_at: startedAt }));
    for (const reading of [now - 60_500, null]) {
      await assert.rejects(
        InstanceLock.acquire(directory, {
          isAlive: () => true,
          bootedAt,
          processStartedAt: () => Promise.resolve(reading),
        }),
        ObserverAlreadyRunningError,
      );
    }
    await assert.rejects(
      InstanceLock.acquire(directory, {
        isAlive: () => true,
        bootedAt,
        processStartedAt: () => Promise.reject(new Error("unavailable")),
      }),
      ObserverAlreadyRunningError,
    );
    const takenOver = await InstanceLock.acquire(directory, {
      isAlive: () => true,
      bootedAt,
      processStartedAt: () => Promise.resolve(now - 5_000),
    });
    await takenOver.release();
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("releasing never removes a lock another observer took over", async () => {
  const directory = await mkdtemp(join(tmpdir(), "phigon-instance-lock-owner-"));
  const path = join(directory, "observer.lock");
  try {
    const lock = await InstanceLock.acquire(directory);
    const other = JSON.stringify({ pid: 424_242, started_at: new Date().toISOString() });
    await writeFile(path, other);
    await lock.release();
    assert.equal(await readFile(path, "utf8"), other);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("a lock is released when its process exits, and a killed holder's lock is taken over", async () => {
  const directory = await mkdtemp(join(tmpdir(), "phigon-instance-lock-process-"));
  const path = join(directory, "observer.lock");
  const holder = (then: string) => [
    "--input-type=module",
    "-e",
    `const { InstanceLock } = await import(${JSON.stringify(lockModule)});` +
      `await InstanceLock.acquire(${JSON.stringify(directory)});` +
      `console.log("held");${then}`,
  ];
  try {
    // process.exit skips every `finally`; the exit hook still releases.
    await promisify(execFile)(process.execPath, holder("process.exit(0);"));
    await assert.rejects(readFile(path, "utf8"), { code: "ENOENT" });

    const child = spawn(process.execPath, holder("setInterval(() => {}, 1000);"), {
      stdio: ["ignore", "pipe", "inherit"],
    });
    await once(child.stdout, "data");
    await assert.rejects(InstanceLock.acquire(directory), ObserverAlreadyRunningError);
    child.kill("SIGKILL");
    await once(child, "exit");
    const lock = await InstanceLock.acquire(directory);
    await lock.release();
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("inspect tells whether an observer holds the directory without touching the lock", async () => {
  const directory = await mkdtemp(join(tmpdir(), "phigon-instance-lock-inspect-"));
  const path = join(directory, "observer.lock");
  try {
    assert.deepEqual(await InstanceLock.inspect(directory), { running: false });

    const held = await InstanceLock.acquire(directory);
    const holder = await InstanceLock.inspect(directory);
    assert.equal(holder.running, true);
    assert.equal(holder.pid, process.pid);
    const content = await readFile(path, "utf8");
    await held.release();
    assert.deepEqual(await InstanceLock.inspect(directory), { running: false });

    // A stale lock is reported as not running and left in place.
    await writeFile(path, content);
    assert.deepEqual(await InstanceLock.inspect(directory, { isAlive: () => false }), { running: false });
    assert.equal(await readFile(path, "utf8"), content);
    assert.deepEqual(
      await InstanceLock.inspect(directory, { bootedAt: () => Date.now() + 3_600_000, processStartedAt: async () => null }),
      { running: false },
    );
    assert.deepEqual(
      await InstanceLock.inspect(directory, { processStartedAt: async () => Date.parse("2001-01-01T00:00:00Z") }),
      { running: false },
    );

    // A lock still being written counts as running for a few seconds.
    await writeFile(path, "");
    assert.deepEqual(await InstanceLock.inspect(directory), { running: true });
    assert.deepEqual(await InstanceLock.inspect(directory, { now: () => Date.now() + 60_000 }), { running: false });
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("a running observer is recognised after the clock changed, as it can just after the computer starts", async () => {
  const directory = await mkdtemp(join(tmpdir(), "phigon-instance-lock-clock-"));
  const path = join(directory, "observer.lock");
  const now = Date.parse("2026-11-03T15:00:00.000Z");
  // The background service started at sign-in while the clock was hours
  // behind; the clock was corrected a few minutes later.
  const startedAt = now - 12 * 3_600_000;
  const options = {
    isAlive: () => true,
    bootedAt: () => now - 3_600_000,
    now: () => now,
  };
  try {
    await writeFile(path, JSON.stringify({ pid: 424_242, started_at: new Date(startedAt).toISOString() }));
    // The system recorded the same start time for that process: it is the holder.
    const sameProcess = { ...options, processStartedAt: () => Promise.resolve(startedAt + 1_500) };
    assert.equal((await InstanceLock.inspect(directory, sameProcess)).running, true);
    await assert.rejects(InstanceLock.acquire(directory, sameProcess), ObserverAlreadyRunningError);

    // A different start time is another program that got the process ID.
    const otherProcess = { ...options, processStartedAt: () => Promise.resolve(now - 600_000) };
    assert.equal((await InstanceLock.inspect(directory, otherProcess)).running, false);
    const lock = await InstanceLock.acquire(directory, otherProcess);
    await lock.release();
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("a running observer is recognised when the clock was corrected between its start and its lock", async () => {
  const directory = await mkdtemp(join(tmpdir(), "phigon-instance-lock-corrected-"));
  const now = Date.parse("2026-11-04T07:43:45.000Z");
  // Windows recorded the service's start with a clock almost four hours
  // slow; the clock was corrected before the observer took its lock.
  const systemStart = Date.parse("2026-11-04T03:01:53.988Z");
  const corrected = Date.parse("2026-11-04T06:53:13.872Z");
  const options = { isAlive: () => true, bootedAt: () => corrected - 27_000, now: () => now };
  try {
    const lock = await InstanceLock.acquire(directory, {
      ...options,
      pid: 9_208,
      startedAt: new Date(corrected),
      processStartedAt: () => Promise.resolve(systemStart),
    });
    const written = JSON.parse(await readFile(join(directory, "observer.lock"), "utf8")) as Record<string, unknown>;
    assert.deepEqual(written, { pid: 9_208, started_at: "2026-11-04T06:53:13.872Z", process_started_at: "2026-11-04T03:01:53.988Z" });
    // The system still gives the start time it recorded, which the lock holds.
    const sameProcess = { ...options, processStartedAt: () => Promise.resolve(systemStart) };
    assert.deepEqual(await InstanceLock.inspect(directory, sameProcess), { running: true, pid: 9_208, startedAt: "2026-11-04T06:53:13.872Z" });
    await assert.rejects(InstanceLock.acquire(directory, sameProcess), ObserverAlreadyRunningError);
    // Another program that got the process ID started at neither time.
    const otherProcess = { ...options, processStartedAt: () => Promise.resolve(now - 60_000) };
    assert.deepEqual(await InstanceLock.inspect(directory, otherProcess), { running: false });
    await lock.release();
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});
