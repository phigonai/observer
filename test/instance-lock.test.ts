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

    // The process ID is in use again, but the lock predates the last boot.
    await writeFile(path, JSON.stringify({ pid: 424_242, started_at: new Date(now - 7_200_000).toISOString() }));
    const afterReboot = await InstanceLock.acquire(directory, {
      isAlive: () => true,
      bootedAt: () => now - 3_600_000,
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
