import assert from "node:assert/strict";
import { mkdir, mkdtemp, readFile, readdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { StreamStateStore } from "../src/stream-state.js";

test("corrupt stream cursor recovers only from a verified delivery checkpoint", async () => {
  const directory = await mkdtemp(join(tmpdir(), "phigon-cursor-recovery-"));
  try {
    const path = join(directory, "stream-state.json");
    const corrupt = "\u0000".repeat(128);
    await writeFile(path, corrupt);
    const store = new StreamStateStore(directory);
    await assert.rejects(store.load("paired-machine"), /no verified delivery checkpoint/u);
    assert.equal(await readFile(path, "utf8"), corrupt);
    assert.equal((await store.load("paired-machine", 429n)).acknowledgedSequence, 429n);
    assert.equal((await new StreamStateStore(directory).load("paired-machine")).acknowledgedSequence, 429n);
    const retained = (await readdir(directory)).filter((name) => name.endsWith(".corrupt"));
    assert.equal(retained.length, 1);
    assert.equal(await readFile(join(directory, retained[0]!), "utf8"), corrupt);
    assert.equal((await store.load("other-machine", 429n)).acknowledgedSequence, 0n);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("an unreadable cursor with an empty restored spool waits for server reconciliation", async () => {
  const directory = await mkdtemp(join(tmpdir(), "phigon-cursor-server-"));
  try {
    const path = join(directory, "stream-state.json");
    await writeFile(path, "\u0000");
    const state = await new StreamStateStore(directory).load("paired-machine", 0n);
    assert.equal(state.recoveryPending, true);
    assert.equal(await readFile(path, "utf8"), "\u0000");
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("stream cursor survives process-local store recreation", async () => {
  const directory = await mkdtemp(join(tmpdir(), "phigon-cursor-"));
  const machineId = "machine-cursor-1";
  try {
    const first = new StreamStateStore(directory);
    assert.equal(
      (await first.load(machineId)).acknowledgedSequence,
      0n,
    );
    await first.save(machineId, 42n);

    const recreated = new StreamStateStore(directory);
    assert.equal(
      (await recreated.load(machineId)).acknowledgedSequence,
      42n,
    );
    assert.equal(
      (await recreated.load("machine-cursor-2"))
        .acknowledgedSequence,
      0n,
    );
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("stream state recovers after a disk-write failure without accepting a false cursor", async () => {
  const directory = await mkdtemp(join(tmpdir(), "phigon-state-pressure-"));
  const blockedPath = join(directory, "stream-state.json");
  const machineId = "machine-pressure-1";
  try {
    await mkdir(blockedPath);
    const store = new StreamStateStore(directory);
    await assert.rejects(store.save(machineId, 7n));
    await rm(blockedPath, { recursive: true });
    assert.equal(
      (await store.load(machineId)).acknowledgedSequence,
      0n,
    );

    await store.save(machineId, 7n);
    assert.equal(
      (await store.load(machineId)).acknowledgedSequence,
      7n,
    );
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});
