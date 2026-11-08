import assert from "node:assert/strict";
import { mkdir, mkdtemp, readFile, readdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { maxCorruptStreamStateCopies, StreamStateStore } from "../src/stream-state.js";

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

test("an unreadable cursor is copied once while recovery waits, and only a few copies are kept", async () => {
  const directory = await mkdtemp(join(tmpdir(), "phigon-cursor-copies-"));
  const copies = async () => (await readdir(directory)).filter((name) => name.endsWith(".corrupt")).sort();
  try {
    const path = join(directory, "stream-state.json");
    await writeFile(path, "\u0000");
    // Every reconnect reads the same unreadable cursor again.
    for (let attempt = 0; attempt < 5; attempt++) {
      assert.equal((await new StreamStateStore(directory).load("paired-machine", 0n)).recoveryPending, true);
    }
    assert.equal((await copies()).length, 1);
    // Older copies, such as ones an earlier version named at random, count too.
    await writeFile(join(directory, "stream-state.json.7f6b3c2a-1111-4222-8333-944445555666.corrupt"), "old");
    for (let index = 0; index < 5; index++) {
      await writeFile(path, `\u0000${index}`);
      await new StreamStateStore(directory).load("paired-machine", 0n);
    }
    const kept = await copies();
    assert.equal(kept.length, maxCorruptStreamStateCopies);
    const contents = await Promise.all(kept.map((name) => readFile(join(directory, name), "utf8")));
    assert.ok(contents.includes("\u00004"), "the newest copy is kept");
    assert.ok(!contents.includes("old"));
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
