import assert from "node:assert/strict";
import { readFileSync, renameSync } from "node:fs";
import { mkdtemp, readFile, rename, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { atomicReplace, atomicReplaceSync } from "../src/atomic-replace.js";

test("Windows spool replacement retries a transient lock synchronously", { skip: process.platform !== "win32" }, async () => {
  const directory = await mkdtemp(join(tmpdir(), "phigon-replace-sync-"));
  const previous = join(directory, "telemetry-spool.jsonl");
  const next = join(directory, "telemetry-spool.jsonl.tmp");
  let attempts = 0;
  try {
    await writeFile(previous, "old spool");
    await writeFile(next, "new spool");
    atomicReplaceSync(next, previous, (source, destination) => {
      assert.equal(readFileSync(previous, "utf8"), "old spool");
      if (++attempts <= 2) throw Object.assign(new Error("busy"), { code: attempts === 1 ? "EBUSY" : "EACCES" });
      renameSync(source, destination);
    });
    assert.equal(attempts, 3);
    assert.equal(await readFile(previous, "utf8"), "new spool");
    // A lock that outlasts every retry, or another error, is reported.
    await writeFile(next, "not saved");
    let held = 0;
    assert.throws(() => atomicReplaceSync(next, previous, () => {
      held++;
      throw Object.assign(new Error("still busy"), { code: "EPERM" });
    }), /still busy/u);
    assert.equal(held, 6);
    const failure = Object.assign(new Error("read-only filesystem"), { code: "EROFS" });
    assert.throws(() => atomicReplaceSync(next, previous, () => { throw failure; }), failure);
    assert.equal(await readFile(previous, "utf8"), "new spool");
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("Windows checkpoint replacement tolerates a transient lock without removing the old checkpoint", { skip: process.platform !== "win32" }, async () => {
  const directory = await mkdtemp(join(tmpdir(), "phigon-replace-"));
  const previous = join(directory, "saved.json");
  const next = join(directory, "next.tmp");
  let attempts = 0;
  try {
    await writeFile(previous, "old checkpoint");
    await writeFile(next, "new checkpoint");
    await atomicReplace(next, previous, async (source, destination) => {
      assert.equal(await readFile(previous, "utf8"), "old checkpoint");
      if (++attempts === 1) throw Object.assign(new Error("busy"), { code: "EPERM" });
      await rename(source, destination);
    });
    assert.equal(attempts, 2);
    assert.equal(await readFile(previous, "utf8"), "new checkpoint");
    await writeFile(next, "not saved");
    const failure = Object.assign(new Error("read-only filesystem"), { code: "EROFS" });
    await assert.rejects(atomicReplace(next, previous, async () => { throw failure; }), failure);
    assert.equal(await readFile(previous, "utf8"), "new checkpoint");
    assert.equal(await readFile(next, "utf8"), "not saved");
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});
