import assert from "node:assert/strict";
import { mkdtemp, readFile, rename, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { atomicReplace } from "../src/atomic-replace.js";

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
