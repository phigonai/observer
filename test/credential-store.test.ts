import assert from "node:assert/strict";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { FileCredentialStore } from "../src/credential-store.js";

test("corrupt pairing data reports recovery instructions without echoing file contents", async () => {
  const directory = await mkdtemp(join(tmpdir(), "phigon-corrupt-credential-"));
  const path = join(directory, "machine-credential.json");
  const damaged = 'private-fixture-credential{"incomplete":';
  try {
    await writeFile(path, damaged);
    await assert.rejects(new FileCredentialStore(directory).load(), (error: unknown) => {
      assert.ok(error instanceof Error);
      assert.doesNotMatch(error.message, /private-fi/);
      assert.match(error.message, /restore.*backup/i);
      assert.match(error.message, /keep.*data directory/i);
      return true;
    });
    assert.equal(await readFile(path, "utf8"), damaged);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});
