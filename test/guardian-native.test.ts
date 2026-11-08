import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { existsSync } from "node:fs";
import { mkdtemp, readFile, rm, utimes, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { basename, dirname, join } from "node:path";
import test from "node:test";
import {
  guardianManifestName,
  guardianRunnerFile,
  guardianRunnerPath,
  guardianRunnerUnverifiedMessage,
  verifyGuardianRunner,
} from "../src/guardian-native.js";

const sha256 = (bytes: string | Buffer) => createHash("sha256").update(bytes).digest("hex");

test("the Guardian runner starts only when it matches the checksum it was built with", async () => {
  const directory = await mkdtemp(join(tmpdir(), "phigon-runner-"));
  try {
    const runner = join(directory, "guardian-runner-test-amd64");
    const manifest = join(directory, guardianManifestName);
    const unverified = (error: Error) => error.message === guardianRunnerUnverifiedMessage;
    // A development build without the runner: starting it reports ENOENT as before.
    assert.doesNotThrow(() => verifyGuardianRunner(runner, manifest));

    await writeFile(runner, "built runner");
    // No checksum shipped with it.
    assert.throws(() => verifyGuardianRunner(runner, manifest), unverified);
    await writeFile(manifest, JSON.stringify({ version: 1, files: { [basename(runner)]: sha256("built runner") } }));
    // The failure was kept for that file; the same file is not read again.
    assert.throws(() => verifyGuardianRunner(runner, manifest), unverified);
    // A file changed since (here, the same bytes written again) is checked again.
    await writeFile(runner, "built runner");
    await utimes(runner, new Date(), new Date(Date.now() + 5_000));
    assert.doesNotThrow(() => verifyGuardianRunner(runner, manifest));

    // Replaced after it was checked.
    await writeFile(runner, "something else entirely");
    await utimes(runner, new Date(), new Date(Date.now() + 10_000));
    assert.throws(() => verifyGuardianRunner(runner, manifest), unverified);

    // An unreadable or incomplete checksum file fails closed.
    for (const text of ["{", JSON.stringify({ files: {} }), JSON.stringify({ files: { [basename(runner)]: "abc" } })]) {
      await writeFile(manifest, text);
      await utimes(runner, new Date(), new Date(Date.now() + 15_000 + text.length));
      assert.throws(() => verifyGuardianRunner(runner, manifest), unverified, text);
    }
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("the built package ships a checksum for this platform's runner", { skip: !existsSync(guardianRunnerFile()) }, async () => {
  const runner = guardianRunnerFile();
  const manifest = JSON.parse(await readFile(join(dirname(runner), guardianManifestName), "utf8")) as { files: Record<string, string> };
  assert.equal(manifest.files[basename(runner)], sha256(await readFile(runner)));
  assert.equal(guardianRunnerPath(), runner);
});
