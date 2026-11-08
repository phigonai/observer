// Checks a globally installed phigon-observer the way a person runs it: by
// name, through the shell (cmd.exe and npm's .cmd shim on Windows). It must
// start, print the packaged version, and report an unpaired computer without
// contacting any server. Run it after `npm install --global <tarball>`.
import assert from "node:assert/strict";
import { execSync } from "node:child_process";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

const expected = JSON.parse(await readFile(new URL("../package.json", import.meta.url), "utf8")).version;
const dataDirectory = await mkdtemp(join(tmpdir(), "phigon-global-install-"));
try {
  const run = (args) => execSync(`phigon-observer ${args}`, {
    encoding: "utf8",
    env: { ...process.env, PHIGON_DATA_DIR: dataDirectory },
    windowsHide: true,
  });
  assert.equal(run("--version").trim(), expected, "the installed command reports the packaged version");
  const doctor = JSON.parse(run("doctor --json"));
  assert.equal(doctor.status, "needs-pairing");
  assert.equal(doctor.observerVersion, expected);
  assert.equal(doctor.machineTokenConfigured, false);
  process.stdout.write(`phigon-observer ${expected} runs from the global install; doctor reports ${doctor.status}.\n`);
} finally {
  // mkdtemp returned this check's own empty directory.
  await rm(dataDirectory, { recursive: true, force: true });
}
