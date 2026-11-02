import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import { minimumNodeVersion, nodeVersionProblem } from "../src/node-version.js";

const execFileAsync = promisify(execFile);

test("Node.js older than 24.5 gets one plain sentence", () => {
  for (const version of ["18.20.4", "v20.11.1", "22.21.0", "24.0.0", "24.4.9"]) {
    assert.equal(
      nodeVersionProblem(version),
      `Phigon observer needs Node.js 24.5 or newer; this computer has ${version.replace(/^v/u, "")}.`,
      version,
    );
  }
  assert.match(nodeVersionProblem("not a version") ?? "", /needs Node\.js 24\.5 or newer/u);
});

test("Node.js 24.5 and newer runs the observer", () => {
  for (const version of ["24.5.0", "v24.14.1", "25.0.0", "26.3.1"]) {
    assert.equal(nodeVersionProblem(version), undefined, version);
  }
  assert.equal(nodeVersionProblem(process.versions.node), undefined);
});

test("the package requires the same Node.js the entry point checks", async () => {
  const manifest = JSON.parse(await readFile(new URL("../../package.json", import.meta.url), "utf8")) as {
    engines: { node: string };
    bin: Record<string, string>;
  };
  assert.equal(manifest.engines.node, `>=${minimumNodeVersion}`);
  assert.equal(manifest.bin["phigon-observer"], "dist/src/entry.js");
  const lock = JSON.parse(await readFile(new URL("../../package-lock.json", import.meta.url), "utf8")) as {
    packages: Record<string, { engines?: { node: string }; bin?: Record<string, string> }>;
  };
  assert.equal(lock.packages[""]?.engines?.node, manifest.engines.node);
  assert.deepEqual(lock.packages[""]?.bin, manifest.bin);
});

test("the entry point loads only the version check before it", async () => {
  const entry = fileURLToPath(new URL("../src/entry.js", import.meta.url));
  const source = await readFile(entry, "utf8");
  const staticImports = [...source.matchAll(/^import\s.*?from\s+"([^"]+)"/gmu)].map((match) => match[1]);
  assert.deepEqual(staticImports, ["./node-version.js"]);

  const { stdout } = await execFileAsync(process.execPath, [entry, "--version"]);
  const manifest = JSON.parse(await readFile(new URL("../../package.json", import.meta.url), "utf8")) as { version: string };
  assert.equal(stdout.trim(), manifest.version);
});
