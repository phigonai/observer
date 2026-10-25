import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import {
  mkdir,
  mkdtemp,
  copyFile,
  readFile,
  rm,
  writeFile,
  symlink,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { spawnSync } from "node:child_process";
import { npmCommand } from "./install.mjs";

const root = resolve(import.meta.dirname, "..");
const work = await mkdtemp(join(tmpdir(), "phigon-installer-"));
const installer = join(work, "install-observer.mjs");
const prefix = join(work, "company tools & agents");
const firstVersion = JSON.parse(
  await readFile(join(root, "package.json"), "utf8"),
).version;
const secondVersion = nextPatchVersion(firstVersion);

try {
  // Exercise the standalone release artifact, not imports from the repository.
  await copyFile(join(root, "scripts", "install.mjs"), installer);
  const first = pack(root, work);
  const unpack = join(work, "unpack");
  await mkdir(unpack, { recursive: true });
  run("tar", ["-xzf", first, "-C", unpack]);
  const manifestPath = join(unpack, "package", "package.json");
  const manifest = JSON.parse(await readFile(manifestPath, "utf8"));
  manifest.version = secondVersion;
  await writeFile(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`);
  const second = pack(join(unpack, "package"), work);

  const firstSHA = sha256(first);
  const secondSHA = sha256(second);
  install(first, firstSHA, firstVersion);
  install(second, secondSHA, secondVersion);
  assert.equal(status().activeVersion, secondVersion);
  assert.equal(status().rollbackAvailable, true);
  run(process.execPath, [installer, "rollback", "--prefix", prefix]);
  assert.equal(status().activeVersion, firstVersion);

  const bad = spawnSync(
    process.execPath,
    [
      installer,
      "install",
      "--artifact",
      first,
      "--sha256",
      "0".repeat(64),
      "--version",
      firstVersion,
      "--prefix",
      prefix,
    ],
    { encoding: "utf8" },
  );
  assert.notEqual(bad.status, 0);
  assert.match(bad.stderr, /Checksum mismatch/u);
  assert.equal(status().activeVersion, firstVersion);
  // Reproduce a retained installation from the previous unscoped package.
  const legacyPrefix = join(work, "legacy-install");
  const legacyVersion = "8.0.0";
  const legacyDirectory = join(legacyPrefix, "versions", legacyVersion);
  const legacyModules = join(legacyDirectory, ...(process.platform === "win32" ? [] : ["lib"]), "node_modules", "phigon-observer");
  await mkdir(legacyModules, { recursive: true });
  await writeFile(join(legacyModules, "package.json"), JSON.stringify({ name: "phigon-observer", version: legacyVersion }));
  await symlink(legacyDirectory, join(legacyPrefix, "current"), process.platform === "win32" ? "junction" : "dir");
  run(process.execPath, [installer, "install", "--artifact", first, "--sha256", firstSHA, "--version", firstVersion, "--prefix", legacyPrefix]);
  const migrated = spawnSync(process.execPath, [installer, "status", "--prefix", legacyPrefix], { encoding: "utf8" });
  assert.equal(migrated.status, 0);
  assert.equal(JSON.parse(migrated.stdout).activeVersion, firstVersion);
  run(process.execPath, [installer, "rollback", "--prefix", legacyPrefix]);
  const restored = spawnSync(process.execPath, [installer, "status", "--prefix", legacyPrefix], { encoding: "utf8" });
  assert.equal(restored.status, 0);
  assert.equal(JSON.parse(restored.stdout).activeVersion, legacyVersion);
  process.stdout.write("installer install, upgrade, rollback, legacy migration, and checksum rejection passed\n");
} finally {
  await rm(work, { recursive: true, force: true });
}

function pack(directory, destination) {
  const npm = npmCommand(["pack", directory, "--pack-destination", destination, "--json"]);
  const result = spawnSync(
    npm.command,
    npm.arguments,
    {
      encoding: "utf8",
      shell: false,
      windowsHide: true,
    },
  );
  if (result.error) throw result.error;
  if (result.status !== 0) {
    throw new Error(result.stderr || result.stdout || "npm pack failed");
  }
  const output = JSON.parse(result.stdout);
  return join(destination, output[0].filename);
}

function install(artifact, checksum, version) {
  run(process.execPath, [
    installer,
    "install",
    "--artifact",
    artifact,
    "--sha256",
    checksum,
    "--version",
    version,
    "--prefix",
    prefix,
  ]);
}

function status() {
  const result = spawnSync(
    process.execPath,
    [installer, "status", "--prefix", prefix],
    { encoding: "utf8" },
  );
  if (result.status !== 0) throw new Error(result.stderr || result.stdout);
  return JSON.parse(result.stdout);
}

function sha256(path) {
  return createHash("sha256").update(readFileSync(path)).digest("hex");
}

function nextPatchVersion(version) {
  const match = /^(\d+)\.(\d+)\.(\d+)$/u.exec(version);
  if (match === null) {
    throw new Error(`Expected a stable semantic version, received ${version}`);
  }
  return `${match[1]}.${match[2]}.${Number(match[3]) + 1}`;
}

function run(command, args) {
  const result = spawnSync(command, args, { stdio: "inherit" });
  if (result.error) throw result.error;
  if (result.status !== 0) {
    throw new Error(`${command} exited with status ${result.status}`);
  }
}
