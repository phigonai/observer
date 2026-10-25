#!/usr/bin/env node

import { createHash } from "node:crypto";
import { realpathSync, statSync } from "node:fs";
import {
  lstat,
  mkdir,
  readFile,
  rename,
  rm,
  symlink,
} from "node:fs/promises";
import { homedir, platform } from "node:os";
import { basename, dirname, isAbsolute, join, resolve } from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const packageName = "@phigon/observer";
const legacyPackageName = "phigon-observer";
const safeVersion = /^[0-9A-Za-z][0-9A-Za-z.+-]{0,63}$/u;
const sha256Pattern = /^[a-f0-9]{64}$/u;

if (process.argv[1] && realpathSync(process.argv[1]) === realpathSync(fileURLToPath(import.meta.url))) {
  process.exitCode = await main(process.argv.slice(2));
}

// Keep the published installer self-contained. Windows .cmd launchers require
// a shell; invoking npm's JS entry point keeps paths as individual arguments.
export function npmCommand(arguments_) {
  if (process.platform !== "win32") return { command: "npm", arguments: arguments_ };
  const candidates = [
    process.env.npm_execpath,
    join(dirname(process.execPath), "node_modules", "npm", "bin", "npm-cli.js"),
  ];
  for (const candidate of candidates) {
    if (!candidate || !isAbsolute(candidate) || basename(candidate).toLowerCase() !== "npm-cli.js") continue;
    try {
      if (statSync(candidate).isFile()) return { command: process.execPath, arguments: [candidate, ...arguments_] };
    } catch { /* Try the Node installation's bundled npm. */ }
  }
  throw new Error("Cannot find npm-cli.js. Use a Node installation with npm, or run this installer through npm.");
}

async function main(argv) {
  const [command, ...args] = argv;
  try {
    if (command === "install") {
      await install(parseOptions(args));
      return 0;
    }
    if (command === "rollback") {
      await rollback(parseOptions(args));
      return 0;
    }
    if (command === "status") {
      await status(parseOptions(args));
      return 0;
    }
    process.stderr.write(help());
    return 2;
  } catch (error) {
    const message = error instanceof Error ? error.message : "Unknown error.";
    process.stderr.write(`Observer installation failed: ${message}\n`);
    return 1;
  }
}

async function install(options) {
  const version = required(options, "version");
  const artifactValue = required(options, "artifact");
  const expectedSHA = required(options, "sha256").toLowerCase();
  if (!safeVersion.test(version)) throw new Error("Invalid release version.");
  if (!sha256Pattern.test(expectedSHA)) {
    throw new Error("--sha256 must be a lowercase SHA-256 digest.");
  }

  const prefix = installPrefix(options);
  const versions = join(prefix, "versions");
  const staging = join(versions, `.${version}.${process.pid}.staging`);
  const destination = join(versions, version);
  const artifact = await acquireArtifact(artifactValue, prefix);
  const actualSHA = await digestFile(artifact.path);
  if (actualSHA !== expectedSHA) {
    await artifact.cleanup();
    throw new Error(
      `Checksum mismatch for ${basename(artifact.path)}: expected ${expectedSHA}, received ${actualSHA}.`,
    );
  }

  await mkdir(versions, { recursive: true, mode: 0o700 });
  await rm(staging, { recursive: true, force: true });
  const npm = npmCommand([
    "install",
    "--global",
    "--prefix",
    staging,
    "--ignore-scripts",
    "--no-audit",
    "--no-fund",
    artifact.path,
  ]);
  const result = spawnSync(
    npm.command,
    npm.arguments,
    {
      stdio: "inherit",
      windowsHide: true,
      shell: false,
    },
  );
  await artifact.cleanup();
  if (result.error) throw result.error;
  if (result.status !== 0) {
    await rm(staging, { recursive: true, force: true });
    throw new Error(`npm exited with status ${result.status ?? "unknown"}.`);
  }

  const installedPackage = packageManifestPath(staging);
  const manifest = JSON.parse(await readFile(installedPackage, "utf8"));
  if (manifest.name !== packageName || manifest.version !== version) {
    await rm(staging, { recursive: true, force: true });
    throw new Error(
      `Artifact identity ${String(manifest.name)}@${String(manifest.version)} does not match ${packageName}@${version}.`,
    );
  }

  await rm(destination, { recursive: true, force: true });
  await rename(staging, destination);
  await activate(prefix, destination);
  process.stdout.write(
    `Installed ${packageName}@${version} at ${destination}.\n` +
      `Add ${join(prefix, "current", binDirectory())} to PATH.\n`,
  );
}

async function activate(prefix, destination) {
  const current = join(prefix, "current");
  const previous = join(prefix, "previous");
  const next = join(prefix, `.current.${process.pid}`);
  await rm(next, { recursive: true, force: true });
  await symlink(
    relativeLinkTarget(prefix, destination),
    next,
    platform() === "win32" ? "junction" : "dir",
  );
  if (await exists(current)) {
    await rm(previous, { recursive: true, force: true });
    await rename(current, previous);
  }
  try {
    await rename(next, current);
  } catch (error) {
    if (await exists(previous)) await rename(previous, current);
    throw error;
  }
}

async function rollback(options) {
  const prefix = installPrefix(options);
  const current = join(prefix, "current");
  const previous = join(prefix, "previous");
  if (!(await exists(current)) || !(await exists(previous))) {
    throw new Error("No reversible previous observer installation exists.");
  }
  const swap = join(prefix, `.rollback.${process.pid}`);
  await rename(current, swap);
  try {
    await rename(previous, current);
    await rename(swap, previous);
  } catch (error) {
    if (await exists(swap) && !(await exists(current))) {
      await rename(swap, current);
    }
    throw error;
  }
  process.stdout.write(`Rolled back to ${await activeVersion(prefix)}.\n`);
}

async function status(options) {
  const prefix = installPrefix(options);
  process.stdout.write(
    `${JSON.stringify(
      {
        prefix,
        activeVersion: await activeVersion(prefix),
        rollbackAvailable: await exists(join(prefix, "previous")),
      },
      null,
      2,
    )}\n`,
  );
}

async function activeVersion(prefix) {
  // Existing versioned installs retain the old package path after migration.
  for (const name of [packageName, legacyPackageName]) {
    try {
      const manifest = JSON.parse(await readFile(packageManifestPath(join(prefix, "current"), name), "utf8"));
      if (manifest.name === name && typeof manifest.version === "string") return manifest.version;
    } catch { /* Try the legacy package path retained for rollback. */ }
  }
  return null;
}

async function acquireArtifact(value, prefix) {
  if (/^https:\/\//u.test(value)) {
    const response = await fetch(value, {
      redirect: "error",
      signal: AbortSignal.timeout(30_000),
    });
    if (!response.ok) {
      throw new Error(`Artifact download returned HTTP ${response.status}.`);
    }
    const downloadDirectory = join(prefix, ".downloads");
    await mkdir(downloadDirectory, { recursive: true, mode: 0o700 });
    const path = join(downloadDirectory, `observer-${process.pid}.tgz`);
    const bytes = new Uint8Array(await response.arrayBuffer());
    const { writeFile } = await import("node:fs/promises");
    await writeFile(path, bytes, { mode: 0o600, flag: "wx" });
    return {
      path,
      cleanup: async () => rm(path, { force: true }),
    };
  }
  if (!isAbsolute(value) && /^[a-z][a-z0-9+.-]*:/iu.test(value)) {
    throw new Error("Only HTTPS downloads and local artifact paths are allowed.");
  }
  const path = resolve(value);
  await lstat(path);
  return { path, cleanup: async () => undefined };
}

async function digestFile(path) {
  const hash = createHash("sha256");
  hash.update(await readFile(path));
  return hash.digest("hex");
}

function parseOptions(args) {
  const options = new Map();
  for (let index = 0; index < args.length; index++) {
    const name = args[index];
    if (!name?.startsWith("--")) throw new Error(`Unexpected argument: ${name}`);
    const value = args[index + 1];
    if (!value || value.startsWith("--")) {
      throw new Error(`${name} requires a value.`);
    }
    options.set(name.slice(2), value);
    index++;
  }
  return options;
}

function required(options, name) {
  const value = options.get(name)?.trim();
  if (!value) throw new Error(`--${name} is required.`);
  return value;
}

function installPrefix(options) {
  const value = options.get("prefix")?.trim();
  return resolve(value || join(homedir(), ".phigon", "observer-install"));
}

function binDirectory() {
  return platform() === "win32" ? "" : "bin";
}

function packageManifestPath(prefix, name = packageName) {
  return join(
    prefix,
    ...(platform() === "win32" ? [] : ["lib"]),
    "node_modules",
    name,
    "package.json",
  );
}

function relativeLinkTarget(prefix, destination) {
  if (platform() === "win32") return destination;
  return join("versions", basename(destination));
}

async function exists(path) {
  try {
    await lstat(path);
    return true;
  } catch (error) {
    if (error instanceof Error && "code" in error && error.code === "ENOENT") {
      return false;
    }
    throw error;
  }
}

function help() {
  return [
    "Phigon observer installer",
    "",
    "Install or upgrade:",
    "  node install.mjs install --artifact <path|https-url> --sha256 <digest> --version <version> [--prefix <directory>]",
    "Rollback:",
    "  node install.mjs rollback [--prefix <directory>]",
    "Status:",
    "  node install.mjs status [--prefix <directory>]",
    "",
  ].join("\n");
}
