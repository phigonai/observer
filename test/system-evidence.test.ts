import assert from "node:assert/strict";
import childProcess from "node:child_process";
import fsPromises, { mkdir, mkdtemp, rm, symlink, writeFile } from "node:fs/promises";
import { syncBuiltinESMExports } from "node:module";
import { tmpdir } from "node:os";
import { delimiter, join } from "node:path";
import test from "node:test";
import {
  ExecutableProbeCache,
  packageVersion,
  SystemEvidenceProvider,
} from "../src/discovery/system-evidence.js";

const windows = process.platform === "win32";

/** What npm writes for a global install of `@example/agent` with bin `agent`. */
async function npmInstall(prefix: string, version: string): Promise<string> {
  const packageDirectory = join(prefix, windows ? "" : "lib", "node_modules", "@example", "agent");
  await mkdir(join(packageDirectory, "bin"), { recursive: true });
  await writeFile(join(packageDirectory, "package.json"), JSON.stringify({ name: "@example/agent", version, bin: { agent: "bin/agent.js" } }));
  await writeFile(join(packageDirectory, "bin", "agent.js"), "#!/usr/bin/env node\nconsole.log('not run');\n", { mode: 0o755 });
  if (windows) {
    const shim = join(prefix, "agent.cmd");
    await writeFile(shim, [
      "@ECHO off", "GOTO start", ":find_dp0", "SET dp0=%~dp0", "EXIT /b", ":start", "SETLOCAL", "CALL :find_dp0",
      "IF EXIST \"%dp0%\\node.exe\" (", "  SET \"_prog=%dp0%\\node.exe\"", ") ELSE (", "  SET \"_prog=node\"", ")",
      "endLocal & goto #_undefined_# 2>NUL || title %COMSPEC% & \"%_prog%\"  \"%dp0%\\node_modules\\@example\\agent\\bin\\agent.js\" %*",
      "",
    ].join("\r\n"));
    await writeFile(join(prefix, "agent.ps1"), "#!/usr/bin/env pwsh\n$basedir=Split-Path $MyInvocation.MyCommand.Definition -Parent\n& \"$basedir/node_modules/@example/agent/bin/agent.js\" $args\n");
    return shim;
  }
  await mkdir(join(prefix, "bin"), { recursive: true });
  const link = join(prefix, "bin", "agent");
  await rm(link, { force: true });
  await symlink(join(packageDirectory, "bin", "agent.js"), link);
  return link;
}

test("an npm-installed CLI's version comes from its package.json, without starting it", async () => {
  // The version is read from the real file, and macOS's temporary folder
  // /var/folders is really /private/var/folders.
  const prefix = await fsPromises.realpath(await mkdtemp(join(tmpdir(), "phigon-npm-prefix-")));
  // Every child process starts through this method.
  const spawned: string[] = [];
  const prototype = childProcess.ChildProcess.prototype as unknown as {
    spawn: (this: unknown, options: { file?: string }) => unknown;
  };
  const originalSpawn = prototype.spawn;
  prototype.spawn = function counted(options) {
    spawned.push(String(options.file));
    return originalSpawn.call(this, options);
  };
  try {
    const executable = await npmInstall(prefix, "1.4.2");
    assert.deepEqual(await packageVersion(executable), {
      version: "1.4.2",
      file: join(prefix, windows ? "" : "lib", "node_modules", "@example", "agent", "package.json"),
      name: "@example/agent",
    });
    let now = 1_000_000;
    const cache = new ExecutableProbeCache({ clock: () => now });
    const environment = windows
      ? { Path: prefix, PathExt: ".COM;.EXE;.CMD" }
      : { PATH: join(prefix, "bin") };
    const inspect = async () => {
      const result = await new SystemEvidenceProvider(process.platform, environment, cache).inspectExecutable(["agent"]);
      assert.equal(result.status, "ok");
      return result.status === "ok" ? result.value?.version : undefined;
    };
    assert.equal(await inspect(), "1.4.2");
    // The command says which package it runs, for a name other programs share.
    const found = await new SystemEvidenceProvider(process.platform, environment).inspectExecutable(["agent"]);
    assert.equal(found.status === "ok" ? found.value?.packageName : undefined, "@example/agent");
    // An upgrade rewrites package.json; the shim stays the same.
    await new Promise((resolve) => setTimeout(resolve, 20));
    await npmInstall(prefix, "1.5.0");
    now += 1_000;
    assert.equal(await inspect(), "1.5.0");
    assert.deepEqual(spawned, [], "no process was started to read a version");
  } finally {
    prototype.spawn = originalSpawn;
    await rm(prefix, { recursive: true, force: true });
  }
});

test("a path that is no npm package, or names another package, gives no package version", async () => {
  const directory = await mkdtemp(join(tmpdir(), "phigon-not-npm-"));
  try {
    const plain = join(directory, windows ? "tool.exe" : "tool");
    await writeFile(plain, "binary");
    assert.equal(await packageVersion(plain), undefined);
    const other = join(directory, "node_modules", "other");
    await mkdir(other, { recursive: true });
    await writeFile(join(other, "package.json"), JSON.stringify({ name: "something-else", version: "9.9.9" }));
    const script = join(other, "cli.js");
    await writeFile(script, "");
    assert.equal(await packageVersion(script), undefined, "the manifest must name the package");
    await writeFile(join(other, "package.json"), JSON.stringify({ name: "other", version: "not a version" }));
    assert.equal(await packageVersion(script), undefined);
    await writeFile(join(other, "package.json"), JSON.stringify({ name: "other", version: "2.0.0-beta.1" }));
    assert.equal((await packageVersion(script))?.version, "2.0.0-beta.1");
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("looking for absent CLIs reads each PATH folder once instead of checking every name", async () => {
  const root = await mkdtemp(join(tmpdir(), "phigon-path-"));
  const folders = Array.from({ length: 12 }, (_, index) => join(root, `bin${index}`));
  for (const folder of folders) {
    await mkdir(folder);
    await writeFile(join(folder, windows ? "unrelated.exe" : "unrelated"), "");
  }
  const environment = windows
    ? { Path: folders.join(delimiter), PathExt: ".COM;.EXE;.BAT;.CMD;.VBS;.JS;.PS1" }
    : { PATH: folders.join(delimiter) };
  const counted = { access: 0, stat: 0, readdir: 0 };
  const promises = fsPromises as unknown as Record<keyof typeof counted, (...args: unknown[]) => unknown>;
  const originals = { ...promises };
  for (const name of Object.keys(counted) as (keyof typeof counted)[]) {
    const original = originals[name];
    promises[name] = (...args) => {
      counted[name]++;
      return original(...args);
    };
  }
  syncBuiltinESMExports();
  try {
    let now = 1_000_000;
    const cache = new ExecutableProbeCache({ clock: () => now });
    const names = ["codex", "claude", "gemini", "opencode", "aider", "goose"];
    const probe = () => Promise.all(names.map((name) =>
      new SystemEvidenceProvider(process.platform, environment, cache).inspectExecutable([name])));
    for (const result of await probe()) assert.deepEqual(result, { status: "ok", value: null });
    // Six absent CLIs over twelve folders: one look at each folder, no
    // name-by-name checks.
    assert.equal(counted.access, 0);
    assert.equal(counted.stat, folders.length);
    assert.equal(counted.readdir, folders.length);
    // A minute later (the absent CLIs are looked for again), unchanged
    // folders are checked but not read.
    now += 60_000;
    counted.stat = 0;
    counted.readdir = 0;
    await probe();
    assert.equal(counted.access, 0);
    assert.equal(counted.stat, folders.length);
    assert.ok(counted.readdir <= folders.length);
    // A CLI installed since is found.
    const installed = join(folders[7] ?? root, windows ? "goose.cmd" : "goose");
    await writeFile(installed, windows ? "@echo off\r\n" : "#!/bin/sh\n", { mode: 0o755 });
    now += 60_000;
    const found = (await probe()).at(-1);
    assert.equal(found?.status, "ok");
    assert.equal(found?.status === "ok" ? found.value?.executableName : undefined, "goose");
  } finally {
    for (const name of Object.keys(counted) as (keyof typeof counted)[]) promises[name] = originals[name];
    syncBuiltinESMExports();
    await rm(root, { recursive: true, force: true });
  }
});

test("a CLI that takes several seconds to print its version still gets one", { skip: process.platform === "win32", timeout: 30_000 }, async () => {
  const directory = await mkdtemp(join(tmpdir(), "phigon-slow-cli-"));
  try {
    // Like copilot.exe from WinGet, which takes 6-10 s to answer.
    await writeFile(join(directory, "slowagent"), "#!/bin/sh\nsleep 6\necho 'slowagent 3.2.1'\n", { mode: 0o755 });
    const result = await new SystemEvidenceProvider(process.platform, { PATH: directory }, new ExecutableProbeCache())
      .inspectExecutable(["slowagent"]);
    assert.equal(result.status === "ok" ? result.value?.version : undefined, "3.2.1");
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});
