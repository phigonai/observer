import assert from "node:assert/strict";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import {
  bundledNpmCli,
  installObserverUpdate,
  latestObserverVersion,
  newerVersion,
  offerObserverUpdate,
  packageVersion,
  runningPackageRoot,
} from "../src/update.js";

test("update comparison handles numeric versions and rejects command syntax/prereleases", () => {
  assert.equal(newerVersion("8.9.0", "8.10.0"), true);
  assert.equal(newerVersion("9.0.0", "8.10.0"), false);
  for (const value of ["8.0.2", "8.0.3; bad", "latest", "9.0.0-beta.1", "09.0.0"]) assert.equal(newerVersion("8.0.2", value), false);
});

test("update checks are bounded, cached and tolerate offline use", async () => {
  const directory = await mkdtemp(join(tmpdir(), "phigon-updates-"));
  let requests = 0;
  const fetcher: typeof fetch = async (url, init) => {
    requests++; assert.equal(String(url), "https://registry.npmjs.org/@phigon%2fobserver/latest");
    assert.ok(init?.signal); assert.equal(init.redirect, "error");
    return Response.json({ name: "@phigon/observer", version: "8.10.0" });
  };
  try {
    assert.equal(await latestObserverVersion(directory, { fetcher, now: 100 }), "8.10.0");
    assert.equal(await latestObserverVersion(directory, { fetcher, now: 200 }), "8.10.0");
    assert.equal(requests, 1);
    assert.equal(await latestObserverVersion(directory, { force: true, fetcher: async () => { throw new Error("offline"); } }), null);
  } finally { await rm(directory, { recursive: true, force: true }); }
});

test("update uses the npm that came with the running Node.js, by absolute path", () => {
  const windowsNode = "C:\\Program Files\\nodejs\\node.exe";
  const windowsNpm = "C:\\Program Files\\nodejs\\node_modules\\npm\\bin\\npm-cli.js";
  assert.equal(bundledNpmCli(windowsNode, "win32", (path) => path === windowsNpm), windowsNpm);
  assert.equal(bundledNpmCli(windowsNode, "win32", () => false), undefined);

  // nvm, distribution packages: bin/npm links into lib.
  const nvmNode = "/home/dev/.nvm/versions/node/v24.5.0/bin/node";
  const nvmNpm = "/home/dev/.nvm/versions/node/v24.5.0/lib/node_modules/npm/bin/npm-cli.js";
  assert.equal(bundledNpmCli(nvmNode, "linux", (path) => path === nvmNpm, (path) => {
    assert.equal(path, "/home/dev/.nvm/versions/node/v24.5.0/bin/npm");
    return nvmNpm;
  }), nvmNpm);
  // Homebrew keeps npm under libexec, without a link it can follow here.
  const brewNode = "/opt/homebrew/Cellar/node/24.5.0/bin/node";
  const brewNpm = "/opt/homebrew/Cellar/node/24.5.0/libexec/lib/node_modules/npm/bin/npm-cli.js";
  assert.equal(bundledNpmCli(brewNode, "darwin", (path) => path === brewNpm, () => { throw new Error("ENOENT"); }), brewNpm);

  // This Node.js's own npm, and the running observer's own package.
  assert.match(bundledNpmCli() ?? "", /npm-cli\.js$/u);
});

test("the running observer's package is the one update checks", async () => {
  const own = JSON.parse(await readFile(new URL("../../package.json", import.meta.url), "utf8")) as { version: string };
  assert.equal(await packageVersion(runningPackageRoot), own.version);
});

test("update runs npm without a shell and reports an install that went elsewhere as a failure", async () => {
  const directory = await mkdtemp(join(tmpdir(), "phigon-update-install-"));
  const packageRoot = join(directory, "observer");
  const calls: Array<readonly string[]> = [];
  try {
    await mkdir(packageRoot);
    await writeFile(join(packageRoot, "package.json"), JSON.stringify({ name: "@phigon/observer", version: "8.11.2" }));
    const options = { execPath: "/opt/node/bin/node", npmCli: "/opt/node/lib/node_modules/npm/bin/npm-cli.js", packageRoot };

    // npm succeeds but installs into another prefix: this observer is unchanged.
    await assert.rejects(
      installObserverUpdate("8.12.0", { ...options, run: async (command, args) => { calls.push([command, ...args]); return 0; } }),
      (error: unknown) => error instanceof Error &&
        error.message.includes(`the observer in ${packageRoot} is still 8.11.2, not 8.12.0`) &&
        error.message.includes("phigon-observer service install"),
    );
    assert.deepEqual(calls, [[
      "/opt/node/bin/node",
      "/opt/node/lib/node_modules/npm/bin/npm-cli.js",
      "install", "--global", "@phigon/observer@8.12.0", "--registry=https://registry.npmjs.org",
    ]]);

    // npm installs into this observer's folder.
    await installObserverUpdate("8.12.0", {
      ...options,
      run: async () => {
        await writeFile(join(packageRoot, "package.json"), JSON.stringify({ name: "@phigon/observer", version: "8.12.0" }));
        return 0;
      },
    });
    assert.equal(await packageVersion(packageRoot), "8.12.0");

    await assert.rejects(installObserverUpdate("8.13.0", { ...options, run: async () => 1 }), /^Error: Update failed\./u);
    await assert.rejects(installObserverUpdate("8.13.0", { ...options, run: () => Promise.reject(new Error("ENOENT")) }), /Could not start npm/u);
    await assert.rejects(
      installObserverUpdate("8.13.0", { ...options, npmCli: undefined }),
      /The npm that came with this Node\.js \(\/opt\/node\/bin\/node\) was not found, so the observer was not updated/u,
    );
    await assert.rejects(installObserverUpdate("8.13.0; rm -rf /", options), /Invalid observer version/u);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("update installs only after yes and asks for a restart", async () => {
  const installed: string[] = []; let text = "";
  const options = { current: "8.0.2", latest: "8.0.3", write: (value: string) => { text += value; }, install: async (version: string) => { installed.push(version); } };
  assert.equal(await offerObserverUpdate({ ...options, confirm: async () => "" }), false);
  assert.deepEqual(installed, []);
  assert.equal(await offerObserverUpdate({ ...options, confirm: async () => "yes" }), true);
  assert.deepEqual(installed, ["8.0.3"]);
  assert.match(text, /queued activity are preserved/u);
});

test("update --yes says it is updating instead of asking", async () => {
  const installed: string[] = []; let text = "";
  assert.equal(await offerObserverUpdate({ current: "8.6.0", latest: "8.6.1", write: (value) => { text += value; }, install: async (version) => { installed.push(version); } }), true);
  assert.deepEqual(installed, ["8.6.1"]);
  assert.match(text, /^Updating the Phigon observer from 8\.6\.0 to 8\.6\.1\.\n/u);
  assert.doesNotMatch(text, /Type "yes"/u);
});

test("a failed update check is retried soon instead of hiding updates for a day", async () => {
  const directory = await mkdtemp(join(tmpdir(), "phigon-updates-retry-"));
  let requests = 0;
  const online: typeof fetch = async () => { requests++; return Response.json({ name: "@phigon/observer", version: "9.0.0" }); };
  const hour = 60 * 60 * 1000;
  try {
    assert.equal(await latestObserverVersion(directory, { fetcher: async () => { throw new Error("offline"); }, now: 1_000 }), null);
    assert.equal(await latestObserverVersion(directory, { fetcher: online, now: 1_000 + 60_000 }), null, "recent failure is not retried immediately");
    assert.equal(requests, 0);
    assert.equal(await latestObserverVersion(directory, { fetcher: online, now: 1_000 + hour }), "9.0.0");
    assert.equal(requests, 1);
  } finally { await rm(directory, { recursive: true, force: true }); }
});
