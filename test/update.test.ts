import assert from "node:assert/strict";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { latestObserverVersion, newerVersion, offerObserverUpdate } from "../src/update.js";

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

test("update installs only after yes and asks for a restart", async () => {
  const installed: string[] = []; let text = "";
  const options = { current: "8.0.2", latest: "8.0.3", write: (value: string) => { text += value; }, install: async (version: string) => { installed.push(version); } };
  assert.equal(await offerObserverUpdate({ ...options, confirm: async () => "" }), false);
  assert.deepEqual(installed, []);
  assert.equal(await offerObserverUpdate({ ...options, confirm: async () => "yes" }), true);
  assert.deepEqual(installed, ["8.0.3"]);
  assert.match(text, /queued activity are preserved/u);
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
