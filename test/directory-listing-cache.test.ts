import assert from "node:assert/strict";
import test from "node:test";
import { DirectoryListingCache } from "../src/activity/json-document-source.js";

type Entry = Readonly<{ name: string; directory: boolean; file: boolean }>;

/** A folder tree in memory that counts how often each folder is checked and listed. */
function fakeFileSystem(start = 100_000) {
  const folders = new Map<string, { modifiedMs: number; entries: Entry[] }>();
  const files = new Map<string, { modifiedMs: number; size: number }>();
  const counts = { listed: 0, checked: 0, statted: 0 };
  let now = start;
  return {
    counts,
    advance: (milliseconds: number) => { now += milliseconds; },
    folder: (path: string, names: readonly string[], modifiedMs: number) => {
      folders.set(path, { modifiedMs, entries: names.map((name) => ({ name, directory: false, file: true })) });
    },
    remove: (path: string) => folders.delete(path),
    file: (path: string, modifiedMs: number, size: number) => { files.set(path, { modifiedMs, size }); },
    fs: {
      metadata: async (path: string) => {
        counts.statted++;
        const file = files.get(path);
        if (!file) throw Object.assign(new Error("missing"), { code: "ENOENT" });
        return { ...file };
      },
      now: () => now,
      modifiedMs: async (path: string) => {
        counts.checked++;
        const folder = folders.get(path);
        if (!folder) throw Object.assign(new Error("missing"), { code: "ENOENT" });
        return folder.modifiedMs;
      },
      readdir: async (path: string) => {
        counts.listed++;
        const folder = folders.get(path);
        if (!folder) throw Object.assign(new Error("missing"), { code: "ENOENT" });
        return [...folder.entries];
      },
    },
  };
}

const names = (entries: readonly Entry[]) => entries.map((entry) => entry.name);

test("an unchanged, settled folder is checked but not listed again", async () => {
  const disk = fakeFileSystem();
  disk.folder("/s", ["a.json"], 50_000);
  const cache = new DirectoryListingCache(disk.fs);
  assert.deepEqual(names(await cache.list("/s")), ["a.json"]);
  disk.advance(1_000);
  assert.deepEqual(names(await cache.list("/s")), ["a.json"]);
  assert.deepEqual(disk.counts, { listed: 1, checked: 2, statted: 0 });
});

test("a folder whose modified time moved is listed again", async () => {
  const disk = fakeFileSystem();
  disk.folder("/s", ["a.json"], 50_000);
  const cache = new DirectoryListingCache(disk.fs);
  await cache.list("/s");
  disk.advance(1_000);
  disk.folder("/s", ["a.json", "b.json"], 99_000);
  assert.deepEqual(names(await cache.list("/s")), ["a.json", "b.json"]);
  assert.equal(disk.counts.listed, 2);
});

test("a folder that changed in the last two seconds is listed until it settles", async () => {
  const disk = fakeFileSystem();
  // Changed 500 ms before the listing: a coarse clock could hide a second
  // change with the same time, so the listing is not trusted yet.
  disk.folder("/s", ["a.json"], 99_500);
  const cache = new DirectoryListingCache(disk.fs);
  await cache.list("/s");
  disk.advance(1_000);
  disk.folder("/s", ["a.json", "b.json"], 99_500);
  assert.deepEqual(names(await cache.list("/s")), ["a.json", "b.json"]);
  // Still within two seconds of the change at the second listing, so the
  // third listing (3.5 s after it) is the first one that is trusted.
  disk.advance(2_000);
  await cache.list("/s");
  assert.equal(disk.counts.listed, 3);
  disk.advance(1_000);
  await cache.list("/s");
  assert.equal(disk.counts.listed, 3, "settled folders are reused");
});

test("every folder is listed afresh after 30 seconds", async () => {
  const disk = fakeFileSystem();
  disk.folder("/s", ["a.json"], 50_000);
  const cache = new DirectoryListingCache(disk.fs);
  await cache.list("/s");
  disk.advance(DirectoryListingCache.relistAfterMs);
  await cache.list("/s");
  assert.equal(disk.counts.listed, 2);
});

test("a trusted listing skips even the folder check, but never past 30 seconds", async () => {
  const disk = fakeFileSystem();
  disk.folder("/s", ["a.json"], 50_000);
  const cache = new DirectoryListingCache(disk.fs);
  await cache.list("/s", 30_000);
  disk.advance(10_000);
  await cache.list("/s", 30_000);
  assert.deepEqual(disk.counts, { listed: 1, checked: 1, statted: 0 });
  disk.advance(25_000);
  await cache.list("/s", 30_000);
  assert.deepEqual(disk.counts, { listed: 2, checked: 2, statted: 0 });
});

test("a folder that disappears fails like a listing and is forgotten", async () => {
  const disk = fakeFileSystem();
  disk.folder("/s", ["a.json"], 50_000);
  const cache = new DirectoryListingCache(disk.fs);
  await cache.list("/s");
  disk.remove("/s");
  await assert.rejects(cache.list("/s"), { code: "ENOENT" });
  disk.folder("/s", ["c.json"], 50_000);
  assert.deepEqual(names(await cache.list("/s")), ["c.json"]);
});

test("the cache holds a bounded number of folders", async () => {
  const disk = fakeFileSystem();
  const cache = new DirectoryListingCache(disk.fs);
  for (let index = 0; index <= DirectoryListingCache.maxFolders; index++) {
    disk.folder(`/f${index}`, [], 50_000);
    await cache.list(`/f${index}`);
  }
  disk.counts.listed = 0;
  await cache.list("/f0");
  assert.equal(disk.counts.listed, 1, "the oldest folder was evicted");
  await cache.list(`/f${DirectoryListingCache.maxFolders}`);
  assert.equal(disk.counts.listed, 1, "the newest folder is still cached");
});

test("a folder untouched for ten minutes is checked every ten seconds, not every scan", async () => {
  const disk = fakeFileSystem(10_000_000);
  disk.folder("/old", ["a.json"], 10_000_000 - DirectoryListingCache.coldAfterMs);
  const cache = new DirectoryListingCache(disk.fs);
  await cache.list("/old");
  for (let tick = 0; tick < 9; tick++) {
    disk.advance(1_000);
    await cache.list("/old");
  }
  assert.deepEqual(disk.counts, { listed: 1, checked: 1, statted: 0 });
  // A new conversation in the quiet folder is found on the next check.
  disk.advance(1_000);
  disk.folder("/old", ["a.json", "b.json"], 10_010_000);
  assert.deepEqual(names(await cache.list("/old")), ["a.json", "b.json"]);
  assert.equal(disk.counts.checked, 2);
});

test("a document untouched for ten minutes is checked every ten seconds; an active one on every scan", async () => {
  const disk = fakeFileSystem(10_000_000);
  disk.file("/old.json", 10_000_000 - DirectoryListingCache.coldAfterMs, 100);
  disk.file("/live.json", 9_999_000, 100);
  const cache = new DirectoryListingCache(disk.fs);
  for (let tick = 0; tick < 5; tick++) {
    await cache.metadata("/old.json");
    await cache.metadata("/live.json");
    disk.advance(1_000);
  }
  assert.equal(disk.counts.statted, 1 + 5);
  // A resumed old conversation is seen once its ten seconds are up.
  disk.file("/old.json", 10_005_000, 200);
  disk.advance(5_000);
  assert.deepEqual(await cache.metadata("/old.json"), { modifiedMs: 10_005_000, size: 200 });
});
