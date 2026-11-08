import assert from "node:assert/strict";
import { appendFile, mkdir, mkdtemp, rm, utimes, writeFile } from "node:fs/promises";
import fsPromises from "node:fs/promises";
import { syncBuiltinESMExports } from "node:module";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { LiveFileListing, type LiveListingFileSystem } from "../src/activity/live-listing.js";
import { JSONLSourceReader } from "../src/activity/source-reader.js";

type FakeFile = { modifiedMs: number; size: number; ino: number };

// The listing joins paths the platform's way; the fake disk uses `/`.
const slashed = (path: string) => path.replaceAll("\\", "/");

/** A folder tree in memory that counts every call, with a clock tests move. */
function fakeDisk(start = 10_000_000) {
  const folders = new Map<string, number>();
  const files = new Map<string, FakeFile>();
  const counts = { stat: 0, readdir: 0, realpath: 0 };
  let now = start;
  let inode = 1;
  let onChange: ((event: string, filename: string | null) => void) | undefined;
  let onError: (() => void) | undefined;
  const parent = (path: string) => path.slice(0, path.lastIndexOf("/"));
  const touchFolder = (path: string) => folders.set(path, now);
  const fileSystem = (watchable: boolean): LiveListingFileSystem => ({
    stat: async (native) => {
      const path = slashed(native);
      counts.stat++;
      const folder = folders.get(path);
      if (folder !== undefined) {
        return { directory: true, file: false, mtimeMs: folder, size: 0, dev: 1, ino: 0, birthtimeMs: 0 };
      }
      const file = files.get(path);
      if (file === undefined) throw Object.assign(new Error("missing"), { code: "ENOENT" });
      return { directory: false, file: true, mtimeMs: file.modifiedMs, size: file.size, dev: 1, ino: file.ino, birthtimeMs: 0 };
    },
    readdir: async (native) => {
      const path = slashed(native);
      counts.readdir++;
      if (!folders.has(path)) throw Object.assign(new Error("missing"), { code: "ENOENT" });
      const prefix = `${path}/`;
      const names = new Map<string, boolean>();
      for (const folder of folders.keys()) {
        if (folder.startsWith(prefix) && !folder.slice(prefix.length).includes("/")) names.set(folder.slice(prefix.length), true);
      }
      for (const file of files.keys()) {
        if (file.startsWith(prefix) && !file.slice(prefix.length).includes("/")) names.set(file.slice(prefix.length), false);
      }
      return [...names].map(([name, directory]) => ({ name, directory, file: !directory }));
    },
    realpath: async (path) => {
      counts.realpath++;
      return path;
    },
    ...(watchable
      ? {
        watch: (_root: string, change: (event: string, filename: string | null) => void, error: () => void) => {
          onChange = change;
          onError = error;
          return { close: () => { onChange = undefined; } };
        },
      }
      : {}),
  });
  return {
    counts,
    fileSystem,
    now: () => now,
    advance: (milliseconds: number) => { now += milliseconds; },
    folder: (path: string, modifiedMs = now) => { folders.set(path, modifiedMs); },
    file: (path: string, size: number, modifiedMs = now) => {
      if (!files.has(path)) touchFolder(parent(path));
      files.set(path, { modifiedMs, size, ino: files.get(path)?.ino ?? inode++ });
    },
    remove: (path: string) => {
      files.delete(path);
      touchFolder(parent(path));
    },
    /** What a watch reports; undefined when nothing watches. */
    report: (event: string, filename: string | null) => onChange?.(event, filename),
    fail: () => onError?.(),
    reset: () => { counts.stat = 0; counts.readdir = 0; counts.realpath = 0; },
  };
}

const paths = (files: readonly { path: string }[]) => files.map((file) => slashed(file.path)).sort();
const sizeOf = (files: readonly { path: string; identity: { size: number } }[], path: string) =>
  files.find((file) => slashed(file.path) === path)?.identity.size;
const old = 10_000_000 - 3_600_000;

/** A tree of 200 sessions, all last written an hour ago. */
function quietTree(disk: ReturnType<typeof fakeDisk>) {
  disk.folder("/r", old);
  for (let folder = 0; folder < 20; folder++) {
    disk.folder(`/r/p${folder}`, old);
    for (let file = 0; file < 10; file++) disk.file(`/r/p${folder}/s${file}.jsonl`, 100, old);
    disk.folder(`/r/p${folder}`, old);
  }
  disk.folder("/r", old);
}

async function tick(listing: LiveFileListing, disk: ReturnType<typeof fakeDisk>, milliseconds = 1_000) {
  disk.advance(milliseconds);
  listing.beginScan();
  return listing.list("/r");
}

test("an idle tick over an unchanged, quiet tree checks no file and lists no folder", async () => {
  const disk = fakeDisk();
  quietTree(disk);
  const listing = new LiveFileListing({ fileSystem: disk.fileSystem(false), now: disk.now, unwatchedFullCheckMs: 10_000 });
  listing.beginScan();
  assert.equal((await listing.list("/r")).length, 200);
  assert.deepEqual(disk.counts, { stat: 1 + 20 + 200, readdir: 21, realpath: 0 });
  disk.reset();
  const first = await tick(listing, disk);
  for (let second = 0; second < 8; second++) {
    // The same array, so what a reader derived from it can be reused.
    assert.equal(await tick(listing, disk), first);
  }
  assert.deepEqual(disk.counts, { stat: 0, readdir: 0, realpath: 0 });
  // The full pass checks everything again, but lists only changed folders.
  await tick(listing, disk);
  assert.deepEqual(disk.counts, { stat: 1 + 20 + 200, readdir: 0, realpath: 0 });
});

test("a hot file is checked on every tick, and growth in a quiet file is found by the full pass", async () => {
  const disk = fakeDisk();
  quietTree(disk);
  disk.file("/r/p0/active.jsonl", 10);
  const listing = new LiveFileListing({ fileSystem: disk.fileSystem(false), now: disk.now, unwatchedFullCheckMs: 10_000 });
  listing.beginScan();
  await listing.list("/r");
  disk.reset();
  disk.file("/r/p0/active.jsonl", 20);
  assert.equal(sizeOf(await tick(listing, disk), "/r/p0/active.jsonl"), 20);
  // The active file and its folder, which changed when it was created.
  assert.equal(disk.counts.stat, 2);

  disk.file("/r/p5/s3.jsonl", 500);
  for (let second = 0; second < 8; second++) {
    assert.equal(sizeOf(await tick(listing, disk), "/r/p5/s3.jsonl"), 100, "a quiet file waits for the full pass");
  }
  assert.equal(sizeOf(await tick(listing, disk), "/r/p5/s3.jsonl"), 500, "found within the full-pass interval");
  // Once it changed it stays hot, so its next growth is seen at once.
  disk.file("/r/p5/s3.jsonl", 600);
  assert.equal(sizeOf(await tick(listing, disk), "/r/p5/s3.jsonl"), 600);
});

test("a new session in an active folder is found on the next tick", async () => {
  const disk = fakeDisk();
  quietTree(disk);
  disk.folder("/r/today");
  disk.file("/r/today/first.jsonl", 10);
  const listing = new LiveFileListing({ fileSystem: disk.fileSystem(false), now: disk.now });
  listing.beginScan();
  await listing.list("/r");
  disk.advance(1_000);
  disk.file("/r/today/second.jsonl", 10);
  assert.ok(paths(await tick(listing, disk)).includes("/r/today/second.jsonl"));
  disk.remove("/r/today/first.jsonl");
  assert.ok(!paths(await tick(listing, disk)).includes("/r/today/first.jsonl"));
});

test("a watched change is checked on the next tick, and a working watch lengthens the full pass", async () => {
  const disk = fakeDisk();
  quietTree(disk);
  const listing = new LiveFileListing({ fileSystem: disk.fileSystem(true), now: disk.now, unwatchedFullCheckMs: 10_000 });
  const hints: number[] = [];
  const stop = listing.onHint(() => hints.push(disk.now()));
  listing.beginScan();
  await listing.list("/r");
  disk.reset();
  // A new session in a quiet folder, reported by the watch.
  disk.file("/r/p7/new.jsonl", 10, disk.now());
  disk.report("rename", "p7/new.jsonl");
  assert.equal(hints.length, 1);
  assert.ok(paths(await tick(listing, disk)).includes("/r/p7/new.jsonl"));
  assert.equal(listing.takeHint(), true);
  assert.equal(listing.takeHint(), false);
  // Growth of a quiet file the watch reports.
  disk.file("/r/p9/s1.jsonl", 900);
  disk.report("change", "p9/s1.jsonl");
  assert.equal(sizeOf(await tick(listing, disk), "/r/p9/s1.jsonl"), 900);
  disk.reset();
  // With the watch working, quiet files wait for the minute-long pass: only
  // the three entries that just changed are checked.
  for (let second = 0; second < 30; second++) await tick(listing, disk);
  assert.equal(disk.counts.stat, 30 * 3);
  // A failed watch is closed; the next tick checks everything.
  disk.fail();
  disk.reset();
  await tick(listing, disk);
  assert.ok(disk.counts.stat >= 200);
  assert.equal(listing.metrics().watchedRoots, 0);
  stop();
  listing.close();
});

test("a folder a watch reported is listed again even when its modified time did not move", async () => {
  const disk = fakeDisk();
  quietTree(disk);
  const listing = new LiveFileListing({ fileSystem: disk.fileSystem(true), now: disk.now });
  listing.beginScan();
  await listing.list("/r");
  // A new session whose folder keeps its time, as on a coarse file system clock.
  disk.file("/r/p4/new.jsonl", 10, old);
  disk.folder("/r/p4", old);
  disk.reset();
  disk.report("rename", "p4/new.jsonl");
  assert.ok(paths(await tick(listing, disk)).includes("/r/p4/new.jsonl"));
  assert.equal(disk.counts.readdir, 1);
  listing.close();
});

test("a watch reporting no file name, or more changes than it can hold, checks everything", async () => {
  const disk = fakeDisk();
  quietTree(disk);
  const listing = new LiveFileListing({ fileSystem: disk.fileSystem(true), now: disk.now });
  listing.beginScan();
  await listing.list("/r");
  await tick(listing, disk);
  disk.reset();
  disk.report("change", null);
  await tick(listing, disk);
  assert.ok(disk.counts.stat >= 200);
  assert.equal(disk.counts.readdir, 21, "and every folder is listed again");
  disk.reset();
  for (let index = 0; index < 2_000; index++) disk.report("change", `p0/x${index}.jsonl`);
  await tick(listing, disk);
  assert.ok(disk.counts.stat >= 200);
});

test("a watch that reports its root itself, or reports without end, is closed", async () => {
  const disk = fakeDisk();
  quietTree(disk);
  const listing = new LiveFileListing({ fileSystem: disk.fileSystem(true), now: disk.now });
  listing.beginScan();
  await listing.list("/r");
  assert.equal(listing.metrics().watchedRoots, 1);
  // What Windows reports, again and again, once a watched root is deleted.
  disk.report("rename", process.platform === "win32" ? "\\\\?\\C:\\r" : "/r");
  assert.equal(listing.metrics().watchedRoots, 0);
  disk.report("rename", "p0/late.jsonl");
  // Set up again after a minute.
  for (let second = 0; second < 59; second++) await tick(listing, disk);
  assert.equal(listing.metrics().watchedRoots, 0);
  await tick(listing, disk);
  assert.equal(listing.metrics().watchedRoots, 1);
  for (let index = 0; index <= 10_000; index++) disk.report("change", "p0/s0.jsonl");
  assert.equal(listing.metrics().watchedRoots, 0);
  listing.close();
});

test("a missing root is looked for again every five seconds, and a root that disappears is forgotten", async () => {
  const disk = fakeDisk();
  const listing = new LiveFileListing({ fileSystem: disk.fileSystem(false), now: disk.now });
  listing.beginScan();
  assert.deepEqual(await listing.list("/r"), []);
  disk.reset();
  disk.folder("/r");
  disk.file("/r/a.jsonl", 10);
  for (let second = 0; second < 4; second++) assert.deepEqual(await tick(listing, disk), []);
  assert.equal(disk.counts.stat, 0);
  assert.deepEqual(paths(await tick(listing, disk)), ["/r/a.jsonl"]);
  assert.deepEqual(await listing.existing(["/r", "/gone"]), ["/r"]);
  disk.reset();
  assert.deepEqual(await listing.existing(["/r", "/gone"]), ["/r"]);
  assert.equal(disk.counts.stat, 0, "remembered for five seconds");
  // The folder is hot, so its disappearance is seen on the next tick.
  disk.remove("/r/a.jsonl");
  disk.advance(1_000);
  listing.beginScan();
  assert.deepEqual(await listing.list("/r"), []);
  listing.retain(new Set());
  assert.deepEqual(listing.metrics(), { roots: 0, watchedRoots: 0, files: 0, directories: 0 });
});

test("a root shared by several sources is checked once per scan", async () => {
  const disk = fakeDisk();
  disk.folder("/r");
  disk.file("/r/a.jsonl", 10);
  const listing = new LiveFileListing({ fileSystem: disk.fileSystem(false), now: disk.now });
  listing.beginScan();
  await listing.list("/r");
  disk.reset();
  disk.advance(1_000);
  listing.beginScan();
  await listing.list("/r");
  await listing.list("/r");
  assert.equal(disk.counts.stat, 2, "the hot folder and file, once");
});

test("an idle live scan of the real reader does not check every saved session", async () => {
  const directory = await mkdtemp(join(tmpdir(), "phigon-live-listing-"));
  const root = join(directory, "sessions");
  const sources = [{ adapterId: "codex", roots: [root] }];
  const hourAgo = new Date(Date.now() - 3_600_000);
  for (let folder = 0; folder < 10; folder++) {
    await mkdir(join(root, `p${folder}`), { recursive: true });
    for (let file = 0; file < 20; file++) {
      const path = join(root, `p${folder}`, `s${file}.jsonl`);
      await writeFile(path, '{"type":"old"}\n');
      await utimes(path, hourAgo, hourAgo);
    }
    await utimes(join(root, `p${folder}`), hourAgo, hourAgo);
  }
  await utimes(root, hourAgo, hourAgo);
  const active = join(root, "p0", "s0.jsonl");
  let now = Date.now();
  const reader = new JSONLSourceReader(join(directory, "data"), false, 4_096, 1, "live", () => now);
  // Count the reader's own calls; every module sees the wrapped functions.
  const counted = { stat: 0, readdir: 0 };
  const promises = fsPromises as unknown as Record<"stat" | "readdir", (...args: unknown[]) => unknown>;
  const originalStat = promises.stat;
  const originalReaddir = promises.readdir;
  promises.stat = (...args) => {
    counted.stat++;
    return originalStat(...args);
  };
  promises.readdir = (...args) => {
    counted.readdir++;
    return originalReaddir(...args);
  };
  syncBuiltinESMExports();
  try {
    await reader.scan(sources);
    assert.ok(counted.stat >= 200, "the first scan checks every file");
    counted.stat = 0;
    counted.readdir = 0;
    // Within the shortest full-pass interval (three seconds without a watch).
    for (let second = 0; second < 2; second++) {
      now += 1_000;
      assert.deepEqual((await reader.scan(sources)).records, []);
    }
    // Only what a watch may report can be checked between full passes.
    assert.ok(counted.stat < 20, `${counted.stat} checks in two idle scans of 200 files`);
    assert.ok(counted.readdir < 5, `${counted.readdir} listings in two idle scans of 11 folders`);
    // Growth of a quiet session is still read, within the full-pass interval.
    await appendFile(active, '{"type":"resumed"}\n');
    let records: unknown[] = [];
    for (let second = 0; second < 61 && records.length === 0; second++) {
      now += 1_000;
      records = (await reader.scan(sources)).records.map((record) => record.value);
    }
    assert.deepEqual(records, [{ type: "resumed" }]);
  } finally {
    promises.stat = originalStat;
    promises.readdir = originalReaddir;
    syncBuiltinESMExports();
    reader.close();
    await rm(directory, { recursive: true, force: true });
  }
});
