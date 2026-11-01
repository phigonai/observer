import assert from "node:assert/strict";
import { appendFile, mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { startedAfter } from "../src/activity/json-document-source.js";
import { JSONLSourceReader } from "../src/activity/source-reader.js";

test("restarting a live reader keeps committed offsets and captures work written while offline", async (t) => {
  const root=await mkdtemp(join(tmpdir(),"phigon-catchup-"));
  t.after(()=>rm(root,{recursive:true,force:true}));
  const file=join(root,"session.jsonl"), state=join(root,"state");
  const sources=[{adapterId:"codex",roots:[root]}];
  await writeFile(file,'{"type":"old"}\n');
  const reader=new JSONLSourceReader(state);
  const baseline=await reader.scan(sources);
  await reader.commit(baseline.checkpoint);
  await appendFile(file,'{"type":"offline-work"}\n');
  const restarted=new JSONLSourceReader(state);
  const caught=await restarted.scan(sources);
  assert.deepEqual(caught.records.map(r=>r.value),[{type:"offline-work"}]);
  await restarted.commit(caught.checkpoint);
  assert.equal((await new JSONLSourceReader(state).scan(sources)).records.length,0);
});

test("sessions that began while the observer was stopped are read from their start", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "phigon-stopped-sessions-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const sessions = join(root, "sessions");
  const documents = join(root, "documents");
  const state = join(root, "state");
  await mkdir(sessions);
  await mkdir(documents);
  const sources = [
    { adapterId: "codex", roots: [sessions] },
    { adapterId: "cline-cli", roots: [documents], format: "json-messages" as const },
  ];
  await writeFile(join(sessions, "old.jsonl"), '{"type":"old"}\n');
  await writeFile(join(documents, "old.json"), JSON.stringify({ messages: [{ text: "old" }] }));

  // The first start ever baselines what exists, as before. Its scan is
  // dated a minute back so every file below is clearly newer.
  const first = new JSONLSourceReader(state, false, 256 << 10, 1, "live", () => Date.now() - 60_000);
  const baseline = await first.scan(sources);
  assert.deepEqual(baseline.records, []);
  await first.commit(baseline.checkpoint);

  // While stopped: an old session continues and new ones begin.
  await appendFile(join(sessions, "old.jsonl"), '{"type":"old-continued"}\n');
  await writeFile(join(sessions, "new.jsonl"), '{"type":"new-1"}\n{"type":"new-2"}\n');
  await writeFile(join(documents, "new.json"), JSON.stringify({ messages: [{ text: "new-1" }, { text: "new-2" }] }));

  const restarted = new JSONLSourceReader(state);
  const caught = await restarted.scan(sources);
  assert.deepEqual(
    caught.records.map((record) => JSON.stringify(record.value)).sort(),
    [
      { text: "new-1" }, { text: "new-2" },
      { type: "new-1" }, { type: "new-2" },
      { type: "old-continued" },
    ].map((value) => JSON.stringify(value)).sort(),
  );
  await restarted.commit(caught.checkpoint);
  assert.deepEqual((await new JSONLSourceReader(state).scan(sources)).records, []);
});

test("only a file created after the last run counts as a new session", () => {
  const lastRun = Date.parse("2026-11-01T12:00:00.000Z");
  const after = lastRun + 1_000;
  const before = lastRun - 1_000;
  assert.equal(startedAfter({ birthtimeMs: after, mtimeMs: after }, lastRun), true);
  // An older file that was only appended to is not uploaded again.
  assert.equal(startedAfter({ birthtimeMs: before, mtimeMs: after }, lastRun), false);
  assert.equal(startedAfter({ birthtimeMs: before, mtimeMs: before }, lastRun), false);
  // Without creation times, the modification time decides.
  assert.equal(startedAfter({ birthtimeMs: 0, mtimeMs: after }, lastRun), true);
  assert.equal(startedAfter({ birthtimeMs: 0, mtimeMs: before }, lastRun), false);
});

test("an unfinished last line does not stall archive import and remains readable after completion",async(t)=>{
  const root=await mkdtemp(join(tmpdir(),"phigon-partial-"));
  t.after(()=>rm(root,{recursive:true,force:true}));
  const file=join(root,"session.jsonl");
  await writeFile(file,'{"type":"partial"');
  const reader=new JSONLSourceReader(join(root,"state"),false,1024,1,"history");
  const sources=[{adapterId:"codex",roots:[root]}];
  await reader.scan(sources);
  const done=await reader.scan(sources);
  assert.equal(done.complete,true);
  await reader.commit(done.checkpoint);
  await appendFile(file,'}\n');
  // A new archive request after restart refreshes the source catalog.
  const result=await new JSONLSourceReader(join(root,"state"),false,1024,1,"history").scan(sources);
  assert.deepEqual(result.records.map(r=>r.value),[{type:"partial"}]);
});
