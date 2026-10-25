import assert from "node:assert/strict";
import { appendFile, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
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
