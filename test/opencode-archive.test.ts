import assert from "node:assert/strict";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";
import test from "node:test";
import { scanOpenCodeSQLiteSources } from "../src/activity/opencode-sqlite-source.js";

test("OpenCode imports pre-event-log conversations and restores speaker evidence after restart", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "phigon-legacy-test-"));
  const db = new DatabaseSync(join(root, "opencode.db"));
  t.after(async () => { db.close(); await rm(root, { recursive: true, force: true }); });
  db.exec(`
    CREATE TABLE session(id TEXT PRIMARY KEY,time_updated INTEGER);
    CREATE TABLE event_sequence(aggregate_id TEXT PRIMARY KEY,seq INTEGER);
    CREATE TABLE event(aggregate_id TEXT,seq INTEGER,type TEXT,data TEXT);
    CREATE TABLE message(id TEXT PRIMARY KEY,session_id TEXT,data TEXT);
    CREATE TABLE part(id TEXT PRIMARY KEY,session_id TEXT,message_id TEXT,data TEXT,time_updated INTEGER);
    INSERT INTO session VALUES ('old',1),('new',2);
    INSERT INTO event_sequence VALUES ('new',1);
  `);
  db.prepare("INSERT INTO message VALUES (?,?,?)").run("user-old", "old", JSON.stringify({role:"user"}));
  db.prepare("INSERT INTO message VALUES (?,?,?)").run("agent-new", "new", JSON.stringify({role:"assistant"}));
  db.prepare("INSERT INTO part VALUES (?,?,?,?,?)").run("old-part", "old", "user-old", JSON.stringify({type:"text",text:"Previous conversation"}), 1000);
  db.prepare("INSERT INTO event VALUES (?,?,?,?)").run("new",1,"message.part.updated.1", JSON.stringify({sessionID:"new",time:2000,part:{id:"new-part",messageID:"agent-new",type:"text",text:"Live response"}}));
  const cursors = new Map<string,number>();
  const options = { adapterId:"opencode",roots:[root],cursors,initialScan:true,replayOnFirstStart:false,maxReplayRecords:1,historical:true };
  const liveLog = await scanOpenCodeSQLiteSources(options);
  assert.equal(liveLog.records.length,1);
  assert.equal((liveLog.records[0]?.value as {message_info:{role:string}}).message_info.role,"assistant");
  assert.equal(liveLog.complete,false);
  // The archived session's message, then its part, one record per batch.
  const archiveCursors = new Map(cursors);
  const archived = [];
  let complete = false;
  for (let pass = 0; pass < 5 && !complete; pass++) {
    const scan = await scanOpenCodeSQLiteSources({...options,cursors:archiveCursors});
    archived.push(...scan.records);
    complete = scan.complete;
  }
  assert.deepEqual(archived.map((record) => (record.value as {type:string}).type),["message.updated.1","message.part.updated.1"]);
  assert.equal((archived[0]?.value as {info:{id:string;role:string}}).info.role,"user");
  const value = archived[1]?.value as {message_info:{role:string};part:{id:string;text:string}};
  assert.equal(value.message_info.role,"user");
  assert.equal(value.part.id,"old-part");
  assert.equal(value.part.text,"Previous conversation");
  assert.notEqual(archived[1]?.sourceRecordId,liveLog.records[0]?.sourceRecordId);
  assert.equal(complete,true);
  db.prepare("UPDATE message SET data=? WHERE id=?").run("invalid JSON","agent-new");
  const withoutRole = await scanOpenCodeSQLiteSources({...options,cursors:new Map()});
  assert.equal(withoutRole.records.length,1,"optional role hydration must not discard a valid source record");
});
