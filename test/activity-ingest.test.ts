import assert from "node:assert/strict";
import {
  mkdtemp,
  readFile,
  readdir,
  rm,
  stat,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Readable } from "node:stream";
import test from "node:test";
import { ingestActivityJSONL } from "../src/activity/ingest.js";

test("activity bridge stores only valid bounded source records", async () => {
  const directory = await mkdtemp(join(tmpdir(), "phigon-ingest-"));
  try {
    const valid = JSON.stringify({
      type: "assistant",
      message: {
        role: "assistant",
        content: "Bridge response.",
      },
    });
    const result = await ingestActivityJSONL({
      agent: "cursor",
      dataDirectory: directory,
      input: Readable.from([
        `${valid}\n`,
        "not-json\n",
        `${"x".repeat((1 << 20) + 1)}\n`,
      ]),
    });
    assert.deepEqual(result, {
      agent: "cursor",
      records: 1,
      malformed: 1,
      oversized: 1,
    });
    const root = join(directory, "bridges", "cursor");
    const files = await readdir(root);
    assert.equal(files.length, 1);
    const target = join(root, files[0] ?? "");
    assert.equal(await readFile(target, "utf8"), `${valid}\n`);
    if (process.platform !== "win32") {
      assert.equal((await stat(target)).mode & 0o777, 0o600);
      assert.equal((await stat(root)).mode & 0o777, 0o700);
    }
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("activity bridge rejects unknown agent identifiers", async () => {
  await assert.rejects(
    ingestActivityJSONL({
      agent: "../../escape",
      dataDirectory: tmpdir(),
      input: Readable.from([]),
    }),
    /supported activity bridge or generic/u,
  );
});

test("generic activity bridge accepts records from an unlisted agent", async () => {
  const directory = await mkdtemp(join(tmpdir(), "phigon-generic-ingest-"));
  try {
    const record = JSON.stringify({
      agent: "Acme Research Agent",
      type: "message",
      message: { role: "assistant", content: "Task complete." },
    });
    const result = await ingestActivityJSONL({
      agent: "generic",
      dataDirectory: directory,
      input: Readable.from([`${record}\n`]),
    });

    assert.deepEqual(result, {
      agent: "generic",
      records: 1,
      malformed: 0,
      oversized: 0,
    });
    const root = join(directory, "bridges", "generic");
    const files = await readdir(root);
    assert.equal(files.length, 1);
    assert.equal(
      await readFile(join(root, files[0] ?? ""), "utf8"),
      `${record}\n`,
    );
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("custom activity bridge rejects a conflicting configured agent label", async () => {
  const directory = await mkdtemp(join(tmpdir(), "phigon-custom-ingest-"));
  try {
    const result = await ingestActivityJSONL({
      agent: "custom",
      agentName: "Release Bot",
      dataDirectory: directory,
      input: Readable.from([
        `${JSON.stringify({
          phigon_agent_name: "Different Bot",
          type: "message",
          content: "must not be attributed",
        })}\n`,
        `${JSON.stringify({
          phigon_agent_name: "Release Bot",
          type: "message",
          content: "consistent evidence",
        })}\n`,
      ]),
    });

    assert.deepEqual(result, {
      agent: "generic",
      agentName: "Release Bot",
      records: 1,
      malformed: 1,
      oversized: 0,
    });
    const root = join(directory, "bridges", "generic");
    const files = await readdir(root);
    const stored = await readFile(join(root, files[0] ?? ""), "utf8");
    assert.doesNotMatch(stored, /Different Bot/u);
    assert.match(stored, /consistent evidence/u);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});
