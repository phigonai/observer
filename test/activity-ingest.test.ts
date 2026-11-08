import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import {
  mkdir,
  mkdtemp,
  readFile,
  readdir,
  rm,
  stat,
  writeFile,
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
    // Without full consent only the record's metadata is kept.
    assert.equal(
      await readFile(target, "utf8"),
      `${JSON.stringify({ type: "assistant", message: { role: "assistant", content: "[REDACTED_POLICY]" } })}\n`,
    );
    if (process.platform !== "win32") {
      assert.equal((await stat(target)).mode & 0o777, 0o600);
      assert.equal((await stat(root)).mode & 0o777, 0o700);
    }
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("ingest deletes the oldest bridge files once they pass the byte or file limit", async () => {
  const directory = await mkdtemp(join(tmpdir(), "phigon-ingest-cap-"));
  try {
    const bridges = join(directory, "bridges");
    await mkdir(join(bridges, "cursor"), { recursive: true });
    await mkdir(join(bridges, "generic"), { recursive: true });
    // Files left while no observer ran, oldest first, across two bridges.
    const name = (time: number) => `${time}-${randomUUID()}.jsonl`;
    const oldest = join(bridges, "cursor", name(1_000));
    const stillWriting = join(bridges, "generic", name(2_000));
    const older = join(bridges, "generic", name(3_000));
    const newer = join(bridges, "cursor", name(4_000));
    for (const path of [oldest, stillWriting, older, newer]) {
      await writeFile(path, `${"x".repeat(99)}\n`);
    }
    await writeFile(`${stillWriting}.writing`, "");
    const unrelated = join(bridges, "generic", "guardian-decisions.jsonl");
    await writeFile(unrelated, `${"x".repeat(999)}\n`);

    // Stored as it came under every profile, so the sizes below hold.
    const record = `${JSON.stringify({ role: "user", type: "abcd" })}\n`;
    const ingest = (limits: Readonly<{ maxBytes?: number; maxFiles?: number }>) =>
      ingestActivityJSONL({
        agent: "cursor",
        dataDirectory: directory,
        input: Readable.from([record]),
        limits,
      });
    const exists = (path: string) => stat(path).then(() => true, () => false);

    // Five ingest files against a limit of four: only the oldest goes.
    await ingest({ maxFiles: 4 });
    assert.deepEqual(
      await Promise.all([oldest, stillWriting, older, newer].map(exists)),
      [false, true, true, true],
    );
    // 358 bytes against 260: the oldest file that is not still being
    // written goes, and that is enough.
    await ingest({ maxBytes: 260 });
    assert.deepEqual(
      await Promise.all([stillWriting, older, newer].map(exists)),
      [true, false, true],
    );
    // Journals and the run's own file are never deleted for the limit.
    assert.ok(await exists(unrelated));
    await ingest({ maxBytes: 1 });
    const left = (await readdir(join(bridges, "cursor"))).length +
      (await readdir(join(bridges, "generic"))).length;
    // The writing file, its marker, the journal and the newest run's file.
    assert.equal(left, 4);
    assert.ok(await exists(stillWriting));
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
    // The agent's name stays; without full consent its reply does not.
    assert.equal(
      await readFile(join(root, files[0] ?? ""), "utf8"),
      `${record.replace("Task complete.", "[REDACTED_POLICY]")}\n`,
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
    assert.equal(stored.trim().split("\n").length, 1);
    assert.equal(JSON.parse(stored).phigon_agent_name, "Release Bot");
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});
