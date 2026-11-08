import assert from "node:assert/strict";
import { appendFile, mkdir, mkdtemp, rename, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { setTimeout as delay } from "node:timers/promises";
import { run } from "../src/cli.js";
import { runLogsCommand, tailLines } from "../src/logs-command.js";
import { followLog, lastLines, logFilePath, logTail } from "../src/observer-log.js";

const line = (index: number) => `2026-11-08T10:${String(index % 60).padStart(2, "0")}:00.000Z INFO  line ${index}`;

async function logs(directory: string, args: readonly string[]) {
  let stdout = "";
  let stderr = "";
  const code = await run(
    ["logs", ...args],
    { PHIGON_DATA_DIR: directory, PHIGON_CONTROL_PLANE_URL: "https://control.example.test" },
    { stdout: (value) => { stdout += value; }, stderr: (value) => { stderr += value; } },
  );
  return { code, stdout, stderr };
}

test("logs prints the last lines of the observer log", async () => {
  const directory = await mkdtemp(join(tmpdir(), "phigon-logs-"));
  try {
    const missing = await logs(directory, []);
    assert.equal(missing.code, 0);
    assert.match(missing.stdout, /^There is no observer log yet \(.*observer\.log\)\. The background service writes it once it runs\.\n$/u);

    await mkdir(join(directory, "logs"));
    await writeFile(logFilePath(directory), `${Array.from({ length: 60 }, (_, index) => line(index)).join("\n")}\n`);
    const fifty = await logs(directory, []);
    assert.equal(fifty.stdout, `${Array.from({ length: 50 }, (_, index) => line(index + 10)).join("\n")}\n`);
    assert.equal((await logs(directory, ["--tail", "5"])).stdout, `${[55, 56, 57, 58, 59].map(line).join("\n")}\n`);
    assert.equal((await logs(directory, ["--tail=2"])).stdout, `${[58, 59].map(line).join("\n")}\n`);

    // A wrong count is a usage error, exit 2, like a missing one.
    for (const bad of [["--tail", "0"], ["--tail", "lots"], ["--tail=100000"]]) {
      const refused = await logs(directory, bad);
      assert.equal(refused.code, 2, bad.join(" "));
      assert.equal(refused.stdout, "", bad.join(" "));
      assert.match(refused.stderr, /--tail takes a number of lines from 1 to 10000\./u);
    }
    // The table of options refuses a --tail without its number, and options logs does not take.
    const noNumber = await logs(directory, ["--tail"]);
    assert.equal(noNumber.code, 2);
    assert.match(noNumber.stderr, /--tail needs a value: --tail <lines>\./u);
    assert.equal((await logs(directory, ["--follw"])).code, 2);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("logs prints every line asked for, from a large log and both rotated files", async () => {
  const directory = await mkdtemp(join(tmpdir(), "phigon-logs-large-"));
  const path = logFilePath(directory);
  try {
    await mkdir(join(directory, "logs"));
    // About 2 MB in the current file: more than one read of the end.
    const long = (index: number) => `${line(index)} ${"x".repeat(180)}`;
    await writeFile(path, `${Array.from({ length: 10_000 }, (_, index) => long(index)).join("\n")}\n`);
    const all = await logTail(directory, 10_000);
    assert.equal(all.length, 10_000);
    assert.equal(all[0], long(0));
    assert.equal(all.at(-1), long(9_999));

    // observer.log, observer.log.1 and observer.log.2, oldest last.
    await writeFile(`${path}.2`, `${[1, 2, 3].map(line).join("\n")}\n`);
    await writeFile(`${path}.1`, `${[4, 5].map(line).join("\n")}\n`);
    await writeFile(path, `${[6, 7].map(line).join("\n")}\n`);
    assert.deepEqual(await logTail(directory, 6), [2, 3, 4, 5, 6, 7].map(line));
    assert.deepEqual(await logTail(directory, 50), [1, 2, 3, 4, 5, 6, 7].map(line));
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("a file's last lines are read backwards across chunk boundaries", async () => {
  const directory = await mkdtemp(join(tmpdir(), "phigon-logs-lines-"));
  const path = join(directory, "log");
  try {
    assert.deepEqual(await lastLines(path, 5), []);
    await writeFile(path, "");
    assert.deepEqual(await lastLines(path, 5), []);
    await writeFile(path, "first line that is long\r\n\nsecond\nthird without newline");
    for (const chunk of [1, 3, 7, 64]) {
      assert.deepEqual(await lastLines(path, 5, chunk), ["first line that is long", "second", "third without newline"], String(chunk));
      assert.deepEqual(await lastLines(path, 2, chunk), ["second", "third without newline"], String(chunk));
    }
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("logs works when a setting that stops the observer is invalid", async () => {
  const directory = await mkdtemp(join(tmpdir(), "phigon-logs-misconfigured-"));
  try {
    await mkdir(join(directory, "logs"));
    await writeFile(logFilePath(directory), "2026-11-08T10:00:00.000Z ERROR Observer command failed: PHIGON_CONTROL_PLANE_URL must be a valid URL.\n");
    let stdout = "";
    let stderr = "";
    const code = await run(
      ["logs", "--tail", "1"],
      { PHIGON_DATA_DIR: directory, PHIGON_CONTROL_PLANE_URL: "not a url", PHIGON_GRPC_URL: "::", PHIGON_DISCOVERY_INTERVAL_MS: "soon" },
      { stdout: (value) => { stdout += value; }, stderr: (value) => { stderr += value; } },
    );
    assert.equal(stderr, "");
    assert.equal(code, 0);
    assert.equal(stdout, "2026-11-08T10:00:00.000Z ERROR Observer command failed: PHIGON_CONTROL_PLANE_URL must be a valid URL.\n");
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("logs reads on into the rotated file and masks secrets", async () => {
  const directory = await mkdtemp(join(tmpdir(), "phigon-logs-rotated-"));
  const key = ["phg", "_m_", "z".repeat(43)].join("");
  try {
    await mkdir(join(directory, "logs"));
    await writeFile(`${logFilePath(directory)}.1`, `${[1, 2, 3, 4].map(line).join("\n")}\n`);
    await writeFile(logFilePath(directory), `${line(5)}\n2026-11-08T10:06:00.000Z ERROR Observer command failed: refused Bearer ${key}\n`);
    const { stdout } = await logs(directory, ["--tail", "4"]);
    assert.equal(stdout, [
      line(3),
      line(4),
      line(5),
      "2026-11-08T10:06:00.000Z ERROR Observer command failed: refused Bearer [REDACTED_SECRET]",
      "",
    ].join("\n"));
    assert.doesNotMatch(stdout, new RegExp(key, "u"));
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("logs --follow prints new lines, also after the log is rotated, until stopped", async () => {
  const directory = await mkdtemp(join(tmpdir(), "phigon-logs-follow-"));
  const path = logFilePath(directory);
  try {
    await mkdir(join(directory, "logs"));
    await writeFile(path, `${line(1)}\n`);
    const printed: string[] = [];
    const controller = new AbortController();
    const following = followLog(directory, (value) => printed.push(value), controller.signal, 10);
    await delay(150);
    await appendFile(path, `${line(2)}\n${line(3)}`);
    await delay(250);
    // The rest of a line arrives later.
    await appendFile(path, " continued\n");
    await delay(250);
    await rename(path, `${path}.1`);
    await writeFile(path, `${line(4)}\n`);
    await delay(250);
    controller.abort();
    await following;
    assert.deepEqual(printed, [line(2), `${line(3)} continued`, line(4)]);

    // The command prints the tail, then follows until stopped.
    const stop = new AbortController();
    stop.abort();
    let stdout = "";
    assert.equal(await runLogsCommand(["--follow", "--tail", "1"], directory, { stdout: (value) => { stdout += value; } }, stop.signal), 0);
    assert.equal(stdout, `${line(4)}\n`);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("logs --follow keeps every line when the new log outgrows the old one before it looks again", async () => {
  const directory = await mkdtemp(join(tmpdir(), "phigon-logs-follow-rotated-"));
  const path = logFilePath(directory);
  try {
    await mkdir(join(directory, "logs"));
    await writeFile(path, `${line(1)}\n`);
    const printed: string[] = [];
    const controller = new AbortController();
    const following = followLog(directory, (value) => printed.push(value), controller.signal, 200);
    await delay(300);
    // Between two looks: a last line in the old file, a rotation, and a new
    // file already far longer than the old one.
    await appendFile(path, `${line(2)}\n`);
    await rename(path, `${path}.1`);
    const fresh = Array.from({ length: 20 }, (_, index) => `${line(100 + index)} ${"y".repeat(40)}`);
    await writeFile(path, `${fresh.join("\n")}\n`);
    await delay(700);
    controller.abort();
    await following;
    assert.deepEqual(printed, [line(2), ...fresh]);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("without --tail, logs prints 50 lines", () => {
  assert.equal(tailLines([]), 50);
  assert.equal(tailLines(["--follow"]), 50);
  assert.equal(tailLines(["--follow", "--tail", "7"]), 7);
});
