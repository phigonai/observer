import assert from "node:assert/strict";
import { mkdtemp, readFile, readdir, rm, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { run } from "../src/cli.js";
import {
  RotatingLogFile,
  levelledOutput,
  logFilePath,
  logLevelFrom,
} from "../src/observer-log.js";

async function temporaryDirectory(): Promise<string> {
  return await mkdtemp(join(tmpdir(), "phigon-log-"));
}

test("each message becomes timestamped lines without control characters", async () => {
  const directory = await temporaryDirectory();
  try {
    const log = new RotatingLogFile(directory, { now: () => new Date("2026-11-02T10:00:00.000Z") });
    log.write("info", "Telemetry stream connected.\n");
    log.write("warn", "first line\r\nsecond \u001b[31mline\u001b[0m\n\n");
    log.write("info", "\n");
    assert.equal(log.path, logFilePath(directory));
    assert.equal(
      await readFile(logFilePath(directory), "utf8"),
      [
        "2026-11-02T10:00:00.000Z INFO  Telemetry stream connected.",
        "2026-11-02T10:00:00.000Z WARN  first line",
        "2026-11-02T10:00:00.000Z WARN  second line",
        "",
      ].join("\n"),
    );
    if (process.platform !== "win32") {
      assert.equal((await stat(logFilePath(directory))).mode & 0o777, 0o600);
      assert.equal((await stat(join(directory, "logs"))).mode & 0o777, 0o700);
    }
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("a credential in a logged message is stored masked, whoever logs it", async () => {
  const directory = await temporaryDirectory();
  // Built at run time so no token-shaped string sits in the source.
  const machineKey = ["phg", "_m_", "q".repeat(43)].join("");
  const bearer = ["eyJhbGciOiJIUzI1NiJ9", "eyJzdWIiOiJtYWNoaW5lIn0", "c2lnbmF0dXJl"].join(".");
  const password = ["hunter", "2-", "correct-horse"].join("");
  const keyBody = ["MIIEvQIBADAN", "BgkqhkiG9w0BAQEFAASC"].join("");
  try {
    const log = new RotatingLogFile(directory, { now: () => new Date("2026-11-08T10:00:00.000Z") });
    const logged = levelledOutput({ stdout: () => undefined, stderr: () => undefined }, "debug", log);
    logged.error(`Observer command failed: the server answered 401 for Bearer ${bearer} with key ${machineKey}.\n`);
    logged.stderr(`Telemetry delivery is paused (proxy http://observer:${password}@proxy.example.test:3128 refused).\n`);
    log.write("warn", `password=${password}\n-----BEGIN PRIVATE KEY-----\n${keyBody}\n-----END PRIVATE KEY-----\n`);
    const stored = await readFile(logFilePath(directory), "utf8");
    for (const secret of [machineKey, bearer, password, keyBody]) {
      assert.ok(!stored.includes(secret), "a credential was written to the log");
    }
    assert.match(stored, /ERROR Observer command failed: the server answered 401 for Bearer \[REDACTED_SECRET\] with key \[REDACTED_SECRET\]\./u);
    assert.match(stored, /WARN {2}Telemetry delivery is paused \(proxy http:\/\/\[REDACTED_SECRET\]@proxy\.example\.test:3128 refused\)\./u);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("very long lines are cut so one message cannot fill the log", async () => {
  const directory = await temporaryDirectory();
  try {
    const log = new RotatingLogFile(directory);
    log.write("info", "x".repeat(20_000));
    const line = (await readFile(logFilePath(directory), "utf8")).trimEnd();
    assert.ok(Buffer.byteLength(line) < 4_200);
    assert.ok(line.endsWith("…"));
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("the log rotates by size and keeps three files", async () => {
  const directory = await temporaryDirectory();
  try {
    const log = new RotatingLogFile(directory, { maxBytes: 400 });
    for (let index = 0; index < 60; index++) {
      log.write("info", `message number ${index.toString().padStart(3, "0")}`);
    }
    const files = (await readdir(join(directory, "logs"))).sort();
    assert.deepEqual(files, ["observer.log", "observer.log.1", "observer.log.2"]);
    for (const file of files) {
      assert.ok((await stat(join(directory, "logs", file))).size <= 400, file);
    }
    const current = await readFile(logFilePath(directory), "utf8");
    const previous = await readFile(`${logFilePath(directory)}.1`, "utf8");
    assert.match(current, /message number 059/u);
    assert.doesNotMatch(current, /message number 000/u);
    assert.doesNotMatch(await readFile(`${logFilePath(directory)}.2`, "utf8"), /message number 000/u);
    // The newest lines are in observer.log, older ones in .1, then .2.
    assert.ok(previous.localeCompare(current) < 0);

    // Writing again after a restart continues the same file and its size.
    const restarted = new RotatingLogFile(directory, { maxBytes: 400 });
    restarted.write("info", "after restart");
    assert.match(await readFile(logFilePath(directory), "utf8"), /after restart/u);
    assert.ok((await stat(logFilePath(directory))).size <= 400);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("a single-file log starts again instead of growing", async () => {
  const directory = await temporaryDirectory();
  try {
    const log = new RotatingLogFile(directory, { maxBytes: 100, files: 1 });
    for (let index = 0; index < 10; index++) log.write("info", `line ${index}`);
    assert.deepEqual(await readdir(join(directory, "logs")), ["observer.log"]);
    assert.ok((await stat(logFilePath(directory))).size <= 100);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("a log that cannot be written is reported once and never stops the observer", async () => {
  const directory = await temporaryDirectory();
  try {
    // A file where the logs folder should be.
    await writeFile(join(directory, "logs"), "not a folder");
    const failures: string[] = [];
    const log = new RotatingLogFile(directory, { onFailure: (message) => failures.push(message) });
    log.write("info", "one");
    log.write("error", "two");
    assert.equal(failures.length, 1);
    assert.match(failures[0] ?? "", /could not be written/u);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("PHIGON_LOG_LEVEL decides what is printed and logged", async () => {
  assert.equal(logLevelFrom(undefined), "info");
  assert.equal(logLevelFrom("verbose"), "info");
  assert.equal(logLevelFrom("debug"), "debug");
  assert.equal(logLevelFrom("warn"), "warn");
  assert.equal(logLevelFrom("error"), "error");

  const directory = await temporaryDirectory();
  try {
    const log = new RotatingLogFile(directory);
    const printed: string[] = [];
    const output = levelledOutput({
      stdout: (value) => printed.push(`out:${value}`),
      stderr: (value) => printed.push(`err:${value}`),
    }, "warn", log);
    output.debug("debug detail\n");
    output.stdout("status\n");
    output.stderr("a problem\n");
    output.error("a failure\n");
    assert.deepEqual(printed, ["err:a problem\n", "err:a failure\n"]);
    const written = await readFile(logFilePath(directory), "utf8");
    assert.match(written, / WARN  a problem\n/u);
    assert.match(written, / ERROR a failure\n/u);
    assert.doesNotMatch(written, /status|debug detail/u);

    const everything: string[] = [];
    const verbose = levelledOutput({
      stdout: (value) => everything.push(value),
      stderr: (value) => everything.push(value),
    }, "debug");
    verbose.debug("detail\n");
    verbose.stdout("status\n");
    assert.deepEqual(everything, ["detail\n", "status\n"]);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("run logs why it stopped, and other commands keep no log", async () => {
  const directory = await temporaryDirectory();
  try {
    let stderr = "";
    const environment = {
      PHIGON_CONTROL_PLANE_URL: "http://127.0.0.1:9",
      PHIGON_GRPC_URL: "http://127.0.0.1:9",
      PHIGON_DATA_DIR: directory,
      PHIGON_UPDATE_CHECK: "false",
    };
    const doctor = await run(["doctor", "--json"], environment, {
      stdout: () => undefined,
      stderr: () => undefined,
    });
    assert.equal(doctor, 0);
    await assert.rejects(readFile(logFilePath(directory), "utf8"), { code: "ENOENT" });

    const code = await run(["run"], { ...environment, PHIGON_LOG_LEVEL: "error" }, {
      stdout: () => undefined,
      stderr: (value) => { stderr += value; },
    });
    assert.equal(code, 1);
    assert.match(stderr, /Observer is not paired/u);
    assert.match(
      await readFile(logFilePath(directory), "utf8"),
      /^\S+ ERROR Observer command failed: Observer is not paired\. Run the pair command first\.\n$/u,
    );
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});
