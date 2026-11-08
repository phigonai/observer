import assert from "node:assert/strict";
import { mkdir, mkdtemp, readFile, rm, stat, utimes, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { run } from "../src/cli.js";
import { logServiceStartupFailure, serviceDataDirectory, trimServiceErrors } from "../src/node-version.js";
import {
  RotatingLogFile,
  lastLoggedError,
  levelledOutput,
  logFilePath,
  serviceConsole,
} from "../src/observer-log.js";
import {
  launchAgentPlist,
  programFromPlist,
  programFromTaskXml,
  programFromUnit,
  serviceDefinitionPath,
  serviceManagerProblem,
  serviceProgramProblem,
  systemdUserUnit,
  windowsTaskXml,
  type CommandResult,
  type ServiceContext,
  type ServicePlatform,
} from "../src/service.js";

function context(platform: ServicePlatform, overrides: Partial<ServiceContext> = {}): ServiceContext {
  const windows = platform === "windows";
  return {
    platform,
    dataDirectory: windows ? "C:\\Users\\Ada Lovelace\\.phigon\\observer" : "/home/ada/.phigon/observer",
    defaultDataDirectory: true,
    nodePath: windows ? "C:\\Program Files\\nodejs\\node.exe" : "/usr/local/bin/node",
    entryPath: windows
      ? "C:\\Users\\Ada Lovelace\\AppData\\Roaming\\npm\\node_modules\\@phigon\\observer\\dist\\src\\entry.js"
      : "/usr/local/lib/node_modules/@phigon/observer/dist/src/entry.js",
    homeDirectory: windows ? "C:\\Users\\Ada Lovelace" : "/home/ada",
    user: windows ? "S-1-5-21-1000-2000-3000-1001" : "501",
    systemRoot: "C:\\Windows",
    run: async () => ({ code: 0, stdout: "", stderr: "" }),
    now: () => new Date(2026, 10, 2, 9, 30, 0),
    ...overrides,
  };
}

function answering(stdout: string, code = 0): ServiceContext["run"] {
  return async (): Promise<CommandResult> => ({ code, stdout, stderr: "" });
}

test("the program a service runs is read back from its definition on every system", () => {
  const mac = context("macos", {
    dataDirectory: "/Users/ada/Phigon & Co",
    nodePath: "/Users/ada/.nvm/versions/node/v24.5.0/bin/node",
    entryPath: "/Users/ada/.nvm/versions/node/v24.5.0/lib/node_modules/@phigon/observer/dist/src/entry.js",
  });
  assert.deepEqual(programFromPlist(launchAgentPlist(mac)), { node: mac.nodePath, entry: mac.entryPath });

  const linux = context("linux", {
    nodePath: "/opt/node$1/bin/node",
    entryPath: '/home/ada/a "quoted" \\ 100% dir/entry.js',
  });
  assert.deepEqual(programFromUnit(systemdUserUnit(linux)), { node: linux.nodePath, entry: linux.entryPath });

  const windows = context("windows", {
    entryPath: "C:\\Users\\Ada & Co\\AppData\\Roaming\\npm\\node_modules\\@phigon\\observer\\dist\\src\\entry.js",
  });
  assert.deepEqual(programFromTaskXml(windowsTaskXml(windows)), { node: windows.nodePath, entry: windows.entryPath });

  assert.equal(programFromPlist("<plist/>"), undefined);
  assert.equal(programFromUnit("[Service]\n"), undefined);
  assert.equal(programFromTaskXml("<Task/>"), undefined);
});

test("a service whose Node.js or observer is gone says to install it again", async () => {
  const root = await mkdtemp(join(tmpdir(), "phigon-service-program-"));
  try {
    const node = join(root, "versions", "v24.5.0", "bin", "node");
    const entry = join(root, "versions", "v24.5.0", "lib", "entry.js");
    const service = context("linux", { homeDirectory: root, dataDirectory: join(root, "data"), nodePath: node, entryPath: entry });
    const unit = serviceDefinitionPath(service)!;
    await mkdir(dirname(unit), { recursive: true });
    await writeFile(unit, systemdUserUnit(service));

    // nvm removed the version the service was installed with.
    await mkdir(dirname(entry), { recursive: true });
    await writeFile(entry, "");
    const missingNode = await serviceProgramProblem(service);
    assert.equal(
      missingNode,
      `The background service starts Node.js from ${node}, which no longer exists, so it cannot run; ` +
        "Node.js was probably upgraded or removed (for example with nvm, Volta or mise). " +
        "Run phigon-observer service install again from a terminal where phigon-observer works.",
    );

    await mkdir(dirname(node), { recursive: true });
    await writeFile(node, "");
    assert.equal(await serviceProgramProblem(service), undefined);

    await rm(entry);
    assert.match(await serviceProgramProblem(service) ?? "", /starts the observer from .*entry\.js, which no longer exists/u);

    // Not installed, or a path schtasks may have printed in another code page.
    assert.equal(await serviceProgramProblem(context("linux", { homeDirectory: join(root, "nobody") })), undefined);
    const garbled = context("windows", {
      run: answering("<Task><Actions><Exec><Arguments>--headless \"C:\\Users\\Jos\uFFFD\\node.exe\" \"C:\\x\\entry.js\" run</Arguments></Exec></Actions></Task>"),
    });
    assert.equal(await serviceProgramProblem(garbled, async (path) => path.endsWith("entry.js")), undefined);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("a service manager's record of a failed start is one plain sentence", async () => {
  assert.equal(
    await serviceManagerProblem(context("macos", { run: answering("gui/501/com.phigon.observer = {\n\tstate = not running\n\tlast exit code = 78: EX_CONFIG\n}\n") })),
    "launchd says the observer last exited with code 78 (EX_CONFIG).",
  );
  assert.equal(await serviceManagerProblem(context("macos", { run: answering("\tlast exit code = 0\n") })), undefined);
  assert.equal(await serviceManagerProblem(context("macos", { run: answering("\tlast exit code = (never exited)\n") })), undefined);
  assert.equal(await serviceManagerProblem(context("macos", { run: answering("", 113) })), undefined);

  assert.equal(
    await serviceManagerProblem(context("linux", {
      run: answering("Result=exit-code\nExecMainStatus=1\nExecMainExitTimestamp=Sun 2026-11-08 10:00:00 UTC\n"),
    })),
    "systemd says the service failed (exit-code, exit status 1) at Sun 2026-11-08 10:00:00 UTC. See journalctl --user -u phigon-observer.service.",
  );
  assert.equal(await serviceManagerProblem(context("linux", { run: answering("Result=success\nExecMainStatus=0\n") })), undefined);

  const row = (result: string) => `"HOST","\\Phigon Observer","N/A","Ready","Interactive only","11/8/2026 10:00:00 AM","${result}","Phigon observer"\r\n`;
  assert.equal(
    await serviceManagerProblem(context("windows", { run: answering(row("-2147024894")) })),
    "Task Scheduler says the last run ended with result 0x80070002.",
  );
  // 2147946720 (0x800710E0): a minute trigger refused while the observer runs.
  for (const result of ["0", "267009", "267011", "2147946720", "-2147020576"]) {
    assert.equal(await serviceManagerProblem(context("windows", { run: answering(row(result)) })), undefined, result);
  }
});

test("a background service that cannot start writes why to its log", async () => {
  const directory = await mkdtemp(join(tmpdir(), "phigon-startup-failure-"));
  const settings = join(directory, "service-settings.json");
  try {
    assert.equal(serviceDataDirectory(["run", "--service-settings", settings], dirname), directory);
    assert.equal(serviceDataDirectory(["run", `--service-settings=${settings}`], dirname), directory);
    assert.equal(serviceDataDirectory(["run"], dirname), undefined);
    assert.equal(serviceDataDirectory(["doctor", "--service-settings", settings], dirname), undefined);

    await logServiceStartupFailure(["doctor"], "not a service");
    await assert.rejects(stat(logFilePath(directory)), { code: "ENOENT" });

    const message = "Phigon observer needs Node.js 24.5 or newer; this computer has 22.1.0. Run phigon-observer service install again from a terminal whose Node.js is 24.5 or newer.";
    await logServiceStartupFailure(["run", "--service-settings", settings], message, new Date("2026-11-08T10:00:00.000Z"));
    assert.equal(await readFile(logFilePath(directory), "utf8"), `2026-11-08T10:00:00.000Z ERROR ${message}\n`);
    assert.deepEqual(await lastLoggedError(directory), { at: "2026-11-08T10:00:00.000Z", message, source: "observer-log" });
    // A credential in a start failure is stored masked too.
    const machineKey = ["phg", "_m_", "w".repeat(43)].join("");
    await logServiceStartupFailure(["run", "--service-settings", settings], `The observer could not start: refused ${machineKey}.`);
    const stored = await readFile(logFilePath(directory), "utf8");
    assert.ok(!stored.includes(machineKey));
    assert.match(stored, /ERROR The observer could not start: refused \[REDACTED_SECRET\]\.\n$/u);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("launchd's file of what Node.js printed is kept small", async () => {
  const directory = await mkdtemp(join(tmpdir(), "phigon-service-errors-"));
  const path = join(directory, "logs", "service-errors.log");
  const argv = ["run", "--service-settings", join(directory, "service-settings.json")];
  try {
    await trimServiceErrors(argv);
    await mkdir(dirname(path));
    const crash = (index: number) => `Error: crash ${index}\n    at start (file:///observer/dist/src/cli.js:1:1)\n\nNode.js v24.5.0\n`;
    await writeFile(path, Array.from({ length: 4_000 }, (_, index) => crash(index)).join(""));
    assert.ok((await stat(path)).size > 256 * 1024);
    await trimServiceErrors(argv);
    const kept = await readFile(path, "utf8");
    assert.ok(Buffer.byteLength(kept) <= 64 * 1024);
    // It starts at a whole line.
    assert.match(kept, /^(?:Error: crash|    at |Node\.js v|\n)/u);
    assert.ok(kept.endsWith(crash(3_999)));
    // A small file is left alone.
    await trimServiceErrors(argv);
    assert.equal(await readFile(path, "utf8"), kept);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("a LaunchAgent's console stays quiet while the observer log works", async () => {
  const directory = await mkdtemp(join(tmpdir(), "phigon-service-console-"));
  try {
    const printed: string[] = [];
    const console = { stdout: (value: string) => printed.push(value), stderr: (value: string) => printed.push(value) };
    const working = new RotatingLogFile(join(directory, "data"));
    const output = levelledOutput(serviceConsole(console, working), "info", working);
    output.stdout("Starting Phigon observer telemetry.\n");
    output.stderr("Activity source cline could not be read.\n");
    assert.deepEqual(printed, []);
    assert.match(await readFile(working.path, "utf8"), /INFO  Starting Phigon observer telemetry\.\n.*WARN  Activity source cline could not be read\./u);

    // A log that cannot be written leaves the console as the only place.
    await writeFile(join(directory, "file"), "");
    const broken = new RotatingLogFile(join(directory, "file", "data"));
    const fallback = levelledOutput(serviceConsole(console, broken), "info", broken);
    fallback.stderr("Telemetry delivery is paused.\n");
    assert.equal(broken.failed, true);
    assert.deepEqual(printed, ["Telemetry delivery is paused.\n"]);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("the last error is the newest one in the observer log or launchd's file, with secrets masked", async () => {
  const directory = await mkdtemp(join(tmpdir(), "phigon-last-error-"));
  const key = ["phg", "_m_", "k".repeat(43)].join("");
  try {
    assert.equal(await lastLoggedError(directory), undefined);
    await mkdir(join(directory, "logs"));
    await writeFile(logFilePath(directory), [
      "2026-11-08T09:00:00.000Z ERROR Observer command failed: an older failure.",
      `2026-11-08T09:30:00.000Z ERROR Observer command failed: the server refused Bearer ${key}.`,
      "2026-11-08T09:45:00.000Z WARN  Activity source cline could not be read.",
      "2026-11-08T09:50:00.000Z INFO  Observer stopped.",
      "",
    ].join("\n"));
    const fromLog = await lastLoggedError(directory);
    assert.equal(fromLog?.at, "2026-11-08T09:30:00.000Z");
    assert.equal(fromLog?.source, "observer-log");
    assert.match(fromLog?.message ?? "", /^Observer command failed: the server refused Bearer \[REDACTED_SECRET\]\.$/u);
    assert.doesNotMatch(JSON.stringify(fromLog), new RegExp(key, "u"));

    // Node.js crashed after that, under launchd.
    const errors = join(directory, "logs", "service-errors.log");
    await writeFile(errors, "file:///observer/dist/src/cli.js:10\n  throw error;\n  ^\n\nTypeError: Cannot read properties of undefined\n    at run (file:///observer/dist/src/cli.js:10:3)\n\nNode.js v24.5.0\n");
    await utimes(errors, new Date("2026-11-08T10:00:00.000Z"), new Date("2026-11-08T10:00:00.000Z"));
    assert.deepEqual(await lastLoggedError(directory), {
      at: "2026-11-08T10:00:00.000Z",
      message: "TypeError: Cannot read properties of undefined",
      source: "service-errors",
    });
    await utimes(errors, new Date("2026-11-08T08:00:00.000Z"), new Date("2026-11-08T08:00:00.000Z"));
    assert.equal((await lastLoggedError(directory))?.source, "observer-log");
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("service status and doctor say why the background service cannot start, and its last error", async () => {
  const root = await mkdtemp(join(tmpdir(), "phigon-service-status-"));
  const data = resolve(join(root, "data"));
  const node = join(root, "removed", "bin", "node");
  try {
    const runner = async (command: string, args: readonly string[]): Promise<CommandResult> =>
      command === "systemctl" && args[1] === "show"
        ? { code: 0, stdout: "Result=exit-code\nExecMainStatus=203\nExecMainExitTimestamp=Sun 2026-11-08 10:00:00 UTC\n", stderr: "" }
        : { code: 0, stdout: "", stderr: "" };
    const dependencies = { serviceRunner: runner, platform: "linux" as const, homeDirectory: root };
    const environment = { PHIGON_DATA_DIR: data, PHIGON_CONTROL_PLANE_URL: "https://control.example.test" };
    const invoke = async (args: readonly string[]) => {
      let stdout = "";
      const code = await run([...args], environment, { stdout: (value) => { stdout += value; }, stderr: () => undefined }, undefined, dependencies);
      return { code, stdout };
    };
    // A unit installed under a Node.js that a version manager later removed.
    const service = context("linux", {
      homeDirectory: root,
      dataDirectory: data,
      defaultDataDirectory: false,
      nodePath: node,
      entryPath: fileURLToPath(new URL("../src/entry.js", import.meta.url)),
    });
    const unit = serviceDefinitionPath(service)!;
    await mkdir(dirname(unit), { recursive: true });
    await writeFile(unit, systemdUserUnit(service));
    await mkdir(join(data, "logs"), { recursive: true });
    await writeFile(logFilePath(data), "2026-11-08T09:59:00.000Z ERROR Observer command failed: Current machine-owner consent is missing.\n");

    const text = await invoke(["service", "status"]);
    assert.equal(text.code, 0);
    assert.match(text.stdout, /^Background service: installed and stopped$/mu);
    assert.match(text.stdout, /^Problem: The background service starts Node\.js from .*node, which no longer exists, so it cannot run; .*service install again/mu);
    assert.match(text.stdout, /^Service manager: systemd says the service failed \(exit-code, exit status 203\) at Sun 2026-11-08 10:00:00 UTC\./mu);
    assert.match(text.stdout, /^Last error: 2026-11-08T09:59:00\.000Z Observer command failed: Current machine-owner consent is missing\.$/mu);

    const json = JSON.parse((await invoke(["service", "status", "--json"])).stdout) as Record<string, unknown>;
    assert.equal(json["state"], "stopped");
    assert.match(String(json["problem"]), /which no longer exists/u);
    assert.match(String(json["serviceManager"]), /^systemd says/u);
    assert.deepEqual(json["lastError"], {
      at: "2026-11-08T09:59:00.000Z",
      message: "Observer command failed: Current machine-owner consent is missing.",
      source: "observer-log",
    });

    assert.match((await invoke(["doctor"])).stdout, /^Background service: The background service starts Node\.js from .*which no longer exists/mu);
    const doctor = JSON.parse((await invoke(["doctor", "--json"])).stdout) as { backgroundService?: { problem: string } };
    assert.match(doctor.backgroundService?.problem ?? "", /service install again/u);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
