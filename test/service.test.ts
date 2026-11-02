import assert from "node:assert/strict";
import { mkdtemp, readFile, readdir, rm, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { run, watchParentProcess } from "../src/cli.js";
import { FileCredentialStore, type StoredMachineCredential } from "../src/credential-store.js";
import { InstanceLock } from "../src/instance-lock.js";
import { logFilePath } from "../src/observer-log.js";
import {
  installService,
  launchAgentPlist,
  readServiceSettings,
  serviceCommand,
  serviceDefinitionPath,
  serviceInstalled,
  serviceName,
  servicePlatform,
  serviceSettings,
  serviceSettingsPath,
  startService,
  stopService,
  systemdUserUnit,
  uninstallService,
  windowsTaskXml,
  writeServiceSettings,
  type CommandResult,
  type ServiceContext,
  type ServicePlatform,
} from "../src/service.js";

const machineKey = ["phg", "_m_", "s".repeat(43)].join("");

type Call = Readonly<{ command: string; args: readonly string[] }>;

/** A command runner that records calls and installs nothing. */
function recorder(answer: (call: Call) => Partial<CommandResult> = () => ({})) {
  const calls: Call[] = [];
  const runner = async (command: string, args: readonly string[]): Promise<CommandResult> => {
    const call = { command, args: [...args] };
    calls.push(call);
    return { code: 0, stdout: "", stderr: "", ...answer(call) };
  };
  return { calls, runner };
}

function context(platform: ServicePlatform, root: string, overrides: Partial<ServiceContext> = {}): ServiceContext {
  const windows = platform === "windows";
  return {
    platform,
    dataDirectory: windows ? "C:\\Users\\Ada Lovelace\\.phigon\\observer" : "/home/ada/.phigon/observer",
    defaultDataDirectory: true,
    nodePath: windows ? "C:\\Program Files\\nodejs\\node.exe" : "/usr/local/bin/node",
    entryPath: windows
      ? "C:\\Users\\Ada Lovelace\\AppData\\Roaming\\npm\\node_modules\\@phigon\\observer\\dist\\src\\entry.js"
      : "/usr/local/lib/node_modules/@phigon/observer/dist/src/entry.js",
    homeDirectory: root,
    user: windows ? "S-1-5-21-1000-2000-3000-1001" : "501",
    systemRoot: "C:\\Windows",
    run: recorder().runner,
    now: () => new Date(2026, 10, 2, 9, 30, 0),
    wait: async () => undefined,
    ...overrides,
  };
}

async function temporary(prefix: string): Promise<string> {
  return await mkdtemp(join(tmpdir(), prefix));
}

test("each data directory gets its own service name", () => {
  const base = { dataDirectory: "/home/ada/.phigon/observer", defaultDataDirectory: true };
  assert.equal(serviceName({ ...base, platform: "windows" }), "Phigon Observer");
  assert.equal(serviceName({ ...base, platform: "macos" }), "com.phigon.observer");
  assert.equal(serviceName({ ...base, platform: "linux" }), "phigon-observer");
  const other = { dataDirectory: "/srv/phigon/workspace-b", defaultDataDirectory: false };
  assert.match(serviceName({ ...other, platform: "linux" }), /^phigon-observer-[0-9a-f]{8}$/u);
  assert.match(serviceName({ ...other, platform: "macos" }), /^com\.phigon\.observer\.[0-9a-f]{8}$/u);
  assert.notEqual(
    serviceName({ ...other, platform: "linux" }),
    serviceName({ dataDirectory: "/srv/phigon/workspace-c", defaultDataDirectory: false, platform: "linux" }),
  );
  // Windows paths are compared without case.
  assert.equal(
    serviceName({ platform: "windows", dataDirectory: "D:\\Phigon\\Team", defaultDataDirectory: false }),
    serviceName({ platform: "windows", dataDirectory: "d:\\phigon\\team", defaultDataDirectory: false }),
  );
  assert.equal(servicePlatform("win32"), "windows");
  assert.equal(servicePlatform("darwin"), "macos");
  assert.equal(servicePlatform("linux"), "linux");
  assert.equal(servicePlatform("freebsd"), undefined);
});

test("the Windows task runs at sign-in as this user, hidden, and is retried every minute", () => {
  const xml = windowsTaskXml(context("windows", "C:\\Users\\Ada Lovelace"));
  assert.match(xml, /<LogonTrigger>\s*<Enabled>true<\/Enabled>\s*<UserId>S-1-5-21-1000-2000-3000-1001<\/UserId>/u);
  assert.match(xml, /<LogonType>InteractiveToken<\/LogonType>/u);
  assert.match(xml, /<RunLevel>LeastPrivilege<\/RunLevel>/u);
  assert.match(xml, /<StartBoundary>2026-11-02T09:30:00<\/StartBoundary>/u);
  assert.match(xml, /<Interval>PT1M<\/Interval>/u);
  assert.match(xml, /<MultipleInstancesPolicy>IgnoreNew<\/MultipleInstancesPolicy>/u);
  assert.match(xml, /<DisallowStartIfOnBatteries>false<\/DisallowStartIfOnBatteries>/u);
  assert.match(xml, /<StopIfGoingOnBatteries>false<\/StopIfGoingOnBatteries>/u);
  assert.match(xml, /<ExecutionTimeLimit>PT0S<\/ExecutionTimeLimit>/u);
  assert.match(xml, /<Command>C:\\Windows\\System32\\conhost\.exe<\/Command>/u);
  assert.match(
    xml,
    /<Arguments>--headless &quot;C:\\Program Files\\nodejs\\node\.exe&quot; &quot;C:\\Users\\Ada Lovelace\\AppData\\Roaming\\npm\\node_modules\\@phigon\\observer\\dist\\src\\entry\.js&quot; run --service-settings &quot;C:\\Users\\Ada Lovelace\\\.phigon\\observer\\service-settings\.json&quot;<\/Arguments>/u,
  );
  assert.match(xml, /<URI>\\Phigon Observer<\/URI>/u);
  assert.doesNotMatch(xml, /phg_|PHIGON_/u);

  const escaped = windowsTaskXml(context("windows", "C:\\Users\\Ada", { dataDirectory: "C:\\Data\\R&D <team>" }));
  assert.match(escaped, /C:\\Data\\R&amp;D &lt;team&gt;/u);
  for (const dataDirectory of ["relative\\path", "C:\\Users\\%USERNAME%\\data", "C:\\a\"b"]) {
    assert.throws(() => windowsTaskXml(context("windows", "C:\\", { dataDirectory })), /cannot be used by a background service/u, dataDirectory);
  }
});

test("the LaunchAgent starts at sign-in and is kept alive", () => {
  const plist = launchAgentPlist(context("macos", "/Users/ada", { dataDirectory: "/Users/ada/Phigon & Co" }));
  assert.match(plist, /<key>Label<\/key>\s*<string>com\.phigon\.observer<\/string>/u);
  assert.match(plist, /<key>RunAtLoad<\/key>\s*<true\/>/u);
  assert.match(plist, /<key>KeepAlive<\/key>\s*<true\/>/u);
  assert.match(plist, /<string>\/usr\/local\/bin\/node<\/string>\s*<string>\/usr\/local\/lib\/node_modules\/@phigon\/observer\/dist\/src\/entry\.js<\/string>\s*<string>run<\/string>\s*<string>--service-settings<\/string>\s*<string>\/Users\/ada\/Phigon &amp; Co\/service-settings\.json<\/string>/u);
  assert.doesNotMatch(plist, /EnvironmentVariables|phg_/u);
  assert.throws(() => launchAgentPlist(context("macos", "/Users/ada", { nodePath: "node" })), /Node\.js path/u);
});

test("the systemd user unit restarts on failure and quotes its command", () => {
  const unit = systemdUserUnit(context("linux", "/home/ada", {
    dataDirectory: "/home/ada/My Data/100%",
    nodePath: "/opt/node$1/bin/node",
  }));
  assert.match(unit, /^Restart=on-failure$/mu);
  assert.match(unit, /^WantedBy=default\.target$/mu);
  assert.match(unit, /^StartLimitIntervalSec=0$/mu);
  assert.match(
    unit,
    /^ExecStart="\/opt\/node\$\$1\/bin\/node" "\/usr\/local\/lib\/node_modules\/@phigon\/observer\/dist\/src\/entry\.js" "run" "--service-settings" "\/home\/ada\/My Data\/100%%\/service-settings\.json"$/mu,
  );
  assert.doesNotMatch(unit, /^Environment=/mu);
  assert.throws(() => systemdUserUnit(context("linux", "/home/ada", { dataDirectory: "/home/ada/a\nb" })), /cannot be used/u);
  assert.deepEqual(serviceCommand(context("linux", "/home/ada")).slice(2, 4), ["run", "--service-settings"]);
});

test("service settings keep what the observer needs and never a secret", async () => {
  const settings = serviceSettings({
    PHIGON_OBSERVABILITY_PROFILE: "full",
    PHIGON_LOG_LEVEL: "warn",
    PHIGON_DATA_DIR: "/elsewhere",
    PHIGON_MACHINE_TOKEN: "do-not-copy",
    PHIGON_SECRET_THING: "do-not-copy",
    Path: "C:\\Windows;C:\\Tools",
    HTTPS_PROXY: "http://proxy.example:3128",
    no_proxy: "internal.example",
    NODE_EXTRA_CA_CERTS: "/etc/ssl/company.pem",
    XDG_DATA_HOME: "/home/ada/.data",
    HOME: "/home/ada",
    AWS_SECRET_ACCESS_KEY: "do-not-copy",
    OPENAI_API_KEY: "do-not-copy",
    PHIGON_EMPTY: "",
  });
  assert.deepEqual(settings, {
    PHIGON_OBSERVABILITY_PROFILE: "full",
    PHIGON_LOG_LEVEL: "warn",
    PATH: "C:\\Windows;C:\\Tools",
    HTTPS_PROXY: "http://proxy.example:3128",
    no_proxy: "internal.example",
    NODE_EXTRA_CA_CERTS: "/etc/ssl/company.pem",
    XDG_DATA_HOME: "/home/ada/.data",
  });

  const directory = await temporary("phigon-service-settings-");
  try {
    const path = await writeServiceSettings(directory, settings);
    assert.equal(path, serviceSettingsPath(directory));
    assert.deepEqual(await readServiceSettings(path), settings);
    if (process.platform !== "win32") assert.equal((await stat(path)).mode & 0o777, 0o600);
    assert.deepEqual((await readdir(directory)).filter((name) => name.endsWith(".tmp")), []);

    for (const content of [
      "{not json",
      JSON.stringify({ version: 2, environment: {} }),
      JSON.stringify({ version: 1, environment: [] }),
      JSON.stringify({ version: 1, environment: { HOME: "/root" } }),
      JSON.stringify({ version: 1, environment: { PHIGON_MACHINE_TOKEN: "x" } }),
      JSON.stringify({ version: 1, environment: { PHIGON_LOG_LEVEL: 3 } }),
      "x".repeat(300 * 1024),
    ]) {
      await writeFile(path, content);
      await assert.rejects(readServiceSettings(path), /are unreadable\. Run phigon-observer service install again\./u);
    }
    await rm(path);
    await assert.rejects(readServiceSettings(path), /settings file .* is missing/u);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("Windows install registers the task from UTF-16 XML, replaces an earlier one and starts it", async () => {
  const home = await temporary("phigon-service-windows-");
  const xmlFiles: string[] = [];
  const { calls, runner } = recorder();
  const capturing = async (command: string, args: readonly string[]) => {
    const index = args.indexOf("/XML");
    if (index >= 0) {
      const raw = await readFile(args[index + 1]!);
      assert.deepEqual([...raw.subarray(0, 2)], [0xff, 0xfe]);
      xmlFiles.push(raw.subarray(2).toString("utf16le"));
    }
    return await runner(command, args);
  };
  try {
    const service = context("windows", home, { dataDirectory: home, defaultDataDirectory: false, run: capturing });
    const first = await installService(service, { PHIGON_LOG_LEVEL: "info" });
    await installService(service, { PHIGON_LOG_LEVEL: "info" });
    const name = serviceName(service);
    const schtasks = "C:\\Windows\\System32\\schtasks.exe";
    assert.deepEqual(calls.map((call) => [call.command, call.args[0], call.args[2]]), [
      [schtasks, "/Create", name], [schtasks, "/Run", name],
      [schtasks, "/Create", name], [schtasks, "/Run", name],
    ]);
    assert.ok(calls[0]!.args.includes("/F"), "an earlier task of the same name is replaced");
    assert.equal(xmlFiles.length, 2);
    assert.match(xmlFiles[0]!, /^<\?xml version="1\.0" encoding="UTF-16"\?>/u);
    assert.equal(first.definition, name);
    // The XML was a temporary file; only the settings stay.
    assert.deepEqual((await readdir(home)).sort(), ["service-settings.json"]);
    assert.deepEqual(await readServiceSettings(first.settingsFile), { PHIGON_LOG_LEVEL: "info" });
  } finally {
    await rm(home, { recursive: true, force: true });
  }
});

test("macOS install writes the LaunchAgent and loads it in the user's session", async () => {
  const home = await temporary("phigon-service-macos-");
  let bootstrapFailures = 2;
  const { calls, runner } = recorder((call) => {
    if (call.args[0] === "bootout") return { code: 3, stderr: "Boot-out failed: 3: No such process" };
    if (call.args[0] === "bootstrap" && bootstrapFailures-- > 0) return { code: 5, stderr: "Bootstrap failed: 5: Input/output error" };
    return {};
  });
  try {
    const service = context("macos", home, { run: runner });
    const result = await installService(service, {});
    const plist = join(home, "Library", "LaunchAgents", "com.phigon.observer.plist");
    assert.equal(result.definition, plist);
    assert.equal(serviceDefinitionPath(service), plist);
    assert.match(await readFile(plist, "utf8"), /<key>KeepAlive<\/key>/u);
    if (process.platform !== "win32") assert.equal((await stat(plist)).mode & 0o022, 0);
    assert.deepEqual(calls.map((call) => call.args.join(" ")), [
      "bootout gui/501/com.phigon.observer",
      "enable gui/501/com.phigon.observer",
      `bootstrap gui/501 ${plist}`,
      `bootstrap gui/501 ${plist}`,
      `bootstrap gui/501 ${plist}`,
    ]);
    assert.equal(await serviceInstalled(service), true);

    calls.length = 0;
    assert.equal(await stopService(service), true);
    await startService(service);
    assert.deepEqual(calls.map((call) => call.args[0]), ["bootout", "bootstrap"]);

    calls.length = 0;
    assert.equal(await uninstallService(service), true);
    assert.deepEqual(calls.map((call) => call.args[0]), ["bootout"]);
    await assert.rejects(stat(plist), { code: "ENOENT" });
    assert.equal(await serviceInstalled(service), false);
    assert.equal(await uninstallService(service), false);
  } finally {
    await rm(home, { recursive: true, force: true });
  }
});

test("Linux install writes a user unit, enables it and restarts it", async () => {
  const home = await temporary("phigon-service-linux-");
  const { calls, runner } = recorder();
  try {
    const service = context("linux", home, { run: runner, dataDirectory: join(home, "data"), configHome: join(home, "config") });
    const result = await installService(service, { PHIGON_LOG_LEVEL: "debug" });
    assert.equal(result.definition, join(home, "config", "systemd", "user", "phigon-observer.service"));
    assert.match(await readFile(result.definition, "utf8"), /^Restart=on-failure$/mu);
    assert.deepEqual(calls.map((call) => `${call.command} ${call.args.join(" ")}`), [
      "systemctl --user daemon-reload",
      "systemctl --user enable phigon-observer.service",
      "systemctl --user restart phigon-observer.service",
    ]);
    calls.length = 0;
    await stopService(service);
    await startService(service);
    await uninstallService(service);
    assert.deepEqual(calls.map((call) => call.args.slice(1).join(" ")), [
      "stop phigon-observer.service",
      "start phigon-observer.service",
      "disable --now phigon-observer.service",
      "daemon-reload",
    ]);
    await assert.rejects(stat(result.definition), { code: "ENOENT" });
    await assert.rejects(stat(result.settingsFile), { code: "ENOENT" });
  } finally {
    await rm(home, { recursive: true, force: true });
  }
});

test("a service manager failure is one plain sentence", async () => {
  const home = await temporary("phigon-service-failure-");
  try {
    const missing = context("linux", home, {
      dataDirectory: join(home, "data"),
      run: async () => ({ code: -1, stdout: "", stderr: "", missing: true }),
    });
    await assert.rejects(installService(missing, {}), /no systemd user session \(systemctl --user\)/u);

    const noBus = context("linux", home, {
      dataDirectory: join(home, "data"),
      run: async () => ({ code: 1, stdout: "", stderr: "Failed to connect to bus: No medium found" }),
    });
    await assert.rejects(installService(noBus, {}), /could not be installed \(Failed to connect to bus: No medium found\)\. Sign in to this computer/u);

    const denied = context("windows", home, {
      dataDirectory: home,
      run: async () => ({ code: 1, stdout: "", stderr: "ERROR: Access is denied.\r\n" }),
    });
    await assert.rejects(installService(denied, {}), /^Error: The background service could not be installed \(ERROR: Access is denied\.\)\.$/u);
    assert.deepEqual((await readdir(home)).filter((name) => name.endsWith(".xml")), []);
    assert.equal(await serviceInstalled(denied), false);
    assert.equal(await stopService(denied), false);
  } finally {
    await rm(home, { recursive: true, force: true });
  }
});

test("Windows stop disables the minute trigger until the task is started again", async () => {
  const { calls, runner } = recorder();
  const service = context("windows", "C:\\Users\\Ada", { run: runner });
  assert.equal(await stopService(service), true);
  await startService(service);
  assert.equal(await uninstallService(service), true);
  assert.deepEqual(calls.map((call) => call.args.filter((value) => value.startsWith("/")).join(" ")), [
    "/Query /TN", "/End /TN", "/Change /TN /DISABLE",
    "/Change /TN /ENABLE", "/Run /TN",
    "/Query /TN", "/End /TN", "/Delete /TN /F",
  ]);
});

function pairedCredential(origin: string, overrides: Partial<StoredMachineCredential> = {}): StoredMachineCredential {
  return {
    machineId: "machine-service",
    tenantId: "tenant-service",
    credential: machineKey,
    controlPlaneOrigin: origin,
    grpcOrigin: origin,
    createdAt: "2026-11-02T00:00:00.000Z",
    consentProfile: "metadata",
    consentPolicyVersion: "observer-policy-v1",
    consentedAt: "2026-11-02T00:00:00.000Z",
    ...overrides,
  };
}

test("service install refuses without pairing or consent, then installs, reports and uninstalls", async () => {
  const root = await temporary("phigon-service-cli-");
  const data = join(root, "data");
  const origin = "http://127.0.0.1:9";
  const { calls, runner } = recorder();
  const dependencies = { serviceRunner: runner, platform: "linux" as const, homeDirectory: root, stopTimeoutMs: 50 };
  const environment = {
    PHIGON_DATA_DIR: data,
    PHIGON_LOG_LEVEL: "warn",
    PHIGON_MACHINE_TOKEN: "never-copied",
    PATH: "/usr/bin:/opt/agents/bin",
  };
  const invoke = async (args: readonly string[], env: NodeJS.ProcessEnv = environment) => {
    let stdout = "";
    let stderr = "";
    const code = await run([...args], env, {
      stdout: (value) => { stdout += value; },
      stderr: (value) => { stderr += value; },
    }, undefined, dependencies);
    return { code, stdout, stderr };
  };
  try {
    const unpaired = await invoke(["service", "install"]);
    assert.equal(unpaired.code, 1);
    assert.match(unpaired.stderr, /This computer is not paired, so a background service would have nothing to collect/u);
    assert.deepEqual(calls, []);

    const store = new FileCredentialStore(data);
    const withoutConsent: Record<string, unknown> = { ...pairedCredential(origin) };
    delete withoutConsent["consentProfile"];
    delete withoutConsent["consentPolicyVersion"];
    delete withoutConsent["consentedAt"];
    await store.save(withoutConsent as StoredMachineCredential);
    const noConsent = await invoke(["service", "install"]);
    assert.equal(noConsent.code, 1);
    assert.match(noConsent.stderr, /owner's consent is missing or out of date/u);

    await store.save(pairedCredential(origin));
    const outsideConsent = await invoke(["service", "install", "--profile", "full"]);
    assert.match(outsideConsent.stderr, /outside the consented metadata profile/u);
    assert.deepEqual(calls, []);

    const installed = await invoke(["service", "install", "--json"]);
    assert.equal(installed.code, 0, installed.stderr);
    const report = JSON.parse(installed.stdout) as Record<string, unknown>;
    assert.equal(report["status"], "installed");
    assert.equal(report["name"], "phigon-observer-" + String(report["name"]).slice(-8));
    assert.equal(report["profile"], "metadata");
    assert.equal(report["logFile"], logFilePath(data));
    assert.ok((report["notes"] as string[]).some((note) => note.includes("loginctl enable-linger")));
    const settings = await readServiceSettings(serviceSettingsPath(data));
    assert.deepEqual(settings, { PHIGON_LOG_LEVEL: "warn", PATH: "/usr/bin:/opt/agents/bin", PHIGON_OBSERVABILITY_PROFILE: "metadata" });
    const unit = await readFile(String(report["definition"]), "utf8");
    assert.doesNotMatch(`${unit}${installed.stdout}`, /never-copied|phg_m_/u);
    assert.match(unit, /entry\.js" "run" "--service-settings"/u);

    const stopped = await invoke(["service", "status"]);
    assert.match(stopped.stdout, /^Background service: installed and stopped$/mu);
    const lock = await InstanceLock.acquire(data);
    try {
      const status = JSON.parse((await invoke(["service", "status", "--json"])).stdout) as Record<string, unknown>;
      assert.equal(status["state"], "running");
    } finally {
      await lock.release();
    }

    const removed = await invoke(["service", "uninstall"]);
    assert.match(removed.stdout, /^Background service removed: phigon-observer-[0-9a-f]{8}\.$/mu);
    assert.match((await invoke(["service", "status"])).stdout, /^Background service: not installed$/mu);
    assert.match((await invoke(["service", "uninstall"])).stdout, /The background service was not installed\./u);
    await assert.rejects(stat(serviceSettingsPath(data)), { code: "ENOENT" });

    const unknown = await invoke(["service", "restart"]);
    assert.equal(unknown.code, 1);
    assert.match(unknown.stderr, /service requires one of: install, uninstall, or status/u);
    assert.match((await invoke(["service", "status", "--profile", "full"])).stderr, /--profile is supported only by doctor, run and service install/u);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("the service runs with its saved settings and logs in its own data directory", async () => {
  const root = await temporary("phigon-service-run-");
  const data = join(root, "data");
  const origin = "http://127.0.0.1:9";
  try {
    await new FileCredentialStore(data).save(pairedCredential(origin));
    const settingsFile = await writeServiceSettings(data, {
      PHIGON_COLLECT_PROMPT_CONTENT: "true",
      PHIGON_UPDATE_CHECK: "false",
      NODE_EXTRA_CA_CERTS: join(root, "missing-authorities.pem"),
    });
    let stderr = "";
    // The caller's own PHIGON_DATA_DIR is ignored: the settings file decides.
    const code = await run(["run", "--service-settings", settingsFile], { PHIGON_DATA_DIR: join(root, "elsewhere") }, {
      stdout: () => undefined,
      stderr: (value) => { stderr += value; },
    });
    assert.equal(code, 1);
    assert.match(stderr, /NODE_EXTRA_CA_CERTS .* could not be read/u);
    assert.match(stderr, /PHIGON_COLLECT_PROMPT_CONTENT turns on content collection/u);
    assert.match(await readFile(logFilePath(data), "utf8"), /ERROR Observer command failed: PHIGON_COLLECT_PROMPT_CONTENT/u);
    await assert.rejects(stat(join(root, "elsewhere")), { code: "ENOENT" });

    await writeFile(settingsFile, "{}");
    stderr = "";
    assert.equal(await run(["run", "--service-settings", settingsFile], {}, {
      stdout: () => undefined,
      stderr: (value) => { stderr += value; },
    }), 1);
    assert.match(stderr, /service settings in .* are unreadable/u);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("the observer notices when the Windows task that started it ends", async () => {
  let checks = 0;
  let gone = 0;
  await new Promise<void>((resolve) => {
    watchParentProcess(1234, () => { gone++; resolve(); }, 5, () => ++checks < 3);
  });
  assert.equal(gone, 1);
  assert.equal(checks, 3);
  let calls = 0;
  const stop = watchParentProcess(1234, () => { calls++; }, 5, () => false);
  stop();
  await new Promise((resolve) => setTimeout(resolve, 30));
  assert.equal(calls, 0);
});
