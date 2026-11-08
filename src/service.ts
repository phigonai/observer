import { execFile } from "node:child_process";
import { createHash, randomUUID } from "node:crypto";
import { chmod, mkdir, readFile, rm, stat, unlink, writeFile } from "node:fs/promises";
import { dirname, isAbsolute, join, posix, win32 } from "node:path";
import { setTimeout as delay } from "node:timers/promises";
import { atomicReplace } from "./atomic-replace.js";
import { logDirectoryName, serviceErrorsFileName } from "./observer-log.js";
import { makeDirectoryPrivate } from "./private-directory.js";

/**
 * The observer as a background service of the signed-in user: a Task
 * Scheduler task on Windows, a LaunchAgent on macOS and a systemd user unit
 * on Linux. It runs as that user, not as SYSTEM or root, because it reads
 * that user's agent files. The definition holds only the Node.js binary,
 * the observer's entry point and the path of the settings file in the data
 * directory; settings and the machine key stay in the data directory.
 */
export type ServicePlatform = "windows" | "macos" | "linux";

export type CommandResult = Readonly<{
  code: number;
  stdout: string;
  stderr: string;
  /** The program does not exist on this computer. */
  missing?: boolean;
}>;

/** Runs a program without a shell. Tests replace it; nothing is installed. */
export type CommandRunner = (command: string, args: readonly string[]) => Promise<CommandResult>;

export const serviceSettingsFileName = "service-settings.json";
const settingsVersion = 1;
const maxSettingsBytes = 256 * 1024;
const maxSettingValueBytes = 32 * 1024;

export type ServiceContext = Readonly<{
  platform: ServicePlatform;
  /** Absolute data directory the service runs with. */
  dataDirectory: string;
  /** Whether that is the default ~/.phigon/observer, which keeps the plain name. */
  defaultDataDirectory: boolean;
  /** The Node.js binary and observer entry point that ran `service install`. */
  nodePath: string;
  entryPath: string;
  homeDirectory: string;
  /** Windows: the account's SID or DOMAIN\user. macOS: the numeric uid. */
  user: string;
  /** Linux: $XDG_CONFIG_HOME when it is set. */
  configHome?: string | undefined;
  /** Windows: %SystemRoot%. */
  systemRoot?: string | undefined;
  run: CommandRunner;
  now?: () => Date;
  /** Waits between retries; tests make it instant. */
  wait?: (ms: number) => Promise<void>;
}>;

export function servicePlatform(platform: NodeJS.Platform): ServicePlatform | undefined {
  if (platform === "win32") return "windows";
  if (platform === "darwin") return "macos";
  if (platform === "linux") return "linux";
  return undefined;
}

/**
 * The service's name. One observer runs per data directory, so a directory
 * other than the default gets its own service, named with a short digest
 * of its path.
 */
export function serviceName(context: Pick<ServiceContext, "platform" | "dataDirectory" | "defaultDataDirectory">): string {
  const path = (context.platform === "windows" ? win32 : posix).resolve(context.dataDirectory);
  const suffix = context.defaultDataDirectory
    ? ""
    : createHash("sha256").update(context.platform === "windows" ? path.toLowerCase() : path).digest("hex").slice(0, 8);
  if (context.platform === "windows") return suffix === "" ? "Phigon Observer" : `Phigon Observer ${suffix}`;
  if (context.platform === "macos") return suffix === "" ? "com.phigon.observer" : `com.phigon.observer.${suffix}`;
  return suffix === "" ? "phigon-observer" : `phigon-observer-${suffix}`;
}

export function serviceSettingsPath(dataDirectory: string): string {
  return join(dataDirectory, serviceSettingsFileName);
}

/** Where the definition file lives; Windows keeps it in Task Scheduler. */
export function serviceDefinitionPath(context: ServiceContext): string | undefined {
  if (context.platform === "macos") {
    return join(context.homeDirectory, "Library", "LaunchAgents", `${serviceName(context)}.plist`);
  }
  if (context.platform === "linux") {
    const configHome = context.configHome !== undefined && isAbsolute(context.configHome)
      ? context.configHome
      : join(context.homeDirectory, ".config");
    return join(configHome, "systemd", "user", `${serviceName(context)}.service`);
  }
  return undefined;
}

function checkedPath(value: string, platform: ServicePlatform, label: string): string {
  const absolute = (platform === "windows" ? /^[A-Za-z]:[\\/]/u.test(value) || value.startsWith("\\\\") : value.startsWith("/")) ||
    // Tests build another system's service from this computer's folders.
    (servicePlatform(process.platform) !== platform && isAbsolute(value));
  if (!absolute || /[\u0000-\u001f\u007f]/u.test(value) || (platform === "windows" && /["%]/u.test(value))) {
    throw new Error(`The ${label} path ${JSON.stringify(value)} cannot be used by a background service. Use a plain absolute path.`);
  }
  return value;
}

/** The command the service runs. */
export function serviceCommand(context: ServiceContext): readonly string[] {
  return [
    checkedPath(context.nodePath, context.platform, "Node.js"),
    checkedPath(context.entryPath, context.platform, "observer"),
    "run",
    "--service-settings",
    checkedPath(
      (context.platform === "windows" ? win32 : posix).join(context.dataDirectory, serviceSettingsFileName),
      context.platform,
      "data directory",
    ),
  ];
}

function xml(value: string): string {
  return value.replaceAll("&", "&amp;").replaceAll("<", "&lt;").replaceAll(">", "&gt;")
    .replaceAll("\"", "&quot;").replaceAll("'", "&apos;");
}

function localTimestamp(date: Date): string {
  const pad = (value: number) => value.toString().padStart(2, "0");
  return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())}T` +
    `${pad(date.getHours())}:${pad(date.getMinutes())}:${pad(date.getSeconds())}`;
}

/**
 * Task Scheduler XML. The task starts at sign-in and is retried every minute
 * (a running copy is left alone), so an observer that stops is started again
 * within a minute. conhost --headless keeps a console window from opening;
 * it does not pass on the exit code, so the minute trigger, not the failure
 * setting, is what restarts it.
 */
export function windowsTaskXml(context: ServiceContext): string {
  const [node, entry, ...rest] = serviceCommand(context);
  const conhost = `${checkedPath(context.systemRoot ?? "C:\\Windows", "windows", "Windows")}\\System32\\conhost.exe`;
  const quote = (value: string) => /^[A-Za-z0-9_.:\\/-]+$/u.test(value) ? value : `"${value}"`;
  const argumentsText = ["--headless", `"${node}"`, `"${entry}"`, ...rest.map(quote)].join(" ");
  const user = xml(context.user);
  return `<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Author>Phigon observer</Author>
    <Description>Collects AI agent activity for this user under the consent the computer's owner gave, and sends it to the Phigon workspace. Remove it with: phigon-observer service uninstall</Description>
    <URI>\\${xml(serviceName(context))}</URI>
  </RegistrationInfo>
  <Triggers>
    <LogonTrigger>
      <Enabled>true</Enabled>
      <UserId>${user}</UserId>
    </LogonTrigger>
    <TimeTrigger>
      <Enabled>true</Enabled>
      <StartBoundary>${localTimestamp((context.now ?? (() => new Date()))())}</StartBoundary>
      <Repetition>
        <Interval>PT1M</Interval>
        <StopAtDurationEnd>false</StopAtDurationEnd>
      </Repetition>
    </TimeTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <UserId>${user}</UserId>
      <LogonType>InteractiveToken</LogonType>
      <RunLevel>LeastPrivilege</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <StartWhenAvailable>true</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <IdleSettings>
      <StopOnIdleEnd>false</StopOnIdleEnd>
      <RestartOnIdle>false</RestartOnIdle>
    </IdleSettings>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>false</Hidden>
    <RunOnlyIfIdle>false</RunOnlyIfIdle>
    <WakeToRun>false</WakeToRun>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
    <Priority>7</Priority>
    <RestartOnFailure>
      <Interval>PT1M</Interval>
      <Count>999</Count>
    </RestartOnFailure>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>${xml(conhost)}</Command>
      <Arguments>${xml(argumentsText)}</Arguments>
      <WorkingDirectory>${xml(checkedPath(context.dataDirectory, "windows", "data directory"))}</WorkingDirectory>
    </Exec>
  </Actions>
</Task>
`;
}

/**
 * A LaunchAgent that starts at sign-in and is started again if it fails.
 * Like the systemd unit's Restart=on-failure, a clean exit is final: `run`
 * exits with 0 on a computer the workspace removed, and launchd would
 * otherwise start it again every ThrottleInterval, for good. A pairing
 * change exits with 75 and is started again.
 */
export function launchAgentPlist(context: ServiceContext): string {
  const program = serviceCommand(context).map((value) => `    <string>${xml(value)}</string>`).join("\n");
  return `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>${xml(serviceName(context))}</string>
  <key>ProgramArguments</key>
  <array>
${program}
  </array>
  <key>WorkingDirectory</key>
  <string>${xml(checkedPath(context.dataDirectory, "macos", "data directory"))}</string>
  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <dict>
    <key>SuccessfulExit</key>
    <false/>
  </dict>
  <key>ThrottleInterval</key>
  <integer>30</integer>
  <key>ProcessType</key>
  <string>Background</string>
  <key>Umask</key>
  <integer>63</integer>
  <key>StandardOutPath</key>
  <string>/dev/null</string>
  <key>StandardErrorPath</key>
  <string>${xml(serviceErrorsPath(context))}</string>
</dict>
</plist>
`;
}

/**
 * The LaunchAgent's stderr: what Node.js itself prints when it cannot
 * start the observer or crashes. The observer keeps it small (see
 * trimServiceErrors) and writes its own messages to observer.log.
 */
function serviceErrorsPath(context: ServiceContext): string {
  return posix.join(checkedPath(context.dataDirectory, "macos", "data directory"), logDirectoryName, serviceErrorsFileName);
}

/** A systemd user unit, restarted when it fails. */
export function systemdUserUnit(context: ServiceContext): string {
  const quoted = (value: string) =>
    `"${value.replaceAll("\\", "\\\\").replaceAll("\"", "\\\"").replaceAll("%", "%%").replaceAll("$", "$$$$")}"`;
  return `[Unit]
Description=Phigon observer for this user
Documentation=https://github.com/phigonai/observer#readme
StartLimitIntervalSec=0

[Service]
Type=simple
ExecStart=${serviceCommand(context).map(quoted).join(" ")}
WorkingDirectory=${checkedPath(context.dataDirectory, "linux", "data directory")}
Restart=on-failure
RestartSec=30
UMask=0077
TimeoutStopSec=20

[Install]
WantedBy=default.target
`;
}

// ---------------------------------------------------------------------------
// Settings the service runs with.

const settingNames = new Set([
  "PATH",
  "HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy", "NO_PROXY", "no_proxy",
  "grpc_proxy", "no_grpc_proxy",
  "NODE_EXTRA_CA_CERTS",
  "XDG_CONFIG_HOME", "XDG_DATA_HOME", "FLATPAK_XDG_DATA_HOME", "GOOSE_PATH_ROOT",
]);

/**
 * Names that may hold a secret are never copied, even from PHIGON_*. That
 * includes PHIGON_ENROLLMENT_CODE, which an enrollment script may still
 * have set when it installs the service.
 */
const secretName = /TOKEN|SECRET|PASSWORD|PASSPHRASE|CREDENTIAL|ENROLLMENT/u;

function allowedSetting(name: string): boolean {
  if (name === "PHIGON_DATA_DIR") return false;
  if (/^PHIGON_[A-Z0-9_]{1,96}$/u.test(name)) return !secretName.test(name);
  return settingNames.has(name);
}

/**
 * The settings from `environment` that the service needs to behave like
 * this terminal: PHIGON_* settings (never a token or password), PATH for
 * finding agents, proxy and certificate settings, and the folders some
 * agents keep their records in. The data directory is where the file is.
 */
export function serviceSettings(environment: NodeJS.ProcessEnv): Record<string, string> {
  const settings: Record<string, string> = {};
  for (const [rawName, value] of Object.entries(environment)) {
    if (value === undefined || value === "") continue;
    // Windows spells PATH as Path.
    const name = rawName.toUpperCase() === "PATH" ? "PATH" : rawName;
    if (!allowedSetting(name)) continue;
    if (value.includes("\u0000") || Buffer.byteLength(value, "utf8") > maxSettingValueBytes) continue;
    settings[name] = value;
  }
  return settings;
}

export async function writeServiceSettings(dataDirectory: string, settings: Readonly<Record<string, string>>): Promise<string> {
  await mkdir(dataDirectory, { recursive: true, mode: 0o700 });
  await makeDirectoryPrivate(dataDirectory);
  const path = serviceSettingsPath(dataDirectory);
  const temporary = `${path}.${process.pid}.${randomUUID()}.tmp`;
  try {
    await writeFile(temporary, `${JSON.stringify({ version: settingsVersion, environment: settings }, null, 2)}\n`, {
      encoding: "utf8", flag: "wx", mode: 0o600,
    });
    await atomicReplace(temporary, path);
    await chmod(path, 0o600);
  } catch (error) {
    await rm(temporary, { force: true });
    throw error;
  }
  return path;
}

/** Reads and checks the settings file; anything unexpected is refused. */
export async function readServiceSettings(path: string): Promise<Record<string, string>> {
  const invalid = () => new Error(
    `The background service settings in ${path} are unreadable. Run phigon-observer service install again.`,
  );
  let raw: string;
  try {
    if ((await stat(path)).size > maxSettingsBytes) throw invalid();
    raw = await readFile(path, "utf8");
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") {
      throw new Error(`The background service settings file ${path} is missing. Run phigon-observer service install again.`);
    }
    throw invalid();
  }
  let value: unknown;
  try {
    value = JSON.parse(raw);
  } catch {
    throw invalid();
  }
  if (
    typeof value !== "object" || value === null || !("version" in value) || value.version !== settingsVersion ||
    !("environment" in value) || typeof value.environment !== "object" || value.environment === null ||
    Array.isArray(value.environment)
  ) {
    throw invalid();
  }
  const settings: Record<string, string> = {};
  for (const [name, setting] of Object.entries(value.environment)) {
    if (!allowedSetting(name) || typeof setting !== "string" || setting.includes("\u0000") ||
      Buffer.byteLength(setting, "utf8") > maxSettingValueBytes) {
      throw invalid();
    }
    settings[name] = setting;
  }
  return settings;
}

/**
 * A saved endpoint setting to point at a server's new address. `from` is
 * the address the earlier pairing stored; a pairing saved before it stored
 * one (older gRPC pairings) used the setting itself, so with no `from` the
 * setting moves whatever it names.
 */
export type EndpointMove = Readonly<{ from: string | undefined; to: string }>;

/**
 * After this computer followed its server to a new address, points the
 * background service's saved endpoints there too: a service installed while
 * PHIGON_CONTROL_PLANE_URL or PHIGON_GRPC_URL was set keeps them, and would
 * otherwise start again with the earlier address and refuse to run. Only a
 * setting that named the earlier address changes. Returns whether the file
 * changed; without a service there is nothing to change.
 */
export async function moveServiceEndpoints(
  dataDirectory: string,
  moves: Readonly<Record<string, EndpointMove>>,
): Promise<boolean> {
  const path = serviceSettingsPath(dataDirectory);
  try {
    await stat(path);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return false;
    throw error;
  }
  const settings = await readServiceSettings(path);
  let changed = false;
  for (const [name, move] of Object.entries(moves)) {
    const value = settings[name];
    if (value === undefined) continue;
    let origin: string;
    try {
      origin = new URL(value).origin;
    } catch {
      continue;
    }
    if ((move.from !== undefined && origin !== move.from) || origin === move.to) continue;
    settings[name] = move.to;
    changed = true;
  }
  if (changed) await writeServiceSettings(dataDirectory, settings);
  return changed;
}

// ---------------------------------------------------------------------------
// Installing, removing and inspecting the service.

export class ServiceError extends Error {}

function describe(result: CommandResult): string {
  const text = `${result.stderr} ${result.stdout}`.replace(/\s+/gu, " ").trim().slice(0, 200);
  return text === "" ? `exit code ${result.code}` : text;
}

function windowsTool(context: ServiceContext, name: string): string {
  return `${context.systemRoot ?? "C:\\Windows"}\\System32\\${name}`;
}

async function required(context: ServiceContext, command: string, args: readonly string[], action: string): Promise<CommandResult> {
  const result = await context.run(command, args);
  if (result.missing === true) {
    throw new ServiceError(
      context.platform === "linux"
        ? "This computer has no systemd user session (systemctl --user), so a background service cannot be installed. Keep phigon-observer run running another way."
        : `${command} is not available on this computer, so the background service could not be ${action}.`,
    );
  }
  if (result.code !== 0) {
    const hint = context.platform === "linux" && /bus|XDG_RUNTIME_DIR/iu.test(describe(result))
      ? " Sign in to this computer as this user (a desktop or SSH session) and try again."
      : context.platform === "macos" && action !== "stopped"
        ? " Sign in to this Mac's desktop as this user and try again."
        : "";
    throw new ServiceError(`The background service could not be ${action} (${describe(result)}).${hint}`);
  }
  return result;
}

export type ServiceInstallResult = Readonly<{
  name: string;
  platform: ServicePlatform;
  /** The definition file, or the Task Scheduler task name on Windows. */
  definition: string;
  settingsFile: string;
}>;

/**
 * Installs the service, replacing an earlier definition of the same name,
 * and starts it. The caller checks pairing and consent first.
 */
export async function installService(
  context: ServiceContext,
  settings: Readonly<Record<string, string>>,
): Promise<ServiceInstallResult> {
  const name = serviceName(context);
  serviceCommand(context);
  const settingsFile = await writeServiceSettings(context.dataDirectory, settings);
  if (context.platform === "windows") {
    const definition = join(context.dataDirectory, `service-task-${randomUUID()}.xml`);
    // schtasks reads task XML as UTF-16.
    await writeFile(definition, Buffer.concat([Buffer.from([0xff, 0xfe]), Buffer.from(windowsTaskXml(context), "utf16le")]), { mode: 0o600 });
    try {
      await required(context, windowsTool(context, "schtasks.exe"), ["/Create", "/TN", name, "/XML", definition, "/F"], "installed");
    } finally {
      await rm(definition, { force: true });
    }
    await required(context, windowsTool(context, "schtasks.exe"), ["/Run", "/TN", name], "started");
    return Object.freeze({ name, platform: context.platform, definition: name, settingsFile });
  }
  const definition = serviceDefinitionPath(context)!;
  await mkdir(dirname(definition), { recursive: true, mode: 0o755 });
  // launchd opens the LaunchAgent's stderr file but does not create its folder.
  if (context.platform === "macos") {
    await mkdir(join(context.dataDirectory, logDirectoryName), { recursive: true, mode: 0o700 });
  }
  const content = context.platform === "macos" ? launchAgentPlist(context) : systemdUserUnit(context);
  const temporary = `${definition}.${randomUUID()}.tmp`;
  await writeFile(temporary, content, { encoding: "utf8", mode: 0o644 });
  await atomicReplace(temporary, definition);
  // launchd and systemd refuse a definition others can write to.
  await chmod(definition, 0o644);
  if (context.platform === "macos") {
    const domain = `gui/${context.user}`;
    await context.run("launchctl", ["bootout", `${domain}/${name}`]);
    await context.run("launchctl", ["enable", `${domain}/${name}`]);
    // launchd can still be unloading the old definition for a moment.
    for (let attempt = 0; ; attempt++) {
      const result = await context.run("launchctl", ["bootstrap", domain, definition]);
      if (result.code === 0 && result.missing !== true) break;
      if (attempt >= 4 || result.missing === true) {
        await required(context, "launchctl", ["bootstrap", domain, definition], "started");
        break;
      }
      await (context.wait ?? delay)(500);
    }
  } else {
    await required(context, "systemctl", ["--user", "daemon-reload"], "installed");
    await required(context, "systemctl", ["--user", "enable", `${name}.service`], "installed");
    await required(context, "systemctl", ["--user", "restart", `${name}.service`], "started");
  }
  return Object.freeze({ name, platform: context.platform, definition, settingsFile });
}

export async function serviceInstalled(context: ServiceContext): Promise<boolean> {
  if (context.platform === "windows") {
    const result = await context.run(windowsTool(context, "schtasks.exe"), ["/Query", "/TN", serviceName(context)]);
    return result.code === 0 && result.missing !== true;
  }
  try {
    await stat(serviceDefinitionPath(context)!);
    return true;
  } catch {
    return false;
  }
}

/** Stops the running service without removing it. Returns false when it is not installed. */
export async function stopService(context: ServiceContext): Promise<boolean> {
  if (!(await serviceInstalled(context))) return false;
  const name = serviceName(context);
  if (context.platform === "windows") {
    // Ending the task ends conhost; the observer notices and stops itself.
    await context.run(windowsTool(context, "schtasks.exe"), ["/End", "/TN", name]);
    // The minute trigger would start it again; keep it off until started.
    await context.run(windowsTool(context, "schtasks.exe"), ["/Change", "/TN", name, "/DISABLE"]);
  } else if (context.platform === "macos") {
    // KeepAlive would restart a stopped job; unloading stops it for good.
    await context.run("launchctl", ["bootout", `gui/${context.user}/${name}`]);
  } else {
    await context.run("systemctl", ["--user", "stop", `${name}.service`]);
  }
  return true;
}

/** Starts the service again after `stopService`. */
export async function startService(context: ServiceContext): Promise<void> {
  const name = serviceName(context);
  if (context.platform === "windows") {
    await required(context, windowsTool(context, "schtasks.exe"), ["/Change", "/TN", name, "/ENABLE"], "started");
    await required(context, windowsTool(context, "schtasks.exe"), ["/Run", "/TN", name], "started");
  } else if (context.platform === "macos") {
    await required(context, "launchctl", ["bootstrap", `gui/${context.user}`, serviceDefinitionPath(context)!], "started");
  } else {
    await required(context, "systemctl", ["--user", "start", `${name}.service`], "started");
  }
}

/** Stops and removes the service and its settings file. Returns false when it was not installed. */
export async function uninstallService(context: ServiceContext): Promise<boolean> {
  const installed = await serviceInstalled(context);
  const name = serviceName(context);
  if (installed) {
    if (context.platform === "windows") {
      await context.run(windowsTool(context, "schtasks.exe"), ["/End", "/TN", name]);
      await required(context, windowsTool(context, "schtasks.exe"), ["/Delete", "/TN", name, "/F"], "removed");
    } else if (context.platform === "macos") {
      await context.run("launchctl", ["bootout", `gui/${context.user}/${name}`]);
      await unlink(serviceDefinitionPath(context)!).catch(() => undefined);
    } else {
      await context.run("systemctl", ["--user", "disable", "--now", `${name}.service`]);
      await unlink(serviceDefinitionPath(context)!).catch(() => undefined);
      await context.run("systemctl", ["--user", "daemon-reload"]);
    }
  }
  await rm(serviceSettingsPath(context.dataDirectory), { force: true });
  return installed;
}

// ---------------------------------------------------------------------------
// What the installed service runs, and what its service manager says.

/** The Node.js and observer entry point an installed service starts. */
export type ServiceProgram = Readonly<{ node: string; entry: string }>;

function unxml(value: string): string {
  return value.replaceAll("&lt;", "<").replaceAll("&gt;", ">").replaceAll("&quot;", "\"")
    .replaceAll("&apos;", "'").replaceAll("&amp;", "&");
}

/** The program a LaunchAgent plist runs, as launchAgentPlist writes it. */
export function programFromPlist(text: string): ServiceProgram | undefined {
  const array = /<key>ProgramArguments<\/key>\s*<array>([\s\S]*?)<\/array>/u.exec(text)?.[1];
  if (array === undefined) return undefined;
  const [node, entry] = [...array.matchAll(/<string>([\s\S]*?)<\/string>/gu)].map((match) => unxml(match[1] ?? ""));
  return node === undefined || entry === undefined ? undefined : { node, entry };
}

/** The program a systemd unit's ExecStart runs, as systemdUserUnit quotes it. */
export function programFromUnit(text: string): ServiceProgram | undefined {
  const line = /^ExecStart=(.*)$/mu.exec(text)?.[1];
  if (line === undefined) return undefined;
  const [node, entry] = [...line.matchAll(/"((?:[^"\\]|\\.)*)"/gu)].map((match) =>
    (match[1] ?? "").replace(/\\(.)|%%|\$\$/gu, (escaped: string, character: string | undefined) =>
      character ?? escaped.slice(1)));
  return node === undefined || entry === undefined ? undefined : { node, entry };
}

/** The program a Task Scheduler task runs through conhost, as windowsTaskXml writes it. */
export function programFromTaskXml(text: string): ServiceProgram | undefined {
  const argumentsText = /<Arguments>([\s\S]*?)<\/Arguments>/u.exec(text)?.[1];
  if (argumentsText === undefined) return undefined;
  const [node, entry] = [...unxml(argumentsText).matchAll(/"([^"]*)"/gu)].map((match) => match[1] ?? "");
  return node === undefined || entry === undefined ? undefined : { node, entry };
}

/**
 * What the installed service starts, read from its definition, or
 * undefined when it is not installed or cannot be read.
 */
export async function installedServiceProgram(context: ServiceContext): Promise<ServiceProgram | undefined> {
  try {
    if (context.platform === "windows") {
      const result = await context.run(windowsTool(context, "schtasks.exe"), ["/Query", "/TN", serviceName(context), "/XML"]);
      return result.code === 0 && result.missing !== true ? programFromTaskXml(result.stdout) : undefined;
    }
    const text = await readFile(serviceDefinitionPath(context)!, "utf8");
    return context.platform === "macos" ? programFromPlist(text) : programFromUnit(text);
  } catch {
    return undefined;
  }
}

/**
 * Why the installed service cannot start, in one plain sentence: the
 * Node.js or observer it was installed with is gone, as after a version
 * manager such as nvm, Volta or mise removed that Node.js. Undefined when
 * both exist or this cannot be told.
 */
export async function serviceProgramProblem(
  context: ServiceContext,
  exists: (path: string) => Promise<boolean> = async (path) => await stat(path).then(() => true, () => false),
): Promise<string | undefined> {
  const program = await installedServiceProgram(context);
  if (program === undefined) return undefined;
  // schtasks may print a path in another code page; a path it garbled is
  // not reported as missing.
  const readable = (path: string) => context.platform !== "windows" || /^[\x20-\x7e]*$/u.test(path);
  const again = "Run phigon-observer service install again from a terminal where phigon-observer works.";
  if (readable(program.node) && !(await exists(program.node))) {
    return `The background service starts Node.js from ${program.node}, which no longer exists, so it cannot run; ` +
      `Node.js was probably upgraded or removed (for example with nvm, Volta or mise). ${again}`;
  }
  if (readable(program.entry) && !(await exists(program.entry))) {
    return `The background service starts the observer from ${program.entry}, which no longer exists, so it cannot run; ` +
      `the observer was probably removed or installed under another Node.js. ${again}`;
  }
  return undefined;
}

/**
 * What the service manager says about the service's last exit, in one
 * plain sentence, when it failed: launchd's last exit code, systemd's
 * result, or Task Scheduler's last result. Undefined when it did not fail
 * or cannot be asked.
 */
export async function serviceManagerProblem(context: ServiceContext): Promise<string | undefined> {
  const name = serviceName(context);
  try {
    if (context.platform === "macos") {
      const result = await context.run("launchctl", ["print", `gui/${context.user}/${name}`]);
      if (result.code !== 0 || result.missing === true) return undefined;
      const exit = /last exit code = (-?\d+)(?::\s*([^\n]+))?/u.exec(result.stdout);
      if (exit === null || exit[1] === "0") return undefined;
      return `launchd says the observer last exited with code ${exit[1]}${exit[2] === undefined ? "" : ` (${exit[2].trim()})`}.`;
    }
    if (context.platform === "linux") {
      const result = await context.run("systemctl", [
        "--user", "show", `${name}.service`, "--property=Result,ExecMainStatus,ExecMainExitTimestamp",
      ]);
      if (result.code !== 0 || result.missing === true) return undefined;
      const property = (key: string) => new RegExp(`^${key}=(.*)$`, "mu").exec(result.stdout)?.[1]?.trim() ?? "";
      const outcome = property("Result");
      if (outcome === "" || outcome === "success") return undefined;
      const status = property("ExecMainStatus");
      const at = property("ExecMainExitTimestamp");
      return `systemd says the service failed (${outcome}${status === "" || status === "0" ? "" : `, exit status ${status}`})` +
        `${at === "" ? "" : ` at ${at}`}. See journalctl --user -u ${name}.service.`;
    }
    const result = await context.run(windowsTool(context, "schtasks.exe"), ["/Query", "/TN", name, "/V", "/FO", "CSV", "/NH"]);
    if (result.code !== 0 || result.missing === true) return undefined;
    // HostName, TaskName, Next Run Time, Status, Logon Mode, Last Run Time, Last Result, ...
    const fields = [...(result.stdout.trim().split(/\r?\n/u)[0] ?? "").matchAll(/"([^"]*)"/gu)].map((match) => match[1] ?? "");
    const code = Number(fields[6]);
    // Success, still running, not run yet, ended by stopping the service,
    // and a minute trigger refused because the observer already runs
    // (0x800710E0, MultipleInstancesPolicy IgnoreNew).
    if (!/^-?\d+$/u.test(fields[6] ?? "") || [0, 0x41301, 0x41303, 0x41306, 0x40010004, 0x800710e0].includes(code >>> 0)) {
      return undefined;
    }
    return `Task Scheduler says the last run ended with result 0x${(code >>> 0).toString(16).toUpperCase()}.`;
  } catch {
    return undefined;
  }
}

/** Runs a program with execFile: no shell, no window, a time limit. */
export const runCommand: CommandRunner = async (command, args) =>
  await new Promise<CommandResult>((resolvePromise) => {
    execFile(command, [...args], { windowsHide: true, timeout: 30_000, encoding: "utf8", maxBuffer: 1 << 20 }, (error, stdout, stderr) => {
      if (error === null) {
        resolvePromise({ code: 0, stdout, stderr });
        return;
      }
      const code = (error as NodeJS.ErrnoException).code;
      resolvePromise({
        code: typeof error.code === "number" ? error.code : 1,
        stdout: stdout ?? "",
        stderr: stderr ?? "",
        ...(code === "ENOENT" ? { missing: true } : {}),
      });
    });
  });
