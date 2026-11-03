import { homedir, userInfo } from "node:os";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { setTimeout as delay } from "node:timers/promises";
import { contentOutsideProfileMessage, type ObserverConfig } from "./config.js";
import { FileCredentialStore } from "./credential-store.js";
import { InstanceLock } from "./instance-lock.js";
import { logFilePath } from "./observer-log.js";
import { OBSERVER_CONSENT_POLICY_VERSION } from "./pair.js";
import { currentUserSID } from "./private-directory.js";
import {
  installService,
  readServiceSettings,
  runCommand,
  serviceDefinitionPath,
  serviceInstalled,
  serviceName,
  servicePlatform,
  serviceSettings,
  serviceSettingsPath,
  startService,
  stopService,
  uninstallService,
  type CommandRunner,
  type ServiceContext,
} from "./service.js";

export type ServiceDependencies = Readonly<{
  /** Runs schtasks, launchctl or systemctl; tests replace it. */
  serviceRunner?: CommandRunner;
  /** The operating system to install for; tests replace it. */
  platform?: NodeJS.Platform;
  /** How long to wait for a stopping observer to let go of its data directory. */
  stopTimeoutMs?: number;
  /** The home folder a LaunchAgent or user unit goes under; tests replace it. */
  homeDirectory?: string;
}>;

type Output = Readonly<{ stdout: (value: string) => void }>;

export function serviceContext(
  config: ObserverConfig,
  environment: NodeJS.ProcessEnv,
  dependencies: ServiceDependencies = {},
): ServiceContext {
  const platform = servicePlatform(dependencies.platform ?? process.platform);
  if (platform === undefined) {
    throw new Error("Background services are available on Windows, macOS and Linux. Keep phigon-observer run running another way.");
  }
  const dataDirectory = resolve(config.dataDirectory);
  const fallback = resolve(join(homedir(), ".phigon", "observer"));
  const same = (a: string, b: string) => platform === "windows" ? a.toLowerCase() === b.toLowerCase() : a === b;
  const account = userInfo();
  return Object.freeze({
    platform,
    dataDirectory,
    defaultDataDirectory: same(dataDirectory, fallback),
    nodePath: process.execPath,
    entryPath: fileURLToPath(new URL("./entry.js", import.meta.url)),
    homeDirectory: dependencies.homeDirectory ?? homedir(),
    user: platform === "windows"
      ? (currentUserSID() ?? `${environment["USERDOMAIN"] ?? process.env["USERDOMAIN"] ?? ""}\\${account.username}`)
      : String(account.uid),
    configHome: environment["XDG_CONFIG_HOME"]?.trim() || undefined,
    systemRoot: process.env["SystemRoot"] ?? process.env["SYSTEMROOT"],
    run: dependencies.serviceRunner ?? runCommand,
  });
}

/** Why collection cannot start on this computer, or undefined when it can. */
async function installRefusal(config: ObserverConfig): Promise<string | undefined> {
  const credential = await new FileCredentialStore(config.dataDirectory).load();
  if (credential === null) {
    return "This computer is not paired, so a background service would have nothing to collect. Pair it with the command from Connect machine, then run service install again.";
  }
  if (credential.controlPlaneOrigin !== config.controlPlaneUrl.origin) {
    return `This computer is paired with ${credential.controlPlaneOrigin}, but the observer is set up for ${config.controlPlaneUrl.origin}. Remove the other control plane setting and try again.`;
  }
  if (credential.consentPolicyVersion !== OBSERVER_CONSENT_POLICY_VERSION || credential.consentProfile === undefined) {
    return "The computer owner's consent is missing or out of date. Pair again with --consent-profile metadata or full, then run service install again.";
  }
  if (config.observabilityProfile === "full" && credential.consentProfile !== "full") {
    return "Full-content collection is outside the consented metadata profile. Install the service with --profile metadata, or pair again with full-activity consent.";
  }
  if (config.contentSettingsOutsideProfile.length > 0) {
    return contentOutsideProfileMessage(config.contentSettingsOutsideProfile);
  }
  return undefined;
}

async function waitUntilStopped(dataDirectory: string, timeoutMs: number): Promise<boolean> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (!(await InstanceLock.inspect(dataDirectory)).running) return true;
    await delay(250);
  }
  return !(await InstanceLock.inspect(dataDirectory)).running;
}

function restartNote(context: ServiceContext): string {
  return context.platform === "windows"
    ? "It starts when you sign in, and again within a minute if it stops."
    : context.platform === "macos"
      ? "It starts when you sign in, and launchd starts it again if it stops."
      : "It starts when you sign in, and systemd restarts it if it fails.";
}

/** What pairing did about the background service. */
export type PairingService =
  | Readonly<{ status: "installed"; name: string; note: string; alreadyRunning: boolean }>
  | Readonly<{ status: "not_installed"; reason: string }>;

/**
 * Installs the background service right after the computer's owner paired
 * it, for the profile they consented to (`config` is loaded with it), so
 * collection keeps running after the terminal closes and starts again after
 * every restart. A computer that cannot have one is still paired: the
 * result says why, and the observer can be run by hand.
 */
export async function installServiceAfterPairing(
  config: ObserverConfig,
  environment: NodeJS.ProcessEnv,
  dependencies: ServiceDependencies = {},
): Promise<PairingService> {
  try {
    const refusal = await installRefusal(config);
    if (refusal !== undefined) return { status: "not_installed", reason: refusal };
    const context = serviceContext(config, environment, dependencies);
    // A service installed before (pairing again, or following a server to a
    // new address) keeps the settings it was installed with, which this
    // terminal may not have; only the consented profile changes.
    const installed = await serviceInstalled(context);
    const kept = installed
      ? await readServiceSettings(serviceSettingsPath(context.dataDirectory)).catch(() => undefined)
      : undefined;
    // An observer started by hand; one the service runs restarts for the new pairing.
    const alreadyRunning = !installed && (await InstanceLock.inspect(context.dataDirectory)).running;
    await installService(context, { ...(kept ?? serviceSettings(environment)), PHIGON_OBSERVABILITY_PROFILE: config.observabilityProfile });
    return { status: "installed", name: serviceName(context), note: restartNote(context), alreadyRunning };
  } catch (error) {
    return { status: "not_installed", reason: error instanceof Error ? error.message : "The background service could not be installed." };
  }
}

/**
 * After an update, starts the background service again, so it runs the new
 * version instead of the old one until the next sign-in. Says what happened.
 */
export async function restartServiceAfterUpdate(
  config: ObserverConfig,
  environment: NodeJS.ProcessEnv,
  dependencies: ServiceDependencies = {},
): Promise<"restarted" | "not_installed" | "failed"> {
  let context: ServiceContext;
  try {
    context = serviceContext(config, environment, dependencies);
    if (!(await stopService(context))) return "not_installed";
  } catch {
    return "failed";
  }
  // Started again even if the old observer is slow to stop: it takes over then.
  await waitUntilStopped(context.dataDirectory, dependencies.stopTimeoutMs ?? 15_000).catch(() => false);
  try {
    await startService(context);
    return "restarted";
  } catch {
    return "failed";
  }
}

/** `service install | uninstall | status`. */
export async function runServiceCommand(
  flags: readonly string[],
  config: ObserverConfig,
  environment: NodeJS.ProcessEnv,
  output: Output,
  json: boolean,
  dependencies: ServiceDependencies = {},
): Promise<number> {
  const subcommand = flags[0];
  if (subcommand !== "install" && subcommand !== "uninstall" && subcommand !== "status") {
    throw new Error("service requires one of: install, uninstall, or status. Run phigon-observer help for usage.");
  }
  const context = serviceContext(config, environment, dependencies);
  const name = serviceName(context);
  const logFile = logFilePath(context.dataDirectory);
  const definition = serviceDefinitionPath(context) ?? name;

  if (subcommand === "status") {
    const installed = await serviceInstalled(context);
    const running = (await InstanceLock.inspect(context.dataDirectory)).running;
    const state = !installed ? "not_installed" : running ? "running" : "stopped";
    output.stdout(json
      ? `${JSON.stringify({ state, installed, running, name, platform: context.platform, definition, dataDirectory: context.dataDirectory, logFile }, null, 2)}\n`
      : [
          `Background service: ${!installed ? "not installed" : running ? "installed and running" : "installed and stopped"}`,
          `Name: ${name}`,
          ...(installed ? [`Log: ${logFile}`] : []),
          ...(!installed && running ? ["An observer started by hand is running with this data directory."] : []),
          "",
        ].join("\n"));
    return 0;
  }

  if (subcommand === "uninstall") {
    const removed = await uninstallService(context);
    const stopped = removed ? await waitUntilStopped(context.dataDirectory, dependencies.stopTimeoutMs ?? 15_000) : true;
    output.stdout(json
      ? `${JSON.stringify({ status: removed ? "removed" : "not_installed", name, platform: context.platform, observerStopped: stopped }, null, 2)}\n`
      : [
          removed ? `Background service removed: ${name}.` : "The background service was not installed.",
          ...(removed && !stopped ? ["The observer is still stopping; it exits within a few seconds."] : []),
          "",
        ].join("\n"));
    return 0;
  }

  const refusal = await installRefusal(config);
  if (refusal !== undefined) throw new Error(refusal);
  const settings = { ...serviceSettings(environment), PHIGON_OBSERVABILITY_PROFILE: config.observabilityProfile };
  const alreadyRunning = (await InstanceLock.inspect(context.dataDirectory)).running;
  const result = await installService(context, settings);
  const notes = [
    restartNote(context),
    ...(alreadyRunning
      ? ["An observer is already running with this data directory. The service takes over when it stops."]
      : []),
    ...(context.platform === "linux"
      ? [`To keep collecting while ${userInfo().username} is signed out, an administrator can run: loginctl enable-linger ${userInfo().username}`]
      : []),
  ];
  output.stdout(json
    ? `${JSON.stringify({ status: "installed", name, platform: context.platform, definition: result.definition, settingsFile: result.settingsFile, logFile, profile: config.observabilityProfile, notes }, null, 2)}\n`
    : [
        `Background service installed: ${name}`,
        `Collection profile: ${config.observabilityProfile}`,
        ...notes,
        `Settings: ${result.settingsFile}`,
        `Log: ${logFile}`,
        "",
      ].join("\n"));
  return 0;
}
