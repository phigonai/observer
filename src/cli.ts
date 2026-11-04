#!/usr/bin/env node

import { create, toJsonString } from "@bufbuild/protobuf";
import { timestampDate, timestampFromDate } from "@bufbuild/protobuf/wkt";
import { constants, readFileSync, realpathSync } from "node:fs";
import { access, readFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { createInterface } from "node:readline";
import type { Readable } from "node:stream";
import { fileURLToPath } from "node:url";
import {
  FileActionPolicyStore,
  managedActionNames,
  type GuardianIntervention,
  type ManagedActionName,
} from "./action-policy.js";
import {
  GuardianDecisionUnavailableError,
  HTTPGuardianDecisionClient,
  readGuardianActionContext,
} from "./agentic-guardian.js";
import { AgentActionExecutor } from "./agent-action-executor.js";
import {
  ActivityCollector,
  historySyncQueueHeadroom,
  mergeInventoryWithSourceIdentities,
  registeredAgentActivitySources,
} from "./activity/collector.js";
import { ingestActivityJSONL } from "./activity/ingest.js";
import {
  consentedCollectionPolicy,
  contentOutsideProfileMessage,
  dataDirectoryFrom,
  loadConfig,
  DEFAULT_CONTROL_PLANE_ORIGIN,
  type CollectionPolicy,
  type ObserverConfig,
} from "./config.js";
import { FileCredentialStore, type RemoteActionConsent, type StoredMachineCredential } from "./credential-store.js";
import { containmentAllowed, remoteActionConsent, remoteActionSentence, remoteActionsAllowed } from "./remote-actions.js";
import {
  CustomAgentRegistry,
  customAgentRegistration,
  type CustomAgentRegistration,
} from "./custom-agent-registry.js";
import {
  DiscoveryEngine,
  runDiscoveryLoop,
  type DiscoverySnapshot,
} from "./discovery/index.js";
import { AgentState } from "./generated/phigon/v1/common_pb.js";
import { AgentInventorySchema } from "./generated/phigon/v1/identity_pb.js";
import {
  HistorySyncResultSchema,
  HistorySyncResultState,
} from "./generated/phigon/v1/history_sync_pb.js";
import {
  HistoricalIdentityStore,
  mergeInventoryWithHistoricalIdentities,
} from "./historical-identity-store.js";
import type {
  CollectionPolicy as WireCollectionPolicy,
} from "./generated/phigon/v1/policy_pb.js";
import {
  consentHealth,
  createHealthSnapshot,
  describeConsent,
  type ObserverStreamCursorHealth,
} from "./health.js";
import {
  OBSERVER_CONSENT_POLICY_VERSION,
  pairMachine,
  type ConsentProfile,
} from "./pair.js";
import {
  EnrollmentError,
  checkedEnrollmentCode,
  enrollMachine,
  enrollmentCodeVariable,
  type EnrollResult,
} from "./enroll.js";
import { removeMachine } from "./remove-machine.js";
import { forgetServerAuthority, parseAuthorityFingerprint, trustAuthority } from "./server-authority.js";
import { followServer, saveMovedServer } from "./server-follow.js";
import { preparePairingAuthority } from "./server-move.js";
import { pairingChanged, pairingChangedExitCode, watchPairing, type PairingChange, type PairingWatch } from "./pairing-watch.js";
import { moveServiceEndpoints, readServiceSettings, serviceSettingsPath, startService, stopService, uninstallService } from "./service.js";
import {
  installServiceAfterPairing,
  restartServiceAfterUpdate,
  runServiceCommand,
  serviceContext,
  type PairingService,
  type ServiceDependencies,
} from "./service-command.js";
import { purgeDataDirectory, removeEmptyDataDirectory } from "./purge.js";
import { hasByteHeadroom } from "./event-queue.js";
import { InstanceLock, ObserverAlreadyRunningError, processIsAlive } from "./instance-lock.js";
import { MachineRemovedError, machineRemovedMessage, rememberMachineRemoved, removedAtStart } from "./machine-removed.js";
import { clearEventSpool } from "./event-spool.js";
import { GuardianDecisionJournal } from "./guardian-decision-journal.js";
import {
  GuardianContainmentExecutor,
  type GuardianContainmentResult,
} from "./guardian-containment.js";
import { ObserverStreamClient } from "./stream-client.js";
import { executeManagedCommand } from "./guardian-managed-exec.js";
import { createHash } from "node:crypto";
import { createExecutionManifest, executionEnvironment, verifyExecutionManifest } from "./guardian-execution-manifest.js";
import { GuardianHostedClient } from "./guardian-hosted-client.js";
import { startGuardianModelBridge } from "./guardian-model-bridge.js";
import { semanticDecision } from "./agentic-guardian.js";
import { guardianRunnerPath } from "./guardian-native.js";
import { GuardianProcessMonitor } from "./guardian-process-monitor.js";
import { setTimeout as delay } from "node:timers/promises";
import { ServerClock, describeClockSkew } from "./server-clock.js";
import { StreamStateStore } from "./stream-state.js";
import { connectionEnvironment } from "./connection-config.js";
import { latestObserverVersion, newerVersion, offerObserverUpdate } from "./update.js";
import { UserNotices } from "./user-notices.js";
import { announceCompanyCollection } from "./collection-notice.js";
import {
  defaultMaxDeliveryAgeMinutes,
  formatDoctorCheck,
  runDoctorCheck,
} from "./doctor-check.js";
import {
  proxyForUrl,
  proxySettings,
  useProxyFromEnvironment,
  type ProxySetup,
} from "./proxy.js";
import {
  RotatingLogFile,
  levelledOutput,
  logLevelFrom,
  type LevelledOutput,
} from "./observer-log.js";

type Output = Readonly<{
  stdout: (value: string) => void;
  stderr: (value: string) => void;
}>;

const defaultOutput: Output = {
  stdout: (value) => process.stdout.write(value),
  stderr: (value) => process.stderr.write(value),
};

export async function run(
  argv: readonly string[],
  environment: NodeJS.ProcessEnv = process.env,
  output: Output = defaultOutput,
  input: Readable = process.stdin,
  dependencies: ServiceDependencies = {},
): Promise<number> {
  const [command, ...flags] = argv;
  let logged: LevelledOutput | undefined;
  // A background service runs `run --service-settings <file>`; the file
  // sits in the data directory and holds the settings it was installed with.
  const serviceSettingsFile = command === "run" ? flagValue(flags, "--service-settings") : undefined;
  const ownEnvironment = environment === process.env;
  if (serviceSettingsFile !== undefined) {
    environment = { ...environment, PHIGON_DATA_DIR: dirname(resolve(serviceSettingsFile)) };
  }

  if (command === "--version" || command === "-v" || command === "version") {
    output.stdout(`${await readVersion()}\n`);
    return 0;
  }

  if (command === undefined || command === "help" || command === "--help" || command === "-h" || flags.includes("--help")) {
    output.stdout(helpText());
    return 0;
  }

  if (
    command !== "doctor" &&
    command !== "update" &&
    command !== "agent" &&
    command !== "authorize-action" &&
    command !== "guardian" &&
    command !== "discover" &&
    command !== "ingest" &&
    command !== "pair" &&
    command !== "remove-machine" &&
    command !== "unpair" &&
    command !== "service" &&
    command !== "run"
  ) {
    output.stderr(`Unknown command: ${command}\n\n${helpText()}`);
    return 2;
  }

  if (command === "run") {
    // A background service throws away what it prints, so `run` also keeps
    // a log file in the data directory, at PHIGON_LOG_LEVEL.
    const log = new RotatingLogFile(dataDirectoryFrom(environment), {
      onFailure: (message) => output.stderr(message),
    });
    logged = levelledOutput(output, logLevelFrom(environment["PHIGON_LOG_LEVEL"]), log);
    output = logged;
  }

  let callerEnvironment = environment;
  let proxy: ProxySetup | undefined;
  try {
    if (serviceSettingsFile !== undefined) {
      const settings = await readServiceSettings(serviceSettingsFile);
      environment = { ...environment, ...settings, PHIGON_DATA_DIR: dirname(resolve(serviceSettingsFile)) };
      if (ownEnvironment) {
        // PATH (to find agents) and the proxy variables (for grpc-js) are
        // read from the process itself.
        Object.assign(process.env, settings);
      }
      callerEnvironment = environment;
      trustExtraCertificates(settings["NODE_EXTRA_CA_CERTS"], output);
    }
    environment = command === "update" ? { PHIGON_DATA_DIR:environment["PHIGON_DATA_DIR"] } : await connectionEnvironment(environment, command === "pair" || command === "run" || command === "doctor" ? flags : []);
    // `run` narrows it to the consent stored with the credential.
    let config = loadConfig(
      observabilityEnvironment(command, flags, environment),
    );
    // Every HTTPS call and the telemetry stream go through the proxy that
    // HTTPS_PROXY, HTTP_PROXY and NO_PROXY name, when there is one.
    proxy = useProxyFromEnvironment(callerEnvironment, { streamUrl: config.grpcUrl });
    if (proxy.notice !== undefined) output.stderr(`${proxy.notice}\n`);
    const version = await readVersion();
    const json = flags.includes("--json");
    // The company's code a device management script enrolls with. It never
    // prompts, so it is never offered an update either.
    const enrollmentCode = command === "pair" ? enrollmentCodeFrom(flags, callerEnvironment) : undefined;
    // A background service has a console under conhost on Windows, but nobody
    // reads it: it never prompts.
    const interactive = input === process.stdin && process.stdin.isTTY === true && process.stdout.isTTY === true && !json &&
      serviceSettingsFile === undefined;
    if (command === "update" || (interactive && ((command === "pair" && enrollmentCode === undefined) || command === "run") && environment["PHIGON_UPDATE_CHECK"] !== "false")) {
      const latest = await latestObserverVersion(config.dataDirectory, { force: command === "update" });
      if (command === "update" && (json || flags.includes("--check"))) {
        output.stdout(`${JSON.stringify({ current: version, latest, updateAvailable: latest !== null && newerVersion(version, latest), status: latest === null ? "unavailable" : "checked" })}\n`);
        return latest === null ? 1 : 0;
      }
      if (command === "update" && !interactive && !flags.includes("--yes")) throw new Error("Use update --check for a read-only check, or update --yes to explicitly authorize an unattended update.");
      const updated = await offerObserverUpdate({ current: version, latest, write: output.stdout, confirm: command === "update" && flags.includes("--yes") ? undefined : () => readConfirmation(input) });
      if (updated) {
        const restart = await restartServiceAfterUpdate(config, callerEnvironment, dependencies);
        if (restart === "restarted") output.stdout("The background service now runs the new version.\n");
        if (restart === "failed") output.stdout("Start the background service again to use the new version: phigon-observer service install.\n");
        return 0;
      }
      if (command === "update") {
        output.stdout(latest === null ? "Could not check for updates. Check your connection and try again.\n" : newerVersion(version, latest) ? "Update skipped.\n" : `Observer ${version} is up to date.\n`);
        return latest === null ? 1 : 0;
      }
    }
    const customAgentRegistry = new CustomAgentRegistry(
      config.dataDirectory,
    );

    if (command === "service") {
      return await runServiceCommand(flags, config, callerEnvironment, output, json, dependencies);
    }

    if (command === "guardian") {
      const subcommand = flags[0] ?? "status";
      if (subcommand === "exec") {
        return await runGuardianExec(
          flags.slice(1),
          environment,
          output,
          input,
          config.dataDirectory,
        );
      }
      if (subcommand === "launch") {
        return await runGuardianLaunch(
          flags.slice(1),
          environment,
          output,
          input,
          config.dataDirectory,
        );
      }
      if (subcommand !== "status") {
        throw new Error("Local Guardian controls have been removed. Administrators manage policies and containment in the Phigon app.");
      }
      const credential = await new FileCredentialStore(config.dataDirectory).load();
      const policy = credential ? await new FileActionPolicyStore(config.dataDirectory).load(credential.machineId) : null;
      let nativeRunner = false;
      try { await access(guardianRunnerPath(), constants.X_OK); nativeRunner = true; } catch { /* Missing or non-executable binaries are a coverage gap. */ }
      const status = { enabled: true, decisionAuthority: "control_plane", containmentAuthority: "admin_policy", localOverrides: false,
        paired: credential !== null, policyDelivered: policy !== null, nativeRunner, machineWidePrevention: "not_attested",
        managedExecution: credential && policy && nativeRunner ? "available_requires_online_grant" : "unavailable" };
      output.stdout(json ? `${JSON.stringify(status, null, 2)}\n`
        : `Phigon Guardian: centrally managed.\nManaged execution: ${status.managedExecution}.\nMachine-wide prevention: not verified.\nLocal policy overrides are unavailable.\n`);
      return 0;
    }

    if (command === "authorize-action") {
      const action = parseManagedAction(flagValue(flags, "--action"));
      const resource = flagValue(flags, "--resource");
      const agentID = flagValue(flags, "--agent") ?? "";
      if (agentID !== "") validatedAgentID(agentID);
      const processID = parseOptionalProcessID(flagValue(flags, "--process-id"));
      const processStartedAt = flagValue(flags, "--process-started-at");
      if ((processID === undefined) !== (processStartedAt === undefined)) {
        throw new Error("--process-id and --process-started-at must be supplied together.");
      }
      if (
        processStartedAt !== undefined &&
        !Number.isFinite(Date.parse(processStartedAt))
      ) {
        throw new Error("--process-started-at must be an RFC 3339 timestamp.");
      }
      const context = await readGuardianActionContext(
        flagValue(flags, "--context-file"),
      );
      if (resource === undefined) {
        throw new Error("authorize-action requires --resource <normalized-resource>.");
      }
      const credential = await new FileCredentialStore(
        config.dataDirectory,
      ).load();
      if (credential === null) {
        throw new Error("Observer is not paired; the managed gateway failed closed.");
      }
      if (credential.controlPlaneOrigin !== config.controlPlaneUrl.origin) {
        throw new Error(
          `Stored machine credential belongs to ${credential.controlPlaneOrigin}, ` +
            `but the observer is configured for ${config.controlPlaneUrl.origin}. ` +
            "The managed gateway failed closed.",
        );
      }
      const policy = await new FileActionPolicyStore(
        config.dataDirectory,
      ).load(credential.machineId);
      const started = performance.now();
      let decision: PresentedGuardianDecision = {
        allowed: false,
        outcome: "policy_unavailable",
        action,
        reason: "No delivered policy revision is available; the managed gateway failed closed.",
        agentMessage: "Phigon Guardian blocked this action because its administrator policy is unavailable.",
        decisionSource: "fail_closed",
        intervention: "block_action",
        latencyMs: 0,
      };
      if (policy !== null) {
        try {
          const semantic = await new HTTPGuardianDecisionClient({
            controlPlaneURL: config.controlPlaneUrl,
            credential: credential.credential,
            timeoutMs: config.guardianDecisionTimeoutMs,
          }).decide({
            policyDigest: policy.policyDigest,
            agentId: agentID,
            ...(processID === undefined ? {} : { processId: processID }),
            ...(processStartedAt === undefined ? {} : { processStartedAt }),
            action,
            resource,
            context,
          });
          const allowed = semantic.decision === "allow";
          decision = {
            allowed,
            outcome: allowed
              ? "allowed"
              : semantic.decision === "deny"
                ? "denied"
                : "approval_required",
            action,
            reason: semantic.reason,
            ...(semantic.matchedContractId === undefined
              ? {}
              : { matchedRuleId: semantic.matchedContractId }),
            ...(semantic.adminContract === undefined
              ? {}
              : { adminContract: semantic.adminContract }),
            agentMessage: guardianAgentMessage(
              action,
              allowed,
              semantic.decision === "require_approval",
              semantic.reason,
              semantic.adminContract,
              semantic.approvalState,
            ),
            decisionSource: semantic.model === "policy-gateway" ? "central_policy"
              : semantic.model === "admin-approval" ? "administrator_approval" : "agentic_guardian",
            model: semantic.model,
            risk: semantic.risk,
            confidence: semantic.confidence,
            ...(semantic.intervention === "none"
              ? {}
              : { intervention: semantic.intervention }),
            cached: semantic.cached,
            latencyMs: semantic.latencyMs,
            policyDigest: policy.policyDigest,
            ...(semantic.approvalId === undefined
              ? {}
              : { approvalId: semantic.approvalId }),
            ...(semantic.approvalState === undefined
              ? {}
              : { approvalState: semantic.approvalState }),
            ...(semantic.approvalExpiresAt === undefined
              ? {}
              : { approvalExpiresAt: semantic.approvalExpiresAt }),
          };
        } catch (error) {
          if (!(error instanceof GuardianDecisionUnavailableError)) throw error;
          decision = {
            allowed: false,
            outcome: "guardian_unavailable",
            action,
            reason: "The semantic Guardian could not return a verified decision; the managed gateway failed closed.",
            agentMessage: guardianAgentMessage(
              action,
              false,
              false,
              "The semantic Guardian was unavailable, so Phigon stopped the action instead of guessing.",
            ),
            decisionSource: "fail_closed",
            intervention: "block_action",
            latencyMs: Math.max(0, Math.round(performance.now() - started)),
            policyDigest: policy.policyDigest,
          };
        }
      }
      if (
        !decision.allowed && decision.intervention !== undefined &&
        decision.intervention !== "block_action"
      ) {
        const containment = await new GuardianContainmentExecutor({
          // An owner who refused stopping agents is never overruled.
          enabled: containmentAllowed(credential, environment, config),
          inventory: async () => (await new DiscoveryEngine({
            customAgentRegistry,
          }).discover(credential.machineId)).inventory,
        }).execute({
          intervention: decision.intervention,
          agentId: agentID,
          ...(processID === undefined ? {} : { processId: processID }),
          ...(processStartedAt === undefined
            ? {}
            : { expectedStartedAt: processStartedAt }),
        });
        decision = Object.freeze({
          ...decision,
          containment,
          agentMessage: `${decision.agentMessage} Containment: ${containment.detail}`,
        });
      }
      await new GuardianDecisionJournal(config.dataDirectory).append({
        agentId: agentID,
        action,
        resource,
        outcome: decision.outcome,
        reason: decision.reason,
        decisionSource: decision.decisionSource,
        latencyMs: decision.latencyMs,
        context,
        ...(decision.adminContract === undefined
          ? {}
          : { adminContract: decision.adminContract }),
        ...(decision.model === undefined ? {} : { model: decision.model }),
        ...(decision.risk === undefined ? {} : { risk: decision.risk }),
        ...(decision.confidence === undefined
          ? {}
          : { confidence: decision.confidence }),
        ...(decision.policyDigest === undefined
          ? {}
          : { policyDigest: decision.policyDigest }),
        ...(decision.intervention === undefined
          ? {}
          : { intervention: decision.intervention }),
        ...(decision.containment === undefined
          ? {}
          : { containment: decision.containment }),
        ...(decision.approvalId === undefined
          ? {}
          : { approvalId: decision.approvalId }),
        ...(decision.approvalState === undefined
          ? {}
          : { approvalState: decision.approvalState }),
        ...(decision.approvalExpiresAt === undefined
          ? {}
          : { approvalExpiresAt: decision.approvalExpiresAt }),
      });
      output.stdout(
        json
          ? `${JSON.stringify(decision, null, 2)}\n`
          : [
              `Decision: ${decision.outcome}`,
              `Action: ${decision.action}`,
              `Message for agent: ${decision.agentMessage}`,
              `Reason: ${decision.reason}`,
              ...(decision.adminContract === undefined
                ? []
                : [`Admin contract: ${decision.adminContract}`]),
              `Decision source: ${decision.decisionSource}${decision.model ? ` (${decision.model})` : ""}`,
              `Latency: ${decision.latencyMs}ms`,
              ...(decision.intervention === undefined
                ? []
                : [`Authorized intervention: ${decision.intervention}`]),
              ...(decision.containment === undefined
                ? []
                : [`Containment: ${decision.containment.state} (${decision.containment.code}) — ${decision.containment.detail}`]),
              ...(decision.matchedRuleId === undefined
                ? []
                : [`Matched rule: ${decision.matchedRuleId}`]),
              ...(decision.approvalId === undefined
                ? []
                : [`Approval: ${decision.approvalId} (${decision.approvalState ?? "pending"})`]),
              ...(decision.approvalExpiresAt === undefined
                ? []
                : [`Approval expires: ${decision.approvalExpiresAt}`]),
              "Boundary: Phigon-managed gateway only",
              "",
            ].join("\n"),
      );
      return decision.allowed ? 0 : 77;
    }

    if (command === "agent") {
      return await runAgentCommand(
        flags,
        customAgentRegistry,
        json,
        output,
        input,
      );
    }

    if (command === "ingest") {
      const agent = flagValue(flags, "--agent");
      if (agent === undefined) {
        throw new Error("ingest requires --agent <agent-id>.");
      }
      const agentName = flagValue(flags, "--name");
      const result = await ingestActivityJSONL({
        agent,
        ...(agentName === undefined ? {} : { agentName }),
        dataDirectory: config.dataDirectory,
        input,
      });
      if (!flags.includes("--quiet")) {
        output.stdout(
          json
            ? `${JSON.stringify(result, null, 2)}\n`
            : [
                `Activity bridge: ${result.agent}`,
                ...(result.agentName === undefined
                  ? []
                  : [`Agent name: ${result.agentName}`]),
                `Accepted records: ${result.records}`,
                `Rejected malformed records: ${result.malformed}`,
                `Rejected oversized records: ${result.oversized}`,
                "",
              ].join("\n"),
        );
      }
      return result.records > 0 ? 0 : 1;
    }

    if (command === "remove-machine" || command === "unpair") {
      if (flags.includes("--purge")) {
        return await removeMachineAndPurge(config, callerEnvironment, flags, json, output, input, dependencies);
      }
      const credentialStore = new FileCredentialStore(config.dataDirectory);
      const credential = await credentialStore.load();
      if (credential === null) {
        throw new Error("Observer is not paired; there is no machine to remove.");
      }
      if (json && !flags.includes("--yes")) {
        throw new Error(
          "JSON machine removal requires --yes after reviewing the removal scope.",
        );
      }
      // A running observer would keep writing the queue this removes, then
      // stop as unpaired and be restarted by its service over and over.
      let removalLock: InstanceLock;
      try {
        removalLock = await InstanceLock.acquire(config.dataDirectory);
      } catch (error) {
        if (!(error instanceof ObserverAlreadyRunningError)) throw error;
        throw new Error(
          "A Phigon observer is running with this data directory. Stop it, " +
            "or stop its service (phigon-observer service uninstall), and then " +
            "run remove-machine again; remove-machine --purge stops the service " +
            "itself. No request was sent.",
        );
      }
      let result: Awaited<ReturnType<typeof removeMachine>>;
      try {
        if (!flags.includes("--yes")) {
          output.stdout(removeMachinePrompt(credential.machineId));
          const confirmed = await readConfirmation(input);
          if (confirmed !== "remove") {
            throw new Error(
              "Machine removal was not confirmed. No request was sent.",
            );
          }
        }
        result = await removeMachine({
          config,
          credential,
          clearCredential: async () => {
            clearEventSpool(config.dataDirectory);
            await forgetServerAuthority(config.dataDirectory);
            return await credentialStore.clear();
          },
        });
      } finally {
        await removalLock.release();
      }
      // A background service left behind would start the unpaired observer
      // again every minute, for good. Its collected activity is not touched.
      let serviceRemoved = false;
      try {
        serviceRemoved = await uninstallService(serviceContext(config, callerEnvironment, dependencies));
      } catch {
        // No service on this computer, or it could not be asked: nothing runs from here.
      }
      output.stdout(
        json
          ? `${JSON.stringify({ ...result, backgroundServiceRemoved: serviceRemoved }, null, 2)}\n`
          : formatRemoveMachineResult(result, serviceRemoved),
      );
      return 0;
    }

    if (command === "discover") {
      const storedCredential = await new FileCredentialStore(
        config.dataDirectory,
      ).load();
      const snapshot = await new DiscoveryEngine({
        customAgentRegistry,
      }).discover(
        storedCredential?.machineId ?? "",
      );
      output.stdout(
        json
          ? formatDiscoveryJSON(snapshot)
          : formatDiscovery(snapshot),
      );
      return 0;
    }

    if (command === "run") {
      const controller = new AbortController();
      const stop = () => controller.abort();
      process.once("SIGINT", stop);
      process.once("SIGTERM", stop);
      // On Windows the service runs the observer under conhost, and ending
      // the scheduled task ends only conhost; stop with it.
      // A service's console can disappear before the observer has stopped;
      // writing to it must not end the process, the log keeps the message.
      const ignoreConsoleError = () => undefined;
      if (serviceSettingsFile !== undefined) {
        process.stdout.on("error", ignoreConsoleError);
        process.stderr.on("error", ignoreConsoleError);
      }
      const stopWatchingParent = serviceSettingsFile !== undefined && process.platform === "win32"
        ? watchParentProcess(process.ppid, () => {
          output.stdout("The background service stopped, so the observer stops too.\n");
          controller.abort();
        })
        : undefined;
      let instanceLock: InstanceLock | undefined;
      let pairingWatch: PairingWatch | undefined;
      try {
        const credential = await new FileCredentialStore(
          config.dataDirectory,
        ).load();
        if (credential === null) {
          throw new Error("Observer is not paired. Run the pair command first.");
        }
        if (
          credential.controlPlaneOrigin !== config.controlPlaneUrl.origin
        ) {
          throw new Error(
            `Stored machine credential belongs to ${credential.controlPlaneOrigin}, ` +
              `but the observer is configured for ${config.controlPlaneUrl.origin}. ` +
              "Refusing to send the credential to a different control plane.",
          );
        }
        if (
          credential.consentPolicyVersion !== OBSERVER_CONSENT_POLICY_VERSION ||
          credential.consentProfile === undefined
        ) {
          throw new Error(
            "Current machine-owner consent is missing. Pair again with an explicit consent profile before starting collection.",
          );
        }
        if (
          config.observabilityProfile === "full" &&
          credential.consentProfile !== "full"
        ) {
          // Consent caps the profile; refusing would only have a background
          // service start again every minute, collecting nothing. Content
          // settings are switched off with the full profile.
          config = loadConfig({
            ...observabilityEnvironment(command, flags, environment),
            PHIGON_OBSERVABILITY_PROFILE: "metadata",
          });
          output.stdout(
            "This computer's consent covers agent metadata only, so the observer collects metadata instead of the full profile it was started with. " +
              "To keep it that way, run phigon-observer service install --profile metadata; to share everything, pair again with --consent-profile full.\n",
          );
        } else if (config.contentSettingsOutsideProfile.length > 0) {
          throw new Error(
            contentOutsideProfileMessage(config.contentSettingsOutsideProfile),
          );
        }
        // Before any queued activity, cursor or saved state is read. A
        // signal only aborts the tasks, so `finally` releases the lock.
        instanceLock = await InstanceLock.acquire(config.dataDirectory);
        logged?.debug(
          `Observer ${version} started for machine ${credential.machineId} ` +
            `with the ${config.observabilityProfile} profile, using ${config.dataDirectory}.\n`,
        );
        // A computer the workspace removed stops here, before any agent scan,
        // so a background service that keeps starting it costs next to
        // nothing. The service asks the server again once an hour.
        const removed = await removedAtStart({
          dataDirectory: config.dataDirectory,
          machine: credential,
          controlPlaneUrl: config.controlPlaneUrl,
          recheckAfterMs: serviceSettingsFile === undefined ? 0 : removedRecheckMs,
        });
        if (removed !== "start") {
          if (removed === "removed") output.stderr(`${machineRemovedMessage}\n`);
          return removedExitCode(serviceSettingsFile !== undefined);
        }
        let effectivePolicy = intersectCollectionPolicy(
          config.policy,
          credential.consentProfile,
        );
        let collector: ActivityCollector | undefined;
        let resolveCollector: ((value: ActivityCollector) => void) | undefined;
        const collectorReady = new Promise<ActivityCollector>((resolve) => {
          resolveCollector = resolve;
        });
        let fatalPersistenceError: Error | undefined;
        // Pairing again while this runs, for example with narrower consent,
        // stops it at once; its service starts it again with the new pairing.
        let pairingChange: PairingChange | undefined;
        pairingWatch = watchPairing({
          dataDirectory: config.dataDirectory,
          current: credential,
          onChange: (change) => {
            pairingChange = change;
            // Nothing more is collected under the earlier pairing, not even
            // by a pass already under way.
            collector?.updatePolicy(intersectCollectionPolicy(config.policy, "metadata"));
            controller.abort();
          },
        });
        const discoveryEngine = new DiscoveryEngine({
          customAgentRegistry,
        });
        const userNotices = new UserNotices({ enabled: config.userNotices });
        const serverClock = new ServerClock({
          onLargeSkew: (offsetMs) => output.stdout(`${describeClockSkew(offsetMs)}\n`),
        });
        // What administrators may do here: what was consented to at pairing,
        // unless the observer's settings say otherwise.
        const allowed = remoteActionsAllowed(credential, environment, config);
        const actionExecutor = new AgentActionExecutor({
          notices: userNotices,
          enabled: allowed.stopAgents,
          commandsEnabled: allowed.commands,
          machineID: credential.machineId,
          dataDirectory: config.dataDirectory,
          inventory: async () =>
            (await discoveryEngine.discover(credential.machineId)).inventory,
          serverNow: () => serverClock.now(),
        });
        const client = new ObserverStreamClient({
          config,
          containmentEnabled: containmentAllowed(credential, environment, config),
          actionExecutor,
          serverClock,
          observerVersion: version,
          onHistorySync: async (syncCommand) => {
            const rejected = (detail: string) => create(HistorySyncResultSchema, {
              jobId: syncCommand.jobId,
              machineId: credential.machineId,
              idempotencyKey: syncCommand.idempotencyKey,
              state: HistorySyncResultState.REJECTED,
              detail,
              observedAt: timestampFromDate(new Date()),
            });
            if (
              syncCommand.machineId !== credential.machineId ||
              syncCommand.expiresAt === undefined
            ) {
              return rejected("History sync command identity or expiry is invalid.");
            }
            if (
              config.observabilityProfile !== "full" ||
              credential.consentProfile !== "full"
            ) {
              return rejected(
                "Machine-owner full-activity consent is required before history can be uploaded.",
              );
            }
            if (!fullHistoryPolicyEnabled(effectivePolicy)) {
              return rejected(
                "Workspace collection policy does not allow readable prompts, replies, and tool activity.",
              );
            }
            const expiresAt = timestampDate(syncCommand.expiresAt).getTime();
            const remainingMs = expiresAt - serverClock.now();
            if (!Number.isFinite(remainingMs) || remainingMs <= 0) {
              return rejected("History sync command expired before execution.");
            }
            const activeCollector = collector ?? await collectorReady;
            const summary = await activeCollector.syncHistory(
              AbortSignal.timeout(Math.max(1, remainingMs)),
            );
            return create(HistorySyncResultSchema, {
              jobId: syncCommand.jobId,
              machineId: credential.machineId,
              idempotencyKey: syncCommand.idempotencyKey,
              state: HistorySyncResultState.SUCCEEDED,
              filesDiscovered: Math.min(summary.filesDiscovered, 0xffff_ffff),
              recordsScanned: BigInt(summary.recordsScanned),
              eventsUploaded: BigInt(summary.eventsUploaded),
              throughSequence: summary.throughSequence,
              detail: summary.recordsScanned === 0
                ? "All supported history was already synchronized."
                : "All supported history was queued and acknowledged by the control plane.",
              observedAt: timestampFromDate(new Date()),
            });
          },
          onStatus: (message) => output.stdout(`${message}\n`),
          onPolicy: (policy) => {
            if (pairingChange !== undefined) return;
            effectivePolicy = intersectCollectionPolicy(
              config.policy,
              credential.consentProfile,
              policy,
            );
            collector?.updatePolicy(effectivePolicy);
          },
          onCursorReset: (
            acknowledgedSequence,
            allocationSequence,
          ) => {
            collector?.resetSequence(
              acknowledgedSequence,
              allocationSequence,
            );
          },
          onAcknowledgement: (sequence) => {
            const activeCollector = collector;
            if (activeCollector === undefined) return;
            return activeCollector.acknowledge(sequence).catch(
              (error: unknown) => {
                fatalPersistenceError = error instanceof Error
                  ? error
                  : new Error(String(error));
                output.stderr(
                  `Unable to persist acknowledged activity source state: ${
                    fatalPersistenceError.message
                  }\n`,
                );
                controller.abort();
                throw fatalPersistenceError;
              },
            );
          },
        });
        const historicalStore = new HistoricalIdentityStore(
          config.dataDirectory,
          {
            tenantId: credential.tenantId,
            machineId: credential.machineId,
          },
          {
            onSaveError: (error) => output.stderr(
              `Saved agent identities could not be written (${
                (error instanceof Error ? error.message : String(error))
                  .replace(/\s+/gu, " ")
                  .slice(0, 200)
              }); retrying on the next pass.\n`,
            ),
          },
        );
        let historicalIdentities = await historicalStore.load();
        const initialDiscovery = await discoveryEngine.discover(
          credential.machineId,
        );
        historicalIdentities = await historicalStore.remember(
          initialDiscovery.inventory.agents,
        );
        let latestDiscoveryInventory = initialDiscovery.inventory;
        actionExecutor.observeInventory(latestDiscoveryInventory);
        const publishInventory = () => {
          const withHistory = mergeInventoryWithHistoricalIdentities(
            latestDiscoveryInventory,
            historicalIdentities,
          );
          client.updateInventory(mergeInventoryWithSourceIdentities(
            withHistory,
            collector?.sourceIdentities() ?? [],
          ));
        };
        publishInventory();
        output.stdout("Starting Phigon observer telemetry.\n");
        const streaming = client.run(controller.signal);
        const discovering = runDiscoveryLoop(
          discoveryEngine,
          credential.machineId,
          config.discoveryIntervalMs,
          controller.signal,
          async (inventory) => {
            latestDiscoveryInventory = inventory;
            actionExecutor.observeInventory(inventory);
            collector?.updateInventory(inventory);
            historicalIdentities = await historicalStore.remember(
              inventory.agents,
            );
            publishInventory();
          },
          (error) => output.stderr(
            `Agent discovery failed and will retry on the next pass: ${
              (error instanceof Error ? error.message : String(error))
                .replace(/\s+/gu, " ")
                .slice(0, 200)
            }\n`,
          ),
        );
        const processMonitor = new GuardianProcessMonitor({
          coverageClient: new GuardianHostedClient({ controlPlaneURL: config.controlPlaneUrl, credential: credential.credential }),
          machineId: credential.machineId,
          policyStore: new FileActionPolicyStore(config.dataDirectory),
          decisionClient: new HTTPGuardianDecisionClient({
            controlPlaneURL: config.controlPlaneUrl,
            credential: credential.credential,
            timeoutMs: config.guardianDecisionTimeoutMs,
          }),
          containment: new GuardianContainmentExecutor({
            enabled: containmentAllowed(credential, environment, config),
            inventory: async () => (await discoveryEngine.discover(credential.machineId)).inventory,
          }),
          journal: new GuardianDecisionJournal(config.dataDirectory),
          notices: userNotices,
          onStatus: (message) => output.stdout(`${message}\n`),
        });
        // Being stopped before the stream first connects is a normal stop.
        const streamReady = async (): Promise<bigint | undefined> => {
          try {
            return await client.waitUntilReady(controller.signal);
          } catch (error) {
            if (controller.signal.aborted) return undefined;
            throw error;
          }
        };
        const monitoring = (async () => {
          if (await streamReady() === undefined) return;
          // Said once when it starts failing, not on every pass.
          let policyUnreadable = false;
          while (!controller.signal.aborted) {
            try {
              await processMonitor.review(latestDiscoveryInventory, controller.signal);
              policyUnreadable = false;
            } catch {
              if (!policyUnreadable) output.stderr("Guardian process monitoring could not read verified policy state.\n");
              policyUnreadable = true;
            }
            try { await delay(config.discoveryIntervalMs, undefined, { signal: controller.signal }); }
            catch { break; }
          }
        })();
        const collecting = (async () => {
          const allocationSequence = await streamReady();
          if (allocationSequence === undefined) return;
          // Collection starts now. Where the company consented, tell the
          // person at the computer; a notice never holds collection up.
          void announceCompanyCollection({
            dataDirectory: config.dataDirectory,
            credential,
            profile: config.observabilityProfile,
            notices: userNotices,
          }).then((outcome) => {
            if (outcome === "shown") output.stdout("Told the person at this computer that Phigon is recording AI agent activity.\n");
          }, () => output.stderr("The start-of-collection notice could not be remembered; it is shown again on the next start.\n"));
          collector = new ActivityCollector({
            config,
            credential,
            initialSequence: allocationSequence,
            initialAcknowledgedSequence:
              client.metrics().lastAcknowledgedSequence,
            durableDelivery: true,
            flushDelivery: () => client.flush(),
            policy: effectivePolicy,
            emit: (event) => client.enqueue(event),
            // The spool also has a byte budget; reaching it fails delivery
            // instead of waiting, so both stop well before it.
            canCollect: () => {
              const queue = client.metrics().queue;
              return (
                hasByteHeadroom(queue) &&
                queue.capacity - queue.depth >=
                Math.max(32, config.activityRateLimitPerMinute)
              );
            },
            canSyncHistory: () => {
              const queue = client.metrics().queue;
              return hasByteHeadroom(queue) &&
                queue.capacity - queue.depth >= Math.min(queue.capacity, historySyncQueueHeadroom);
            },
            onDeliveryRefused: (error) => output.stderr(
              `Telemetry delivery is paused (${
                (error instanceof Error ? error.message : String(error))
                  .replace(/\s+/gu, " ")
                  .slice(0, 200)
              }). Collection resumes from the same records once queued events are acknowledged.\n`,
            ),
            onSourceFailure: (failure) => output.stderr(
              `Activity source ${failure.adapterId} could not be read (${failure.message}). ` +
                "It is retried shortly; other sources keep collecting.\n",
            ),
            additionalSources: async () =>
              registeredAgentActivitySources(
                await customAgentRegistry.list(),
              ),
            onSourceIdentity: async (identity) => {
              // Make the source target addressable immediately, then durably
              // record only its sanitized inventory metadata.
              publishInventory();
              historicalIdentities = await historicalStore.remember([
                identity,
              ]);
              publishInventory();
            },
          });
          resolveCollector?.(collector);
          resolveCollector = undefined;
          collector.updateInventory(latestDiscoveryInventory);
          publishInventory();
          const historyCollector = collector;
          const initialHistory = async () => {
            if (config.observabilityProfile !== "full" || credential.consentProfile !== "full") return;
            // Said once: a workspace that keeps a category off would
            // otherwise repeat it every 30 seconds for good.
            let waitingSaid = false;
            while (!controller.signal.aborted) {
              if (!fullHistoryPolicyEnabled(effectivePolicy)) {
                if (!waitingSaid) output.stdout("Saved-history sync waits until the workspace allows every kind of full activity. Live collection remains active.\n");
                waitingSaid = true;
              } else {
                try {
                  output.stdout("Synchronizing saved agent history in the background. Live collection remains active.\n");
                  const summary = await historyCollector.syncHistory(controller.signal);
                  output.stdout(`History scan complete: ${summary.recordsScanned} records scanned, ${summary.eventsUploaded} events queued for server delivery.\n`);
                  return;
                } catch {
                  if (controller.signal.aborted) return;
                  output.stderr("Saved-history sync was interrupted. It will retry from its durable cursor.\n");
                }
              }
              try { await delay(30_000, undefined, { signal: controller.signal }); } catch { return; }
            }
          };
          await Promise.all([collector.run(controller.signal), initialHistory()]);
        })();
        const maintaining = (async () => {
          while (!controller.signal.aborted) {
            try { await actionExecutor.maintainReceipts(); }
            catch { output.stderr("Local operation receipt cleanup will retry.\n"); }
            try { await delay(3_600_000, undefined, { signal: controller.signal }); }
            catch { break; }
          }
        })();
        // A background service follows the Phigon app's server when its
        // computer gets a new address; the pairing watch then restarts it.
        const following = serviceSettingsFile === undefined ? Promise.resolve() : followServer({
          dataDirectory: config.dataDirectory,
          credential,
          signal: controller.signal,
          proxyFor: (url) => proxyForUrl(url, proxySettings(callerEnvironment)),
          onMoved: async (moved) => {
            try {
              return await saveMovedServer(config.dataDirectory, credential, moved);
            } catch {
              output.stderr(`Phigon's server now answers at ${moved.controlPlaneOrigin}, but the new address could not be saved. The observer tries again in a few minutes.\n`);
              return false;
            }
          },
        }).catch(() => undefined);
        let removedWhileRunning = false;
        try {
          await settleObserverTasks(
            [streaming, discovering, collecting, monitoring, maintaining, following],
            controller,
            () => fatalPersistenceError,
          );
        } catch (error) {
          // The stream can see the new pairing first, as endpoints that no
          // longer match or a key the workspace no longer accepts; the
          // change is the reason to stop.
          pairingChange ??= await pairingWatch.check().catch(() => undefined);
          if (pairingChange === undefined) {
            if (!(error instanceof MachineRemovedError)) throw error;
            removedWhileRunning = true;
          }
        } finally {
          // Write what the spool still buffers. Nothing depends on it:
          // checkpoints only moved past written events, and a lost
          // acknowledgement only sends an event again.
          try { client.flush(); } catch { /* Read again on the next start. */ }
        }
        if (removedWhileRunning) {
          // The stream's refusal is confirmed with the server before the
          // observer stops for good; until then a service starts it again.
          // Without the file the next start scans and fails again; it is
          // only slower, so a failed write does not change the outcome.
          await rememberMachineRemoved(config.dataDirectory, credential).catch(() => undefined);
          const confirmed = await removedAtStart({
            dataDirectory: config.dataDirectory,
            machine: credential,
            controlPlaneUrl: config.controlPlaneUrl,
            recheckAfterMs: 0,
          }).catch(() => "start" as const) === "removed";
          // Pairing again just as the old key was refused restarts instead.
          pairingChange ??= await pairingWatch.check().catch(() => undefined);
          if (pairingChange === undefined) {
            if (!confirmed) {
              output.stderr("Phigon's server refused this computer's key but did not confirm that the computer was removed. The observer stops and starts again to check.\n");
              return 1;
            }
            output.stderr(`${machineRemovedMessage}\n`);
            return removedExitCode(serviceSettingsFile !== undefined);
          }
        }
        if (pairingChange !== undefined) {
          output.stdout(`${pairingChange.message}\n`);
          return pairingChangedExitCode;
        }
        output.stdout("Observer stopped.\n");
      } finally {
        pairingWatch?.stop();
        process.removeListener("SIGINT", stop);
        process.removeListener("SIGTERM", stop);
        stopWatchingParent?.();
        process.stdout.removeListener("error", ignoreConsoleError);
        process.stderr.removeListener("error", ignoreConsoleError);
        await instanceLock?.release();
      }
      return 0;
    }

    if (command === "pair" && enrollmentCode !== undefined) {
      if (config.controlPlaneUrl.origin !== DEFAULT_CONTROL_PLANE_ORIGIN && !config.grpcEndpointConfigured) {
        throw new Error("Custom workspaces require --grpc-url alongside --control-plane-url (or PHIGON_GRPC_URL). Copy both endpoints from your workspace's Connect machine dialog.");
      }
      return await enrollWithCode(enrollmentCode, flags, config, callerEnvironment, json, version, output);
    }

    if (command === "pair") {
      if (config.controlPlaneUrl.origin !== DEFAULT_CONTROL_PLANE_ORIGIN && !config.grpcEndpointConfigured) {
        throw new Error("Custom workspaces require --grpc-url alongside --control-plane-url (or PHIGON_GRPC_URL). Copy both endpoints from your workspace's Connect machine dialog.");
      }
      const code = flagValue(flags, "--code");
      if (code === undefined) {
        throw new Error("pair requires --code <one-time-code>.");
      }
      const displayName = flagValue(flags, "--name");
      const consentProfile = parseConsentProfile(
        flagValue(flags, "--consent-profile"),
      );
      const authorityFlag = flagValue(flags, "--server-ca-sha256");
      const authority = authorityFlag === undefined ? undefined : parseAuthorityFingerprint(authorityFlag);
      // Pairing also keeps the observer running in the background, unless
      // whoever runs it keeps it running another way.
      const background = !flags.includes("--no-service");
      // The owner also agrees to what the company's administrators may do here.
      const remoteActions = remoteActionConsent(flags);
      if (json && !flags.includes("--accept-consent")) {
        throw new Error(
          "JSON pairing requires --accept-consent after reviewing the selected profile.",
        );
      }
      if (!flags.includes("--accept-consent")) {
        output.stdout(consentPrompt(consentProfile, background, remoteActions));
        const confirmed = await readConfirmation(input);
        if (confirmed !== "yes") {
          throw new Error("Consent was not granted. No pairing request was sent.");
        }
      }
      const pairingAuthority = await preparePairingAuthority({
        config,
        fingerprint: authority,
        proxy: proxyForUrl(config.controlPlaneUrl, proxySettings(callerEnvironment)),
      });
      const credentialStore = new FileCredentialStore(config.dataDirectory);
      const before = await credentialStore.load();
      const observerRunning = (await InstanceLock.inspect(config.dataDirectory)).running;
      const result = await pairMachine({
        config,
        code,
        consentProfile,
        remoteActions,
        serverMoved: pairingAuthority.serverMoved,
        ...(displayName === undefined ? {} : { displayName }),
      });
      await pairingAuthority.commit();
      await followServiceEndpoints(config, before);
      // A running observer stops for the new pairing within a second.
      const restarts = observerRunning && before !== null && pairingChanged(before, await credentialStore.load());
      const service = background
        ? await installServiceAfterPairing(
          loadConfig({ ...environment, PHIGON_OBSERVABILITY_PROFILE: consentProfile }),
          callerEnvironment,
          dependencies,
        )
        : undefined;
      output.stdout(
        json
          ? `${JSON.stringify({
            ...result,
            remoteActions,
            ...(restarts ? { runningObserverRestarts: true } : {}),
            ...(service === undefined ? {} : { backgroundService: service }),
          }, null, 2)}\n`
          : formatPairResult(result, restarts, service, consentProfile, remoteActions),
      );
      return 0;
    }

    if (flags.includes("--check")) {
      const report = await runDoctorCheck({
        config,
        observerVersion: version,
        maxDeliveryAgeMinutes: parseMaxDeliveryAge(flagValue(flags, "--max-delivery-age")),
      });
      output.stdout(json ? `${JSON.stringify(report, null, 2)}\n` : formatDoctorCheck(report));
      return report.exitCode;
    }
    const storedCredential = await new FileCredentialStore(
      config.dataDirectory,
    ).load();
    let streamCursor: ObserverStreamCursorHealth | undefined;
    let streamCursorIssue: string | undefined;
    if (storedCredential !== null) {
      try {
        const state = await new StreamStateStore(config.dataDirectory).load(
          storedCredential.machineId,
        );
        streamCursor = {
          machineId: state.machineId,
          acknowledgedSequence: state.acknowledgedSequence.toString(),
          updatedAt: state.updatedAt,
        };
      } catch {
        streamCursorIssue = "Stored stream cursor could not be read.";
      }
    }
    // Report what the background service collects, not this terminal's
    // default: the service's profile, narrowed to the consent as `run` does.
    let shown = config;
    if (flagValue(flags, "--profile") === undefined && (environment["PHIGON_OBSERVABILITY_PROFILE"]?.trim() ?? "") === "") {
      const serviceProfile = (await readServiceSettings(serviceSettingsPath(config.dataDirectory)).catch(() => undefined))?.["PHIGON_OBSERVABILITY_PROFILE"];
      const profile = serviceProfile === "full" && storedCredential?.consentProfile === "full" ? "full" : serviceProfile === undefined ? undefined : "metadata";
      if (profile !== undefined && profile !== config.observabilityProfile) {
        shown = loadConfig({ ...environment, PHIGON_OBSERVABILITY_PROFILE: profile });
      }
    }
    const health = createHealthSnapshot(
      {
        ...shown,
        machineTokenConfigured:
          config.machineTokenConfigured || storedCredential !== null,
      },
      version,
      new Date(),
      streamCursor,
      streamCursorIssue,
      storedCredential === null ? undefined : consentHealth(storedCredential),
    );
    output.stdout(
      json ? `${JSON.stringify(health, null, 2)}\n` : formatHealth(health),
    );
    return 0;
  } catch (error) {
    const message = error instanceof Error ? error.message : "Unknown error.";
    (logged?.error ?? output.stderr)(`Observer command failed: ${message}\n`);
    if (error instanceof EnrollmentError) {
      if (flags.includes("--json")) {
        output.stdout(`${JSON.stringify({
          enrolled: false,
          error: { code: error.code, message: error.message },
          exitCode: error.exitCode,
        }, null, 2)}\n`);
      }
      return error.exitCode;
    }
    return 1;
  } finally {
    proxy?.restore();
  }
}

/**
 * The enrollment code from --enrollment-code or PHIGON_ENROLLMENT_CODE, or
 * undefined for an owner's pairing. The value is never repeated in errors.
 */
function enrollmentCodeFrom(flags: readonly string[], environment: NodeJS.ProcessEnv): string | undefined {
  const flagGiven = flags.some((flag) => flag === "--enrollment-code" || flag.startsWith("--enrollment-code="));
  const fromFlag = flagValue(flags, "--enrollment-code");
  if (flagGiven && (fromFlag === undefined || fromFlag.trim() === "")) {
    throw new Error(`--enrollment-code needs the code. Device management scripts should set ${enrollmentCodeVariable} instead, which keeps it out of process lists.`);
  }
  const fromEnvironment = environment[enrollmentCodeVariable]?.trim() || undefined;
  const code = fromFlag ?? fromEnvironment;
  if (code === undefined) return undefined;
  if (flags.some((flag) => flag === "--code" || flag.startsWith("--code="))) {
    throw new Error(`Use either --code with a one-time pairing code, or an enrollment code (--enrollment-code or ${enrollmentCodeVariable}), not both.`);
  }
  if (flags.some((flag) => flag === "--accept-consent" || flag === "--consent-profile" || flag.startsWith("--consent-profile="))) {
    throw new Error("With an enrollment code your company has chosen the collection profile and given consent. Remove --consent-profile and --accept-consent.");
  }
  return code;
}

/**
 * `pair` with an enrollment code: no prompt, the company's consent, and a
 * distinct exit code for each failure a device management script can act on.
 */
async function enrollWithCode(
  code: string,
  flags: readonly string[],
  config: ObserverConfig,
  environment: NodeJS.ProcessEnv,
  json: boolean,
  version: string,
  output: Output,
): Promise<number> {
  // Checked before anything is pinned or sent.
  const enrollmentCode = checkedEnrollmentCode(code);
  const displayName = flagValue(flags, "--name");
  const authorityFlag = flagValue(flags, "--server-ca-sha256");
  const authority = authorityFlag === undefined ? undefined : parseAuthorityFingerprint(authorityFlag);
  const pairingAuthority = await preparePairingAuthority({
    config,
    fingerprint: authority,
    proxy: proxyForUrl(config.controlPlaneUrl, proxySettings(environment)),
  });
  const before = await new FileCredentialStore(config.dataDirectory).load();
  const result = await enrollMachine({
    config,
    code: enrollmentCode,
    observerVersion: version,
    remoteActions: remoteActionConsent(flags),
    serverMoved: pairingAuthority.serverMoved,
    ...(displayName === undefined ? {} : { displayName }),
    onRetry: (waitMs) => output.stderr(
      `The Phigon server is busy. Trying again in ${Math.ceil(waitMs / 1_000)} seconds.\n`,
    ),
  });
  await pairingAuthority.commit();
  await followServiceEndpoints(config, before);
  const warning = config.observabilityProfile === "full" && result.consent.profile !== "full"
    ? "Your company's code covers the metadata profile only, so the observer collects metadata even with PHIGON_OBSERVABILITY_PROFILE=full. Ask your company for a full-activity code to change it."
    : undefined;
  if (warning !== undefined) output.stderr(`${warning}\n`);
  const remoteActions = remoteActionConsent(flags);
  output.stdout(json ? `${JSON.stringify({ enrolled: true, ...result, remoteActions }, null, 2)}\n` : formatEnrollResult(result, remoteActions));
  return 0;
}

/**
 * After a pairing at a new address, points the background service's saved
 * endpoints there too, when they named the address this computer used.
 */
async function followServiceEndpoints(
  config: ObserverConfig,
  before: StoredMachineCredential | null,
): Promise<void> {
  if (before === null || before.controlPlaneOrigin === config.controlPlaneUrl.origin) return;
  try {
    await moveServiceEndpoints(config.dataDirectory, {
      PHIGON_CONTROL_PLANE_URL: { from: before.controlPlaneOrigin, to: config.controlPlaneUrl.origin },
      PHIGON_GRPC_URL: { from: before.grpcOrigin, to: config.grpcUrl.origin },
    });
  } catch {
    throw new Error("This computer is paired at the new address, but its background service settings could not be updated. Run phigon-observer service install again.");
  }
}

function formatEnrollResult(result: EnrollResult, remoteActions: RemoteActionConsent): string {
  return [
    "Computer enrolled.",
    `Machine: ${result.displayName} (${result.machineId})`,
    `Control plane: ${result.controlPlaneOrigin}`,
    `Consent: given by your company${result.consent.enrollmentCodeLabel === undefined ? "" : ` with the enrollment code "${result.consent.enrollmentCodeLabel}"`}, ${result.consent.profile} profile`,
    remoteActionSentence(remoteActions),
    "Machine credential: stored securely",
    ...(result.previousControlPlaneOrigin === undefined || result.replacedMachineId !== undefined
      ? []
      : [`Earlier address: ${result.previousControlPlaneOrigin}. Activity this computer had not delivered yet is sent to the new address.`]),
    ...(result.replacedMachineId === undefined
      ? []
      : [
          `Earlier machine: ${result.replacedMachineId} (the workspace no longer accepted its key)`,
          "This computer was enrolled as a new machine. Activity the earlier machine had not delivered was moved to the retired-pairings folder in the data directory.",
        ]),
    "Next step: phigon-observer service install",
    "",
  ].join("\n");
}

type PresentedGuardianDecision = Readonly<{
  allowed: boolean;
  outcome: string;
  action: ManagedActionName;
  reason: string;
  agentMessage: string;
  decisionSource: string;
  latencyMs: number;
  policyDigest?: string;
  matchedRuleId?: string;
  adminContract?: string;
  model?: string;
  risk?: string;
  confidence?: number;
  cached?: boolean;
  intervention?: GuardianIntervention;
  containment?: GuardianContainmentResult;
  approvalId?: string;
  approvalState?: "pending" | "approved" | "rejected" | "consumed" | "expired";
  approvalExpiresAt?: string;
}>;

function guardianAgentMessage(
  action: ManagedActionName,
  allowed: boolean,
  approvalRequired: boolean,
  reason: string,
  adminContract?: string,
  approvalState?: "pending" | "approved" | "rejected" | "consumed" | "expired",
): string {
  const operation = action.replace(".", " ");
  if (allowed) {
    return approvalState === "consumed"
      ? `${operation} allowed by a one-time Phigon administrator approval.`
      : `${operation} allowed by Phigon Guardian.`;
  }
  const result = !approvalRequired
    ? `${operation} blocked by Phigon Guardian.`
    : approvalState === "rejected"
      ? `${operation} blocked because an administrator rejected the exact proposal.`
      : approvalState === "consumed"
        ? `${operation} blocked because its one-time administrator approval was already consumed.`
        : approvalState === "expired"
          ? `${operation} blocked because its administrator approval expired.`
          : `${operation} held by Phigon Guardian for administrator approval.`;
  const contract = adminContract
    ? ` Admin contract: ${adminContract}`
    : "";
  return `${result} Reason: ${reason}${contract}`;
}

async function runGuardianExec(
  flags: readonly string[],
  environment: NodeJS.ProcessEnv,
  output: Output,
  input: Readable,
  dataDirectory: string,
): Promise<number> {
  const separator = flags.indexOf("--");
  if (separator < 0 || separator === flags.length - 1) {
    throw new Error("guardian exec requires -- <executable> [arguments...].");
  }
  const gatewayFlags = flags.slice(0, separator);
  validateGuardianExecFlags(gatewayFlags);
  if (gatewayFlags.includes("--json")) {
    throw new Error("guardian exec does not support --json because command output is streamed directly.");
  }
  const executable = flags[separator + 1] as string;
  const commandArguments = flags.slice(separator + 2);
  if (executable.trim() === "" || /[\u0000\r\n]/u.test(executable) ||
    commandArguments.some((argument) => /[\u0000]/u.test(argument))) {
    throw new Error("guardian exec executable or arguments are invalid.");
  }
  return await runGuardedCommand(executable, commandArguments, gatewayFlags, undefined, environment, output, dataDirectory);
}

async function runGuardianLaunch(
  flags: readonly string[],
  environment: NodeJS.ProcessEnv,
  output: Output,
  input: Readable,
  dataDirectory: string,
): Promise<number> {
  const separator = flags.indexOf("--");
  if (separator < 0 || separator === flags.length - 1) {
    throw new Error("guardian launch requires -- <executable> [arguments...].");
  }
  const gatewayFlags = flags.slice(0, separator);
  validateGuardianLaunchFlags(gatewayFlags);
  if (gatewayFlags.includes("--json")) {
    throw new Error("guardian launch does not support --json because agent output is streamed directly.");
  }
  const agentID = flagValue(gatewayFlags, "--agent");
  if (agentID === undefined) {
    throw new Error("guardian launch requires --agent <agent-id>.");
  }
  validatedAgentID(agentID);
  const model = validatedModelResource(flagValue(gatewayFlags, "--model"));
  const executable = flags[separator + 1] as string;
  const commandArguments = flags.slice(separator + 2);
  if (executable.trim() === "" || /[\u0000\r\n]/u.test(executable) ||
    commandArguments.some((argument) => /[\u0000]/u.test(argument))) {
    throw new Error("guardian launch executable or arguments are invalid.");
  }
  return await runGuardedCommand(executable, commandArguments, gatewayFlags, model, environment, output, dataDirectory);
}

// The control plane refuses any other agent ID with a generic manifest error,
// so check here and say what is wrong.
function validatedAgentID(value: string): string {
  if (!/^[A-Za-z0-9._:-]{1,128}$/u.test(value)) {
    throw new Error("--agent must be 1-128 letters, numbers, dots, underscores, colons or hyphens.");
  }
  return value;
}

function validateGuardianExecFlags(flags: readonly string[]): void {
  const valued = new Set([
    "--agent",
    "--context-file",
  ]);
  for (let index = 0; index < flags.length; index += 1) {
    const flag = flags[index] as string;
    if (flag === "--json") continue;
    if (!valued.has(flag) || index + 1 >= flags.length) {
      throw new Error(`guardian exec does not support ${flag}.`);
    }
    index += 1;
  }
}

function validateGuardianLaunchFlags(flags: readonly string[]): void {
  const valued = new Set([
    "--agent",
    "--model",
    "--context-file",
  ]);
  for (let index = 0; index < flags.length; index += 1) {
    const flag = flags[index] as string;
    if (flag === "--json") continue;
    if (!valued.has(flag) || index + 1 >= flags.length) {
      throw new Error(`guardian launch does not support ${flag}.`);
    }
    index += 1;
  }
}

function validatedModelResource(value: string | undefined): string {
  if (value === undefined) {
    throw new Error("guardian launch requires --model <provider:model> so model policy cannot be skipped.");
  }
  const normalized = value.trim();
  if (
    Buffer.byteLength(normalized, "utf8") > 256 ||
    !/^[A-Za-z0-9][A-Za-z0-9._-]{0,63}:[A-Za-z0-9][A-Za-z0-9._:/-]{0,190}$/u.test(normalized)
  ) {
    throw new Error("--model must use the stable provider:model identifier format.");
  }
  return normalized;
}

async function runGuardedCommand(
  executable: string, arguments_: readonly string[], flags: readonly string[], model: string | undefined,
  environment: NodeJS.ProcessEnv, output: Output, dataDirectory: string,
): Promise<number> {
  const config = loadConfig(environment);
  const credential = await new FileCredentialStore(dataDirectory).load();
  if (!credential || credential.controlPlaneOrigin !== config.controlPlaneUrl.origin) throw new Error("Guardian execution requires a paired machine and its configured control plane.");
  const policy = await new FileActionPolicyStore(dataDirectory).load(credential.machineId);
  if (!policy) { output.stdout("Phigon Guardian blocked execution: administrator policy is unavailable.\n"); return 77; }
  const agentId = validatedAgentID(flagValue(flags, "--agent") ?? "managed-agent");
  const context = await readGuardianActionContext(flagValue(flags, "--context-file"));
  const hosted = new GuardianHostedClient({ controlPlaneURL: config.controlPlaneUrl, credential: credential.credential });
  const childEnvironment = executionEnvironment({ ...process.env, ...environment });
  const bridge = model === undefined ? undefined : await startGuardianModelBridge({
    controlPlaneURL: config.controlPlaneUrl, credential: credential.credential, agentId, provider: model.split(":")[0]!.toLowerCase(),
  });
  const lifetime = new AbortController();
  try {
    const assigned = await hosted.post("/v1/machine/guardian/execution-profile", {}, lifetime.signal, 10_000);
    if (assigned["policy_digest"] !== policy.policyDigest || typeof assigned["sandbox"] !== "string" || Buffer.byteLength(assigned["sandbox"]) > 24 << 10) throw new GuardianDecisionUnavailableError("Guardian could not bind the current OS restrictions.");
    if (bridge) {
      for (const key of Object.keys(childEnvironment)) {
        if (/^(OPENAI_API_KEY|OPENAI_BASE_URL|OPENAI_ORG_ID|OPENAI_PROJECT_ID|ANTHROPIC_API_KEY|ANTHROPIC_AUTH_TOKEN|ANTHROPIC_BASE_URL)$/iu.test(key)) delete childEnvironment[key];
      }
      childEnvironment["OPENAI_API_KEY"] = bridge.token;
      childEnvironment["OPENAI_BASE_URL"] = bridge.baseURL;
      childEnvironment["ANTHROPIC_API_KEY"] = bridge.token;
      childEnvironment["ANTHROPIC_AUTH_TOKEN"] = bridge.token;
      childEnvironment["ANTHROPIC_BASE_URL"] = bridge.baseURL.replace(/\/v1$/u, "");
    }
    const manifest = await createExecutionManifest({ executable, arguments: arguments_, agentId, ...(model === undefined ? {} : { model }), environment: childEnvironment,
      sandbox: assigned["sandbox"],
      cgroupRoot: environment["PHIGON_GUARDIAN_CGROUP_ROOT"] ?? process.env["PHIGON_GUARDIAN_CGROUP_ROOT"] ?? "" });
    const serialized = JSON.stringify(manifest);
    const manifestDigest = createHash("sha256").update(serialized).digest("hex");
    const request = { policy_digest: policy.policyDigest, manifest: serialized, context: {
      task_id: context.taskId, proposal_id: context.proposalId, plan_step_id: context.planStepId,
      user_prompt: context.userPrompt, agent_plan: context.agentPlan, justification: context.justification,
      expected_effect: context.expectedEffect, recent_activity: context.recentActivity,
    } };
    let grant = await hosted.post("/v1/machine/guardian/executions", request);
    const approvalDeadline = Date.now() + 5 * 60_000;
    let waitingMessage = false;
    while (grant["decision"] !== undefined) {
      const review = semanticDecision(grant["decision"], 0);
      if (review.decision !== "require_approval" || review.approvalState !== "pending" || Date.now() >= approvalDeadline) break;
      if (!waitingMessage) { output.stdout("Phigon Guardian is waiting for your administrator to approve this complete launch.\n"); waitingMessage = true; }
      await delay(5_000);
      await verifyExecutionManifest(manifest, childEnvironment);
      grant = await hosted.post("/v1/machine/guardian/executions", request);
    }
    if (grant["decision"] !== undefined) {
      const decision = semanticDecision(grant["decision"], 0);
      if (decision.decision === "allow") throw new GuardianDecisionUnavailableError("Guardian omitted the execution grant.");
      const action = parseManagedAction(typeof grant["action"] === "string" ? grant["action"] : undefined);
      output.stdout(`Action: ${action}\n${guardianAgentMessage(action, false, decision.decision === "require_approval", decision.reason, decision.adminContract, decision.approvalState)}\n`);
      await new GuardianDecisionJournal(dataDirectory).append({ agentId, action: String(grant["action"]), resource: manifest.executable,
        outcome: decision.decision, reason: decision.reason, decisionSource: "execution_grant", latencyMs: decision.latencyMs, policyDigest: policy.policyDigest, context });
      return 77;
    }
    if (typeof grant["token"] !== "string" || !/^[a-f0-9]{64}$/u.test(grant["token"]) || grant["manifest_digest"] !== manifestDigest || grant["policy_digest"] !== policy.policyDigest ||
        typeof grant["expires_at"] !== "string" || !Number.isFinite(Date.parse(grant["expires_at"])) || Date.parse(grant["expires_at"]) <= Date.now() || Date.parse(grant["expires_at"]) > Date.now() + 30_000) {
      throw new GuardianDecisionUnavailableError("Guardian returned an invalid execution grant.");
    }
    await verifyExecutionManifest(manifest, childEnvironment);
    const consumed = await hosted.post("/v1/machine/guardian/executions/consume", { ...request, token: grant["token"] }, undefined, 10_000);
    if (consumed["authorized"] !== true || consumed["manifest_digest"] !== manifestDigest || consumed["policy_digest"] !== policy.policyDigest) throw new GuardianDecisionUnavailableError("Guardian did not authorize this exact execution.");
    if (consumed["lease_seconds"] !== 30) throw new GuardianDecisionUnavailableError("Guardian did not establish an execution lease.");
    const leaseBody = { ...request, token: grant["token"] };
    try {
      const execution = await executeManagedCommand({ executable: manifest.executable, arguments: manifest.arguments, agentId,
        sessionId: context.taskId ?? context.proposalId ?? `managed:${agentId}`, dataDirectory, manifest, environment: childEnvironment, signal: lifetime.signal,
        lease: { origin: config.controlPlaneUrl.origin, credential: credential.credential, request: leaseBody } });
      let reported = false;
      for (let attempt = 0; attempt < 3; attempt++) {
        try {
          const receipt = await hosted.post("/v1/machine/guardian/executions/finish", leaseBody, undefined, 3_000);
          if (receipt["finished"] !== true) throw new Error("Invalid completion receipt.");
          reported = true;
          break;
        } catch {
          if (attempt < 2) await delay(200 * (attempt + 1));
        }
      }
      if (!reported) output.stderr(`Phigon Guardian: the command executed and exited with code ${execution.exitCode}. Its completion report could not be acknowledged; the observed result is journaled locally. Do not rerun the command to retry the report.\n`);
      return execution.exitCode;
    } finally { lifetime.abort(); }
  } catch (error) {
    output.stdout(`${error instanceof Error ? error.message : "Phigon Guardian could not verify execution."}\n`);
    return 77;
  } finally { lifetime.abort(); await bridge?.close(); }
}

/**
 * Calls `onGone` once the process `pid` has exited, checking every few
 * seconds. Returns a function that stops watching.
 */
export function watchParentProcess(
  pid: number,
  onGone: () => void,
  intervalMs = 5_000,
  isAlive: (pid: number) => boolean = processIsAlive,
): () => void {
  const timer = setInterval(() => {
    if (pid > 0 && isAlive(pid)) return;
    clearInterval(timer);
    onGone();
  }, intervalMs);
  timer.unref();
  return () => clearInterval(timer);
}

/**
 * NODE_EXTRA_CA_CERTS from the service settings. Node.js reads the variable
 * only when it starts, so the service adds those authorities itself.
 */
function trustExtraCertificates(file: string | undefined, output: Output): void {
  if (file === undefined || file === "") return;
  try {
    const certificates = readFileSync(file, "utf8")
      .match(/-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/gu) ?? [];
    for (const certificate of certificates) trustAuthority(`${certificate}\n`);
  } catch {
    output.stderr(`The certificates in NODE_EXTRA_CA_CERTS (${file}) could not be read; HTTPS uses the system's authorities only.\n`);
  }
}

/** How often a background service asks again whether a removed computer is back. */
const removedRecheckMs = 60 * 60_000;

/**
 * How `run` exits on a computer the workspace removed. A background service
 * exits cleanly: systemd then leaves it stopped, and on Windows and macOS,
 * which start it again anyway, the next start stops at once. A person
 * running it in a terminal sees a failure.
 */
function removedExitCode(service: boolean): number {
  return service ? 0 : 1;
}

export async function settleObserverTasks(
  tasks: readonly Promise<void>[],
  controller: AbortController,
  fatalError: () => Error | undefined,
): Promise<void> {
  try {
    await Promise.all(tasks);
    const error = fatalError();
    if (error !== undefined) throw error;
  } finally {
    controller.abort();
    await Promise.allSettled(tasks);
  }
}

function intersectCollectionPolicy(
  configured: CollectionPolicy,
  consentProfile: ConsentProfile | undefined,
  server?: WireCollectionPolicy,
): CollectionPolicy {
  const local = consentedCollectionPolicy(configured, consentProfile);
  return Object.freeze({
    promptContent: local.promptContent &&
      server?.promptContent === true,
    responseContent: local.responseContent &&
      server?.responseContent === true,
    reasoningContent: local.reasoningContent &&
      server?.reasoningContent === true,
    commandArguments: local.commandArguments &&
      server?.commandArguments === true,
    terminalOutput: local.terminalOutput &&
      server?.terminalOutput === true,
    filePaths: local.filePaths && server?.filePaths === true,
    fileContent: local.fileContent && server?.fileContent === true,
    browserUrls: local.browserUrls && server?.browserUrls === true,
    browserContent: local.browserContent &&
      server?.browserContent === true,
    networkEndpoints: local.networkEndpoints &&
      server?.networkEndpoints === true,
    gitPatchContent: local.gitPatchContent &&
      server?.gitPatchContent === true,
    environmentValues: local.environmentValues &&
      server?.environmentValues === true,
    toolOutput: local.toolOutput && server?.toolOutput === true,
    vendorPayload: local.vendorPayload &&
      server?.vendorPayload === true,
    processMetadata: local.processMetadata &&
      server?.processMetadata === true,
    processArguments: local.processArguments &&
      server?.processArguments === true,
    fileMetadata: local.fileMetadata && server?.fileMetadata === true,
    fileDiffs: local.fileDiffs && server?.fileDiffs === true,
    networkMetadata: local.networkMetadata &&
      server?.networkMetadata === true,
    networkContent: local.networkContent &&
      server?.networkContent === true,
    browserMetadata: local.browserMetadata &&
      server?.browserMetadata === true,
    mcpArguments: local.mcpArguments && server?.mcpArguments === true,
    mcpOutput: local.mcpOutput && server?.mcpOutput === true,
    modelPrompts: local.modelPrompts && server?.modelPrompts === true,
    modelResponses: local.modelResponses &&
      server?.modelResponses === true,
  });
}

function fullHistoryPolicyEnabled(policy: CollectionPolicy): boolean {
  return policy.promptContent &&
    policy.responseContent &&
    policy.commandArguments &&
    policy.toolOutput &&
    policy.vendorPayload &&
    policy.modelPrompts &&
    policy.modelResponses;
}

function helpText(): string {
  return [
    "Phigon observer",
    "",
    "Usage:",
    "  phigon-observer authorize-action --action <action> --resource <normalized-resource> [--agent <agent-id>] [--process-id <pid> --process-started-at <RFC3339>] [--context-file <path>] [--json]",
    "  phigon-observer guardian status [--json]",
    "  phigon-observer guardian exec [--agent <agent-id>] [--context-file <path>] -- <executable> [arguments...]",
    "  phigon-observer guardian launch --agent <agent-id> --model <provider:model> [--context-file <path>] -- <executable> [arguments...]",
    "  phigon-observer agent add --id <id> --name <name> [--executable <name>] [--process <name>] [--config-path <path>] [--activity-dir <path>] [--capability <name>] [--json]",
    "  phigon-observer agent list [--json]",
    "  phigon-observer agent remove --id <id> [--yes] [--json]",
    "  phigon-observer doctor [--profile <metadata|full>] [--json]",
    "  phigon-observer doctor --check [--max-delivery-age <minutes>] [--json]",
    "  phigon-observer update [--check] [--yes] [--json]",
    "  phigon-observer --version",
    "  phigon-observer discover [--json]",
    "  phigon-observer ingest --agent <agent-id|custom> [--name <agent-name>] [--quiet] [--json]",
    "  phigon-observer pair --code <one-time-code> --consent-profile <metadata|full> [--control-plane-url <url> --grpc-url <url> [--server-ca-sha256 <fingerprint>]] [--name <machine-name>] [--accept-consent] [--no-service] [--no-remote-commands | --no-remote-actions] [--json]",
    "  PHIGON_ENROLLMENT_CODE=<code> phigon-observer pair [--control-plane-url <url> --grpc-url <url> [--server-ca-sha256 <fingerprint>]] [--name <machine-name>] [--json]",
    "  phigon-observer pair --enrollment-code <code> [same options]",
    "  phigon-observer remove-machine [--purge] [--yes] [--json]",
    "  phigon-observer run [--profile <metadata|full>]",
    "  phigon-observer service install [--profile <metadata|full>] [--json]",
    "  phigon-observer service uninstall [--json]",
    "  phigon-observer service status [--json]",
    "  phigon-observer help",
    "",
    "The doctor command validates local configuration without transmitting data. With --check it also probes the control plane and exits non-zero when something needs attention: 3 not paired, 4 consent missing or outdated, 5 observer not running, 6 nothing delivered within --max-delivery-age minutes (default 15), 7 control plane unreachable.",
    "The agent commands manage dynamic local monitoring definitions for custom agents without changing observer code.",
    "The authorize-action command is a fail-closed decision point for managed gateways; it does not intercept actions performed outside that boundary. Stop/force-stop requires an administrator policy and exact process identity.",
    "The optional Guardian context file supplies bounded task_id, user_prompt, agent_plan, justification, and recent_activity fields for semantic review.",
    "The guardian status command reports central management. Only administrator policies authorize blocking and containment; local overrides are unavailable.",
    "The guardian exec command checks agent.start and command.execute, launches without a shell after authorization, and journals command input/output and its exit code for hosted telemetry delivery.",
    "The guardian launch command requires a model claim and a single-use grant covering agent.start, model.use, and command.execute. The native supervisor stops the managed process tree when its online lease is revoked or unavailable.",
    "The discover command reports a sanitized one-time local inventory.",
    "The ingest command accepts NDJSON on stdin for every supported bridge; use --agent custom --name <agent-name> for any other agent.",
    "The pair command shows the selected collection scope, requires machine-owner acceptance, and stores that evidence with the mode-0600 credential.",
    "With a company's enrollment code (phe_...), pair asks nothing: the company has given consent and chosen the profile, which the observer stores and keeps collection within. Prefer PHIGON_ENROLLMENT_CODE to --enrollment-code, which shows in process lists. The code is never printed or stored. A busy server is retried a few times. Exit codes: 20 try again later, 21 the code expired, was revoked, is used up or outdated, 22 not a valid code, 23 this computer already used this code, 24 already connected to this workspace. Then run phigon-observer service install.",
    "The remove-machine command stops collection on this paired machine and revokes its credential; activity already collected stays until an administrator deletes the machine or it expires. It requires local confirmation. With --purge it also removes the background service and every file the observer keeps in the data directory.",
    "The run command maintains an authenticated, resumable telemetry stream; --profile applies the same portable local collection profile on Windows, macOS, and Linux.",
    "The service commands run the observer in the background for the signed-in user (a Task Scheduler task, a LaunchAgent or a systemd user unit) with this data directory and these settings, starting it at sign-in and again if it stops. Install needs a paired computer with the owner's consent.",
    "",
  ].join("\n");
}

function parseManagedAction(value: string | undefined): ManagedActionName {
  if (
    value !== undefined &&
    managedActionNames.includes(value as ManagedActionName)
  ) {
    return value as ManagedActionName;
  }
  throw new Error(
    `authorize-action requires --action ${managedActionNames.join(" | ")}.`,
  );
}

function parseOptionalProcessID(value: string | undefined): number | undefined {
  if (value === undefined) return undefined;
  if (!/^[1-9][0-9]{0,14}$/u.test(value)) {
    throw new Error("--process-id must be a positive safe integer.");
  }
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed)) {
    throw new Error("--process-id must be a positive safe integer.");
  }
  return parsed;
}

function formatDiscoveryJSON(snapshot: DiscoverySnapshot): string {
  return `${JSON.stringify(
    {
      inventory: JSON.parse(
        toJsonString(AgentInventorySchema, snapshot.inventory),
      ),
      adapterHealth: snapshot.adapterHealth,
    },
    null,
    2,
  )}\n`;
}

function formatDiscovery(snapshot: DiscoverySnapshot): string {
  const agents =
    snapshot.inventory.agents.length === 0
      ? ["No supported agent installations or processes were detected."]
      : snapshot.inventory.agents.map((agent) => {
          const state =
            AgentState[agent.state]?.toLowerCase() ?? "unknown";
          const version =
            agent.version.length > 0 ? ` ${agent.version}` : "";
          return `${agent.displayName}${version}: ${state}`;
        });
  return [
    `Observed agents: ${snapshot.inventory.agents.length}`,
    `Inventory complete: ${snapshot.inventory.partial ? "no" : "yes"}`,
    ...agents,
    "",
  ].join("\n");
}

function formatPairResult(
  result: Awaited<ReturnType<typeof pairMachine>>,
  observerRestarts: boolean,
  service: PairingService | undefined,
  profile: ConsentProfile,
  remoteActions: RemoteActionConsent,
): string {
  return [
    "Machine paired successfully.",
    `Machine: ${result.displayName} (${result.machineId})`,
    `Control plane: ${result.controlPlaneOrigin}`,
    remoteActionSentence(remoteActions),
    "Machine credential: stored securely",
    ...(result.previousControlPlaneOrigin === undefined || result.replacedMachineId !== undefined
      ? []
      : [`Earlier address: ${result.previousControlPlaneOrigin}. Activity this computer had not delivered yet is sent to the new address.`]),
    ...(result.replacedMachineId === undefined
      ? []
      : [
          `Earlier machine: ${result.replacedMachineId} (the workspace no longer accepted its key)`,
          "This computer was paired as a new machine. Activity the earlier machine had not delivered was moved to the retired-pairings folder in the data directory.",
        ]),
    ...(observerRestarts
      ? ["The observer running with this data directory stops within a few seconds to use the new pairing. Its background service starts it again; if you started it yourself, run it again."]
      : []),
    ...pairingServiceLines(service, profile),
    "",
  ].join("\n");
}

function pairingServiceLines(service: PairingService | undefined, profile: ConsentProfile): string[] {
  if (service === undefined) return [`Start collecting with: phigon-observer run --profile ${profile}`];
  if (service.status === "installed") {
    return [
      "",
      `Phigon now runs in the background on this computer (${service.name}). You can close this window.`,
      service.note,
      ...(service.alreadyRunning ? ["An observer you started is still running; the service takes over when it stops."] : []),
      "To stop it: phigon-observer service uninstall",
    ];
  }
  return [
    "",
    `Phigon could not keep running in the background: ${service.reason}`,
    `Start collecting with: phigon-observer run --profile ${profile}, and keep that window open.`,
  ];
}

/**
 * `remove-machine --purge`: the usual removal, then the background service
 * and every file the observer keeps on this computer. The company's copy of
 * the activity is not touched; only an administrator or retention removes it.
 */
async function removeMachineAndPurge(
  config: ObserverConfig,
  environment: NodeJS.ProcessEnv,
  flags: readonly string[],
  json: boolean,
  output: Output,
  input: Readable,
  dependencies: ServiceDependencies,
): Promise<number> {
  const credentialStore = new FileCredentialStore(config.dataDirectory);
  const credential = await credentialStore.load();
  if (json && !flags.includes("--yes")) {
    throw new Error("JSON machine removal requires --yes after reviewing the removal scope.");
  }
  if (!flags.includes("--yes")) {
    output.stdout(purgePrompt(credential?.machineId, config.dataDirectory));
    if (await readConfirmation(input) !== "remove") {
      throw new Error("Machine removal was not confirmed. Nothing was changed.");
    }
  }
  // The service would restart the observer this removes, so stop it first,
  // and start it again if the removal fails.
  let service: ReturnType<typeof serviceContext> | undefined;
  try {
    service = serviceContext(config, environment, dependencies);
  } catch {
    // No background service on this system; there is nothing to stop.
  }
  const serviceStopped = service !== undefined && await stopService(service);
  const restartService = async () => {
    if (serviceStopped && service !== undefined) await startService(service).catch(() => undefined);
  };
  if (serviceStopped) await waitForObserverToStop(config.dataDirectory, dependencies.stopTimeoutMs ?? 15_000);
  let removalLock: InstanceLock;
  try {
    removalLock = await InstanceLock.acquire(config.dataDirectory);
  } catch (error) {
    await restartService();
    if (!(error instanceof ObserverAlreadyRunningError)) throw error;
    throw new Error(
      "A Phigon observer is running with this data directory. Stop it, or stop its service, " +
        "and then run remove-machine again. No request was sent.",
    );
  }
  let result: Awaited<ReturnType<typeof removeMachine>> | undefined;
  let purged: Awaited<ReturnType<typeof purgeDataDirectory>>;
  try {
    if (credential !== null) {
      try {
        result = await removeMachine({
          config,
          credential,
          clearCredential: async () => {
            clearEventSpool(config.dataDirectory);
            await forgetServerAuthority(config.dataDirectory);
            return await credentialStore.clear();
          },
        });
      } catch (error) {
        await removalLock.release();
        await restartService();
        throw error;
      }
    }
    if (service !== undefined) await uninstallService(service);
    purged = await purgeDataDirectory(config.dataDirectory, ["observer.lock"]);
  } finally {
    await removalLock.release();
  }
  const directoryRemoved = purged.leftBehind.length === 0 &&
    await removeEmptyDataDirectory(config.dataDirectory);
  const local = {
    serviceRemoved: serviceStopped,
    filesRemoved: purged.removed,
    dataDirectory: config.dataDirectory,
    dataDirectoryRemoved: directoryRemoved,
    leftBehind: purged.leftBehind,
  };
  output.stdout(json
    ? `${JSON.stringify({ ...(result ?? { status: "not_paired" }), purged: local }, null, 2)}\n`
    : [
        ...(result === undefined
          ? ["This computer was not paired, so nothing was sent to a workspace."]
          : [formatRemoveMachineResult(result).trimEnd()]),
        `Background service: ${serviceStopped ? "removed" : "was not installed"}`,
        directoryRemoved
          ? `Local data: removed, with ${config.dataDirectory}`
          : `Local data: removed from ${config.dataDirectory}${purged.leftBehind.length === 0 ? "" : `; ${purged.leftBehind.length} file(s) the observer did not create were left there`}`,
        "To remove the program too, run: npm uninstall --global @phigon/observer",
        "",
      ].join("\n"));
  return 0;
}

async function waitForObserverToStop(dataDirectory: string, timeoutMs: number): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline && (await InstanceLock.inspect(dataDirectory)).running) {
    await delay(250);
  }
}

function purgePrompt(machineId: string | undefined, dataDirectory: string): string {
  return [
    "Remove this computer from Phigon and delete its local data?",
    ...(machineId === undefined ? ["This computer is not paired."] : [
      `Machine: ${machineId}`,
      "Collection stops at once and this computer's observer key is revoked.",
      "Activity already collected stays with your company until an administrator deletes this computer or it expires under the retention policy.",
    ]),
    "The background service is removed, and every file the observer keeps in",
    `${dataDirectory} is deleted, including activity not yet delivered.`,
    'Type "remove" to continue: ',
  ].join("\n");
}

function removeMachinePrompt(machineId: string): string {
  return [
    "Remove this machine from Phigon?",
    `Machine: ${machineId}`,
    "Collection stops at once and this computer's observer key is revoked.",
    "Activity already collected stays with your company until an administrator deletes this computer or it expires under the retention policy.",
    'Type "remove" to continue: ',
  ].join("\n");
}

function formatRemoveMachineResult(
  result: Awaited<ReturnType<typeof removeMachine>>,
  serviceRemoved = false,
): string {
  return [
    result.status === "already_removed"
      ? "This machine was already removed from the workspace, or its key was revoked. The local copy is now cleaned up."
      : "Machine removed successfully.",
    `Machine: ${result.machineId}`,
    `Control plane: ${result.controlPlaneOrigin}`,
    "Collection: stopped; the observer key is revoked",
    ...(serviceRemoved ? ["Background service: removed"] : []),
    "Machine credential: removed from this device",
    "Collected activity: kept until an administrator deletes this computer or it expires",
    "Next step: pair again to reconnect this observer.",
    "",
  ].join("\n");
}

async function runAgentCommand(
  flags: readonly string[],
  registry: CustomAgentRegistry,
  json: boolean,
  output: Output,
  input: Readable,
): Promise<number> {
  const subcommand = flags[0];
  if (subcommand === "list") {
    const agents = await registry.list();
    output.stdout(
      json
        ? `${JSON.stringify({ agents }, null, 2)}\n`
        : formatCustomAgentList(agents),
    );
    return 0;
  }
  if (subcommand === "add") {
    const id = flagValue(flags, "--id");
    const displayName = flagValue(flags, "--name");
    if (id === undefined || displayName === undefined) {
      throw new Error("agent add requires --id <id> and --name <name>.");
    }
    const registration = customAgentRegistration({
      id,
      displayName,
      executableNames: flagValues(flags, "--executable"),
      processNames: flagValues(flags, "--process"),
      configurationPaths: flagValues(flags, "--config-path"),
      activityDirectories: flagValues(flags, "--activity-dir"),
      capabilities: flagValues(flags, "--capability"),
    });
    const added = await registry.add(registration);
    output.stdout(
      json
        ? `${JSON.stringify({ status: "added", agent: added }, null, 2)}\n`
        : formatCustomAgentChange("added", added),
    );
    return 0;
  }
  if (subcommand === "remove") {
    const id = flagValue(flags, "--id");
    if (id === undefined) {
      throw new Error("agent remove requires --id <id>.");
    }
    if (json && !flags.includes("--yes")) {
      throw new Error(
        "JSON custom-agent removal requires --yes after reviewing the target.",
      );
    }
    if (!flags.includes("--yes")) {
      output.stdout(
        `Remove custom monitoring definition ${id}?\n` +
          'Type "remove" to continue: ',
      );
      if (await readConfirmation(input) !== "remove") {
        throw new Error(
          "Custom-agent removal was not confirmed. No change was made.",
        );
      }
    }
    const removed = await registry.remove(id);
    if (removed === undefined) {
      throw new Error(`Custom agent ${id} is not registered.`);
    }
    output.stdout(
      json
        ? `${JSON.stringify({ status: "removed", agent: removed }, null, 2)}\n`
        : formatCustomAgentChange("removed", removed),
    );
    return 0;
  }
  throw new Error(
    "agent requires one of: add, list, or remove. Run phigon-observer help for usage.",
  );
}

function formatCustomAgentList(
  agents: readonly CustomAgentRegistration[],
): string {
  if (agents.length === 0) {
    return "Custom agents: 0\nNo dynamic monitoring definitions are registered.\n";
  }
  return [
    `Custom agents: ${agents.length}`,
    ...agents.map((agent) => {
      const signals = [
        agent.executableNames.length > 0 ? "executable" : "",
        agent.processNames.length > 0 ? "process" : "",
        agent.configurationPaths.length > 0 ? "configuration" : "",
        agent.activityDirectories.length > 0 ? "activity" : "",
      ].filter(Boolean).join(", ");
      return `${agent.displayName} (${agent.id}): ${signals}`;
    }),
    "",
  ].join("\n");
}

function formatCustomAgentChange(
  status: "added" | "removed",
  agent: CustomAgentRegistration,
): string {
  return [
    `Custom agent ${status}.`,
    `Agent: ${agent.displayName} (${agent.id})`,
    `Discovery signals: ${
      agent.executableNames.length +
      agent.processNames.length +
      agent.configurationPaths.length
    }`,
    `Activity directories: ${agent.activityDirectories.length}`,
    status === "added"
      ? "Monitoring definition is active on the next discovery and activity scan."
      : "The observer will stop using this definition on the next scan.",
    "",
  ].join("\n");
}

function flagValue(
  flags: readonly string[],
  name: string,
): string | undefined {
  const equalsPrefix = `${name}=`;
  for (let index = 0; index < flags.length; index++) {
    const flag = flags[index];
    if (flag === name) {
      const value = flags[index + 1];
      return value === undefined || value.startsWith("--") ? undefined : value;
    }
    if (flag?.startsWith(equalsPrefix)) {
      return flag.slice(equalsPrefix.length);
    }
  }
  return undefined;
}

function flagValues(flags: readonly string[], name: string): string[] {
  const values: string[] = [];
  const equalsPrefix = `${name}=`;
  for (let index = 0; index < flags.length; index++) {
    const flag = flags[index];
    if (flag === name) {
      const value = flags[index + 1];
      if (value !== undefined && !value.startsWith("--")) values.push(value);
      continue;
    }
    if (flag?.startsWith(equalsPrefix)) {
      values.push(flag.slice(equalsPrefix.length));
    }
  }
  return values;
}

function observabilityEnvironment(
  command: string,
  flags: readonly string[],
  environment: NodeJS.ProcessEnv,
): NodeJS.ProcessEnv {
  const profile = flagValue(flags, "--profile");
  if (profile === undefined) return environment;
  if (command !== "doctor" && command !== "run" && !(command === "service" && flags[0] === "install")) {
    throw new Error("--profile is supported only by doctor, run and service install.");
  }
  if (profile !== "metadata" && profile !== "full") {
    throw new Error("--profile must be metadata or full.");
  }
  return {
    ...environment,
    PHIGON_OBSERVABILITY_PROFILE: profile,
  };
}

function parseMaxDeliveryAge(value: string | undefined): number {
  if (value === undefined) return defaultMaxDeliveryAgeMinutes;
  const minutes = Number(value);
  if (!/^\d{1,5}$/u.test(value) || minutes < 1 || minutes > 10_080) {
    throw new Error("--max-delivery-age must be a number of minutes from 1 to 10080.");
  }
  return minutes;
}

function parseConsentProfile(value: string | undefined): ConsentProfile {
  if (value === "metadata" || value === "full") return value;
  throw new Error(
    "pair requires --consent-profile metadata or --consent-profile full.",
  );
}

function consentPrompt(profile: ConsentProfile, background: boolean, remoteActions: RemoteActionConsent): string {
  const scope = profile === "metadata"
    ? "process, file, network, and browser metadata; no prompts, responses, file contents, terminal output, or browser contents"
    : "metadata plus prompts, responses, reasoning, command arguments and output, file/browser/network content, tool output, and model content; environment values remain excluded";
  return [
    `Consent profile: ${profile}`,
    `Collection scope: ${scope}.`,
    ...(background
      ? ["Phigon then keeps running in the background on this computer and starts when you sign in."]
      : []),
    remoteActionSentence(remoteActions),
    ...(remoteActions === "all"
      ? ["To allow only stopping agents, add --no-remote-commands; to allow neither, add --no-remote-actions."]
      : []),
    `The machine owner can stop the observer at any time${background ? " (phigon-observer service uninstall)" : ""}.`,
    'Type "yes" to grant this scope and pair the machine: ',
  ].join("\n");
}

async function readConfirmation(input: Readable): Promise<string> {
  const lines = createInterface({ input, crlfDelay: Infinity });
  try {
    for await (const line of lines) return line.trim().toLowerCase();
    return "";
  } finally {
    lines.close();
  }
}

function formatHealth(health: ReturnType<typeof createHealthSnapshot>): string {
  return [
    `Status: ${health.status}`,
    `Observer: ${health.observerVersion}`,
    `Control plane: ${health.controlPlaneOrigin}`,
    `Telemetry stream: ${health.grpcOrigin}`,
    `Host: ${health.host.platform}/${health.host.architecture}`,
    `Machine credential configured: ${health.machineTokenConfigured ? "yes" : "no"}`,
    ...(health.streamCursor === undefined
      ? health.streamCursorIssue === undefined
        ? []
        : [`Stream cursor: unavailable (${health.streamCursorIssue})`]
      : [
          `Stream cursor: ${health.streamCursor.acknowledgedSequence} for ${health.streamCursor.machineId}`,
        ]),
    ...(health.consent === undefined ? [] : [`Consent: ${describeConsent(health.consent)}`]),
    `Content collection: ${health.safeCollectionDefaults ? "metadata only" : "explicit categories enabled"}`,
    "",
  ].join("\n");
}

async function readVersion(): Promise<string> {
  const packagePath = new URL("../../package.json", import.meta.url);
  const raw = await readFile(packagePath, "utf8");
  const value: unknown = JSON.parse(raw);
  if (
    typeof value === "object" &&
    value !== null &&
    "version" in value &&
    typeof value.version === "string"
  ) {
    return value.version;
  }
  throw new Error("Observer package version is unavailable.");
}

export function isCliEntryPoint(candidate: string | undefined): boolean {
  if (candidate === undefined) return false;
  try {
    return realpathSync(fileURLToPath(import.meta.url)) ===
      realpathSync(candidate);
  } catch {
    return false;
  }
}

if (isCliEntryPoint(process.argv[1])) {
  process.exitCode = await run(process.argv.slice(2));
}
