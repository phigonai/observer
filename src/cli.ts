#!/usr/bin/env node

import { create, toJsonString } from "@bufbuild/protobuf";
import { timestampDate, timestampFromDate } from "@bufbuild/protobuf/wkt";
import { constants, realpathSync } from "node:fs";
import { access, readFile } from "node:fs/promises";
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
  loadConfig,
  DEFAULT_CONTROL_PLANE_ORIGIN,
  type CollectionPolicy,
} from "./config.js";
import { FileCredentialStore } from "./credential-store.js";
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
  createHealthSnapshot,
  type ObserverStreamCursorHealth,
} from "./health.js";
import {
  OBSERVER_CONSENT_POLICY_VERSION,
  pairMachine,
  type ConsentProfile,
} from "./pair.js";
import { removeMachine } from "./remove-machine.js";
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
import { StreamStateStore } from "./stream-state.js";
import { connectionEnvironment } from "./connection-config.js";
import { latestObserverVersion, newerVersion, offerObserverUpdate } from "./update.js";

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
): Promise<number> {
  const [command, ...flags] = argv;

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
    command !== "run"
  ) {
    output.stderr(`Unknown command: ${command}\n\n${helpText()}`);
    return 2;
  }

  try {
    environment = command === "update" ? { PHIGON_DATA_DIR:environment["PHIGON_DATA_DIR"] } : await connectionEnvironment(environment, command === "pair" || command === "run" || command === "doctor" ? flags : []);
    const config = loadConfig(
      observabilityEnvironment(command, flags, environment),
    );
    const version = await readVersion();
    const json = flags.includes("--json");
    const interactive = input === process.stdin && process.stdin.isTTY === true && process.stdout.isTTY === true && !json;
    if (command === "update" || (interactive && (command === "pair" || command === "run") && environment["PHIGON_UPDATE_CHECK"] !== "false")) {
      const latest = await latestObserverVersion(config.dataDirectory, { force: command === "update" });
      if (command === "update" && (json || flags.includes("--check"))) {
        output.stdout(`${JSON.stringify({ current: version, latest, updateAvailable: latest !== null && newerVersion(version, latest), status: latest === null ? "unavailable" : "checked" })}\n`);
        return latest === null ? 1 : 0;
      }
      if (command === "update" && !interactive && !flags.includes("--yes")) throw new Error("Use update --check for a read-only check, or update --yes to explicitly authorize an unattended update.");
      const updated = await offerObserverUpdate({ current: version, latest, write: output.stdout, confirm: () => command === "update" && flags.includes("--yes") ? Promise.resolve("yes") : readConfirmation(input) });
      if (updated) return 0;
      if (command === "update") {
        output.stdout(latest === null ? "Could not check for updates. Check your connection and try again.\n" : newerVersion(version, latest) ? "Update skipped.\n" : `Observer ${version} is up to date.\n`);
        return latest === null ? 1 : 0;
      }
    }
    const customAgentRegistry = new CustomAgentRegistry(
      config.dataDirectory,
    );

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
          enabled: true,
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
      if (!flags.includes("--yes")) {
        output.stdout(removeMachinePrompt(credential.machineId));
        const confirmed = await readConfirmation(input);
        if (confirmed !== "remove") {
          throw new Error(
            "Machine removal was not confirmed. No request was sent.",
          );
        }
      }
      const result = await removeMachine({
        config,
        credential,
        clearCredential: async () => {
          clearEventSpool(config.dataDirectory);
          return await credentialStore.clear();
        },
      });
      output.stdout(
        json
          ? `${JSON.stringify(result, null, 2)}\n`
          : formatRemoveMachineResult(result),
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
          throw new Error(
            "Full-content collection is outside the consented metadata profile.",
          );
        }
        let effectivePolicy = intersectCollectionPolicy(config.policy);
        let collector: ActivityCollector | undefined;
        let resolveCollector: ((value: ActivityCollector) => void) | undefined;
        const collectorReady = new Promise<ActivityCollector>((resolve) => {
          resolveCollector = resolve;
        });
        let fatalPersistenceError: Error | undefined;
        const discoveryEngine = new DiscoveryEngine({
          customAgentRegistry,
        });
        const actionExecutor = new AgentActionExecutor({
          enabled: config.remoteActionsEnabled,
          commandsEnabled: config.remoteCommandsEnabled,
          machineID: credential.machineId,
          dataDirectory: config.dataDirectory,
          inventory: async () =>
            (await discoveryEngine.discover(credential.machineId)).inventory,
        });
        const client = new ObserverStreamClient({
          config,
          actionExecutor,
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
            const remainingMs = expiresAt - Date.now();
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
            effectivePolicy = intersectCollectionPolicy(
              config.policy,
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
        );
        let historicalIdentities = await historicalStore.load();
        const initialDiscovery = await discoveryEngine.discover(
          credential.machineId,
        );
        historicalIdentities = await historicalStore.remember(
          initialDiscovery.inventory.agents,
        );
        let latestDiscoveryInventory = initialDiscovery.inventory;
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
            collector?.updateInventory(inventory);
            historicalIdentities = await historicalStore.remember(
              inventory.agents,
            );
            publishInventory();
          },
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
            enabled: true,
            inventory: async () => (await discoveryEngine.discover(credential.machineId)).inventory,
          }),
          journal: new GuardianDecisionJournal(config.dataDirectory),
          onStatus: (message) => output.stdout(`${message}\n`),
        });
        const monitoring = (async () => {
          await client.waitUntilReady(controller.signal);
          while (!controller.signal.aborted) {
            try {
              await processMonitor.review(latestDiscoveryInventory, controller.signal);
            } catch {
              output.stderr("Guardian process monitoring could not read verified policy state.\n");
            }
            try { await delay(config.discoveryIntervalMs, undefined, { signal: controller.signal }); }
            catch { break; }
          }
        })();
        const collecting = (async () => {
          const allocationSequence = await client.waitUntilReady(
            controller.signal,
          );
          collector = new ActivityCollector({
            config,
            credential,
            initialSequence: allocationSequence,
            initialAcknowledgedSequence:
              client.metrics().lastAcknowledgedSequence,
            durableDelivery: true,
            policy: effectivePolicy,
            emit: (event) => client.enqueue(event),
            canCollect: () => {
              const queue = client.metrics().queue;
              return (
                queue.capacity - queue.depth >=
                Math.max(32, config.activityRateLimitPerMinute)
              );
            },
            canSyncHistory: () => {
              const queue = client.metrics().queue;
              return queue.capacity - queue.depth >= Math.min(queue.capacity, historySyncQueueHeadroom);
            },
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
            while (!controller.signal.aborted) {
              if (!fullHistoryPolicyEnabled(effectivePolicy)) {
                output.stdout("Saved-history sync is waiting for the workspace full-activity policy.\n");
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
        await settleObserverTasks(
          [streaming, discovering, collecting, monitoring, maintaining],
          controller,
          () => fatalPersistenceError,
        );
        output.stdout("Observer stopped.\n");
      } finally {
        process.removeListener("SIGINT", stop);
        process.removeListener("SIGTERM", stop);
      }
      return 0;
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
      if (json && !flags.includes("--accept-consent")) {
        throw new Error(
          "JSON pairing requires --accept-consent after reviewing the selected profile.",
        );
      }
      if (!flags.includes("--accept-consent")) {
        output.stdout(consentPrompt(consentProfile));
        const confirmed = await readConfirmation(input);
        if (confirmed !== "yes") {
          throw new Error("Consent was not granted. No pairing request was sent.");
        }
      }
      const result = await pairMachine({
        config,
        code,
        consentProfile,
        ...(displayName === undefined ? {} : { displayName }),
      });
      output.stdout(
        json
          ? `${JSON.stringify(result, null, 2)}\n`
          : formatPairResult(result),
      );
      return 0;
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
    const health = createHealthSnapshot(
      {
        ...config,
        machineTokenConfigured:
          config.machineTokenConfigured || storedCredential !== null,
      },
      version,
      new Date(),
      streamCursor,
      streamCursorIssue,
    );
    output.stdout(
      json ? `${JSON.stringify(health, null, 2)}\n` : formatHealth(health),
    );
    return 0;
  } catch (error) {
    const message = error instanceof Error ? error.message : "Unknown error.";
    output.stderr(`Observer command failed: ${message}\n`);
    return 1;
  }
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
  local: CollectionPolicy,
  server?: WireCollectionPolicy,
): CollectionPolicy {
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
    "  phigon-observer update [--check] [--yes] [--json]",
    "  phigon-observer --version",
    "  phigon-observer discover [--json]",
    "  phigon-observer ingest --agent <agent-id|custom> [--name <agent-name>] [--quiet] [--json]",
    "  phigon-observer pair --code <one-time-code> --consent-profile <metadata|full> [--control-plane-url <url> --grpc-url <url>] [--name <machine-name>] [--accept-consent] [--json]",
    "  phigon-observer remove-machine [--yes] [--json]",
    "  phigon-observer run [--profile <metadata|full>]",
    "  phigon-observer help",
    "",
    "The doctor command validates local configuration without transmitting data.",
    "The agent commands manage dynamic local monitoring definitions for custom agents without changing observer code.",
    "The authorize-action command is a fail-closed decision point for managed gateways; it does not intercept actions performed outside that boundary. Stop/force-stop requires an administrator policy and exact process identity.",
    "The optional Guardian context file supplies bounded task_id, user_prompt, agent_plan, justification, and recent_activity fields for semantic review.",
    "The guardian status command reports central management. Only administrator policies authorize blocking and containment; local overrides are unavailable.",
    "The guardian exec command checks agent.start and command.execute, launches without a shell after authorization, and journals command input/output and its exit code for hosted telemetry delivery.",
    "The guardian launch command requires a model claim and a single-use grant covering agent.start, model.use, and command.execute. The native supervisor stops the managed process tree when its online lease is revoked or unavailable.",
    "The discover command reports a sanitized one-time local inventory.",
    "The ingest command accepts NDJSON on stdin for every supported bridge; use --agent custom --name <agent-name> for any other agent.",
    "The pair command shows the selected collection scope, requires machine-owner acceptance, and stores that evidence with the mode-0600 credential.",
    "The remove-machine command unregisters only this paired machine, revokes its credential, and requires local confirmation.",
    "The run command maintains an authenticated, resumable telemetry stream; --profile applies the same portable local collection profile on Windows, macOS, and Linux.",
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
): string {
  return [
    "Machine paired successfully.",
    `Machine: ${result.displayName} (${result.machineId})`,
    `Control plane: ${result.controlPlaneOrigin}`,
    "Machine credential: stored securely",
    "",
  ].join("\n");
}

function removeMachinePrompt(machineId: string): string {
  return [
    "Remove this machine from Phigon?",
    `Machine: ${machineId}`,
    "This unregisters the machine and immediately revokes its observer credential.",
    "Its stored telemetry and machine-scoped data will be durably purged; a minimal deletion tombstone plus consent and audit evidence remain according to retention policy.",
    'Type "remove" to continue: ',
  ].join("\n");
}

function formatRemoveMachineResult(
  result: Awaited<ReturnType<typeof removeMachine>>,
): string {
  return [
    "Machine removed successfully.",
    `Machine: ${result.machineId}`,
    `Control plane: ${result.controlPlaneOrigin}`,
    "Machine credential: removed from this device",
    "Stored machine telemetry: deletion scheduled",
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
  if (command !== "doctor" && command !== "run") {
    throw new Error("--profile is supported only by doctor and run.");
  }
  if (profile !== "metadata" && profile !== "full") {
    throw new Error("--profile must be metadata or full.");
  }
  return {
    ...environment,
    PHIGON_OBSERVABILITY_PROFILE: profile,
  };
}

function parseConsentProfile(value: string | undefined): ConsentProfile {
  if (value === "metadata" || value === "full") return value;
  throw new Error(
    "pair requires --consent-profile metadata or --consent-profile full.",
  );
}

function consentPrompt(profile: ConsentProfile): string {
  const scope = profile === "metadata"
    ? "process, file, network, and browser metadata; no prompts, responses, file contents, terminal output, or browser contents"
    : "metadata plus prompts, responses, reasoning, command arguments and output, file/browser/network content, tool output, and model content; environment values remain excluded";
  return [
    `Consent profile: ${profile}`,
    `Collection scope: ${scope}.`,
    "The machine owner can stop the observer at any time.",
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
