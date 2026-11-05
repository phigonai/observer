import {
  Client,
  Metadata,
  credentials,
  status,
  type ServiceError,
} from "@grpc/grpc-js";
import { createHash, randomBytes } from "node:crypto";
import { readFileSync } from "node:fs";
import { isIP } from "node:net";
import {
  clone,
  create,
  fromBinary,
  toBinary,
} from "@bufbuild/protobuf";
import { timestampDate, timestampFromDate } from "@bufbuild/protobuf/wkt";
import { abortableDelay } from "./abortable-delay.js";
import type { AgentActionExecutor } from "./agent-action-executor.js";
import { DEFAULT_CONTROL_PLANE_ORIGIN, type ObserverConfig } from "./config.js";
import {
  ActionCapabilityManifestSchema,
  AgentActionResultSchema,
  RemoteActionResultState,
  type AgentActionCommand,
} from "./generated/phigon/v1/action_pb.js";
import {
  ActionPolicySupersededError,
  FileActionPolicyStore,
  type ActionPolicyPersistence,
} from "./action-policy.js";
import { LocalPolicyEngine } from "./activity/policy.js";
import {
  FileCredentialStore,
  type CredentialStore,
} from "./credential-store.js";
import type { BoundedEventQueue, QueueMetrics } from "./event-queue.js";
import { FileBackedEventQueue, type SpoolRestoreNotice } from "./event-spool.js";
import {
  HeartbeatSchema,
  type AgentInventory,
} from "./generated/phigon/v1/identity_pb.js";
import {
  HistorySyncResultSchema,
  HistorySyncResultState,
  type HistorySyncCommand,
  type HistorySyncResult,
} from "./generated/phigon/v1/history_sync_pb.js";
import {
  ResumeCursorSchema,
  PolicyReceiptSchema,
  PolicyReceiptState,
  StreamErrorCode,
  StreamTelemetryRequestSchema,
  StreamTelemetryResponseSchema,
  type StreamTelemetryRequest,
  type StreamTelemetryResponse,
} from "./generated/phigon/v1/observer_service_pb.js";
import {
  ActionGuardrailPolicySchema,
  GuardrailIntervention,
  ManagedAction,
  type ActionGuardrailPolicy,
  type CollectionPolicy,
} from "./generated/phigon/v1/policy_pb.js";
import {
  ActivityKind,
  BuildInfoSchema,
  PrivacyClass,
} from "./generated/phigon/v1/common_pb.js";
import {
  EventEnvelopeSchema,
  VendorEventSchema,
  type EventEnvelope,
  type ResourceReference,
} from "./generated/phigon/v1/telemetry_pb.js";
import { MachineRemovedError } from "./machine-removed.js";
import { inspectionMessage, relayHost, relayNotConnectedMessage } from "./server-authority.js";
import type { ServerClock } from "./server-clock.js";
import { StreamStateStore } from "./stream-state.js";
import { noProxyForAll } from "./proxy.js";

type StreamStatePersistence = Pick<StreamStateStore, "load" | "save">;

const streamMethod =
  "/phigon.v1.ObserverService/StreamTelemetry";
const maxMessageBytes = 1 << 20;
const policyReceiptRefreshMs = 5 * 60 * 1_000;
/** How often an unchanged checkpoint is saved again while connected. */
export const streamStateRefreshMs = 60 * 1_000;
// The longest wait between reconnect attempts. A server that is off, such
// as the Phigon app's computer overnight, is tried about once a minute, so
// computers are back within a minute of it starting.
const maxReconnectDelayMs = 60_000;
// The same reason for being disconnected is logged again after this long.
const failureRepeatMs = 30 * 60_000;

export type ObserverStreamMetrics = Readonly<{
  reconnects: number;
  acknowledgements: number;
  lastAcknowledgedSequence: bigint;
  queue: QueueMetrics;
}>;

/** What the stream needs from the action executor. */
export type ActionExecutor = Pick<AgentActionExecutor, "execute" | "manifest">;

export type StreamClientOptions = Readonly<{
  config: ObserverConfig;
  /**
   * Whether Guardian may stop agents here (see containmentAllowed); the
   * policy receipt tells the server. Allowed unless said otherwise.
   */
  containmentEnabled?: boolean;
  credentialStore?: CredentialStore;
  stateStore?: StreamStatePersistence;
  queue?: BoundedEventQueue<EventEnvelope>;
  actionPolicyStore?: ActionPolicyPersistence;
  onStatus?: (message: string) => void;
  onPolicy?: (policy: CollectionPolicy) => void;
  onCursorReset?: (
    acknowledgedSequence: bigint,
    allocationSequence: bigint,
  ) => void;
  onAcknowledgement?: (
    sequence: bigint,
  ) => void | Promise<void>;
  actionExecutor?: ActionExecutor;
  onHistorySync?: (command: HistorySyncCommand) => Promise<HistorySyncResult>;
  /** Learns the server's time from the timestamps on its replies. */
  serverClock?: ServerClock;
  handshakeTimeoutMs?: number;
  /** How often an unchanged checkpoint is saved again; tests shorten it. */
  stateRefreshMs?: number;
  responseTimeoutMs?: number;
  /** This observer's version, sent with every heartbeat. */
  observerVersion?: string;
}>;

export class ObserverStreamClient {
  readonly #config: ObserverConfig;
  readonly #credentialStore: CredentialStore;
  readonly #stateStore: StreamStatePersistence;
  readonly #queue: BoundedEventQueue<EventEnvelope>;
  readonly #actionPolicyStore: ActionPolicyPersistence;
  readonly #onStatus: (message: string) => void;
  readonly #onPolicy: (policy: CollectionPolicy) => void;
  readonly #onCursorReset: (
    acknowledgedSequence: bigint,
    allocationSequence: bigint,
  ) => void;
  readonly #onAcknowledgement: (
    sequence: bigint,
  ) => void | Promise<void>;
  readonly #actionExecutor: ActionExecutor | undefined;
  readonly #containmentEnabled: boolean;
  readonly #onHistorySync:
    | ((command: HistorySyncCommand) => Promise<HistorySyncResult>)
    | undefined;
  #reconnects = 0;
  /** When the stream checkpoint was last saved; 0 before the first save. */
  #stateSavedAt = 0;
  #acknowledgements = 0;
  #lastAcknowledgedSequence = 0n;
  #pumpEvents: (() => void) | undefined;
  #latestInventory: AgentInventory | undefined;
  #sendInventory: ((inventory: AgentInventory) => void) | undefined;
  #readySequence: bigint | undefined;
  #establishedSinceConnect = false;
  // While the stream stays down, its attempts are not logged one by one:
  // only a new reason, or the same one again after a long while.
  #reconnectingQuietly = false;
  #lastLoggedFailure: Readonly<{ summary: string; at: number }> | undefined;
  readonly #readyWaiters = new Set<(sequence: bigint) => void>();
  readonly #handshakeTimeoutMs: number;
  readonly #stateRefreshMs: number;
  readonly #responseTimeoutMs: number;
  readonly #serverClock: ServerClock | undefined;
  readonly #observerVersion: string | undefined;

  constructor(options: StreamClientOptions) {
    this.#serverClock = options.serverClock;
    this.#observerVersion = reportableVersion(options.observerVersion);
    this.#handshakeTimeoutMs = options.handshakeTimeoutMs ?? 20_000;
    this.#stateRefreshMs = options.stateRefreshMs ?? streamStateRefreshMs;
    this.#responseTimeoutMs = options.responseTimeoutMs ?? Math.max(30_000, options.config.heartbeatIntervalMs * 3);
    this.#config = options.config;
    this.#credentialStore =
      options.credentialStore ??
      new FileCredentialStore(options.config.dataDirectory);
    this.#stateStore =
      options.stateStore ??
      new StreamStateStore(options.config.dataDirectory);
    this.#queue =
      options.queue ??
      new FileBackedEventQueue(
        options.config.dataDirectory,
        options.config.activityQueueCapacity,
      );
    this.#actionPolicyStore = options.actionPolicyStore ??
      new FileActionPolicyStore(options.config.dataDirectory);
    this.#onStatus = options.onStatus ?? (() => undefined);
    this.#onPolicy = options.onPolicy ?? (() => undefined);
    this.#onCursorReset = options.onCursorReset ?? (() => undefined);
    this.#onAcknowledgement =
      options.onAcknowledgement ?? (() => undefined);
    this.#actionExecutor = options.actionExecutor;
    this.#containmentEnabled = options.containmentEnabled ?? true;
    this.#onHistorySync = options.onHistorySync;
  }

  enqueue(event: EventEnvelope, coalesceKey?: string): void {
    if (!this.#queue.canEnqueue(coalesceKey)) {
      throw new Error(
        "Telemetry delivery queue is full; source collection stopped " +
          "before an unacknowledged event could be discarded.",
      );
    }
    this.#queue.enqueue(event, event.sequence, coalesceKey);
    this.#pumpEvents?.();
  }

  /**
   * Writes the events queued so far to the durable spool. The spool groups
   * its writes, so a source checkpoint may move past an event only after
   * this returns. Throws when the spool cannot be written.
   */
  flush(): void {
    if (this.#queue instanceof FileBackedEventQueue) this.#queue.flush();
  }

  updateInventory(inventory: AgentInventory): void {
    this.#latestInventory = inventory;
    this.#sendInventory?.(inventory);
  }

  async waitUntilReady(signal?: AbortSignal): Promise<bigint> {
    if (this.#readySequence !== undefined) return this.#readySequence;
    return await new Promise<bigint>((resolve, reject) => {
      const ready = (sequence: bigint) => {
        signal?.removeEventListener("abort", aborted);
        resolve(sequence);
      };
      const aborted = () => {
        this.#readyWaiters.delete(ready);
        reject(new Error("Telemetry readiness wait was aborted."));
      };
      if (signal?.aborted === true) {
        aborted();
        return;
      }
      this.#readyWaiters.add(ready);
      signal?.addEventListener("abort", aborted, { once: true });
    });
  }

  async run(signal: AbortSignal): Promise<void> {
    try {
      await this.#run(signal);
    } finally {
      // Write what the spool still buffers; losing it only resends events.
      try { this.flush(); } catch { /* Retried by the next write. */ }
    }
  }

  async #run(signal: AbortSignal): Promise<void> {
    const initialBackoffMs = 250;
    let backoffMs = initialBackoffMs;
    // Whether this outage began with a connection that worked dropping.
    let afterDrop = false;
    while (!signal.aborted) {
      this.#establishedSinceConnect = false;
      try {
        await this.#connectOnce(signal);
        if (!signal.aborted) throw new Error("The telemetry server closed the connection.");
      } catch (error) {
        if (signal.aborted) return;
        if (isServiceError(error) && error.code === status.UNAUTHENTICATED) {
          // An administrator removed the computer or revoked its key.
          throw new MachineRemovedError();
        }
        if (error instanceof PermanentTelemetryError) throw error;
        // A connection that completed its handshake ends the outage; the
        // next disconnect (for example a server restart) retries promptly
        // instead of inheriting the longest delay of an earlier outage.
        if (this.#establishedSinceConnect) {
          backoffMs = initialBackoffMs;
          afterDrop = true;
        }
        this.#reconnects++;
        const summary = telemetryErrorSummary(error, this.#config.grpcUrl);
        const waitMs = reconnectDelay(backoffMs, Math.random, afterDrop);
        const now = Date.now();
        const last = this.#lastLoggedFailure;
        if (this.#establishedSinceConnect || last?.summary !== summary || now - last.at >= failureRepeatMs) {
          this.#lastLoggedFailure = { summary, at: now };
          this.#onStatus(`Telemetry disconnected (${summary}); retrying in ${waitMs}ms.`);
        }
        // The first attempt after a connection that worked starts a new
        // outage, so it says it is connecting; the ones after it do not.
        this.#reconnectingQuietly = !this.#establishedSinceConnect;
        await abortableDelay(waitMs, signal);
        backoffMs = Math.min(backoffMs * 2, maxReconnectDelayMs);
      }
    }
  }

  metrics(): ObserverStreamMetrics {
    return Object.freeze({
      reconnects: this.#reconnects,
      acknowledgements: this.#acknowledgements,
      lastAcknowledgedSequence: this.#lastAcknowledgedSequence,
      queue: this.#queue.metrics(),
    });
  }

  async #connectOnce(signal: AbortSignal): Promise<void> {
    const credential = await this.#credentialStore.load();
    if (credential === null) {
      throw new PermanentTelemetryError("Observer is not paired. Run the pair command first.");
    }
    if (credential.grpcOrigin === undefined &&
        credential.controlPlaneOrigin !== DEFAULT_CONTROL_PLANE_ORIGIN &&
        !this.#config.grpcEndpointConfigured) {
      throw new PermanentTelemetryError("This private pairing has no saved telemetry endpoint. Use --grpc-url or PHIGON_GRPC_URL from your workspace setup instructions; keep the existing data directory and queued activity.");
    }
    if (credential.controlPlaneOrigin !== this.#config.controlPlaneUrl.origin ||
        (credential.grpcOrigin !== undefined && credential.grpcOrigin !== this.#config.grpcUrl.origin)) {
      throw new PermanentTelemetryError("Stored machine endpoints do not match this workspace. Refusing to send its credential to a different endpoint. Pair again using the workspace's setup commands.");
    }
    if (signal.aborted) return;
    if (this.#queue instanceof FileBackedEventQueue) {
      try {
        const notice = this.#queue.restore(
          credential.tenantId,
          credential.machineId,
          credential.credential,
        );
        if (notice !== undefined) this.#onStatus(describeSpoolRestore(notice));
      } catch (error) {
        // A damaged, oversized or foreign spool is moved aside by restore.
        // What is left, such as a spool the disk will not let the observer
        // read or rewrite, needs someone to look at the computer.
        throw new PermanentTelemetryError(
          `The local telemetry spool cannot be used (${error instanceof Error ? error.message : "unknown error"}). ` +
            "Keep the data directory and contact your administrator before removing it.",
        );
      }
    }
    const spooledAcknowledgement = this.#queue.metrics().acknowledged;
    const state = await this.#stateStore.load(
      credential.machineId,
      this.#queue instanceof FileBackedEventQueue ? spooledAcknowledgement : undefined,
    );
    if (state.recoveryPending) this.#onStatus("Local stream cursor is unreadable. Waiting for the authenticated server checkpoint before resuming collection.");
    const localAcknowledgement =
      spooledAcknowledgement > state.acknowledgedSequence
        ? spooledAcknowledgement
        : state.acknowledgedSequence;
    if (localAcknowledgement > state.acknowledgedSequence) {
      await this.#stateStore.save(credential.machineId, localAcknowledgement);
    }
    this.#lastAcknowledgedSequence = localAcknowledgement;
    this.#queue.reconcileAcknowledged(localAcknowledgement);

    const client = new Client(
      this.#config.grpcUrl.host,
      channelCredentials(this.#config),
      {
        "grpc.max_receive_message_length": maxMessageBytes,
        "grpc.max_send_message_length": maxMessageBytes,
        "grpc.keepalive_time_ms": 300_000,
        "grpc.keepalive_timeout_ms": 10_000,
        // grpc-js reads grpc_proxy and no_proxy itself, but cannot read a
        // NO_PROXY of "*", which turns the proxy off for every host.
        ...(noProxyForAll(process.env) ? { "grpc.enable_http_proxy": 0 } : {}),
      },
    );
    const metadata = new Metadata();
    metadata.set("authorization", `Bearer ${credential.credential}`);
    metadata.set("traceparent", createTraceParent());
    const stream = client.makeBidiStreamRequest<
      StreamTelemetryRequest,
      StreamTelemetryResponse
    >(
      streamMethod,
      (value) =>
        Buffer.from(toBinary(StreamTelemetryRequestSchema, value)),
      (value) =>
        fromBinary(StreamTelemetryResponseSchema, value),
      metadata,
    );

    if (!this.#reconnectingQuietly) this.#onStatus(`Connecting telemetry to ${this.#config.grpcUrl.origin}…`);
    const abort = () => stream.cancel();
    signal.addEventListener("abort", abort, { once: true });
    let heartbeat: NodeJS.Timeout | undefined;
    let handshake: NodeJS.Timeout | undefined;
    let watchdog: NodeJS.Timeout | undefined;
    let lastResponseAt = Date.now();
    let saveState = Promise.resolve();
    let actionPolicyUpdates = Promise.resolve();
    let historySyncExecutions = Promise.resolve();
    const activeHistorySyncJobs = new Set<string>();
    const connectionAbort = new AbortController();
    let sentThroughSequence = localAcknowledgement;
    const inFlightSequences = new Set<bigint>();
    let waitingForDrain = false;
    let activePolicy: CollectionPolicy | undefined;
    let activeActionPolicy: ActionGuardrailPolicy | undefined;
    let lastPolicyReceiptAt = 0;
    let acknowledgedResume: bigint | undefined;
    let resumeComplete = false;
    const pumpEvents = () => {
      if (
        !resumeComplete ||
        activePolicy === undefined ||
        waitingForDrain ||
        signal.aborted
      ) return;
      const available =
        this.#config.activityMaxInFlightEvents -
        inFlightSequences.size;
      if (available < 1) return;
      for (
        const event of this.#queue.pendingAfter(
          sentThroughSequence,
          available,
        )
      ) {
        const sanitized = sanitizeEventForPolicy(event, activePolicy);
        const writable = stream.write(
          create(StreamTelemetryRequestSchema, {
            payload: { case: "event", value: sanitized },
          }),
        );
        sentThroughSequence = event.sequence;
        inFlightSequences.add(event.sequence);
        if (!writable) {
          waitingForDrain = true;
          stream.once("drain", () => {
            waitingForDrain = false;
            pumpEvents();
          });
          break;
        }
      }
    };
    const completeResume = () => {
      if (
        resumeComplete ||
        activePolicy === undefined ||
        acknowledgedResume === undefined
      ) return;
      resumeComplete = true;
      if (handshake !== undefined) clearTimeout(handshake);
      this.#onStatus("Telemetry stream connected; workspace policy and resume checkpoint received.");
      const queuedHighWatermark = this.#queue.latestSequence();
      this.#markReady(
        queuedHighWatermark !== undefined &&
            queuedHighWatermark > acknowledgedResume
          ? queuedHighWatermark
          : acknowledgedResume,
      );
      sendHeartbeat();
      pumpEvents();
    };
    const sendActionCapabilities = () => {
      if (!resumeComplete || signal.aborted) return;
      const actionManifest = this.#actionExecutor?.manifest() ?? {
        enabled: false,
        executorVersion: "observer-agent-actions-unavailable-v1",
        actions: [],
      };
      stream.write(create(StreamTelemetryRequestSchema, {
        payload: {
          case: "actionCapabilities",
          value: create(ActionCapabilityManifestSchema, {
            machineId: credential.machineId,
            ...actionManifest,
            observedAt: timestampFromDate(new Date()),
          }),
        },
      }));
    };
    const sendHeartbeat = () => {
      if (!resumeComplete || signal.aborted) return;
      const queueMetrics = this.#queue.metrics();
      stream.write(
        create(StreamTelemetryRequestSchema, {
          payload: {
            case: "heartbeat",
            value: create(HeartbeatSchema, {
              machineId: credential.machineId,
              observedAt: timestampFromDate(new Date()),
              uptimeSeconds: BigInt(Math.floor(process.uptime())),
              bufferedEvents: queueMetrics.depth,
              lastSequence:
                this.#queue.latestSequence() ??
                queueMetrics.acknowledged,
              queueCapacity: queueMetrics.capacity,
              droppedEvents: BigInt(queueMetrics.dropped),
              coalescedEvents: BigInt(queueMetrics.coalesced),
              acknowledgedSequence: queueMetrics.acknowledged,
              ...(this.#observerVersion === undefined
                ? {}
                : { observerBuild: create(BuildInfoSchema, { version: this.#observerVersion }) }),
            }),
          },
        }),
      );
      sendActionCapabilities();
      if (
        activeActionPolicy !== undefined &&
        Date.now() - lastPolicyReceiptAt >= policyReceiptRefreshMs
      ) {
        sendPolicyReceipt(
          activeActionPolicy,
          PolicyReceiptState.APPLIED,
        );
      }
    };
    const sendPolicyReceipt = (
      policy: ActionGuardrailPolicy,
      state: PolicyReceiptState,
    ) => {
      stream.write(
        create(StreamTelemetryRequestSchema, {
          payload: {
            case: "policyReceipt",
            value: create(PolicyReceiptSchema, {
              machineId: credential.machineId,
              policyDigest: policy.policyDigest,
              state,
              gatewayVersion: "observer-action-gateway-v2",
              capabilities: state === PolicyReceiptState.APPLIED
                ? [...managedGatewayCapabilities]
                : [],
              containmentEnabled: state === PolicyReceiptState.APPLIED && this.#containmentEnabled,
              containmentCapabilities: state === PolicyReceiptState.APPLIED && this.#containmentEnabled
                ? [...guardianContainmentCapabilities]
                : [],
              ...(state === PolicyReceiptState.REJECTED
                ? { detail: "Local policy validation or persistence failed." }
                : {}),
              receivedAt: timestampFromDate(new Date()),
            }),
          },
        }),
      );
      lastPolicyReceiptAt = Date.now();
    };
    const sendInventory = (inventory: AgentInventory) => {
      stream.write(
        create(StreamTelemetryRequestSchema, {
          payload: { case: "inventory", value: inventory },
        }),
      );
    };
    try {
      await new Promise<void>((resolve, reject) => {
        watchdog = setInterval(() => {
          if (resumeComplete && Date.now() - lastResponseAt > this.#responseTimeoutMs) {
            reject(new Error("Telemetry heartbeat acknowledgement timed out. Reconnecting without discarding queued activity."));
            stream.cancel();
          }
        }, Math.min(1_000, this.#responseTimeoutMs));
        handshake = setTimeout(() => {
          reject(new Error("Telemetry handshake timed out. Check the workspace gRPC endpoint, HTTP/2 proxy support, and firewall."));
          stream.cancel();
        }, this.#handshakeTimeoutMs);
        // The server acknowledges every event. Persisting each one would
        // queue a flushed file replace per event behind the previous one;
        // only the newest acknowledgement matters, so while one save runs
        // later acknowledgements collapse into a single follow-up save.
        let queuedAcknowledgement:
          | Readonly<{ sequence: bigint; commitSourceCheckpoint: boolean }>
          | undefined;
        const persistAcknowledgement = (
          sequence: bigint,
          commitSourceCheckpoint: boolean,
        ) => {
          const alreadyQueued = queuedAcknowledgement !== undefined;
          queuedAcknowledgement = {
            sequence,
            commitSourceCheckpoint:
              commitSourceCheckpoint ||
              (queuedAcknowledgement?.commitSourceCheckpoint ?? false),
          };
          if (alreadyQueued) return;
          const pendingSave = saveState.then(async () => {
            const next = queuedAcknowledgement;
            queuedAcknowledgement = undefined;
            if (next === undefined) return;
            if (next.commitSourceCheckpoint) {
              await this.#onAcknowledgement(next.sequence);
            }
            await this.#stateStore.save(credential.machineId, next.sequence);
            this.#stateSavedAt = Date.now();
          });
          saveState = pendingSave;
          void pendingSave.catch((error: unknown) => {
            reject(error);
            stream.cancel();
          });
        };
        stream.on("data", (response: StreamTelemetryResponse) => {
          lastResponseAt = Date.now();
          const serverTime = response.payload.case === "acknowledgement"
            ? response.payload.value.receivedAt
            : response.payload.case === "policy"
              ? response.payload.value.effectiveAt
              : undefined;
          if (serverTime !== undefined) {
            this.#serverClock?.observe(timestampDate(serverTime));
          }
          if (response.payload.case === "historySyncCommand") {
            const command = response.payload.value;
            const commandKey = `${command.jobId}:${command.idempotencyKey}`;
            if (activeHistorySyncJobs.has(commandKey)) return;
            activeHistorySyncJobs.add(commandKey);
            historySyncExecutions = historySyncExecutions.then(async () => {
              try {
                let receipt: HistorySyncResult;
                try {
                  receipt = this.#onHistorySync === undefined
                    ? rejectedHistorySyncReceipt(
                      command,
                      credential.machineId,
                      "Full-history sync is not available in this observer.",
                    )
                    : await this.#onHistorySync(command);
                } catch (error) {
                  receipt = failedHistorySyncReceipt(
                    command,
                    credential.machineId,
                    safeStatusDetail(
                      error instanceof Error ? error.message : "History sync failed.",
                    ),
                  );
                }
                if (
                  receipt.state === HistorySyncResultState.SUCCEEDED &&
                  receipt.throughSequence > this.#lastAcknowledgedSequence
                ) {
                  await this.#waitForAcknowledgement(
                    receipt.throughSequence,
                    connectionAbort.signal,
                  );
                }
                if (connectionAbort.signal.aborted || signal.aborted) return;
                stream.write(create(StreamTelemetryRequestSchema, {
                  payload: { case: "historySyncResult", value: receipt },
                }));
              } finally {
                activeHistorySyncJobs.delete(commandKey);
              }
            });
            void historySyncExecutions.catch((error: unknown) => {
              reject(error);
              stream.cancel();
            });
            return;
          }
          if (response.payload.case === "actionCommand") {
            const command = response.payload.value;
            // Executors serialize each kind of work and keep durable receipts,
            // so actions run independently here: a stop or force-stop must not
            // wait behind a command that may run for two minutes, and a lost
            // connection must not wait for it before reconnecting. A result
            // that outlives its connection is replayed from the receipt when
            // the control plane redelivers the command.
            const execution = (async () => {
              const receipt = this.#actionExecutor === undefined
                ? disabledActionReceipt(command, credential.machineId)
                : await this.#actionExecutor.execute(command);
              if (signal.aborted || connectionAbort.signal.aborted) return;
              stream.write(create(StreamTelemetryRequestSchema, {
                payload: { case: "actionResult", value: receipt },
              }));
            })();
            void execution.catch((error: unknown) => {
              reject(error);
              stream.cancel();
            });
            return;
          }
          if (response.payload.case === "policy") {
            const snapshot = response.payload.value;
            if (
              snapshot.machineId !== credential.machineId ||
              snapshot.tenantId !== credential.tenantId ||
              snapshot.collection === undefined
            ) {
              reject(
                new PermanentTelemetryError(
                  "Control plane returned an invalid collection policy.",
                ),
              );
              stream.cancel();
              return;
            }
            const collectionPolicy = snapshot.collection;
            activePolicy = collectionPolicy;
            try {
              this.#queue.replacePending((event) =>
                sanitizeEventForPolicy(event, collectionPolicy)
              );
            } catch (error) {
              reject(error);
              stream.cancel();
              return;
            }
            this.#onPolicy(collectionPolicy);
            let generation: number;
            try {
              activeActionPolicy = undefined;
              generation = this.#actionPolicyStore.invalidate(credential.machineId);
            } catch (error) {
              reject(error);
              stream.cancel();
              return;
            }
            if (snapshot.actionGuardrails !== undefined) {
              const actionPolicy = clone(
                ActionGuardrailPolicySchema,
                snapshot.actionGuardrails,
              );
              actionPolicyUpdates = actionPolicyUpdates.then(async () => {
                try {
                  await this.#actionPolicyStore.save(
                    credential.machineId,
                    actionPolicy,
                    generation,
                  );
                } catch (error) {
                  if (error instanceof ActionPolicySupersededError) return;
                  if (!signal.aborted) {
                    sendPolicyReceipt(actionPolicy, PolicyReceiptState.REJECTED);
                    completeResume();
                    pumpEvents();
                  }
                  return;
                }
                if (signal.aborted) return;
                activeActionPolicy = actionPolicy;
                sendPolicyReceipt(
                  actionPolicy,
                  PolicyReceiptState.APPLIED,
                );
                completeResume();
                pumpEvents();
              });
            } else {
              actionPolicyUpdates = actionPolicyUpdates.then(() => {
                if (signal.aborted) return;
                completeResume();
                pumpEvents();
              });
            }
            void actionPolicyUpdates.catch((error: unknown) => {
              reject(error);
              stream.cancel();
            });
            return;
          }
          if (response.payload.case === "acknowledgement") {
            if (response.payload.value.machineId !== credential.machineId) {
              reject(new PermanentTelemetryError("Control plane acknowledgement belongs to a different machine."));
              stream.cancel();
              return;
            }
            const sequence = response.payload.value.throughSequence;
            if (state.recoveryPending && acknowledgedResume === undefined && sequence === this.#lastAcknowledgedSequence) {
              persistAcknowledgement(sequence, false);
            }
            // The first acknowledgement answers the resume; later ones that
            // repeat the checkpoint answer heartbeats.
            const heartbeatAnswer = acknowledgedResume !== undefined;
            acknowledgedResume ??= sequence;
            if (sequence < this.#lastAcknowledgedSequence) {
              try {
                this.#queue.reconcileAcknowledged(sequence);
              } catch (error) {
                reject(error);
                stream.cancel();
                return;
              }
              this.#lastAcknowledgedSequence = sequence;
              sentThroughSequence = sequence;
              inFlightSequences.clear();
              persistAcknowledgement(sequence, false);
              this.#onCursorReset(
                sequence,
                this.#queue.latestSequence() ?? sequence,
              );
              completeResume();
              pumpEvents();
              return;
            }
            if (sequence > this.#lastAcknowledgedSequence) {
              this.#lastAcknowledgedSequence = sequence;
              this.#acknowledgements++;
              try {
                this.#queue.acknowledge(sequence);
              } catch (error) {
                reject(error);
                stream.cancel();
                return;
              }
              for (const sent of inFlightSequences) {
                if (sent <= sequence) inFlightSequences.delete(sent);
              }
              persistAcknowledgement(sequence, true);
            } else if (
              heartbeatAnswer &&
              sequence === this.#lastAcknowledgedSequence &&
              Date.now() - this.#stateSavedAt >= this.#stateRefreshMs
            ) {
              // The server answers every heartbeat with its checkpoint. Saving
              // it now and then, even unchanged, records that this computer
              // is still in touch, which `doctor --check` reads.
              persistAcknowledgement(sequence, false);
            }

            completeResume();
            pumpEvents();
            return;
          }
          if (response.payload.case === "error") {
            const streamError = response.payload.value;
            const message = `Control plane rejected telemetry: ${streamError.message}`;
            if (
              !streamError.retryable &&
              streamError.rejectedSequence > 0n &&
              (streamError.code === StreamErrorCode.INVALID_EVENT ||
                streamError.code === StreamErrorCode.POLICY_VIOLATION)
            ) {
              const rejectedSequence = streamError.rejectedSequence;
              try {
                this.#queue.discard(rejectedSequence);
              } catch (error) {
                reject(error);
                stream.cancel();
                return;
              }
              inFlightSequences.delete(rejectedSequence);
              persistAcknowledgement(rejectedSequence, true);
              this.#onStatus(
                `${message} Quarantined sequence ${rejectedSequence}.`,
              );
              pumpEvents();
              return;
            }
            reject(
              streamError.retryable
                ? new Error(message)
                : new PermanentTelemetryError(message),
            );
            stream.cancel();
          }
        });
        stream.once("error", (error: ServiceError) => {
          if (signal.aborted && error.code === status.CANCELLED) {
            resolve();
            return;
          }
          reject(error);
        });
        stream.once("end", resolve);

        stream.write(
          create(StreamTelemetryRequestSchema, {
            payload: {
              case: "resume",
              value: create(ResumeCursorSchema, {
                machineId: credential.machineId,
                acknowledgedSequence: localAcknowledgement,
              }),
            },
          }),
        );
        sendActionCapabilities();
        this.#sendInventory = sendInventory;
        if (this.#latestInventory !== undefined) {
          sendInventory(this.#latestInventory);
        }
        this.#pumpEvents = pumpEvents;
        heartbeat = setInterval(
          sendHeartbeat,
          this.#config.heartbeatIntervalMs,
        );
      });
      connectionAbort.abort();
      await Promise.all([
        saveState,
        actionPolicyUpdates,
        historySyncExecutions,
      ]);
    } finally {
      connectionAbort.abort();
      if (this.#pumpEvents === pumpEvents) {
        this.#pumpEvents = undefined;
      }
      if (this.#sendInventory === sendInventory) {
        this.#sendInventory = undefined;
      }
      if (heartbeat !== undefined) clearInterval(heartbeat);
      if (handshake !== undefined) clearTimeout(handshake);
      if (watchdog !== undefined) clearInterval(watchdog);
      this.#readySequence = undefined;
      signal.removeEventListener("abort", abort);
      stream.end();
      client.close();
    }
  }

  async #waitForAcknowledgement(
    sequence: bigint,
    signal: AbortSignal,
  ): Promise<void> {
    while (this.#lastAcknowledgedSequence < sequence) {
      if (signal.aborted) {
        throw new Error("Telemetry disconnected before history upload was acknowledged.");
      }
      await abortableDelay(100, signal);
    }
  }

  #markReady(sequence: bigint): void {
    this.#establishedSinceConnect = true;
    this.#reconnectingQuietly = false;
    this.#readySequence = sequence;
    for (const ready of this.#readyWaiters) ready(sequence);
    this.#readyWaiters.clear();
  }
}

function rejectedHistorySyncReceipt(
  command: HistorySyncCommand,
  machineID: string,
  detail: string,
): HistorySyncResult {
  return create(HistorySyncResultSchema, {
    jobId: command.jobId,
    machineId: machineID,
    idempotencyKey: command.idempotencyKey,
    state: HistorySyncResultState.REJECTED,
    detail,
    observedAt: timestampFromDate(new Date()),
  });
}

function failedHistorySyncReceipt(
  command: HistorySyncCommand,
  machineID: string,
  detail: string,
): HistorySyncResult {
  return create(HistorySyncResultSchema, {
    jobId: command.jobId,
    machineId: machineID,
    idempotencyKey: command.idempotencyKey,
    state: HistorySyncResultState.FAILED,
    detail,
    observedAt: timestampFromDate(new Date()),
  });
}

function disabledActionReceipt(
  command: AgentActionCommand,
  machineID: string,
) {
  return create(AgentActionResultSchema, {
    actionId: command.actionId,
    idempotencyKey: command.idempotencyKey,
    machineId: machineID,
    state: RemoteActionResultState.REJECTED,
    resultCode: "executor_disabled",
    detail: "Machine owner has not enabled remote agent actions.",
    observedAt: timestampFromDate(new Date()),
    targetStillRunning: true,
  });
}

const managedGatewayCapabilities = Object.freeze([
  ManagedAction.FILE_READ,
  ManagedAction.FILE_WRITE,
  ManagedAction.FILE_DELETE,
  ManagedAction.COMMAND_EXECUTE,
  ManagedAction.PROCESS_LAUNCH,
  ManagedAction.NETWORK_CONNECT,
  ManagedAction.BROWSER_NAVIGATE,
  ManagedAction.CREDENTIAL_ACCESS,
  ManagedAction.AGENT_START,
  ManagedAction.MODEL_USE,
]);

const guardianContainmentCapabilities = Object.freeze([
  GuardrailIntervention.STOP_AGENT,
  GuardrailIntervention.KILL_AGENT,
]);

function createTraceParent(): string {
  return `00-${randomBytes(16).toString("hex")}-${randomBytes(8).toString("hex")}-01`;
}

class PermanentTelemetryError extends Error {}

/** A plain sentence for the log; it names no activity content. */
export function describeSpoolRestore(notice: SpoolRestoreNotice): string {
  switch (notice.reason) {
    case "other_machine":
      return "Queued activity from an earlier pairing of this computer cannot be " +
        `delivered as this machine; it was moved to ${notice.directory}.`;
    case "damaged":
      return "The queued activity on this computer was damaged and could not be " +
        `read. It was moved to ${notice.directory}, and collection continues ` +
        "with an empty queue.";
    case "over_capacity":
      return `${notice.dropped} queued ${notice.dropped === 1 ? "event" : "events"} ` +
        "did not fit in the activity queue (PHIGON_ACTIVITY_QUEUE_CAPACITY). The " +
        "newest were kept and the oldest were left out.";
  }
}

function telemetryErrorSummary(error: unknown, grpcUrl?: URL): string {
  const plain = grpcUrl === undefined ? undefined : plainTelemetryProblem(error, grpcUrl);
  if (plain !== undefined) return plain;
  if (isServiceError(error)) {
    const codeName = Object.entries(status).find(
      ([, value]) => typeof value === "number" && value === error.code,
    )?.[0];
    const detail = safeStatusDetail(error.details || error.message);
    return `${codeName ?? `gRPC ${error.code}`}: ${detail}`;
  }
  if (error instanceof Error) return safeStatusDetail(error.message);
  return "unknown transport error";
}

/**
 * What grpc-js reports in its own words, said plainly where a person can
 * act on it: a relay that closed the connection because the server is not
 * connected to it, or a certificate re-signed on the way. Undefined for
 * anything else.
 */
export function plainTelemetryProblem(error: unknown, grpcUrl: URL): string | undefined {
  const text = error instanceof Error ? `${(error as Partial<ServiceError>).details ?? ""} ${error.message}` : "";
  if (/unable to verify|unable to get (?:local )?issuer|self[- ]signed certificate|certificate signature failure/iu.test(text)) {
    return inspectionMessage(grpcUrl).replace(/\.$/u, "");
  }
  if (relayHost(grpcUrl.hostname) && /ECONNRESET|socket disconnected before secure TLS|socket hang up/iu.test(text)) {
    return relayNotConnectedMessage.replace(/\.$/u, "");
  }
  return undefined;
}

function safeStatusDetail(value: string): string {
  const detail = value.replace(/[\r\n\t]+/gu, " ").trim();
  if (!detail) return "no error detail";
  return detail.length <= 180 ? detail : `${detail.slice(0, 177)}...`;
}

export function sanitizeEventForPolicy(
  event: EventEnvelope,
  policy: CollectionPolicy,
): EventEnvelope {
  const metadataCategory = disabledMetadataCategory(event, policy);
  if (metadataCategory !== undefined) {
    return policyRedactedMetadataEvent(event, metadataCategory);
  }
  const sanitized = clone(EventEnvelopeSchema, event);
  const policyEngine = new LocalPolicyEngine(policy);
  switch (sanitized.payload.case) {
    case "activity": {
      const activity = sanitized.payload.value;
      const contentAllowed =
        (activity.kind === ActivityKind.PROMPT &&
          policy.promptContent) ||
        (activity.kind === ActivityKind.RESPONSE &&
          policy.responseContent) ||
        (activity.kind === ActivityKind.REASONING &&
          policy.reasoningContent);
      if (!contentAllowed) {
        delete activity.content;
        activity.contentRedacted = true;
      }
      for (const resource of activity.resources) {
        sanitizeResource(resource, policy);
      }
      break;
    }
    case "tool": {
      const tool = sanitized.payload.value;
      if (!policy.commandArguments) {
        delete tool.argumentsJson;
        tool.argumentsRedacted = true;
      } else if (tool.argumentsJson !== undefined) {
        const value = sanitizeQueuedJSON(
          policyEngine,
          tool.argumentsJson,
          "commandArguments",
        );
        if (value.value === undefined) delete tool.argumentsJson;
        else tool.argumentsJson = value.value;
        tool.argumentsRedacted ||= value.redacted || value.truncated;
      }
      if (!policy.toolOutput) {
        delete tool.output;
        tool.outputRedacted = true;
      } else if (tool.output !== undefined) {
        const value = sanitizeQueuedJSON(
          policyEngine,
          tool.output,
          "toolOutput",
        );
        if (value.value === undefined) delete tool.output;
        else tool.output = value.value;
        tool.outputRedacted ||= value.redacted || value.truncated;
      }
      for (const resource of tool.resources) {
        sanitizeResource(resource, policy);
      }
      break;
    }
    case "terminal": {
      const terminal = sanitized.payload.value;
      if (!policy.commandArguments) delete terminal.arguments;
      if (!policy.terminalOutput) {
        delete terminal.output;
        terminal.outputRedacted = true;
      }
      break;
    }
    case "filesystem": {
      const filesystem = sanitized.payload.value;
      if (!policy.fileContent) {
        delete filesystem.content;
        filesystem.contentRedacted = true;
      }
      if (filesystem.resource !== undefined) {
        sanitizeResource(filesystem.resource, policy);
      }
      break;
    }
    case "browser": {
      const browser = sanitized.payload.value;
      if (!policy.browserUrls) delete browser.url;
      if (!policy.browserContent) {
        delete browser.target;
        browser.contentRedacted = true;
      }
      break;
    }
    case "git": {
      const git = sanitized.payload.value;
      if (!policy.gitPatchContent) {
        delete git.patch;
        git.patchRedacted = true;
      }
      break;
    }
    case "vendor": {
      const vendor = sanitized.payload.value;
      if (!policy.vendorPayload) {
        delete vendor.payloadJson;
        vendor.payloadOmitted = true;
        vendor.payloadRedacted = true;
        vendor.payloadTruncated = false;
        vendor.redactedFields = [];
      } else if (vendor.payloadJson !== undefined) {
        const value = sanitizeQueuedVendor(
          policyEngine,
          vendor.payloadJson,
        );
        if (value.value === undefined) {
          delete vendor.payloadJson;
          vendor.payloadOmitted = true;
        } else {
          vendor.payloadJson = value.value;
        }
        vendor.payloadRedacted ||= value.redacted;
        vendor.payloadTruncated ||= value.truncated;
        vendor.redactedFields = Array.from(
          new Set([
            ...vendor.redactedFields,
            ...value.redactedFields,
          ]),
        ).slice(0, 256);
      }
      break;
    }
    case "process": {
      const processEvent = sanitized.payload.value;
      if (!policy.processArguments) {
        delete processEvent.arguments;
        processEvent.argumentsRedacted = true;
      }
      break;
    }
    case "lifecycle":
    case undefined:
      break;
  }
  return sanitized;
}

function disabledMetadataCategory(
  event: EventEnvelope,
  policy: CollectionPolicy,
): "process" | "filesystem" | "browser" | undefined {
  switch (event.payload.case) {
    case "process":
      return policy.processMetadata ? undefined : "process";
    case "filesystem":
      return policy.fileMetadata ? undefined : "filesystem";
    case "browser":
      return policy.browserMetadata ? undefined : "browser";
    default:
      return undefined;
  }
}

function policyRedactedMetadataEvent(
  event: EventEnvelope,
  category: "process" | "filesystem" | "browser",
): EventEnvelope {
  const sanitized = clone(EventEnvelopeSchema, event);
  sanitized.privacyClass = PrivacyClass.SYSTEM_METADATA;
  sanitized.payload = {
    case: "vendor",
    value: create(VendorEventSchema, {
      source: "phigon-observer",
      vendorType: `${category}-metadata-redacted`,
      sourceRecordDigest: createHash("sha256")
        .update(toBinary(EventEnvelopeSchema, event))
        .digest("hex"),
      payloadRedacted: true,
      payloadOmitted: true,
    }),
  };
  return sanitized;
}

function sanitizeQueuedJSON(
  policy: LocalPolicyEngine,
  value: string,
  category: "commandArguments" | "toolOutput",
) {
  try {
    return policy.json(JSON.parse(value), category);
  } catch {
    return {
      value: undefined,
      redacted: true,
      truncated: false,
    } as const;
  }
}

function sanitizeQueuedVendor(
  policy: LocalPolicyEngine,
  value: string,
) {
  try {
    return policy.vendorRecord(JSON.parse(value));
  } catch {
    return {
      value: undefined,
      redacted: true,
      truncated: false,
      redactedFields: [],
    } as const;
  }
}

function sanitizeResource(
  resource: ResourceReference,
  policy: CollectionPolicy,
): void {
  const identifierAllowed =
    ((resource.kind === "file" ||
      resource.kind === "directory" ||
      resource.kind === "repository") &&
      policy.filePaths) ||
    ((resource.kind === "url" || resource.kind === "origin") &&
      policy.browserUrls) ||
    (resource.kind === "network" && policy.networkEndpoints);
  if (!identifierAllowed) delete resource.identifier;
}

/**
 * After a connection that worked drops, the first attempts wait anywhere
 * up to this long: every computer behind a server or relay that restarted
 * lost it at the same moment, and would otherwise come back in waves.
 */
export const dropSpreadMs = 5_000;

/**
 * The wait before a reconnect attempt: up to a quarter less than the
 * backoff, at random, so computers that lost the same server do not all
 * try at once, and never longer than the backoff, so a computer is back
 * within a minute of the server. After a connection that worked dropped
 * (`afterDrop`), the attempts whose backoff is still under five seconds
 * wait any time up to five seconds instead.
 */
export function reconnectDelay(backoffMs: number, random: () => number = Math.random, afterDrop = false): number {
  if (afterDrop && backoffMs < dropSpreadMs) return Math.floor(random() * dropSpreadMs);
  return backoffMs - Math.floor(random() * backoffMs / 4);
}

let ipServerNameWarningMuted = false;

/**
 * grpc-js always sends the server's host as the TLS server name, even an IP
 * address such as a company's own Phigon server on its network, and Node.js
 * warns once that this is deprecated (DEP0123). The certificate is checked
 * against the address either way, so that one warning is left out of the
 * log; every other warning is shown as usual.
 */
export function muteIpServerNameWarning(): void {
  if (ipServerNameWarningMuted) return;
  ipServerNameWarningMuted = true;
  const emitWarning = process.emitWarning.bind(process) as (...args: unknown[]) => void;
  process.emitWarning = ((...args: unknown[]) => {
    const [, typeOrOptions, code] = args;
    const warningCode = typeof typeOrOptions === "object" && typeOrOptions !== null && "code" in typeOrOptions
      ? typeOrOptions.code
      : code;
    if (warningCode === "DEP0123") return;
    emitWarning(...args);
  }) as typeof process.emitWarning;
}

function channelCredentials(config: ObserverConfig) {
  if (config.grpcUrl.protocol === "https:") {
    if (isIP(config.grpcUrl.hostname.replace(/^\[|\]$/gu, "")) !== 0) muteIpServerNameWarning();
    const rootCertificates = config.tlsCaFile === undefined
      ? undefined
      : readFileSync(config.tlsCaFile);
    const privateKey = config.tlsClientKeyFile === undefined
      ? undefined
      : readFileSync(config.tlsClientKeyFile);
    const certificateChain = config.tlsClientCertFile === undefined
      ? undefined
      : readFileSync(config.tlsClientCertFile);
    return credentials.createSsl(
      rootCertificates,
      privateKey,
      certificateChain,
    );
  }
  return credentials.createInsecure();
}

function isServiceError(error: unknown): error is ServiceError {
  return error instanceof Error && "code" in error;
}

/**
 * The version a heartbeat reports: printable ASCII of at most 64 bytes, as
 * the protocol allows. Anything else is left out rather than sent.
 */
function reportableVersion(version: string | undefined): string | undefined {
  const value = version?.trim() ?? "";
  return /^[!-~]{1,64}$/u.test(value) ? value : undefined;
}
