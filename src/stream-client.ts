import {
  Client,
  Metadata,
  credentials,
  status,
  type ServiceError,
} from "@grpc/grpc-js";
import { createHash, randomBytes } from "node:crypto";
import { readFileSync } from "node:fs";
import {
  clone,
  create,
  fromBinary,
  toBinary,
} from "@bufbuild/protobuf";
import { timestampFromDate } from "@bufbuild/protobuf/wkt";
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
import { FileBackedEventQueue } from "./event-spool.js";
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
  PrivacyClass,
} from "./generated/phigon/v1/common_pb.js";
import {
  EventEnvelopeSchema,
  VendorEventSchema,
  type EventEnvelope,
  type ResourceReference,
} from "./generated/phigon/v1/telemetry_pb.js";
import { StreamStateStore } from "./stream-state.js";

type StreamStatePersistence = Pick<StreamStateStore, "load" | "save">;

const streamMethod =
  "/phigon.v1.ObserverService/StreamTelemetry";
const maxMessageBytes = 1 << 20;
const policyReceiptRefreshMs = 5 * 60 * 1_000;

export type ObserverStreamMetrics = Readonly<{
  reconnects: number;
  acknowledgements: number;
  lastAcknowledgedSequence: bigint;
  queue: QueueMetrics;
}>;

export type StreamClientOptions = Readonly<{
  config: ObserverConfig;
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
  actionExecutor?: AgentActionExecutor;
  onHistorySync?: (command: HistorySyncCommand) => Promise<HistorySyncResult>;
  handshakeTimeoutMs?: number;
  responseTimeoutMs?: number;
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
  readonly #actionExecutor: AgentActionExecutor | undefined;
  readonly #onHistorySync:
    | ((command: HistorySyncCommand) => Promise<HistorySyncResult>)
    | undefined;
  #reconnects = 0;
  #acknowledgements = 0;
  #lastAcknowledgedSequence = 0n;
  #pumpEvents: (() => void) | undefined;
  #latestInventory: AgentInventory | undefined;
  #sendInventory: ((inventory: AgentInventory) => void) | undefined;
  #readySequence: bigint | undefined;
  readonly #readyWaiters = new Set<(sequence: bigint) => void>();
  readonly #handshakeTimeoutMs: number;
  readonly #responseTimeoutMs: number;

  constructor(options: StreamClientOptions) {
    this.#handshakeTimeoutMs = options.handshakeTimeoutMs ?? 20_000;
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
    let backoffMs = 250;
    while (!signal.aborted) {
      try {
        await this.#connectOnce(signal);
        if (!signal.aborted) throw new Error("The telemetry server closed the connection.");
      } catch (error) {
        if (signal.aborted) return;
        if (isServiceError(error) && error.code === status.UNAUTHENTICATED) {
          throw new Error("Machine credential was rejected. Generate a new pairing code in your workspace and pair again; keep the existing data directory.");
        }
        if (error instanceof PermanentTelemetryError) throw error;
        this.#reconnects++;
        this.#onStatus(
          `Telemetry disconnected (${telemetryErrorSummary(error)}); ` +
            `retrying in ${backoffMs}ms.`,
        );
        await abortableDelay(backoffMs + Math.floor(Math.random() * backoffMs / 4), signal);
        backoffMs = Math.min(backoffMs * 2, 10_000);
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
        this.#queue.restore(
          credential.tenantId,
          credential.machineId,
          credential.credential,
        );
      } catch (error) {
        // Retrying cannot repair a corrupt, oversized or foreign spool; stop
        // and say so instead of reconnecting forever with nothing delivered.
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

    this.#onStatus(`Connecting telemetry to ${this.#config.grpcUrl.origin}…`);
    const abort = () => stream.cancel();
    signal.addEventListener("abort", abort, { once: true });
    let heartbeat: NodeJS.Timeout | undefined;
    let handshake: NodeJS.Timeout | undefined;
    let watchdog: NodeJS.Timeout | undefined;
    let lastResponseAt = Date.now();
    let saveState = Promise.resolve();
    let actionPolicyUpdates = Promise.resolve();
    let actionExecutions = Promise.resolve();
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
              containmentEnabled: state === PolicyReceiptState.APPLIED,
              containmentCapabilities: state === PolicyReceiptState.APPLIED
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
        const persistAcknowledgement = (
          sequence: bigint,
          commitSourceCheckpoint: boolean,
        ) => {
          const pendingSave = saveState.then(async () => {
            if (commitSourceCheckpoint) {
              await this.#onAcknowledgement(sequence);
            }
            await this.#stateStore.save(credential.machineId, sequence);
          });
          saveState = pendingSave;
          void pendingSave.catch((error: unknown) => {
            reject(error);
            stream.cancel();
          });
        };
        stream.on("data", (response: StreamTelemetryResponse) => {
          lastResponseAt = Date.now();
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
            actionExecutions = actionExecutions.then(async () => {
              const receipt = this.#actionExecutor === undefined
                ? disabledActionReceipt(command, credential.machineId)
                : await this.#actionExecutor.execute(command);
              if (signal.aborted) return;
              stream.write(create(StreamTelemetryRequestSchema, {
                payload: { case: "actionResult", value: receipt },
              }));
            });
            void actionExecutions.catch((error: unknown) => {
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
        actionExecutions,
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

function telemetryErrorSummary(error: unknown): string {
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

function channelCredentials(config: ObserverConfig) {
  if (config.grpcUrl.protocol === "https:") {
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

async function abortableDelay(
  milliseconds: number,
  signal: AbortSignal,
): Promise<void> {
  if (signal.aborted) return;
  await new Promise<void>((resolve) => {
    const timeout = setTimeout(resolve, milliseconds);
    signal.addEventListener(
      "abort",
      () => {
        clearTimeout(timeout);
        resolve();
      },
      { once: true },
    );
  });
}
