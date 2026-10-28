import assert from "node:assert/strict";
import {
  Server,
  ServerCredentials,
  type ServerDuplexStream,
  type ServiceDefinition,
  type UntypedServiceImplementation,
} from "@grpc/grpc-js";
import {
  create,
  fromBinary,
  type MessageInitShape,
  toBinary,
} from "@bufbuild/protobuf";
import { timestampFromDate } from "@bufbuild/protobuf/wkt";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { loadConfig } from "../src/config.js";
import { FileActionPolicyStore } from "../src/action-policy.js";
import type {
  CredentialStore,
  StoredMachineCredential,
} from "../src/credential-store.js";
import { BoundedEventQueue } from "../src/event-queue.js";
import { FileBackedEventQueue } from "../src/event-spool.js";
import { PrivacyClass } from "../src/generated/phigon/v1/common_pb.js";
import {
  AgentInventorySchema,
  type AgentInventory,
} from "../src/generated/phigon/v1/identity_pb.js";
import {
  HistorySyncCommandSchema,
  HistorySyncResultSchema,
  HistorySyncResultState,
} from "../src/generated/phigon/v1/history_sync_pb.js";
import {
  AcknowledgementSchema,
  StreamErrorCode,
  StreamErrorSchema,
  StreamTelemetryRequestSchema,
  StreamTelemetryResponseSchema,
  type StreamTelemetryRequest,
  type StreamTelemetryResponse,
} from "../src/generated/phigon/v1/observer_service_pb.js";
import {
  ActionGuardrailPolicySchema,
  ActionGuardrailRuleSchema,
  CollectionPolicySchema,
  GuardrailEffect,
  ManagedAction,
  PolicySnapshotSchema,
} from "../src/generated/phigon/v1/policy_pb.js";
import {
  BrowserEventSchema,
  EventEnvelopeSchema,
  FilesystemEventSchema,
  LifecycleEventSchema,
  LifecyclePhase,
  ProcessEventSchema,
  ResourceReferenceSchema,
  ToolEventSchema,
  ToolPhase,
  VendorEventSchema,
  type EventEnvelope,
} from "../src/generated/phigon/v1/telemetry_pb.js";
import {
  ObserverStreamClient,
  sanitizeEventForPolicy,
} from "../src/stream-client.js";
import { StreamStateStore } from "../src/stream-state.js";

test("a corrupt local cursor resumes from the authenticated server before capturing new events", async () => {
  const dataDirectory = await mkdtemp(join(tmpdir(), "phigon-stream-recovery-"));
  const machineId = "5f1b4cb4-a77d-4f53-af66-197e184683f4";
  const server = new Server();
  const controller = new AbortController();
  const received: bigint[] = [];
  let resumed: bigint | undefined;
  server.addService(observerServiceDefinition, {
    streamTelemetry(call: ServerDuplexStream<StreamTelemetryRequest, StreamTelemetryResponse>) {
      call.on("data", (request: StreamTelemetryRequest) => {
        if (request.payload.case === "resume") {
          resumed = request.payload.value.acknowledgedSequence;
          call.write(policySnapshot(machineId));
          call.write(acknowledgement(machineId, 429n));
        }
        if (request.payload.case === "event") {
          received.push(request.payload.value.sequence);
          call.write(acknowledgement(machineId, request.payload.value.sequence));
        }
      });
      call.on("end", () => call.end());
    },
  });
  const port = await bindServer(server);
  await writeFile(join(dataDirectory, "stream-state.json"), "\u0000".repeat(128));
  const client = new ObserverStreamClient({
    config: streamConfig(dataDirectory, port), credentialStore: testCredentialStore(machineId),
    onAcknowledgement: (sequence) => { if (sequence === 430n) setTimeout(() => controller.abort(), 20); },
  });
  const deadline = setTimeout(() => controller.abort(), 5000);
  try {
    const ready = client.waitUntilReady(controller.signal);
    const running = client.run(controller.signal);
    assert.equal(await ready, 429n);
    client.enqueue(lifecycleEvent(machineId, 430n));
    await running;
    assert.equal(resumed, 0n);
    assert.deepEqual(received, [430n]);
    assert.equal((await new StreamStateStore(dataDirectory).load(machineId)).acknowledgedSequence, 430n);
    assert.equal(client.metrics().queue.dropped, 0);
  } finally {
    clearTimeout(deadline); controller.abort();
    await shutdownServer(server);
    await rm(dataDirectory, { recursive: true, force: true });
  }
});

test("queued metadata is replaced locally when its policy is revoked", () => {
  const common = {
    tenantId: "7d1b4cb4-a77d-4f53-af66-197e184683f4",
    machineId: "5f1b4cb4-a77d-4f53-af66-197e184683f4",
    agentId: "agent-test",
    sessionId: "session-test",
    observedAt: timestampFromDate(new Date()),
    schemaVersion: 1,
    privacyClass: PrivacyClass.RESOURCE_METADATA,
  };
  const queued = [
    create(EventEnvelopeSchema, {
      ...common,
      sequence: 1n,
      payload: {
        case: "process",
        value: create(ProcessEventSchema, {
          arguments: "--token process-private-value",
        }),
      },
    }),
    create(EventEnvelopeSchema, {
      ...common,
      sequence: 2n,
      payload: {
        case: "filesystem",
        value: create(FilesystemEventSchema, {
          resource: create(ResourceReferenceSchema, {
            kind: "file",
            displayName: "private file",
            identifierDigest: "a".repeat(64),
            identifier: "/queued/private/file.txt",
          }),
          content: Buffer.from("filesystem-private-value"),
        }),
      },
    }),
    create(EventEnvelopeSchema, {
      ...common,
      sequence: 3n,
      payload: {
        case: "browser",
        value: create(BrowserEventSchema, {
          url: "https://private.example/queued",
          urlDigest: "b".repeat(64),
          target: "browser-private-value",
        }),
      },
    }),
  ];
  const policy = create(CollectionPolicySchema);

  for (const event of queued) {
    const originalCase = event.payload.case;
    const sanitized = sanitizeEventForPolicy(event, policy);
    assert.equal(sanitized.sequence, event.sequence);
    assert.equal(sanitized.privacyClass, PrivacyClass.SYSTEM_METADATA);
    assert.equal(sanitized.payload.case, "vendor");
    if (sanitized.payload.case !== "vendor") {
      assert.fail("revoked metadata was not replaced");
    }
    assert.equal(sanitized.payload.value.source, "phigon-observer");
    assert.equal(
      sanitized.payload.value.vendorType,
      `${originalCase}-metadata-redacted`,
    );
    assert.match(
      sanitized.payload.value.sourceRecordDigest,
      /^[a-f0-9]{64}$/u,
    );
    assert.equal(sanitized.payload.value.payloadOmitted, true);
    assert.equal(sanitized.payload.value.payloadRedacted, true);
    const wire = Buffer.from(
      toBinary(EventEnvelopeSchema, sanitized),
    ).toString("utf8");
    assert.doesNotMatch(
      wire,
      /process-private|queued\/private|filesystem-private|private\.example|browser-private/u,
    );
  }
});

test("observer reconciles a restored server cursor and persists new acknowledgements", async () => {
  const dataDirectory = await mkdtemp(join(tmpdir(), "phigon-stream-"));
  const machineId = "5f1b4cb4-a77d-4f53-af66-197e184683f4";
  const server = new Server();
  const controller = new AbortController();
  let resumeSequence = -1n;
  let serverSequence = 2n;
  let receivedEventSequence = -1n;
  let receivedInventory = false;
  let receivedVendorPolicy = false;
  const heartbeatMetrics: Array<{
    queueCapacity: number;
    droppedEvents: bigint;
    coalescedEvents: bigint;
    acknowledgedSequence: bigint;
  }> = [];
  let client: ObserverStreamClient | undefined;
  let liveEvent: EventEnvelope | undefined;
  let liveInventory: AgentInventory | undefined;

  const implementation: UntypedServiceImplementation = {
    streamTelemetry(
      call: ServerDuplexStream<
        StreamTelemetryRequest,
        StreamTelemetryResponse
      >,
    ) {
      assert.equal(
        call.metadata.get("authorization")[0],
        "Bearer phg_m_0123456789012345678901234567890123456789012",
      );
      call.on("data", (request: StreamTelemetryRequest) => {
        if (request.payload.case === "resume") {
          resumeSequence =
            request.payload.value.acknowledgedSequence;
          call.write(policySnapshot(machineId));
          setTimeout(() => {
            call.write(acknowledgement(machineId, serverSequence));
          }, 25);
        }
        if (request.payload.case === "heartbeat") {
          heartbeatMetrics.push({
            queueCapacity: request.payload.value.queueCapacity,
            droppedEvents: request.payload.value.droppedEvents,
            coalescedEvents: request.payload.value.coalescedEvents,
            acknowledgedSequence:
              request.payload.value.acknowledgedSequence,
          });
          call.write(acknowledgement(machineId, serverSequence));
          if (liveEvent !== undefined) {
            client?.enqueue(liveEvent);
          }
          if (liveInventory !== undefined) {
            client?.updateInventory(liveInventory);
          }
        }
        if (request.payload.case === "inventory") {
          receivedInventory =
            request.payload.value.machineId === machineId;
        }
        if (request.payload.case === "event") {
          receivedEventSequence = request.payload.value.sequence;
          serverSequence = receivedEventSequence;
          call.write(
            acknowledgement(machineId, receivedEventSequence),
          );
          setTimeout(() => controller.abort(), 100);
        }
      });
      call.on("end", () => call.end());
    },
  };
  server.addService(observerServiceDefinition, implementation);
  const port = await new Promise<number>((resolve, reject) => {
    server.bindAsync(
      "127.0.0.1:0",
      ServerCredentials.createInsecure(),
      (error, boundPort) => {
        if (error) reject(error);
        else resolve(boundPort);
      },
    );
  });

  try {
    const config = loadConfig({
      PHIGON_CONTROL_PLANE_URL: "http://127.0.0.1:8080",
      PHIGON_GRPC_URL: `http://127.0.0.1:${port}`,
      PHIGON_DATA_DIR: dataDirectory,
      PHIGON_HEARTBEAT_INTERVAL_MS: "1000",
    });
    const stateStore = new StreamStateStore(dataDirectory);
    await stateStore.save(machineId, 5n);
    const queue = new BoundedEventQueue<EventEnvelope>(4);
    liveEvent = create(EventEnvelopeSchema, {
      tenantId: "tenant-test",
      machineId,
      agentId: "agent-test",
      sessionId: "session-test",
      sequence: 3n,
      observedAt: timestampFromDate(new Date()),
      schemaVersion: 1,
      privacyClass: PrivacyClass.SYSTEM_METADATA,
      payload: {
        case: "lifecycle",
        value: create(LifecycleEventSchema, {
          phase: LifecyclePhase.STARTED,
          reason: "test event",
        }),
      },
    });
    liveInventory = create(AgentInventorySchema, {
      machineId,
      observedAt: timestampFromDate(new Date()),
      agents: [],
      partial: false,
      notices: ["adapter=fixture;status=healthy"],
    });
    client = new ObserverStreamClient({
      config,
      credentialStore: new StaticCredentialStore({
        machineId,
        tenantId: "7d1b4cb4-a77d-4f53-af66-197e184683f4",
        credential:
          "phg_m_0123456789012345678901234567890123456789012",
        controlPlaneOrigin: "http://127.0.0.1:8080",
        createdAt: new Date().toISOString(),
      }),
      stateStore,
      queue,
      onPolicy: (policy) => {
        receivedVendorPolicy = policy.vendorPayload;
      },
    });

    const ready = client.waitUntilReady(controller.signal);
    const running = client.run(controller.signal);
    assert.equal(await ready, 2n);
    await running;

    assert.equal(resumeSequence, 5n);
    assert.equal(receivedEventSequence, 3n);
    assert.equal(receivedInventory, true);
    assert.equal(receivedVendorPolicy, true);
    assert.deepEqual(heartbeatMetrics[0], {
      queueCapacity: 4,
      droppedEvents: 0n,
      coalescedEvents: 0n,
      acknowledgedSequence: 2n,
    });
    assert.equal(
      heartbeatMetrics.some(
        (metrics) => metrics.acknowledgedSequence === 5n,
      ),
      false,
    );
    assert.equal(
      (await stateStore.load(machineId)).acknowledgedSequence,
      3n,
    );
    assert.equal(client.metrics().queue.depth, 0);
    assert.ok(client.metrics().acknowledgements >= 1);
  } finally {
    await new Promise<void>((resolve) => {
      server.tryShutdown(() => resolve());
    });
    await rm(dataDirectory, { recursive: true, force: true });
  }
});

test("observer validates, persists, and acknowledges managed action policy", async () => {
  const dataDirectory = await mkdtemp(join(tmpdir(), "phigon-action-stream-"));
  const machineId = "5f1b4cb4-a77d-4f53-af66-197e184683f4";
  const digest = "a".repeat(64);
  const server = new Server();
  const controller = new AbortController();
  let receiptState = -1;
  let receiptCapabilities: readonly ManagedAction[] = [];
  const implementation: UntypedServiceImplementation = {
    streamTelemetry(
      call: ServerDuplexStream<StreamTelemetryRequest, StreamTelemetryResponse>,
    ) {
      call.on("data", (request: StreamTelemetryRequest) => {
        if (request.payload.case === "resume") {
          const response = policySnapshot(machineId);
          if (response.payload.case !== "policy") assert.fail("policy fixture missing");
          response.payload.value.actionGuardrails = create(ActionGuardrailPolicySchema, {
            policyDigest: digest,
            defaultEffect: "allow",
            rules: [create(ActionGuardrailRuleSchema, {
              ruleId: "72b1f93f-6317-46c7-bbba-6174d19c4119",
              action: ManagedAction.FILE_DELETE,
              effect: GuardrailEffect.DENY,
              resourcePattern: "**",
              reason: "Prevent managed deletion.",
            })],
          });
          call.write(response);
          call.write(acknowledgement(machineId, 0n));
        }
        if (request.payload.case === "policyReceipt") {
          receiptState = request.payload.value.state;
          receiptCapabilities = request.payload.value.capabilities;
          setTimeout(() => controller.abort(), 20);
        }
      });
      call.on("end", () => call.end());
    },
  };
  server.addService(observerServiceDefinition, implementation);
  const port = await bindServer(server);
  const client = new ObserverStreamClient({
    config: streamConfig(dataDirectory, port),
    credentialStore: testCredentialStore(machineId),
  });
  try {
    await client.run(controller.signal);
    const stored = await new FileActionPolicyStore(dataDirectory).load(machineId);
    assert.equal(stored?.policyDigest, digest);
    assert.equal(receiptState, 1);
    assert.ok(receiptCapabilities.includes(ManagedAction.FILE_DELETE));
  } finally {
    controller.abort();
    await shutdownServer(server);
    await rm(dataDirectory, { recursive: true, force: true });
  }
});

test("observer reports centrally authorized containment without a local override", async () => {
  const dataDirectory = await mkdtemp(join(tmpdir(), "phigon-action-disabled-"));
  const machineId = "5f1b4cb4-a77d-4f53-af66-197e184683f4";
  const server = new Server();
  const controller = new AbortController();
  let receiptState = -1;
  let receiptDetail = "";
  let capabilityCount = -1;
  const implementation: UntypedServiceImplementation = {
    streamTelemetry(
      call: ServerDuplexStream<StreamTelemetryRequest, StreamTelemetryResponse>,
    ) {
      call.on("data", (request: StreamTelemetryRequest) => {
        if (request.payload.case === "resume") {
          const response = policySnapshot(machineId);
          if (response.payload.case !== "policy") assert.fail("policy fixture missing");
          response.payload.value.actionGuardrails = create(ActionGuardrailPolicySchema, {
            policyDigest: "b".repeat(64),
            defaultEffect: "allow",
            rules: [create(ActionGuardrailRuleSchema, {
              ruleId: "72b1f93f-6317-46c7-bbba-6174d19c4119",
              action: ManagedAction.FILE_DELETE,
              effect: GuardrailEffect.DENY,
              resourcePattern: "**",
              reason: "Prevent managed deletion.",
              sourceText: "Do not delete files.",
            })],
          });
          call.write(response);
          call.write(acknowledgement(machineId, 0n));
        }
        if (request.payload.case === "policyReceipt") {
          receiptState = request.payload.value.state;
          receiptDetail = request.payload.value.detail;
          capabilityCount = request.payload.value.capabilities.length;
          setTimeout(() => controller.abort(), 20);
        }
      });
      call.on("end", () => call.end());
    },
  };
  server.addService(observerServiceDefinition, implementation);
  const port = await bindServer(server);
  const client = new ObserverStreamClient({
    config: streamConfig(dataDirectory, port),
    credentialStore: testCredentialStore(machineId),

  });
  try {
    await client.run(controller.signal);
    assert.equal(receiptState, 1);
    assert.equal(receiptDetail, "");
    assert.equal(capabilityCount, 10);
  } finally {
    controller.abort();
    await shutdownServer(server);
    await rm(dataDirectory, { recursive: true, force: true });
  }
});

test("observer renews the owner action capability manifest on heartbeats", async () => {
  const dataDirectory = await mkdtemp(join(tmpdir(), "phigon-action-capabilities-"));
  const machineId = "5f1b4cb4-a77d-4f53-af66-197e184683f4";
  const server = new Server();
  const controller = new AbortController();
  let manifests = 0;
  const implementation: UntypedServiceImplementation = {
    streamTelemetry(
      call: ServerDuplexStream<StreamTelemetryRequest, StreamTelemetryResponse>,
    ) {
      call.on("data", (request: StreamTelemetryRequest) => {
        if (request.payload.case === "resume") {
          call.write(policySnapshot(machineId));
          call.write(acknowledgement(machineId, 0n));
        }
        if (request.payload.case === "actionCapabilities") {
          manifests += 1;
          assert.equal(request.payload.value.machineId, machineId);
          assert.equal(request.payload.value.enabled, false);
          if (manifests === 2) controller.abort();
        }
      });
      call.on("end", () => call.end());
    },
  };
  server.addService(observerServiceDefinition, implementation);
  const port = await bindServer(server);
  const client = new ObserverStreamClient({
    config: streamConfig(dataDirectory, port),
    credentialStore: testCredentialStore(machineId),
  });
  try {
    await client.run(controller.signal);
    assert.equal(manifests, 2);
  } finally {
    controller.abort();
    await shutdownServer(server);
    await rm(dataDirectory, { recursive: true, force: true });
  }
});

test("observer reports successful history sync only after uploaded events are acknowledged", async () => {
  const dataDirectory = await mkdtemp(join(tmpdir(), "phigon-history-sync-"));
  const machineId = "5f1b4cb4-a77d-4f53-af66-197e184683f4";
  const tenantId = "7d1b4cb4-a77d-4f53-af66-197e184683f4";
  const jobId = "47d0ce9f-2905-4304-bef0-39a445466004";
  const idempotencyKey = "895873f8-5cf6-48c9-b8dc-dc9f8cdbf603";
  const server = new Server();
  const controller = new AbortController();
  const order: string[] = [];
  let historySyncCalls = 0;
  let historySyncResults = 0;
  const implementation: UntypedServiceImplementation = {
    streamTelemetry(
      call: ServerDuplexStream<StreamTelemetryRequest, StreamTelemetryResponse>,
    ) {
      call.on("data", (request: StreamTelemetryRequest) => {
        if (request.payload.case === "resume") {
          call.write(policySnapshot(machineId));
          call.write(acknowledgement(machineId, 0n));
          const historyCommand = create(StreamTelemetryResponseSchema, {
            payload: {
              case: "historySyncCommand",
              value: create(HistorySyncCommandSchema, {
                jobId,
                machineId,
                idempotencyKey,
                requestedAt: timestampFromDate(new Date()),
                expiresAt: timestampFromDate(new Date(Date.now() + 60_000)),
              }),
            },
          });
          call.write(historyCommand);
          call.write(historyCommand);
        }
        if (request.payload.case === "event") {
          order.push("event");
          setTimeout(() => {
            order.push("acknowledgement");
            call.write(acknowledgement(machineId, 1n));
          }, 20);
        }
        if (request.payload.case === "historySyncResult") {
          historySyncResults += 1;
          order.push("result");
          assert.equal(request.payload.value.jobId, jobId);
          assert.equal(request.payload.value.state, HistorySyncResultState.SUCCEEDED);
          assert.equal(request.payload.value.throughSequence, 1n);
          controller.abort();
        }
      });
      call.on("end", () => call.end());
    },
  };
  server.addService(observerServiceDefinition, implementation);
  const port = await bindServer(server);
  const client = new ObserverStreamClient({
    config: streamConfig(dataDirectory, port),
    credentialStore: testCredentialStore(machineId),
    onHistorySync: async (command) => {
      historySyncCalls += 1;
      client.enqueue(create(EventEnvelopeSchema, {
        tenantId,
        machineId,
        agentId: "agent-history",
        sessionId: "session-history",
        sequence: 1n,
        observedAt: timestampFromDate(new Date()),
        schemaVersion: 1,
        privacyClass: PrivacyClass.SYSTEM_METADATA,
        sourceEventId: "a".repeat(64),
        payload: {
          case: "lifecycle",
          value: create(LifecycleEventSchema, {
            phase: LifecyclePhase.STARTED,
            reason: "historical record",
          }),
        },
      }));
      return create(HistorySyncResultSchema, {
        jobId: command.jobId,
        machineId,
        idempotencyKey: command.idempotencyKey,
        state: HistorySyncResultState.SUCCEEDED,
        filesDiscovered: 1,
        recordsScanned: 1n,
        eventsUploaded: 1n,
        throughSequence: 1n,
        observedAt: timestampFromDate(new Date()),
      });
    },
  });
  try {
    await client.run(controller.signal);
    assert.deepEqual(order, ["event", "acknowledgement", "result"]);
    assert.equal(historySyncCalls, 1);
    assert.equal(historySyncResults, 1);
  } finally {
    controller.abort();
    await shutdownServer(server);
    await rm(dataDirectory, { recursive: true, force: true });
  }
});

test("observer waits for resume policy and sanitizes queued content", async () => {
  const dataDirectory = await mkdtemp(join(tmpdir(), "phigon-stream-"));
  const machineId = "5f1b4cb4-a77d-4f53-af66-197e184683f4";
  const server = new Server();
  const controller = new AbortController();
  let policySent = false;
  let eventArrivedBeforePolicy = false;
  const receivedEvents: EventEnvelope[] = [];

  const implementation: UntypedServiceImplementation = {
    streamTelemetry(
      call: ServerDuplexStream<
        StreamTelemetryRequest,
        StreamTelemetryResponse
      >,
    ) {
      call.on("data", (request: StreamTelemetryRequest) => {
        if (request.payload.case === "resume") {
          setTimeout(() => {
            policySent = true;
            call.write(policySnapshot(machineId, {
              commandArguments: true,
              responseContent: true,
              toolOutput: true,
              vendorPayload: true,
            }));
            call.write(acknowledgement(machineId, 0n));
          }, 25);
        }
        if (request.payload.case === "event") {
          eventArrivedBeforePolicy = !policySent;
          receivedEvents.push(request.payload.value);
          if (receivedEvents.length === 2) controller.abort();
        }
      });
      call.on("end", () => call.end());
    },
  };
  server.addService(observerServiceDefinition, implementation);
  const port = await new Promise<number>((resolve, reject) => {
    server.bindAsync(
      "127.0.0.1:0",
      ServerCredentials.createInsecure(),
      (error, boundPort) => {
        if (error) reject(error);
        else resolve(boundPort);
      },
    );
  });

  try {
    const config = loadConfig({
      PHIGON_CONTROL_PLANE_URL: "http://127.0.0.1:8080",
      PHIGON_GRPC_URL: `http://127.0.0.1:${port}`,
      PHIGON_DATA_DIR: dataDirectory,
      PHIGON_HEARTBEAT_INTERVAL_MS: "1000",
    });
    const queue = new BoundedEventQueue<EventEnvelope>(4);
    const payloadJson = JSON.stringify({
      authorization: "Bearer secret-value",
      prompt: "queued private prompt",
      response: "safe queued response",
    });
    queue.enqueue(
      create(EventEnvelopeSchema, {
        tenantId: "7d1b4cb4-a77d-4f53-af66-197e184683f4",
        machineId,
        agentId: "agent-test",
        sessionId: "session-test",
        sequence: 1n,
        observedAt: timestampFromDate(new Date()),
        schemaVersion: 1,
        privacyClass: PrivacyClass.USER_CONTENT,
        payload: {
          case: "vendor",
          value: create(VendorEventSchema, {
            source: "codex",
            vendorType: "response_item",
            sourceRecordDigest: "a".repeat(64),
            payloadJson,
            redactedFields: ["authorization"],
          }),
        },
      }),
      1n,
    );
    queue.enqueue(
      create(EventEnvelopeSchema, {
        tenantId: "7d1b4cb4-a77d-4f53-af66-197e184683f4",
        machineId,
        agentId: "agent-test",
        sessionId: "session-test",
        sequence: 2n,
        observedAt: timestampFromDate(new Date()),
        schemaVersion: 1,
        privacyClass: PrivacyClass.USER_CONTENT,
        payload: {
          case: "tool",
          value: create(ToolEventSchema, {
            invocationId: "call-test",
            toolName: "custom.deploy",
            phase: ToolPhase.SUCCEEDED,
            argumentsJson: JSON.stringify({
              env: { PUBLIC_VALUE: "queued-private-value" },
              nested: [{ path: "/queued/private/path" }],
              safe: "release-e2e",
            }),
            output: JSON.stringify({
              file_content: "queued private output",
              safe: "completed",
            }),
          }),
        },
      }),
      2n,
    );
    const client = new ObserverStreamClient({
      config,
      credentialStore: new StaticCredentialStore({
        machineId,
        tenantId: "7d1b4cb4-a77d-4f53-af66-197e184683f4",
        credential:
          "phg_m_0123456789012345678901234567890123456789012",
        controlPlaneOrigin: "http://127.0.0.1:8080",
        createdAt: new Date().toISOString(),
      }),
      queue,
    });

    await client.run(controller.signal);

    assert.equal(eventArrivedBeforePolicy, false);
    const receivedEvent = receivedEvents.find(
      (event) => event.payload.case === "vendor",
    );
    assert.equal(receivedEvent?.payload.case, "vendor");
    if (receivedEvent?.payload.case !== "vendor") {
      assert.fail("queued vendor event was not delivered");
    }
    assert.notEqual(receivedEvent.payload.value.payloadJson, undefined);
    const sanitizedVendor = JSON.parse(
      receivedEvent.payload.value.payloadJson ?? "{}",
    ) as Record<string, unknown>;
    assert.equal(sanitizedVendor["prompt"], "[REDACTED_POLICY]");
    assert.equal(sanitizedVendor["response"], "safe queued response");
    assert.equal(
      sanitizedVendor["authorization"],
      "[REDACTED_SECRET]",
    );
    assert.equal(receivedEvent.payload.value.payloadOmitted, false);
    assert.equal(receivedEvent.payload.value.payloadRedacted, true);
    assert.ok(
      receivedEvent.payload.value.redactedFields.includes(
        "authorization",
      ),
    );
    const receivedTool = receivedEvents.find(
      (event) => event.payload.case === "tool",
    );
    assert.equal(receivedTool?.payload.case, "tool");
    if (receivedTool?.payload.case !== "tool") {
      assert.fail("queued tool event was not delivered");
    }
    const sanitizedTool = JSON.stringify(receivedTool.payload.value);
    assert.match(sanitizedTool, /release-e2e/u);
    assert.match(sanitizedTool, /completed/u);
    assert.match(sanitizedTool, /\[REDACTED_POLICY\]/u);
    assert.doesNotMatch(
      sanitizedTool,
      /queued-private-value|\/queued\/private\/path|queued private output/u,
    );
    assert.equal(receivedTool.payload.value.argumentsRedacted, true);
    assert.equal(receivedTool.payload.value.outputRedacted, true);
  } finally {
    controller.abort();
    await new Promise<void>((resolve) => {
      server.tryShutdown(() => resolve());
    });
    await rm(dataDirectory, { recursive: true, force: true });
  }
});

test("observer drops one rejected record and continues the stream", async () => {
  const dataDirectory = await mkdtemp(join(tmpdir(), "phigon-stream-"));
  const machineId = "5f1b4cb4-a77d-4f53-af66-197e184683f4";
  const server = new Server();
  const controller = new AbortController();
  const received: bigint[] = [];
  const statuses: string[] = [];

  const implementation: UntypedServiceImplementation = {
    streamTelemetry(
      call: ServerDuplexStream<
        StreamTelemetryRequest,
        StreamTelemetryResponse
      >,
    ) {
      call.on("data", (request: StreamTelemetryRequest) => {
        if (request.payload.case === "resume") {
          call.write(policySnapshot(machineId));
          call.write(acknowledgement(machineId, 0n));
        }
        if (request.payload.case !== "event") return;
        received.push(request.payload.value.sequence);
        if (request.payload.value.sequence === 1n) {
          call.write(
            create(StreamTelemetryResponseSchema, {
              payload: {
                case: "error",
                value: create(StreamErrorSchema, {
                  code: StreamErrorCode.INVALID_EVENT,
                  message: "fixture rejected sequence",
                  retryable: false,
                  rejectedSequence: 1n,
                }),
              },
            }),
          );
          setTimeout(() => {
            client.enqueue(lifecycleEvent(machineId, 2n));
          }, 25);
          return;
        }
        call.write(acknowledgement(machineId, 2n));
        setTimeout(() => controller.abort(), 25);
      });
      call.on("end", () => call.end());
    },
  };
  server.addService(observerServiceDefinition, implementation);
  const port = await bindServer(server);
  const client = new ObserverStreamClient({
    config: streamConfig(dataDirectory, port),
    credentialStore: testCredentialStore(machineId),
    queue: new BoundedEventQueue<EventEnvelope>(4),
    onStatus: (message) => statuses.push(message),
  });
  client.enqueue(lifecycleEvent(machineId, 1n));

  try {
    await client.run(controller.signal);
    assert.deepEqual(received, [1n, 2n]);
    assert.equal(client.metrics().queue.depth, 0);
    assert.match(statuses.join("\n"), /Quarantined sequence 1/u);
  } finally {
    controller.abort();
    await shutdownServer(server);
    await rm(dataDirectory, { recursive: true, force: true });
  }
});

test("observer persists a terminally quarantined last event", async () => {
  const dataDirectory = await mkdtemp(join(tmpdir(), "phigon-stream-"));
  const machineId = "5f1b4cb4-a77d-4f53-af66-197e184683f4";
  const server = new Server();
  const controller = new AbortController();
  const acknowledged: bigint[] = [];
  const persistenceOrder: string[] = [];
  const queue = new BoundedEventQueue<EventEnvelope>(4);
  queue.enqueue(lifecycleEvent(machineId, 1n), 1n);

  const implementation: UntypedServiceImplementation = {
    streamTelemetry(
      call: ServerDuplexStream<
        StreamTelemetryRequest,
        StreamTelemetryResponse
      >,
    ) {
      call.on("data", (request: StreamTelemetryRequest) => {
        if (request.payload.case === "resume") {
          call.write(policySnapshot(machineId));
          call.write(acknowledgement(machineId, 0n));
          return;
        }
        if (request.payload.case !== "event") return;
        call.write(
          create(StreamTelemetryResponseSchema, {
            payload: {
              case: "error",
              value: create(StreamErrorSchema, {
                code: StreamErrorCode.INVALID_EVENT,
                message: "terminal fixture rejection",
                retryable: false,
                rejectedSequence: 1n,
              }),
            },
          }),
        );
        setTimeout(() => controller.abort(), 50);
      });
      call.on("end", () => call.end());
    },
  };
  server.addService(observerServiceDefinition, implementation);
  const port = await bindServer(server);
  let storedSequence = 0n;
  const client = new ObserverStreamClient({
    config: streamConfig(dataDirectory, port),
    credentialStore: testCredentialStore(machineId),
    stateStore: {
      load: async () => ({
        machineId,
        acknowledgedSequence: storedSequence,
        updatedAt: new Date(0).toISOString(),
      }),
      save: async (_machineId, sequence) => {
        persistenceOrder.push("stream cursor");
        storedSequence = sequence;
      },
    },
    queue,
    onAcknowledgement: async (sequence) => {
      acknowledged.push(sequence);
      persistenceOrder.push("source checkpoint started");
      await new Promise((resolve) => setTimeout(resolve, 20));
      persistenceOrder.push("source checkpoint committed");
    },
  });

  try {
    await client.run(controller.signal);
    assert.deepEqual(acknowledged, [1n]);
    assert.equal(queue.metrics().depth, 0);
    assert.equal(storedSequence, 1n);
    assert.deepEqual(persistenceOrder, [
      "source checkpoint started",
      "source checkpoint committed",
      "stream cursor",
    ]);
  } finally {
    controller.abort();
    await shutdownServer(server);
    await rm(dataDirectory, { recursive: true, force: true });
  }
});

test("per-event acknowledgements are persisted in coalesced order without a write per event", async () => {
  const dataDirectory = await mkdtemp(join(tmpdir(), "phigon-stream-"));
  const machineId = "5f1b4cb4-a77d-4f53-af66-197e184683f4";
  const server = new Server();
  const controller = new AbortController();
  const total = 200;
  const committed: bigint[] = [];
  const saved: bigint[] = [];
  const order: string[] = [];
  let concurrentSaves = 0;
  let maxConcurrentSaves = 0;
  const queue = new BoundedEventQueue<EventEnvelope>(total);
  for (let index = 1; index <= total; index++) {
    queue.enqueue(lifecycleEvent(machineId, BigInt(index)), BigInt(index));
  }
  server.addService(observerServiceDefinition, {
    streamTelemetry(
      call: ServerDuplexStream<StreamTelemetryRequest, StreamTelemetryResponse>,
    ) {
      call.on("data", (request: StreamTelemetryRequest) => {
        if (request.payload.case === "resume") {
          call.write(policySnapshot(machineId));
          call.write(acknowledgement(machineId, 0n));
          return;
        }
        // The control plane acknowledges every accepted event.
        if (request.payload.case === "event") {
          call.write(acknowledgement(machineId, request.payload.value.sequence));
        }
      });
      call.on("end", () => call.end());
    },
  });
  const port = await bindServer(server);
  const client = new ObserverStreamClient({
    config: streamConfig(dataDirectory, port),
    credentialStore: testCredentialStore(machineId),
    stateStore: {
      load: async () => ({
        machineId,
        acknowledgedSequence: 0n,
        updatedAt: new Date(0).toISOString(),
      }),
      save: async (_machineId, sequence) => {
        concurrentSaves++;
        maxConcurrentSaves = Math.max(maxConcurrentSaves, concurrentSaves);
        // A flushed atomic replace takes milliseconds on a real disk.
        await new Promise((resolve) => setTimeout(resolve, 5));
        concurrentSaves--;
        saved.push(sequence);
        order.push(`save ${sequence}`);
        if (sequence === BigInt(total)) controller.abort();
      },
    },
    queue,
    onAcknowledgement: (sequence) => {
      committed.push(sequence);
      order.push(`commit ${sequence}`);
    },
  });
  const deadline = setTimeout(() => controller.abort(), 10_000);
  try {
    await client.run(controller.signal);
    assert.equal(client.metrics().lastAcknowledgedSequence, BigInt(total));
    assert.equal(queue.metrics().depth, 0);
    assert.equal(saved.at(-1), BigInt(total));
    assert.equal(committed.at(-1), BigInt(total));
    assert.equal(maxConcurrentSaves, 1);
    for (const values of [saved, committed]) {
      for (let index = 1; index < values.length; index++) {
        assert.ok((values[index] ?? 0n) > (values[index - 1] ?? 0n));
      }
    }
    // Each saved cursor follows its source checkpoint commit.
    for (const sequence of saved) {
      assert.ok(
        order.indexOf(`commit ${sequence}`) < order.indexOf(`save ${sequence}`),
      );
    }
    assert.ok(
      saved.length < total / 4,
      `expected coalesced cursor writes, saw ${saved.length} for ${total} acknowledgements`,
    );
  } finally {
    clearTimeout(deadline);
    controller.abort();
    await shutdownServer(server);
    await rm(dataDirectory, { recursive: true, force: true });
  }
});

test("observer bounds in-flight events by count when sequences contain gaps", async () => {
  const dataDirectory = await mkdtemp(join(tmpdir(), "phigon-stream-"));
  const machineId = "5f1b4cb4-a77d-4f53-af66-197e184683f4";
  const server = new Server();
  const controller = new AbortController();
  let received = 0;
  let outstanding = 0;
  let maxOutstanding = 0;
  let observationTimer: NodeJS.Timeout | undefined;
  const acknowledged: bigint[] = [];

  const implementation: UntypedServiceImplementation = {
    streamTelemetry(
      call: ServerDuplexStream<
        StreamTelemetryRequest,
        StreamTelemetryResponse
      >,
    ) {
      call.on("data", (request: StreamTelemetryRequest) => {
        if (request.payload.case === "resume") {
          call.write(policySnapshot(machineId));
          call.write(acknowledgement(machineId, 0n));
          return;
        }
        if (request.payload.case !== "event") return;
        received++;
        outstanding++;
        maxOutstanding = Math.max(maxOutstanding, outstanding);
        if (received === 1) {
          outstanding--;
          call.write(
            acknowledgement(
              machineId,
              request.payload.value.sequence,
            ),
          );
          observationTimer = setTimeout(() => controller.abort(), 150);
        }
      });
      call.on("end", () => call.end());
    },
  };
  server.addService(observerServiceDefinition, implementation);
  const port = await bindServer(server);
  const queue = new BoundedEventQueue<EventEnvelope>(32);
  for (let index = 1; index <= 32; index++) {
    const sequence = BigInt(index * 1_000);
    queue.enqueue(lifecycleEvent(machineId, sequence), sequence);
  }
  const client = new ObserverStreamClient({
    config: {
      ...streamConfig(dataDirectory, port),
      activityMaxInFlightEvents: 16,
    },
    credentialStore: testCredentialStore(machineId),
    queue,
    onAcknowledgement: (sequence) => {
      acknowledged.push(sequence);
    },
  });

  try {
    await client.run(controller.signal);
    assert.equal(received, 17);
    assert.equal(maxOutstanding, 16);
    assert.deepEqual(acknowledged, [1_000n]);
  } finally {
    if (observationTimer !== undefined) clearTimeout(observationTimer);
    controller.abort();
    await shutdownServer(server);
    await rm(dataDirectory, { recursive: true, force: true });
  }
});

test("observer handles cursor persistence failure through reconnect logic", async () => {
  const dataDirectory = await mkdtemp(join(tmpdir(), "phigon-stream-"));
  const machineId = "5f1b4cb4-a77d-4f53-af66-197e184683f4";
  const server = new Server();
  const controller = new AbortController();
  let saveAttempts = 0;
  const statuses: string[] = [];

  const implementation: UntypedServiceImplementation = {
    streamTelemetry(
      call: ServerDuplexStream<
        StreamTelemetryRequest,
        StreamTelemetryResponse
      >,
    ) {
      call.on("data", (request: StreamTelemetryRequest) => {
        if (request.payload.case === "resume") {
          call.write(policySnapshot(machineId));
          call.write(acknowledgement(machineId, 0n));
        }
        if (request.payload.case === "event") {
          call.write(acknowledgement(machineId, 1n));
        }
      });
      call.on("end", () => call.end());
    },
  };
  server.addService(observerServiceDefinition, implementation);
  const port = await bindServer(server);
  const queue = new BoundedEventQueue<EventEnvelope>(4);
  queue.enqueue(lifecycleEvent(machineId, 1n), 1n);
  const client = new ObserverStreamClient({
    config: streamConfig(dataDirectory, port),
    credentialStore: testCredentialStore(machineId),
    stateStore: {
      load: async () => ({
        machineId,
        acknowledgedSequence: 0n,
        updatedAt: new Date(0).toISOString(),
      }),
      save: async () => {
        saveAttempts++;
        throw new Error("fixture state store is unwritable");
      },
    },
    queue,
    onStatus: (message) => {
      statuses.push(message);
      if (message.includes("retrying")) controller.abort();
    },
  });

  try {
    await client.run(controller.signal);
    assert.equal(saveAttempts, 1);
    assert.equal(client.metrics().reconnects, 1);
    assert.match(statuses.join("\n"), /fixture state store is unwritable/u);
  } finally {
    controller.abort();
    await shutdownServer(server);
    await rm(dataDirectory, { recursive: true, force: true });
  }
});

test("observer refuses queue overflow before an unacknowledged event is evicted", () => {
  const machineId = "5f1b4cb4-a77d-4f53-af66-197e184683f4";
  const queue = new BoundedEventQueue<EventEnvelope>(1);
  const client = new ObserverStreamClient({
    config: streamConfig("/tmp/phigon-queue-overflow-test", 1),
    queue,
  });
  client.enqueue(lifecycleEvent(machineId, 1n));

  assert.throws(
    () => client.enqueue(lifecycleEvent(machineId, 2n)),
    /queue is full/,
  );
  assert.deepEqual(
    queue.pending().map((event) => event.sequence),
    [1n],
  );
  assert.equal(queue.metrics().dropped, 0);
});

class StaticCredentialStore implements CredentialStore {
  readonly #value: StoredMachineCredential;

  constructor(value: StoredMachineCredential) {
    this.#value = value;
  }

  async save(): Promise<void> {
    throw new Error("not implemented");
  }

  async load(): Promise<StoredMachineCredential> {
    return this.#value;
  }
}

function testCredentialStore(machineId: string): CredentialStore {
  return new StaticCredentialStore({
    machineId,
    tenantId: "7d1b4cb4-a77d-4f53-af66-197e184683f4",
    credential: `phg_m_${"0".repeat(43)}`,
    controlPlaneOrigin: "http://127.0.0.1:8080",
    createdAt: new Date().toISOString(),
  });
}

function streamConfig(dataDirectory: string, port: number) {
  return loadConfig({
    PHIGON_CONTROL_PLANE_URL: "http://127.0.0.1:8080",
    PHIGON_GRPC_URL: `http://127.0.0.1:${port}`,
    PHIGON_DATA_DIR: dataDirectory,
    PHIGON_HEARTBEAT_INTERVAL_MS: "1000",
  });
}

function lifecycleEvent(machineId: string, sequence: bigint): EventEnvelope {
  return create(EventEnvelopeSchema, {
    tenantId: "7d1b4cb4-a77d-4f53-af66-197e184683f4",
    machineId,
    agentId: "agent-test",
    sessionId: "session-test",
    sequence,
    observedAt: timestampFromDate(new Date()),
    schemaVersion: 1,
    privacyClass: PrivacyClass.SYSTEM_METADATA,
    payload: {
      case: "lifecycle",
      value: create(LifecycleEventSchema, {
        phase: LifecyclePhase.STARTED,
        reason: "test event",
      }),
    },
  });
}

async function bindServer(server: Server): Promise<number> {
  return await new Promise<number>((resolve, reject) => {
    server.bindAsync(
      "127.0.0.1:0",
      ServerCredentials.createInsecure(),
      (error, boundPort) => {
        if (error) reject(error);
        else resolve(boundPort);
      },
    );
  });
}

async function shutdownServer(server: Server): Promise<void> {
  await new Promise<void>((resolve) => {
    server.tryShutdown(() => resolve());
  });
}

function acknowledgement(
  machineId: string,
  sequence: bigint,
): StreamTelemetryResponse {
  return create(StreamTelemetryResponseSchema, {
    payload: {
      case: "acknowledgement",
      value: create(AcknowledgementSchema, {
        machineId,
        throughSequence: sequence,
        receivedAt: timestampFromDate(new Date()),
      }),
    },
  });
}

function policySnapshot(
  machineId: string,
  collection: MessageInitShape<typeof CollectionPolicySchema> = {
    vendorPayload: true,
  },
): StreamTelemetryResponse {
  return create(StreamTelemetryResponseSchema, {
    payload: {
      case: "policy",
      value: create(PolicySnapshotSchema, {
        tenantId: "7d1b4cb4-a77d-4f53-af66-197e184683f4",
        machineId,
        revision: 1n,
        effectiveAt: timestampFromDate(new Date()),
        collection: create(CollectionPolicySchema, collection),
      }),
    },
  });
}

const observerServiceDefinition: ServiceDefinition = {
  streamTelemetry: {
    path: "/phigon.v1.ObserverService/StreamTelemetry",
    requestStream: true,
    responseStream: true,
    requestSerialize: (value: StreamTelemetryRequest) =>
      Buffer.from(toBinary(StreamTelemetryRequestSchema, value)),
    requestDeserialize: (value: Buffer) =>
      fromBinary(StreamTelemetryRequestSchema, value),
    responseSerialize: (value: StreamTelemetryResponse) =>
      Buffer.from(toBinary(StreamTelemetryResponseSchema, value)),
    responseDeserialize: (value: Buffer) =>
      fromBinary(StreamTelemetryResponseSchema, value),
  },
};

test("silent handshake and silent established connections time out without losing queued events", async () => {
  for (const established of [false, true]) {
    const directory = await mkdtemp(join(tmpdir(), "phigon-silent-stream-"));
    const machineId = "5f1b4cb4-a77d-4f53-af66-197e184683f4";
    const server = new Server(); const controller = new AbortController();
    const messages: string[] = [];
    server.addService(observerServiceDefinition, { streamTelemetry(call: ServerDuplexStream<StreamTelemetryRequest, StreamTelemetryResponse>) {
      call.on("data", (request: StreamTelemetryRequest) => {
        if (established && request.payload.case === "resume") { call.write(policySnapshot(machineId)); call.write(acknowledgement(machineId, 0n)); }
      });
      call.on("end", () => call.end());
    } });
    const port = await bindServer(server);
    const client = new ObserverStreamClient({ config:streamConfig(directory, port), credentialStore:testCredentialStore(machineId), queue:new BoundedEventQueue<EventEnvelope>(8), handshakeTimeoutMs:150, responseTimeoutMs:150,
      onStatus: message => { messages.push(message); if (message.includes("timed out")) controller.abort(); }
    });
    client.enqueue(lifecycleEvent(machineId, 1n));
    const deadline = setTimeout(() => controller.abort(), 5000);
    try {
      await client.run(controller.signal);
      assert.ok(messages.some(message => message.includes(established ? "heartbeat acknowledgement timed out" : "handshake timed out")), messages.join("\n"));
      assert.equal(messages.some(message => message.startsWith("Telemetry stream connected")), established);
      assert.equal(client.metrics().queue.dropped, 0);
      assert.equal(client.metrics().queue.depth, 1);
      await assert.rejects(client.waitUntilReady(AbortSignal.abort()), /aborted/);
    } finally { clearTimeout(deadline); controller.abort(); server.forceShutdown(); await rm(directory, { recursive:true, force:true }); }
  }
});

test("a clean server disconnect uses reconnect backoff instead of a busy loop", async () => {
  const directory = await mkdtemp(join(tmpdir(), "phigon-ended-stream-"));
  const server = new Server(); const controller = new AbortController();
  let connections = 0; const messages: string[] = [];
  server.addService(observerServiceDefinition, { streamTelemetry(call: ServerDuplexStream<StreamTelemetryRequest, StreamTelemetryResponse>) { connections++; call.resume(); call.end(); } });
  const port = await bindServer(server);
  const client = new ObserverStreamClient({ config:streamConfig(directory, port), credentialStore:testCredentialStore("machine"), onStatus: message => { messages.push(message); } });
  const deadline = setTimeout(() => controller.abort(), 700);
  try {
    await client.run(controller.signal);
    assert.ok(connections >= 1 && connections <= 3, `unexpected reconnect count ${connections}`);
    assert.ok(messages.some(message => message.includes("retrying in")));
  } finally { clearTimeout(deadline); controller.abort(); server.forceShutdown(); await rm(directory, { recursive:true, force:true }); }
});

test("reconnect backoff starts over after a connection completed its handshake", async () => {
  const directory = await mkdtemp(join(tmpdir(), "phigon-backoff-reset-"));
  const machineId = "5f1b4cb4-a77d-4f53-af66-197e184683f4";
  const server = new Server(); const controller = new AbortController();
  let connections = 0; const retries: number[] = [];
  server.addService(observerServiceDefinition, { streamTelemetry(call: ServerDuplexStream<StreamTelemetryRequest, StreamTelemetryResponse>) {
    connections++;
    // Two failed attempts grow the backoff; the third connection is healthy
    // and then closes, as a restarting control plane would.
    if (connections <= 2) { call.resume(); call.end(); return; }
    call.on("data", (request: StreamTelemetryRequest) => {
      if (request.payload.case !== "resume") return;
      call.write(policySnapshot(machineId)); call.write(acknowledgement(machineId, 0n));
      setTimeout(() => call.end(), 50);
    });
  } });
  const port = await bindServer(server);
  const client = new ObserverStreamClient({ config:streamConfig(directory, port), credentialStore:testCredentialStore(machineId), queue:new BoundedEventQueue<EventEnvelope>(8),
    onStatus: message => {
      const delay = /retrying in (\d+)ms/u.exec(message)?.[1];
      if (delay === undefined) return;
      retries.push(Number(delay));
      if (retries.length === 3) controller.abort();
    } });
  const deadline = setTimeout(() => controller.abort(), 8_000);
  try {
    await client.run(controller.signal);
    assert.deepEqual(retries, [250, 500, 250]);
  } finally { clearTimeout(deadline); controller.abort(); server.forceShutdown(); await rm(directory, { recursive:true, force:true }); }
});

test("telemetry refuses a credential bound to another stream origin", async () => {
  const directory = await mkdtemp(join(tmpdir(), "phigon-stream-origin-"));
  const original = testCredentialStore("machine");
  const credential = await original.load(); assert.ok(credential);
  const client = new ObserverStreamClient({ config:streamConfig(directory, 1), credentialStore:{ load:async () => ({ ...credential, grpcOrigin:"https://other.customer.test" }), save:async () => undefined } });
  try { await assert.rejects(client.run(new AbortController().signal), /Refusing to send/); }
  finally { await rm(directory, { recursive:true, force:true }); }
});

test("legacy private pairings cannot fall back to hosted telemetry", async () => {
  const controller = new AbortController();
  let checkpointReads = 0;
  const credential = await testCredentialStore("machine").load();
  assert.ok(credential);
  const client = new ObserverStreamClient({
    config: loadConfig({ PHIGON_CONTROL_PLANE_URL: "https://api.customer.test" }),
    credentialStore: { load: async () => ({ ...credential, controlPlaneOrigin: "https://api.customer.test" }), save: async () => undefined },
    queue: new BoundedEventQueue<EventEnvelope>(8),
    // Stops the old implementation before any network request can happen.
    stateStore: { load: async () => { checkpointReads++; throw new Error("test stops before network"); }, save: async () => undefined },
    onStatus: () => controller.abort(),
  });
  await assert.rejects(client.run(controller.signal), /saved telemetry endpoint.*--grpc-url/);
  assert.equal(checkpointReads, 0);
});

test("an unusable local spool stops the observer instead of retrying forever", async () => {
  const directory = await mkdtemp(join(tmpdir(), "phigon-stream-spool-"));
  const controller = new AbortController();
  const statuses: string[] = [];
  const client = new ObserverStreamClient({
    config: streamConfig(directory, 1),
    credentialStore: testCredentialStore("machine"),
    queue: new FileBackedEventQueue(directory, 8),
    // A transient-retry regression would report a disconnect; stop it there.
    onStatus: (message) => { statuses.push(message); if (/disconnected/u.test(message)) controller.abort(); },
  });
  try {
    await writeFile(join(directory, "telemetry-spool.jsonl"), "this is not a spool record\n", "utf8");
    await assert.rejects(client.run(controller.signal), /spool/iu);
    assert.deepEqual(statuses.filter((message) => /disconnected/u.test(message)), []);
  } finally { await rm(directory, { recursive: true, force: true }); }
});
