import { createHash } from "node:crypto";
import { join } from "node:path";
import { create, toBinary } from "@bufbuild/protobuf";
import { timestampFromDate } from "@bufbuild/protobuf/wkt";
import type { ObserverConfig } from "../config.js";
import type { CollectionPolicy } from "../config.js";
import type { StoredMachineCredential } from "../credential-store.js";
import {
  ActivityKind,
  AgentKind,
  AgentState,
} from "../generated/phigon/v1/common_pb.js";
import {
  AgentIdentitySchema,
  type AgentIdentity,
  type AgentInventory,
} from "../generated/phigon/v1/identity_pb.js";
import { mergeInventoryWithHistoricalIdentities } from "../historical-identity-store.js";
import {
  EventEnvelopeSchema,
  type EventEnvelope,
} from "../generated/phigon/v1/telemetry_pb.js";
import { claudeActivityAdapter } from "./adapters/claude.js";
import { codexActivityAdapter } from "./adapters/codex.js";
import { copilotActivityAdapter } from "./adapters/copilot.js";
import { hermesActivityAdapter } from "./adapters/hermes.js";
import { openClawActivityAdapter } from "./adapters/openclaw.js";
import { openCodeActivityAdapter } from "./adapters/opencode.js";
import { createOpenAICompatibleAdapter } from "./adapters/openai-compatible.js";
import { activityBridgeAgents } from "./bridges.js";
import { genericActivityAdapter } from "./adapters/generic.js";
import { LocalPolicyEngine } from "./policy.js";
import { vendorDraft } from "./normalize.js";
import {
  objectValue,
  recordObservedAt,
  stringField,
} from "./record.js";
import {
  type ActivitySourceCheckpoint,
  JSONLSourceReader,
  type ActivitySource,
} from "./source-reader.js";
import type { VendorActivityAdapter } from "./types.js";
import { processKeyCapability } from "../discovery/process-identity.js";

const maxEnvelopeBytes = 1 << 20;
const maxPendingCheckpoints = 256;
export const historySyncQueueHeadroom = 1_024;
const maxDraftsPerRecord = 32;

const adapters: ReadonlyMap<string, VendorActivityAdapter> = new Map([
  ["claude", claudeActivityAdapter],
  ["codex", codexActivityAdapter],
  ["copilot", copilotActivityAdapter],
  ["hermes", hermesActivityAdapter],
  ["openclaw", openClawActivityAdapter],
  ...activityBridgeAgents.map(
    (agent): [string, VendorActivityAdapter] => [
      agent.id,
      createOpenAICompatibleAdapter(
        agent.id,
        AgentKind.GENERIC,
        agent.displayName,
      ),
    ],
  ),
  // Keep the flexible generic parser after the generated bridge adapters so
  // the generic bridge cannot accidentally replace it with a fixed label.
  ["generic", genericActivityAdapter],
  ["opencode", openCodeActivityAdapter],
]);

export type ActivityCollectorMetrics = Readonly<{
  sourceRecords: number;
  malformedRecords: number;
  oversizedRecords: number;
  emittedEvents: number;
  rateLimitedEvents: number;
  oversizedEvents: number;
  lastSequence: bigint;
  pendingCheckpoints: number;
  backpressuredScans: number;
}>;

export type HistorySyncSummary = Readonly<{
  filesDiscovered: number;
  recordsScanned: number;
  eventsUploaded: number;
  throughSequence: bigint;
}>;

export type ActivityCollectorOptions = Readonly<{
  config: ObserverConfig;
  credential: StoredMachineCredential;
  initialSequence: bigint;
  initialAcknowledgedSequence?: bigint;
  durableDelivery?: boolean;
  emit: (event: EventEnvelope) => void;
  sources?: readonly ActivitySource[];
  additionalSources?: () => Promise<readonly ActivitySource[]>;
  reader?: JSONLSourceReader;
  clock?: () => Date;
  policy?: CollectionPolicy;
  canCollect?: () => boolean;
  canSyncHistory?: () => boolean;
  onSourceIdentity?: (
    identity: AgentIdentity,
  ) => void | Promise<void>;
}>;

type PendingCheckpoint = Readonly<{
  throughSequence: bigint;
  checkpoint: ActivitySourceCheckpoint;
  reader: JSONLSourceReader;
}>;

type CollectionPass = Readonly<{
  complete: boolean;
  metrics: ActivityCollectorMetrics;
  sourceRecords: number;
  discoveredFiles: number;
}>;

export class ActivityCollector {
  readonly #config: ObserverConfig;
  readonly #credential: StoredMachineCredential;
  readonly #emit: (event: EventEnvelope) => void;
  readonly #sources: readonly ActivitySource[];
  readonly #additionalSources: () => Promise<readonly ActivitySource[]>;
  readonly #reader: JSONLSourceReader;
  readonly #historyReader: JSONLSourceReader;
  #historyWork: Promise<unknown> = Promise.resolve();
  readonly #clock: () => Date;
  readonly #canCollect: () => boolean;
  readonly #canSyncHistory: () => boolean;
  readonly #onSourceIdentity: (
    identity: AgentIdentity,
  ) => void | Promise<void>;
  #policy: LocalPolicyEngine;
  readonly #limiter: MinuteRateLimiter;
  readonly #agentsByKind = new Map<AgentKind, AgentIdentity[]>();
  readonly #sourceIdentities = new Map<string, AgentIdentity>();
  #lastSequence: bigint;
  #sourceRecords = 0;
  #malformedRecords = 0;
  #oversizedRecords = 0;
  #emittedEvents = 0;
  #rateLimitedEvents = 0;
  #oversizedEvents = 0;
  #acknowledgedSequence: bigint;
  readonly #durableDelivery: boolean;
  #pendingCheckpoints: ReadonlyArray<PendingCheckpoint> = [];
  #checkpointSave = Promise.resolve();
  readonly #sourceIdentitySaves: Promise<void>[] = [];
  #backpressuredScans = 0;
  #scanWork: Promise<void> = Promise.resolve();

  constructor(options: ActivityCollectorOptions) {
    this.#config = options.config;
    this.#credential = options.credential;
    this.#emit = options.emit;
    this.#sources = options.sources ?? configuredSources(options.config);
    this.#additionalSources = options.additionalSources ?? (async () => []);
    this.#reader =
      options.reader ??
      new JSONLSourceReader(
        options.config.dataDirectory,
        options.config.activityReplayOnFirstStart,
        options.config.activityInitialReplayBytes,
        options.config.activityInitialReplaySessions,
      );
    this.#historyReader = new JSONLSourceReader(
      join(options.config.dataDirectory, "history-sync"),
      false,
      options.config.activityInitialReplayBytes,
      1,
      "history",
    );
    this.#clock = options.clock ?? (() => new Date());
    this.#canCollect = options.canCollect ?? (() => true);
    this.#canSyncHistory = options.canSyncHistory ?? this.#canCollect;
    this.#onSourceIdentity = options.onSourceIdentity ?? (() => undefined);
    this.#policy = new LocalPolicyEngine(
      options.policy ?? options.config.policy,
      options.config.redactionPathPatterns,
    );
    this.#limiter = new MinuteRateLimiter(
      options.config.activityRateLimitPerMinute,
    );
    this.#lastSequence = options.initialSequence;
    this.#acknowledgedSequence =
      options.initialAcknowledgedSequence ?? options.initialSequence;
    if (
      this.#acknowledgedSequence < 0n ||
      this.#acknowledgedSequence > this.#lastSequence
    ) {
      throw new Error("Initial activity acknowledgement is invalid.");
    }
    this.#durableDelivery = options.durableDelivery ?? false;
  }

  updateInventory(inventory: AgentInventory): void {
    this.#agentsByKind.clear();
    for (const agent of inventory.agents) this.#rememberAgent(agent);
  }

  updatePolicy(policy: CollectionPolicy): void {
    this.#policy = new LocalPolicyEngine(
      policy,
      this.#config.redactionPathPatterns,
    );
  }

  resetSequence(
    acknowledgedSequence: bigint,
    allocationSequence = acknowledgedSequence,
  ): void {
    if (acknowledgedSequence < 0n || allocationSequence < 0n) {
      throw new Error("Activity sequence must not be negative.");
    }
    this.#acknowledgedSequence = acknowledgedSequence;
    this.#lastSequence =
      allocationSequence < acknowledgedSequence
        ? acknowledgedSequence
        : allocationSequence;
  }

  async acknowledge(sequence: bigint): Promise<void> {
    if (sequence <= this.#acknowledgedSequence) return;
    this.#acknowledgedSequence = sequence;
    this.#scheduleCheckpointSave();
    await this.#checkpointSave;
  }

  async scanOnce(): Promise<ActivityCollectorMetrics> {
    const pass = await this.#withScanLock(() =>
      this.#collectOnce(this.#reader, false)
    );
    return pass.metrics;
  }

  async syncHistory(signal?: AbortSignal): Promise<HistorySyncSummary> {
    const operation = () => this.#syncHistory(signal);
    const result = this.#historyWork.then(operation, operation);
    this.#historyWork = result.catch(() => undefined);
    return result;
  }

  async #syncHistory(signal?: AbortSignal): Promise<HistorySyncSummary> {
      let eventsUploaded = 0;
      let recordsScanned = 0;
      let filesDiscovered = 0;
      let complete = false;
      while (!complete) {
        if (signal?.aborted === true) {
          throw new Error("History sync expired before all available records were uploaded.");
        }
        if (!this.#canSyncHistory()) {
          await abortableDelay(250, signal ?? new AbortController().signal);
          continue;
        }
        // Release the collection lock between bounded batches. A large archive
        // must not prevent the live reader from following current work.
        const pass = await this.#withScanLock(async () => {
          const before = this.#emittedEvents;
          const result = await this.#collectOnce(this.#historyReader, true);
          eventsUploaded += this.#emittedEvents - before;
          return result;
        });
        recordsScanned += pass.sourceRecords;
        filesDiscovered = Math.max(filesDiscovered, pass.discoveredFiles);
        complete = pass.complete;
        if (!complete && pass.sourceRecords === 0) {
          await abortableDelay(100, signal ?? new AbortController().signal);
        }
      }
      return Object.freeze({
        filesDiscovered,
        recordsScanned,
        eventsUploaded,
        throughSequence: this.#lastSequence,
      });
  }

  async #collectOnce(
    reader: JSONLSourceReader,
    historical: boolean,
  ): Promise<CollectionPass> {
    const allowance = historical
      ? Math.min(historySyncQueueHeadroom, this.#config.activityQueueCapacity)
      : this.#limiter.remaining(this.#clock());
    if (!(historical ? this.#canSyncHistory() : this.#canCollect()) || allowance === 0) {
      this.#backpressuredScans++;
      return {
        complete: false,
        metrics: this.metrics(),
        sourceRecords: 0,
        discoveredFiles: 0,
      };
    }
    if (this.#pendingCheckpoints.length >= maxPendingCheckpoints) {
      return {
        complete: false,
        metrics: this.metrics(),
        sourceRecords: 0,
        discoveredFiles: 0,
      };
    }
    const scan = await reader.scan([
      ...this.#sources,
      ...await this.#additionalSources(),
    ], Math.max(1, Math.floor(allowance / maxDraftsPerRecord)));
    this.#sourceRecords += scan.metrics.records;
    this.#malformedRecords += scan.metrics.malformed;
    this.#oversizedRecords += scan.metrics.oversized;
    const now = this.#clock();
    for (const record of scan.records) {
      const adapter = adapters.get(record.adapterId);
      if (adapter === undefined) continue;
      const sessionID = reportedSessionID(
        record.adapterId,
        record.value,
        record.sourceId,
      );
      const drafts = adapter.parse(record.value, {
        sessionId: sessionID,
        observedAt: record.observedAt,
        policy: this.#policy,
      });
      const context = {
        sessionId: sessionID,
        observedAt: recordObservedAt(
          record.value,
          record.observedAt,
        ),
        policy: this.#policy,
      };
      const genericAgent = record.adapterId === "generic"
        ? reportedGenericAgentIdentity(
          record.value,
          record.sourceDisplayName,
        )
        : undefined;
      const nativeDraft = vendorDraft(
        adapter.agentKind,
        context,
        genericAgent?.hint !== undefined
          ? genericAgent.hint
          : adapter.id,
        vendorType(record.value),
        record.value,
      );
      const candidateDrafts = [nativeDraft, ...drafts.slice(0, 31)];
      const permittedDrafts =
        !historical && record.initialReplay === true &&
        this.#config.activityInitialReplayMode === "messages"
          ? candidateDrafts.filter((draft) =>
              draft.payload.case === "activity" &&
              (
                draft.payload.value.kind === ActivityKind.PROMPT ||
                draft.payload.value.kind === ActivityKind.RESPONSE
              )
            )
          : candidateDrafts;
      // A source record is atomic: never advance its cursor after dropping
      // part of its normalized activity. One record may use the final budget
      // plus a bounded burst; the next scan waits for replenishment.
      if (!historical) this.#limiter.consume(now, permittedDrafts.length);
      for (const [draftIndex, draft] of permittedDrafts.entries()) {
        const nextSequence = this.#lastSequence + 1n;
        const event = create(EventEnvelopeSchema, {
          tenantId: this.#credential.tenantId,
          machineId: this.#credential.machineId,
          agentId: this.#agentID(
            draft.agentKind,
            record.adapterId,
            record.sourceId,
            record.value,
            record.observedAt,
            genericAgent?.displayName,
          ),
          sessionId: draft.sessionId,
          sequence: nextSequence,
          observedAt: timestampFromDate(
            clampObservedAt(draft.observedAt, now),
          ),
          schemaVersion: 1,
          privacyClass: draft.privacyClass,
          sourceEventId: createHash("sha256")
            .update(`${record.sourceRecordId}\u0000${draftIndex}\u0000${draft.payload.case}`)
            .digest("hex"),
          payload: draft.payload,
        });
        if (
          toBinary(EventEnvelopeSchema, event).byteLength >
          maxEnvelopeBytes
        ) {
          this.#oversizedEvents++;
          continue;
        }
        this.#lastSequence = nextSequence;
        this.#emit(event);
        this.#emittedEvents++;
      }
    }
    await this.#flushSourceIdentitySaves();
    const pending = {
      throughSequence: this.#lastSequence,
      checkpoint: scan.checkpoint,
      reader,
    };
    const sameSequence = this.#pendingCheckpoints.findIndex(
      (candidate) =>
        candidate.throughSequence === pending.throughSequence &&
        candidate.reader === pending.reader,
    );
    this.#pendingCheckpoints =
      sameSequence < 0
        ? [...this.#pendingCheckpoints, pending]
        : this.#pendingCheckpoints.map((candidate, index) =>
            index === sameSequence ? pending : candidate
          );
    this.#scheduleCheckpointSave();
    await this.#checkpointSave;
    return {
      complete: scan.complete,
      metrics: this.metrics(),
      sourceRecords: scan.metrics.records,
      discoveredFiles: scan.metrics.discoveredFiles,
    };
  }

  async run(signal: AbortSignal): Promise<void> {
    while (!signal.aborted) {
      await this.scanOnce();
      await abortableDelay(
        this.#config.activityScanIntervalMs,
        signal,
      );
    }
  }

  metrics(): ActivityCollectorMetrics {
    return Object.freeze({
      sourceRecords: this.#sourceRecords,
      malformedRecords: this.#malformedRecords,
      oversizedRecords: this.#oversizedRecords,
      emittedEvents: this.#emittedEvents,
      rateLimitedEvents: this.#rateLimitedEvents,
      oversizedEvents: this.#oversizedEvents,
      lastSequence: this.#lastSequence,
      pendingCheckpoints: this.#pendingCheckpoints.length,
      backpressuredScans: this.#backpressuredScans,
    });
  }

  sourceIdentities(): AgentIdentity[] {
    return [...this.#sourceIdentities.values()].sort((left, right) =>
      left.agentId.localeCompare(right.agentId)
    );
  }

  #scheduleCheckpointSave(): void {
    const durableThrough = this.#durableDelivery
      ? this.#lastSequence
      : this.#acknowledgedSequence;
    const eligible = this.#pendingCheckpoints.filter(
      (candidate) => candidate.throughSequence <= durableThrough,
    );
    if (eligible.length === 0) return;
    this.#checkpointSave = this.#checkpointSave
      .catch(() => undefined)
      .then(async () => {
        const currentDurableThrough = this.#durableDelivery
          ? this.#lastSequence
          : this.#acknowledgedSequence;
        const committed = new Set<PendingCheckpoint>();
        for (const pending of eligible) {
          if (pending.throughSequence > currentDurableThrough) continue;
          await pending.reader.commit(pending.checkpoint);
          committed.add(pending);
        }
        this.#pendingCheckpoints = this.#pendingCheckpoints.filter(
          (candidate) => !committed.has(candidate),
        );
      });
  }

  async #withScanLock<T>(operation: () => Promise<T>): Promise<T> {
    const result = this.#scanWork.then(operation, operation);
    this.#scanWork = result.then(
      () => undefined,
      () => undefined,
    );
    return await result;
  }

  #rememberAgent(agent: AgentIdentity): void {
    if (
      agent.kind === AgentKind.UNSPECIFIED ||
      agent.agentId.length === 0
    ) return;
    const agents = this.#agentsByKind.get(agent.kind) ?? [];
    const existing = agents.findIndex(
      (candidate) => candidate.agentId === agent.agentId,
    );
    if (existing >= 0) {
      agents[existing] = agent;
    } else {
      agents.push(agent);
    }
    agents.sort((left, right) =>
      left.agentId.localeCompare(right.agentId)
    );
    this.#agentsByKind.set(agent.kind, agents);
  }

  #agentID(
    kind: AgentKind,
    adapterId: string,
    sourceId: string,
    record: unknown,
    observedAt: Date,
    sourceDisplayName?: string,
  ): string {
    const agents = this.#agentsByKind.get(kind) ?? [];
    const fallback = fallbackAgentID(kind, adapterId, sourceId);
    const attributed = attributedRuntimeAgentID(agents, record);
    if (attributed !== undefined) return attributed;
    this.#rememberSourceIdentity(
      fallback,
      kind,
      adapterId,
      sourceId,
      observedAt,
      sourceDisplayName,
    );
    return fallback;
  }

  #rememberSourceIdentity(
    agentID: string,
    kind: AgentKind,
    adapterID: string,
    sourceID: string,
    observedAt: Date,
    sourceDisplayName?: string,
  ): void {
    if (this.#sourceIdentities.has(agentID)) return;
    if (this.#sourceIdentities.size >= 256) {
      const oldest = this.#sourceIdentities.keys().next().value;
      if (oldest !== undefined) this.#sourceIdentities.delete(oldest);
    }
    const identity = create(AgentIdentitySchema, {
      agentId: agentID,
      kind,
      displayName: sourceIdentityDisplayName(
        adapterID,
        sourceID,
        sourceDisplayName,
      ),
      state: AgentState.UNKNOWN,
      processId: 0n,
      lastObservedAt: timestampFromDate(observedAt),
      capabilities: ["activity", "source-isolated", "unattributed"],
    });
    this.#sourceIdentities.set(agentID, identity);
    try {
      this.#sourceIdentitySaves.push(
        Promise.resolve(this.#onSourceIdentity(identity)),
      );
    } catch (error) {
      this.#sourceIdentitySaves.push(Promise.reject(error));
    }
  }

  async #flushSourceIdentitySaves(): Promise<void> {
    const pending = this.#sourceIdentitySaves.splice(0);
    if (pending.length === 0) return;
    const results = await Promise.allSettled(pending);
    const failure = results.find(
      (result): result is PromiseRejectedResult =>
        result.status === "rejected",
    );
    if (failure !== undefined) throw failure.reason;
  }
}

export function mergeInventoryWithSourceIdentities(
  inventory: AgentInventory,
  sourceIdentities: readonly AgentIdentity[],
): AgentInventory {
  return mergeInventoryWithHistoricalIdentities(
    inventory,
    sourceIdentities,
  );
}

export function attributedRuntimeAgentID(
  agents: readonly AgentIdentity[],
  record: unknown,
): string | undefined {
  const reported = reportedProcessIdentity(record);
  if (
    !reported.coverageComplete ||
    reported.conflict ||
    reported.processKey === undefined
  ) {
    return undefined;
  }
  const keyCapability = processKeyCapability(reported.processKey);
  if (keyCapability === undefined) return undefined;
  const matches = agents.filter(
    (agent) =>
      agent.state === AgentState.RUNNING &&
      agent.capabilities.includes("process-instance") &&
      agent.capabilities.includes(keyCapability),
  );
  if (matches.length !== 1) return undefined;
  const matched = matches[0];
  if (
    matched === undefined ||
    (reported.processID !== undefined &&
      matched.processId !== reported.processID)
  ) {
    return undefined;
  }
  return matched.agentId;
}

export type ReportedProcessIdentity = Readonly<{
  processKey?: string;
  processID?: bigint;
  conflict: boolean;
  coverageComplete: boolean;
}>;

/**
 * Keeps agent-native process claims independent from inventory/OS evidence.
 * A PID can reject a contradictory match, but can never create one.
 */
export function reportedProcessIdentity(
  record: unknown,
): ReportedProcessIdentity {
  const object = objectValue(record);
  if (object === null) {
    return { conflict: false, coverageComplete: false };
  }
  const metadata = objectValue(object["metadata"]);
  const keyValues = new Set<string>();
  let invalidKeyClaim = false;
  for (const candidate of [
    object["process_key"],
    object["processKey"],
    metadata?.["process_key"],
    metadata?.["processKey"],
  ]) {
    if (candidate === undefined) continue;
    if (
      typeof candidate !== "string" ||
      candidate.length === 0 ||
      candidate !== candidate.trim() ||
      Buffer.byteLength(candidate, "utf8") > 256 ||
      /[\u0000-\u001f\u007f]/u.test(candidate)
    ) {
      invalidKeyClaim = true;
      continue;
    }
    keyValues.add(candidate);
  }
  const processIDs = new Set<bigint>();
  let invalidProcessID = false;
  for (const candidate of [
    object["process_id"],
    object["processId"],
    object["pid"],
    metadata?.["process_id"],
    metadata?.["processId"],
    metadata?.["pid"],
  ]) {
    if (
      typeof candidate === "number" &&
      Number.isSafeInteger(candidate) &&
      candidate > 0
    ) {
      processIDs.add(BigInt(candidate));
      continue;
    }
    if (
      typeof candidate === "string" &&
      /^[1-9][0-9]{0,18}$/u.test(candidate)
    ) {
      try {
        processIDs.add(BigInt(candidate));
      } catch {
        invalidProcessID = true;
      }
      continue;
    }
    if (candidate !== undefined) invalidProcessID = true;
  }
  const conflict = keyValues.size > 1 || processIDs.size > 1;
  return {
    ...(
      keyValues.size === 1
        ? { processKey: [...keyValues][0] }
        : {}
    ),
    ...(
      processIDs.size === 1
        ? { processID: [...processIDs][0] }
        : {}
    ),
    conflict,
    coverageComplete:
      keyValues.size === 1 &&
      !invalidKeyClaim &&
      !invalidProcessID &&
      !conflict,
  };
}

const embeddedSessionAdapters = new Set(["generic", "opencode"]);

/**
 * Uses a provider-reported session only on adapters whose records carry that
 * identity per event. Missing, invalid, or conflicting claims fail closed to
 * the source-file identity so concurrent transcripts are never guessed into
 * one conversation.
 */
export function reportedSessionID(
  adapterID: string,
  record: unknown,
  sourceID: string,
): string {
  if (!embeddedSessionAdapters.has(adapterID)) return sourceID;
  const object = objectValue(record);
  if (object === null) return sourceID;
  const metadata = objectValue(object["metadata"]);
  const values = new Set<string>();
  for (const candidate of [
    object["session_id"],
    object["sessionId"],
    object["sessionID"],
    object["thread_id"],
    object["threadId"],
    object["conversation_id"],
    object["conversationId"],
    metadata?.["session_id"],
    metadata?.["sessionId"],
    metadata?.["sessionID"],
    metadata?.["thread_id"],
    metadata?.["threadId"],
  ]) {
    if (
      typeof candidate === "string" &&
      candidate === candidate.trim() &&
      Buffer.byteLength(candidate, "utf8") <= 128 &&
      /^[^\u0000-\u001f\u007f]+$/u.test(candidate)
    ) {
      values.add(candidate);
    }
  }
  return values.size === 1 ? [...values][0] ?? sourceID : sourceID;
}

function vendorType(record: unknown): string {
  const object = objectValue(record);
  if (object === null) return "record";
  const outer = stringField(object, "type") || "record";
  const payload = objectValue(object["payload"]);
  const inner = stringField(payload, "type");
  return inner === "" || inner === outer ? outer : `${outer}/${inner}`;
}

function configuredSources(config: ObserverConfig): readonly ActivitySource[] {
  return [
    {
      adapterId: "codex",
      roots: config.activitySourceDirectories.codex,
    },
    {
      adapterId: "claude",
      roots: config.activitySourceDirectories.claude,
    },
    {
      adapterId: "hermes",
      roots: config.activitySourceDirectories.hermes,
    },
    {
      adapterId: "openclaw",
      roots: config.activitySourceDirectories.openclaw,
    },
    {
      adapterId: "copilot",
      roots: config.activitySourceDirectories.copilot,
    },
    {
      adapterId: "opencode",
      roots: config.activitySourceDirectories.opencode,
      format: "opencode-sqlite",
    },
    {
      adapterId: "generic",
      roots: config.activitySourceDirectories.generic,
    },
    ...activityBridgeAgents.map((agent) => ({
      adapterId: agent.id,
      roots: [join(config.dataDirectory, "bridges", agent.id)],
    })),
  ];
}

class MinuteRateLimiter {
  readonly #limit: number;
  readonly #accepted: number[] = [];

  constructor(limit: number) {
    this.#limit = limit;
  }

  remaining(now: Date): number {
    const threshold = now.getTime() - 60_000;
    while (
      this.#accepted.length > 0 &&
      (this.#accepted[0] ?? 0) <= threshold
    ) {
      this.#accepted.shift();
    }
    return Math.max(0, this.#limit - this.#accepted.length);
  }

  consume(now: Date, count: number): void {
    for (let index = 0; index < count; index++) this.#accepted.push(now.getTime());
  }
}

function fallbackAgentID(
  kind: AgentKind,
  adapterId: string,
  sourceId: string,
): string {
  return `agt_${createHash("sha256")
    .update(`phigon-activity-v2:${kind}:${adapterId}:${sourceId}`)
    .digest("hex")
    .slice(0, 32)}`;
}

function sourceIdentityDisplayName(
  adapterID: string,
  sourceID: string,
  sourceDisplayName?: string,
): string {
  const configured = activityBridgeAgents.find(
    (agent) => agent.id === adapterID,
  )?.displayName;
  const product = sourceDisplayName ?? configured ?? (() => {
    switch (adapterID) {
      case "claude": return "Claude Code";
      case "codex": return "OpenAI Codex";
      case "copilot": return "GitHub Copilot CLI";
      case "hermes": return "Hermes Agent";
      case "openclaw": return "OpenClaw";
      case "opencode": return "OpenCode";
      default: return "Agent activity";
    }
  })();
  const sourceSuffix = sourceID.replace(/[^a-zA-Z0-9]/gu, "").slice(-8);
  return `${product} · Source ${sourceSuffix || "unknown"} (unattributed)`
    .slice(0, 128);
}

export type ReportedGenericAgentIdentity = Readonly<{
  hint?: string;
  displayName?: string;
  conflict: boolean;
  coverageComplete: boolean;
}>;

/**
 * Keeps user-provided custom bridge identity independent from vendor claims.
 * A single consistent label can name an unattributed source, while conflicts,
 * invalid claims, and missing evidence always fail closed.
 */
export function reportedGenericAgentIdentity(
  record: unknown,
  configuredDisplayName?: string,
): ReportedGenericAgentIdentity {
  const object = objectValue(record);
  if (object === null) {
    return { conflict: false, coverageComplete: false };
  }
  const metadata = objectValue(object["metadata"]);
  const values = new Map<string, string>();
  let invalidClaim = false;
  for (const candidate of [
    configuredDisplayName,
    object["phigon_agent_name"],
    object["agent_id"],
    object["agentId"],
    object["agent"],
    object["agent_name"],
    object["agentName"],
    object["source"],
    object["provider"],
    metadata?.["agent"],
    metadata?.["source"],
  ]) {
    if (candidate === undefined) continue;
    if (
      typeof candidate !== "string" ||
      candidate !== candidate.trim() ||
      candidate.length === 0 ||
      Buffer.byteLength(candidate, "utf8") > 128 ||
      /[\u0000-\u001f\u007f]/u.test(candidate)
    ) {
      invalidClaim = true;
      continue;
    }
    const hint = normalizeAgentHint(candidate);
    if (hint === "") {
      invalidClaim = true;
      continue;
    }
    if (!values.has(hint)) values.set(hint, candidate);
  }
  if (invalidClaim || values.size !== 1) {
    return {
      conflict: values.size > 1,
      coverageComplete: false,
    };
  }
  const [hint, displayName] = values.entries().next().value ?? [];
  if (hint === undefined || displayName === undefined) {
    return { conflict: false, coverageComplete: false };
  }
  return {
    hint,
    displayName,
    conflict: false,
    coverageComplete: true,
  };
}

export function registeredAgentActivitySources(
  registrations: readonly Readonly<{
    displayName: string;
    activityDirectories: readonly string[];
  }>[],
): readonly ActivitySource[] {
  return registrations
    .filter((registration) => registration.activityDirectories.length > 0)
    .map((registration) => ({
      adapterId: "generic",
      roots: registration.activityDirectories,
      sourceDisplayName: registration.displayName,
    }));
}

function normalizeAgentHint(value: string): string {
  return value
    .toLowerCase()
    .replace(/[^a-z0-9]+/gu, "-")
    .replace(/^-+|-+$/gu, "");
}

function clampObservedAt(value: Date, now: Date): Date {
  if (Number.isNaN(value.getTime())) return now;
  if (value.getTime() > now.getTime() + 5 * 60_000) return now;
  return value;
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
