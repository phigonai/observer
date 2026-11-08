import { createHash } from "node:crypto";
import { readdir, stat, unlink } from "node:fs/promises";
import { join } from "node:path";
import { create, toBinary } from "@bufbuild/protobuf";
import { timestampFromDate } from "@bufbuild/protobuf/wkt";
import { abortableDelay } from "../abortable-delay.js";
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
import { rememberEncoding } from "../event-queue.js";
import {
  EventEnvelopeSchema,
  type EventEnvelope,
} from "../generated/phigon/v1/telemetry_pb.js";
import { claudeActivityAdapter } from "./adapters/claude.js";
import {
  clineExtensionActivityAdapter,
  clineTaskFirstMessageField,
  kiloCodeActivityAdapter,
  rooCodeActivityAdapter,
} from "./adapters/cline-task.js";
import { clineActivityAdapter } from "./adapters/cline.js";
import { codexActivityAdapter } from "./adapters/codex.js";
import { copilotActivityAdapter } from "./adapters/copilot.js";
import { copilotChatActivityAdapter } from "./adapters/copilot-chat.js";
import { cursorActivityAdapter } from "./adapters/cursor.js";
import { factoryDroidActivityAdapter } from "./adapters/factory-droid.js";
import { geminiActivityAdapter } from "./adapters/gemini.js";
import { gooseActivityAdapter } from "./adapters/goose.js";
import { hermesActivityAdapter } from "./adapters/hermes.js";
import { kiroActivityAdapter } from "./adapters/kiro.js";
import { openClawActivityAdapter } from "./adapters/openclaw.js";
import { openCodeActivityAdapter } from "./adapters/opencode.js";
import { zedActivityAdapter } from "./adapters/zed.js";
import { createOpenAICompatibleAdapter } from "./adapters/openai-compatible.js";
import { activityBridgeAgents } from "./bridges.js";
import { genericActivityAdapter } from "./adapters/generic.js";
import { loadIdentifierKey } from "./identifier-key.js";
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
  fileReadThrough,
  type ActivitySource,
  type SourceFailure,
  type SourceRecord,
} from "./source-reader.js";
import { bridgeWritingSuffix, ingestedBridgeFile } from "./ingest.js";
import { closedJournalSegments, guardianDecisionFilePattern, phigonGuardianCapability } from "../bridge-journal.js";
import type { VendorActivityAdapter } from "./types.js";
import { processKeyCapability } from "../discovery/process-identity.js";

const maxEnvelopeBytes = 1 << 20;
const maxPendingCheckpoints = 256;
// Bridge files are cleaned up this often, and kept at most this long.
const bridgePruneIntervalMs = 5 * 60_000;
const bridgeFileRetentionMs = 7 * 86_400_000;
// A closed journal segment untouched this long has no writer left.
const closedSegmentQuietMs = 60_000;
// Saved live checkpoints remembered while their events await acknowledgement.
const retainedLiveCheckpoints = 8;
// The live reader writes its cursors at most this often while an agent is
// active; see JSONLSourceReader. Written again when collection stops.
const liveCheckpointSaveIntervalMs = 5_000;
// After this long without a record, live collection scans every
// `idleScanIntervalMs` instead of every scan interval, until a record
// arrives or a watched folder reports a change.
const defaultIdleAfterMs = 2 * 60_000;
const defaultIdleScanIntervalMs = 5_000;
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
  // Deliberately replaces the generated OpenCode bridge parser: the native
  // adapter reads both OpenCode's database events and the structured CLI
  // records (step_start, tool_use, text, step_finish) that
  // `ingest --agent opencode` receives, as docs/activity-collection.md says.
  ["opencode", openCodeActivityAdapter],
  // Native recordings use their own adapter IDs so the OpenAI-compatible
  // `ingest --agent` bridges for the same products keep their parser.
  ["gemini-cli", geminiActivityAdapter],
  ["cline-cli", clineActivityAdapter],
  ["goose-session", gooseActivityAdapter],
  ["cursor-transcript", cursorActivityAdapter],
  ["copilot-chat", copilotChatActivityAdapter],
  ["kiro-session", kiroActivityAdapter],
  ["zed-thread", zedActivityAdapter],
  ["factory-droid", factoryDroidActivityAdapter],
  ["cline-task", clineExtensionActivityAdapter],
  ["roo-code-task", rooCodeActivityAdapter],
  ["kilo-code-task", kiloCodeActivityAdapter],
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
  /** Scans whose records delivery refused; they are read again later. */
  refusedDeliveries: number;
  /** Sources or files currently skipped after a failure. */
  failingSources: number;
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
  /**
   * Makes every event emitted so far durable, for example by writing the
   * buffered telemetry spool. With durable delivery a source checkpoint
   * moves past an unacknowledged event only after this succeeds.
   */
  flushDelivery?: () => void | Promise<void>;
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
  /**
   * Called when delivery first refuses an event after accepting the
   * previous ones, for example because the spool is full.
   */
  onDeliveryRefused?: (error: unknown) => void;
  /**
   * Called when a source (or one of its files) starts failing. It is
   * skipped for a while and retried; every other source keeps collecting.
   */
  onSourceFailure?: (failure: SourceFailure) => void;
  /** How long without records before scanning slows down; tests shorten it. */
  idleAfterMs?: number;
  /** The scan interval while idle. */
  idleScanIntervalMs?: number;
}>;

/**
 * `emit` refused an event. The reader was put back to where the scan
 * started, so its records are read again once delivery has room.
 */
class DeliveryRefusedError extends Error {}

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

type ConvertedRecord = Readonly<{
  events: readonly EventEnvelope[];
  /** Normalized drafts, which the rate limit counts. */
  drafts: number;
  oversized: number;
}>;

const sourceIdentityFailureKey = "agent identities";

/** The kind of an error, never its message, which may quote a record. */
function errorName(error: unknown): string {
  const name = error instanceof Error ? error.name : "";
  return /^[A-Za-z][A-Za-z0-9]{0,63}$/u.test(name) ? name : "unknown error";
}

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
  readonly #onDeliveryRefused: (error: unknown) => void;
  readonly #onSourceFailure: (failure: SourceFailure) => void;
  readonly #reportedFailures = new WeakSet<SourceFailure>();
  // Failures in a row of record conversion, per adapter, and of saving
  // source identities. The keys are a fixed, small set.
  readonly #collectionFailures = new Map<string, number>();
  #registeredSourcesFailing = false;
  #deliveryRefused = false;
  #refusedDeliveries = 0;
  #policy: LocalPolicyEngine;
  readonly #identifierKey: Buffer;
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
  // Saved live-reader checkpoints, oldest first, with the sequence that
  // their events end at. Bridge files they read through can be deleted once
  // the server acknowledges that sequence.
  #committedLive: ReadonlyArray<Readonly<{
    cursors: ReadonlyMap<string, number>;
    throughSequence: bigint;
  }>> = [];
  readonly #flushDelivery: () => void | Promise<void>;
  #pendingCheckpoints: ReadonlyArray<PendingCheckpoint> = [];
  #checkpointSave = Promise.resolve();
  readonly #sourceIdentitySaves: Promise<void>[] = [];
  #backpressuredScans = 0;
  #scanWork: Promise<void> = Promise.resolve();
  readonly #idleAfterMs: number;
  readonly #idleScanIntervalMs: number;
  // When the last live scan finished, for health output.
  #lastScanAt: Date | undefined;
  #lastScanDurationMs = 0;
  #idle = false;

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
        "live",
        undefined,
        liveCheckpointSaveIntervalMs,
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
    this.#onDeliveryRefused = options.onDeliveryRefused ?? (() => undefined);
    this.#onSourceFailure = options.onSourceFailure ?? (() => undefined);
    this.#identifierKey = loadIdentifierKey(options.config.dataDirectory);
    this.#policy = new LocalPolicyEngine(
      options.policy ?? options.config.policy,
      options.config.redactionPathPatterns,
      undefined,
      this.#identifierKey,
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
    this.#flushDelivery = options.flushDelivery ?? (() => undefined);
    this.#idleAfterMs = options.idleAfterMs ?? defaultIdleAfterMs;
    this.#idleScanIntervalMs = options.idleScanIntervalMs ?? defaultIdleScanIntervalMs;
  }

  updateInventory(inventory: AgentInventory): void {
    this.#agentsByKind.clear();
    for (const agent of inventory.agents) this.#rememberAgent(agent);
  }

  updatePolicy(policy: CollectionPolicy): void {
    this.#policy = new LocalPolicyEngine(
      policy,
      this.#config.redactionPathPatterns,
      undefined,
      this.#identifierKey,
    );
  }

  resetSequence(
    acknowledgedSequence: bigint,
    allocationSequence = acknowledgedSequence,
  ): void {
    if (acknowledgedSequence < 0n || allocationSequence < 0n) {
      throw new Error("Activity sequence must not be negative.");
    }
    // The server lost acknowledgements: no saved checkpoint is known to be
    // delivered any more.
    this.#committedLive = [];
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
          await abortableDelay(250, signal);
          continue;
        }
        // Release the collection lock between bounded batches. A large archive
        // must not prevent the live reader from following current work.
        const started = performance.now();
        let pass: CollectionPass;
        try {
          pass = await this.#withScanLock(async () => {
            const before = this.#emittedEvents;
            const result = await this.#collectOnce(this.#historyReader, true);
            eventsUploaded += this.#emittedEvents - before;
            return result;
          });
        } catch (error) {
          if (!(error instanceof DeliveryRefusedError)) throw error;
          await abortableDelay(250, signal);
          continue;
        }
        recordsScanned += pass.sourceRecords;
        filesDiscovered = Math.max(filesDiscovered, pass.discoveredFiles);
        complete = pass.complete;
        if (!complete && pass.sourceRecords === 0) {
          await abortableDelay(100, signal);
        } else if (!complete) {
          await abortableDelay(historyRest(performance.now() - started), signal);
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
    const start = reader.position();
    const scan = await reader.scan([
      ...this.#sources,
      ...await this.#registeredSources(),
    ], Math.max(1, Math.floor(allowance / maxDraftsPerRecord)));
    this.#reportSourceFailures(reader);
    this.#sourceRecords += scan.metrics.records;
    this.#malformedRecords += scan.metrics.malformed;
    this.#oversizedRecords += scan.metrics.oversized;
    const now = this.#clock();
    for (const record of scan.records) {
      const adapter = adapters.get(record.adapterId);
      if (adapter === undefined) continue;
      let converted: ConvertedRecord;
      try {
        converted = this.#convertRecord(record, adapter, historical, now);
      } catch (error) {
        // A record this observer cannot convert is skipped like a malformed
        // one: reading it again would fail the same way, and stopping
        // would end collection from every source.
        this.#malformedRecords++;
        this.#reportCollectionFailure(
          record.adapterId,
          `one record could not be converted and was skipped (${errorName(error)})`,
        );
        continue;
      }
      this.#collectionFailures.delete(record.adapterId);
      this.#oversizedEvents += converted.oversized;
      // A source record is atomic: never advance its cursor after dropping
      // part of its normalized activity. One record may use the final budget
      // plus a bounded burst; the next scan waits for replenishment.
      if (!historical) this.#limiter.consume(now, converted.drafts);
      for (const event of converted.events) {
        try {
          this.#emit(event);
        } catch (error) {
          // The reader already moved past this scan's records. Put it back
          // so none is skipped; the ones delivered before this event are
          // sent again with the same source event IDs, which the server
          // deduplicates. The sequence stays unused, leaving no gap.
          reader.rewind(start);
          this.#refusedDeliveries++;
          if (!this.#deliveryRefused) {
            this.#deliveryRefused = true;
            this.#onDeliveryRefused(error);
          }
          throw new DeliveryRefusedError(
            "Telemetry delivery refused an activity event.",
            { cause: error },
          );
        }
        this.#lastSequence = event.sequence;
        this.#emittedEvents++;
      }
    }
    this.#deliveryRefused = false;
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

  /**
   * The events for one source record, numbered from the next sequence, and
   * how many normalized drafts they came from. Throws when the record cannot
   * be converted; nothing is emitted for it then.
   */
  #convertRecord(
    record: SourceRecord,
    adapter: VendorActivityAdapter,
    historical: boolean,
    now: Date,
  ): ConvertedRecord {
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
    const events: EventEnvelope[] = [];
    let oversized = 0;
    for (const [draftIndex, draft] of permittedDrafts.entries()) {
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
          record.sourceCapabilities,
        ),
        sessionId: draft.sessionId,
        sequence: this.#lastSequence + 1n + BigInt(events.length),
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
      const encoded = toBinary(EventEnvelopeSchema, event);
      if (encoded.byteLength > maxEnvelopeBytes) {
        oversized++;
        continue;
      }
      // The spool stores this encoding rather than making it again.
      rememberEncoding(event, encoded);
      events.push(event);
    }
    return { events, drafts: permittedDrafts.length, oversized };
  }

  /**
   * Says that collection work keeps failing, at the 1st, 2nd, 4th, 8th...
   * failure in a row, so it stays visible without flooding the log. The
   * message never includes activity content.
   */
  #reportCollectionFailure(key: string, message: string): void {
    const failures = (this.#collectionFailures.get(key) ?? 0) + 1;
    this.#collectionFailures.set(key, failures);
    if ((failures & (failures - 1)) !== 0) return;
    const now = this.#clock();
    this.#onSourceFailure(Object.freeze({
      adapterId: key,
      failures,
      message,
      failedAt: now,
      retryAt: now,
    }));
  }

  /**
   * Scans every scan interval (a second) while agents are active. After
   * two minutes without a record it scans every five seconds instead, and
   * goes back to every second at once when a record arrives or a watched
   * agent folder reports a change (Windows and macOS; elsewhere the next
   * five-second scan finds it). Whether the computer runs on battery is not
   * used: no system reports it cheaply and reliably without starting a
   * process.
   */
  async run(signal: AbortSignal): Promise<void> {
    let prunedAt = 0;
    let activeAt = this.#clock().getTime();
    try {
      while (!signal.aborted) {
        const recordsBefore = this.#sourceRecords;
        const started = performance.now();
        try {
          await this.scanOnce();
        } catch (error) {
          // A full queue or spool waits for acknowledgements like any
          // other backpressure; the refused records are read again.
          if (!(error instanceof DeliveryRefusedError)) throw error;
        }
        this.#lastScanDurationMs = performance.now() - started;
        this.#lastScanAt = this.#clock();
        const now = this.#lastScanAt.getTime();
        if (this.#reader.takeActivityHint() || this.#sourceRecords !== recordsBefore || now < activeAt) {
          activeAt = now;
        }
        if (now - prunedAt >= bridgePruneIntervalMs) {
          prunedAt = now;
          // Cleanup only frees disk space; it retries on the next pass.
          await this.pruneBridgeFiles().catch(() => undefined);
        }
        const interval = this.#config.activityScanIntervalMs;
        this.#idle = now - activeAt >= this.#idleAfterMs && this.#idleScanIntervalMs > interval;
        await abortableDelay(interval, signal);
        if (this.#idle) await this.#restUntilHint(this.#idleScanIntervalMs - interval, signal);
      }
    } finally {
      // Write the cursors a commit kept back; losing them only reads a few
      // seconds of records again.
      try {
        await this.#checkpointSave;
        await this.#reader.flushCheckpoint();
      } catch {
        // Read again on the next start.
      }
      this.close();
    }
  }

  /** Waits `milliseconds`, or less once a watched folder reports a change. */
  async #restUntilHint(milliseconds: number, signal: AbortSignal): Promise<void> {
    if (signal.aborted || this.#reader.activityHinted()) return;
    await new Promise<void>((resolve) => {
      let stopListening: () => void = () => undefined;
      const done = () => {
        clearTimeout(timer);
        signal.removeEventListener("abort", done);
        stopListening();
        resolve();
      };
      const timer = setTimeout(done, milliseconds);
      signal.addEventListener("abort", done, { once: true });
      stopListening = this.#reader.onActivityHint(done);
    });
  }

  /** When the last live scan finished and how long it took, and whether collection is resting. */
  scanHealth(): Readonly<{ lastScanAt?: Date; lastScanDurationMs: number; idle: boolean }> {
    return Object.freeze({
      ...(this.#lastScanAt === undefined ? {} : { lastScanAt: this.#lastScanAt }),
      lastScanDurationMs: this.#lastScanDurationMs,
      idle: this.#idle,
    });
  }

  /**
   * Deletes bridge files this observer is done with: an `ingest` file or a
   * closed journal segment whose records were all read under a checkpoint
   * the server has acknowledged through, or any of them after seven days.
   * A file an `ingest` run is still writing, and each journal's newest
   * segment, are never deleted while in use.
   */
  async pruneBridgeFiles(): Promise<void> {
    const now = this.#clock().getTime();
    const acknowledged = this.#acknowledgedSequence;
    const settled = this.#committedLive.findLast(
      (checkpoint) => checkpoint.throughSequence <= acknowledged,
    );
    for (const agent of activityBridgeAgents) {
      const root = join(this.#config.dataDirectory, "bridges", agent.id);
      let names: string[];
      try {
        names = await readdir(root);
      } catch {
        continue;
      }
      const present = new Set(names);
      const closedSegments = new Set(closedJournalSegments(names));
      for (const name of names) {
        const ingested = ingestedBridgeFile.test(name);
        if (!ingested && !closedSegments.has(name)) continue;
        const path = join(root, name);
        try {
          const modifiedMs = (await stat(path)).mtimeMs;
          const expired = now - modifiedMs >= bridgeFileRetentionMs;
          const inUse = ingested
            ? present.has(`${name}${bridgeWritingSuffix}`)
            // A segment closes when its journal starts the next one; a
            // writer that chose it just before may still be appending.
            : now - modifiedMs < closedSegmentQuietMs;
          if (
            expired ||
            (!inUse && settled !== undefined &&
              await fileReadThrough(path, settled.cursors))
          ) {
            await unlink(path);
            if (ingested) {
              await unlink(`${path}${bridgeWritingSuffix}`).catch(() => undefined);
            }
          }
        } catch {
          // Gone, or locked by another program: retried on the next pass.
        }
      }
    }
  }

  /**
   * Release the database connections the live reader keeps open. A later
   * scan opens them again.
   */
  close(): void {
    this.#reader.close();
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
      refusedDeliveries: this.#refusedDeliveries,
      failingSources: this.#reader.sourceFailures().length,
    });
  }

  /**
   * Sources of registered custom agents. When their list cannot be read,
   * this scan goes on with the built-in sources.
   */
  async #registeredSources(): Promise<readonly ActivitySource[]> {
    try {
      const sources = await this.#additionalSources();
      this.#registeredSourcesFailing = false;
      return sources;
    } catch (error) {
      if (!this.#registeredSourcesFailing) {
        this.#registeredSourcesFailing = true;
        const now = this.#clock();
        this.#onSourceFailure(Object.freeze({
          adapterId: "registered agents",
          failures: 1,
          message: (error instanceof Error ? error.message : String(error))
            .replace(/\s+/gu, " ")
            .slice(0, 200),
          failedAt: now,
          // Read again on the next scan.
          retryAt: now,
        }));
      }
      return [];
    }
  }

  #reportSourceFailures(reader: JSONLSourceReader): void {
    for (const failure of reader.sourceFailures()) {
      if (failure.failures !== 1 || this.#reportedFailures.has(failure)) continue;
      this.#reportedFailures.add(failure);
      this.#onSourceFailure(failure);
    }
  }

  /** Sources and files skipped after a failure, by the live and history readers. */
  sourceFailures(): readonly SourceFailure[] {
    return [
      ...this.#reader.sourceFailures(),
      ...this.#historyReader.sourceFailures(),
    ];
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
        let currentDurableThrough = this.#acknowledgedSequence;
        if (this.#durableDelivery) {
          const emittedThrough = this.#lastSequence;
          try {
            await this.#flushDelivery();
            currentDurableThrough = emittedThrough;
          } catch {
            // Not written: only checkpoints the server acknowledged move.
            // The rest stay pending for the next save, and delivery refuses
            // new events until the spool can be written again.
          }
        }
        const committed = new Set<PendingCheckpoint>();
        for (const pending of eligible) {
          if (pending.throughSequence > currentDurableThrough) continue;
          await pending.reader.commit(pending.checkpoint);
          committed.add(pending);
          if (pending.reader === this.#reader) {
            this.#committedLive = [
              ...this.#committedLive.slice(-(retainedLiveCheckpoints - 1)),
              {
                cursors: pending.checkpoint.cursors,
                throughSequence: pending.throughSequence,
              },
            ];
          }
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
    sourceCapabilities: readonly string[] = [],
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
      sourceCapabilities,
    );
    return fallback;
  }

  #rememberSourceIdentity(
    agentID: string,
    kind: AgentKind,
    adapterID: string,
    sourceID: string,
    observedAt: Date,
    sourceDisplayName: string | undefined,
    sourceCapabilities: readonly string[],
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
      capabilities: ["activity", "source-isolated", "unattributed", ...sourceCapabilities],
    });
    this.#sourceIdentities.set(agentID, identity);
    // An identity that could not be saved is forgotten, so the source's
    // next record saves it again.
    const forget = (error: unknown): never => {
      if (this.#sourceIdentities.get(agentID) === identity) {
        this.#sourceIdentities.delete(agentID);
      }
      throw error;
    };
    let save: Promise<void>;
    try {
      save = Promise.resolve(this.#onSourceIdentity(identity)).catch(forget);
    } catch (error) {
      save = Promise.reject(error).catch(forget);
    }
    // Handled here too: a scan that stops early leaves the save for the
    // next flush, and an unhandled rejection would end the process.
    save.catch(() => undefined);
    this.#sourceIdentitySaves.push(save);
  }

  /**
   * Waits for the identity saves this scan started. A failed save is
   * reported and retried with a later record; it never stops collection,
   * because the events already carry the agent ID.
   */
  async #flushSourceIdentitySaves(): Promise<void> {
    const pending = this.#sourceIdentitySaves.splice(0);
    if (pending.length === 0) return;
    const results = await Promise.allSettled(pending);
    const failure = results.find(
      (result): result is PromiseRejectedResult =>
        result.status === "rejected",
    );
    if (failure === undefined) {
      this.#collectionFailures.delete(sourceIdentityFailureKey);
      return;
    }
    const reason: unknown = failure.reason;
    this.#reportCollectionFailure(
      sourceIdentityFailureKey,
      (reason instanceof Error ? reason.message : String(reason))
        .replace(/\s+/gu, " ")
        .slice(0, 200),
    );
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
      adapterId: "gemini-cli",
      roots: config.activitySourceDirectories.gemini,
      // <project>/chats/session-*.jsonl and subagent <parent>/<id>.jsonl.
      pathPattern: "^[^/]+/chats/",
    },
    {
      adapterId: "cline-cli",
      roots: config.activitySourceDirectories.cline,
      format: "json-messages",
      // <session>/<session>.messages.json, rewritten in place per turn.
      pathPattern: "^[^/]+/[^/]+\\.messages\\.json$",
      messagesField: "messages",
    },
    {
      adapterId: "goose-session",
      roots: config.activitySourceDirectories.goose,
      format: "goose-sqlite",
    },
    {
      adapterId: "cursor-transcript",
      roots: config.activitySourceDirectories.cursor,
      format: "json-messages",
      // <project>/agent-transcripts/<id>/<id>.jsonl and
      // <id>/subagents/<sub>.jsonl. The final line often has no newline yet.
      pathPattern: "^[^/]+/agent-transcripts/.+\\.jsonl$",
      document: {
        documentFormat: "jsonl",
        directoryPattern:
          "^[^/]+(?:/agent-transcripts(?:/[^/]+(?:/subagents)?)?)?$",
      },
    },
    // VS Code chat sessions: <workspace>/chatSessions/<id>.json documents
    // and, with operation-log storage, <id>.jsonl logs of the same session.
    ...(["json", "jsonl"] as const).map((extension) => ({
      adapterId: "copilot-chat",
      roots: config.activitySourceDirectories.copilotChat,
      format: "json-messages" as const,
      pathPattern: `^(?:[^/]+/chatSessions/)?[^/]+\\.${extension}$`,
      messagesField: "requests",
      document: {
        documentFormat: extension === "json"
          ? "json" as const
          : "mutation-log" as const,
        directoryPattern: "^[^/]+(?:/chatSessions)?$",
        messageIdField: "requestId",
        completeFields: ["result", "isCanceled", "modelState.completedAt"],
        sessionIdField: "sessionId",
      },
    })),
    {
      adapterId: "kiro-session",
      roots: config.activitySourceDirectories.kiro,
      format: "json-messages",
      // <workspace>/<session id>.json beside the <workspace>/sessions.json index.
      pathPattern: "^[^/]+/(?!sessions[.]json$)[^/]+[.]json$",
      messagesField: "history",
      document: {
        directoryPattern: "^[^/]+$",
        messageIdField: "message.id",
        sessionIdField: "sessionId",
      },
    },
    {
      adapterId: "zed-thread",
      roots: config.activitySourceDirectories.zed,
      format: "zed-sqlite",
    },
    {
      adapterId: "factory-droid",
      roots: config.activitySourceDirectories.droid,
      // <project>/<session id>.jsonl, appended as the session runs, beside
      // <session id>.settings.json.
      pathPattern: "^(?:[^/]+/)?[^/]+\\.jsonl$",
    },
    // Cline, Roo Code and Kilo Code tasks: <task id>/ui_messages.json, the
    // list of messages the extension shows, rewritten as the task runs.
    ...([
      ["cline-task", config.activitySourceDirectories.clineTasks],
      ["roo-code-task", config.activitySourceDirectories.rooCode],
      ["kilo-code-task", config.activitySourceDirectories.kiloCode],
    ] as const).map(([adapterId, roots]) => ({
      adapterId,
      roots,
      format: "json-messages" as const,
      pathPattern: "^[^/]+/ui_messages[.]json$",
      messagesField: "",
      document: {
        directoryPattern: "^[^/]+$",
        messageIdField: "ts",
        pendingField: "partial",
        firstMessageField: clineTaskFirstMessageField,
      },
    })),
    {
      adapterId: "generic",
      roots: config.activitySourceDirectories.generic,
    },
    ...activityBridgeSources(config.dataDirectory),
  ];
}

/**
 * The bridge folders in the observer's data directory. Guardian's decision
 * journal in the generic bridge is a source of its own, whose identity says it
 * is Phigon's, so it is never listed as an agent.
 */
export function activityBridgeSources(dataDirectory: string): readonly ActivitySource[] {
  return activityBridgeAgents.flatMap((agent): ActivitySource[] => {
    const roots = [join(dataDirectory, "bridges", agent.id)];
    if (agent.id !== "generic") return [{ adapterId: agent.id, roots }];
    return [
      { adapterId: agent.id, roots, pathPattern: `^(?!${guardianDecisionFilePattern}$)` },
      {
        adapterId: agent.id,
        roots,
        pathPattern: `^${guardianDecisionFilePattern}$`,
        sourceCapabilities: [phigonGuardianCapability],
      },
    ];
  });
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
      case "gemini-cli": return "Gemini CLI";
      case "cline-cli": return "Cline";
      case "goose-session": return "Goose";
      case "cursor-transcript": return "Cursor";
      case "copilot-chat": return "GitHub Copilot";
      case "kiro-session": return "Kiro";
      case "zed-thread": return "Zed";
      case "factory-droid": return "Factory Droid";
      case "cline-task": return "Cline";
      case "roo-code-task": return "Roo Code";
      case "kilo-code-task": return "Kilo Code";
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

/**
 * How long a history import rests after a batch that took `spentMs`. Resting
 * as long as the batch worked keeps a large first import near half a core,
 * and leaves the other half of the event loop to live collection; a full
 * catch-up once held a whole core for minutes. One second at most.
 */
export function historyRest(spentMs: number): number {
  if (!Number.isFinite(spentMs) || spentMs <= 0) return 0;
  return Math.min(1_000, Math.round(spentMs));
}
