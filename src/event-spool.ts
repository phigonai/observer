import { makeDirectoryPrivateSync } from "./private-directory.js";
import {
  createCipheriv,
  createDecipheriv,
  createHash,
  randomBytes,
} from "node:crypto";
import {
  appendFileSync,
  chmodSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
  statSync,
  unlinkSync,
  writeFileSync,
} from "node:fs";
import { join } from "node:path";
import { equals, fromBinary, toBinary } from "@bufbuild/protobuf";
import { atomicReplaceSync } from "./atomic-replace.js";
import {
  EventEnvelopeSchema,
  type EventEnvelope,
} from "./generated/phigon/v1/telemetry_pb.js";
import { BoundedEventQueue, takeEncoding, type QueueMetrics, type QueuedEvent } from "./event-queue.js";
import { streamStateFileName } from "./stream-state.js";

const spoolVersion = 1;
const spoolFileName = "telemetry-spool.jsonl";
const defaultMaxSpoolBytes = 64 << 20;
// Buffered records are written together, at most this long after the first.
const flushDelayMs = 100;
// A burst this large is written at once rather than held in memory.
const flushAfterBytes = 1 << 20;
// The spool is rewritten once records that no longer matter (acknowledged,
// discarded or replaced events, and acknowledgements) outweigh the queued
// events and pass this size, or a quarter of the budget if that is smaller.
const compactAfterDeadBytes = 1 << 20;
const scopedIDPattern = /^[A-Za-z0-9._:-]{1,128}$/u;
const retiredPairingsDirectory = "retired-pairings";
const damagedSpoolsDirectory = "damaged-spools";
// Each retired or damaged spool can be as large as the spool budget.
const retainedRetiredPairings = 3;
// Stored lines of queued events kept in memory, so a compaction writes
// them again instead of encrypting each event anew. Beyond this many bytes
// an event is encrypted again when the spool is rewritten.
const maxRememberedLineBytes = 16 << 20;

/**
 * What `restore` did instead of loading the spool as it was:
 * - `other_machine`: an earlier pairing's spool, moved to `directory`.
 * - `damaged`: a spool that could not be read, moved to `directory`.
 * - `over_capacity`: more events than the queue holds; the newest were kept
 *   and `dropped` of the oldest were left out.
 */
export type SpoolRestoreNotice =
  | Readonly<{ reason: "other_machine" | "damaged"; directory: string }>
  | Readonly<{ reason: "over_capacity"; dropped: number }>;

type SpoolScope = Readonly<{
  tenantID: string;
  machineID: string;
}>;

type SpoolEvent = Readonly<{
  version: 1;
  tenant_id: string;
  machine_id: string;
  operation: "event";
  sequence: string;
  coalesce_key?: string;
  nonce: string;
  ciphertext: string;
}>;

type SpoolSequenceRecord = Readonly<{
  version: 1;
  tenant_id: string;
  machine_id: string;
  sequence: string;
}> & (
  Readonly<{ operation: "acknowledge" }> |
  Readonly<{ operation: "discard" }>
);

type SpoolRecord = SpoolEvent | SpoolSequenceRecord;

type StoredLine = Readonly<{ line: string; sequence: bigint; coalesceKey: string | undefined }>;

/**
 * An encrypted append-only delivery spool. The in-memory queue remains the hot
 * path, while this log makes unacknowledged events recoverable after an
 * observer restart without writing prompt or tool content as plaintext.
 *
 * Records are group-committed: they are buffered and written with one
 * flushed append at most 100 ms later, or at once by `flush`. An event is
 * durable only after a flush, so a source checkpoint may move past an event
 * only after `flush` returns (the collector's `flushDelivery`). Events the
 * server already acknowledged are safe either way, and a lost
 * acknowledgement or discard record only sends an event again.
 */
export class FileBackedEventQueue extends BoundedEventQueue<EventEnvelope> {
  readonly #dataDirectory: string;
  readonly #path: string;
  readonly #maxBytes: number;
  readonly #compactAfterDeadBytes: number;
  #scope: SpoolScope | undefined;
  #key: Buffer | undefined;
  // Prepare the private directory and secure the file once, and track the
  // spool size here instead of stat-ing it before each write.
  #directoryPrepared = false;
  #fileSecured = false;
  #size: number | undefined;
  // Records accepted in memory but not yet written, oldest first.
  #buffer: string[] = [];
  #bufferBytes = 0;
  #flushTimer: NodeJS.Timeout | undefined;
  // Why the last write failed. A failed append can leave a partial record,
  // so the next write rewrites the whole spool instead of appending.
  #writeFailure: unknown;
  // Each queued event's stored line (an encrypted record), by event.
  #lines = new Map<EventEnvelope, StoredLine>();
  #lineBytes = 0;

  constructor(
    dataDirectory: string,
    capacity = 2048,
    maxBytes = defaultMaxSpoolBytes,
  ) {
    super(capacity);
    if (!Number.isSafeInteger(maxBytes) || maxBytes < 1) {
      throw new Error("Telemetry spool byte budget must be a positive integer.");
    }
    this.#dataDirectory = dataDirectory;
    this.#path = join(dataDirectory, spoolFileName);
    this.#maxBytes = maxBytes;
    this.#compactAfterDeadBytes = Math.min(
      compactAfterDeadBytes,
      Math.max(1, Math.floor(maxBytes / 4)),
    );
  }

  /**
   * Writes every buffered record with one flushed append. Throws when the
   * spool cannot be written; the records stay buffered and the next write
   * retries them.
   */
  flush(): void {
    if (this.#flushTimer !== undefined) {
      clearTimeout(this.#flushTimer);
      this.#flushTimer = undefined;
    }
    if (this.#writeFailure !== undefined) {
      this.#compact();
      return;
    }
    if (this.#buffer.length === 0) return;
    const encoded = this.#buffer.join("");
    try {
      this.#appendToFile(encoded);
    } catch (error) {
      this.#writeFailure = error;
      this.#size = undefined;
      throw error;
    }
    this.#size = this.#currentSize() + this.#bufferBytes;
    this.#buffer = [];
    this.#bufferBytes = 0;
  }

  /**
   * Adds the spool's size by bytes: the stored size of the unacknowledged
   * events, which is what a compaction keeps, and the budget it must fit.
   */
  override metrics(): QueueMetrics {
    return Object.freeze({
      ...super.metrics(),
      bytes: this.queuedBytes(),
      byteCapacity: this.#maxBytes,
    });
  }

  /**
   * Loads the spool for this machine. None of these stops the observer, and
   * the returned notice says which one happened:
   * - A spool that an earlier pairing of this data directory left for
   *   another machine cannot be delivered as this one: it is moved aside
   *   with its stream cursor.
   * - A spool that is too large to read safely, or holds a record that does
   *   not verify before its last line, is moved aside on its own and the
   *   queue starts empty. Its events were written before their sources'
   *   checkpoints moved, so they are not read again; the moved copy keeps
   *   them for an administrator.
   * - A spool with more events than the queue holds, as after lowering
   *   PHIGON_ACTIVITY_QUEUE_CAPACITY, keeps the newest events, as a full
   *   queue does while running. The control plane records the skipped
   *   sequence numbers as a gap.
   */
  restore(
    tenantID: string,
    machineID: string,
    credential: string,
  ): SpoolRestoreNotice | undefined {
    validateScope(tenantID, machineID);
    if (!credential.startsWith("phg_m_") || credential.length > 256) {
      throw new Error("Telemetry spool credential is invalid.");
    }
    const scope = Object.freeze({ tenantID, machineID });
    const key = spoolKey(scope, credential);
    if (this.#scope !== undefined) {
      if (
        this.#scope.tenantID !== tenantID ||
        this.#scope.machineID !== machineID ||
        !this.#key?.equals(key)
      ) {
        throw new Error("Telemetry spool scope changed while the observer was running.");
      }
      return undefined;
    }
    this.#scope = scope;
    this.#key = key;
    try {
      if (!existsSync(this.#path)) return undefined;
      const metadata = statSync(this.#path);
      if (!metadata.isFile() || metadata.size > this.#maxBytes) {
        return this.#setAsideDamaged();
      }
      const restored = new BoundedEventQueue<EventEnvelope>(this.metrics().capacity);
      const raw = readFileSync(this.#path, "utf8");
      // Every record names its machine in plain text, so another machine's
      // spool is told apart from a damaged one.
      const owner = spoolOwner(raw);
      if (
        owner !== undefined &&
        (owner.tenantID !== tenantID || owner.machineID !== machineID)
      ) {
        this.#size = undefined;
        const directory = retirePairingState(this.#dataDirectory, owner.machineID);
        return directory === undefined
          ? undefined
          : { reason: "other_machine", directory };
      }
      const lines = raw.split("\n");
      const completeLines = lines.slice(0, -1);
      // Events left out because the queue was full, until a later record
      // acknowledges or discards them.
      const dropped = new Set<bigint>();
      const storedLines = new Map<EventEnvelope, StoredLine>();
      try {
        for (const line of completeLines) {
          if (line.length === 0) continue;
          const record = parseRecord(line, scope);
          const event = this.#restoreRecord(record, restored, Buffer.byteLength(line) + 1, dropped);
          if (event !== undefined) {
            storedLines.set(event, { line, sequence: event.sequence, coalesceKey: record.operation === "event" ? record.coalesce_key : undefined });
          }
        }
      } catch {
        return this.#setAsideDamaged();
      }
      this.#keepLines(restored.entries(), storedLines);
      // A crash can leave only the final write incomplete. Its records were
      // never flushed, so no source checkpoint moved past them: that tail
      // is left out by rewriting the verified prefix. A spool that ends
      // cleanly, with nothing left out and not much to drop, is kept as it
      // is and appended to, as it was before the restart.
      const torn = raw.length > 0 && !raw.endsWith("\n");
      const live = restored.entries().reduce((total, entry) => total + (entry.bytes ?? 0), 0);
      const dead = Buffer.byteLength(raw) - live;
      if (torn || dropped.size > 0 || (dead >= this.#compactAfterDeadBytes && dead > live)) {
        const sizes = this.#writeCompactedQueue(restored);
        this.replaceState(restored);
        this.reweigh(sizes);
      } else {
        this.replaceState(restored);
        this.#size = Buffer.byteLength(raw);
      }
      const acknowledged = restored.metrics().acknowledged;
      const lost = [...dropped].filter((sequence) => sequence > acknowledged).length;
      return lost === 0 ? undefined : { reason: "over_capacity", dropped: lost };
    } catch (error) {
      this.#scope = undefined;
      this.#key = undefined;
      throw error;
    }
  }

  override enqueue(
    value: EventEnvelope,
    sequence: bigint,
    coalesceKey?: string,
  ): void {
    const scope = this.#requireScope();
    if (!this.canEnqueue(coalesceKey)) {
      throw new Error(
        "Telemetry delivery queue is full; source collection stopped " +
          "before an unacknowledged event could be discarded.",
      );
    }
    validateEventScope(value, scope, sequence);
    // While the disk refuses writes, refuse new events before they reach
    // memory, as an unbuffered append did; the collector reads them again.
    if (this.#writeFailure !== undefined) this.flush();
    const line = JSON.stringify(this.#encryptedRecord(value, sequence, coalesceKey));
    const bytes = this.#appendLine(line);
    super.enqueue(value, sequence, coalesceKey, bytes);
    this.#rememberLine(value, { line, sequence, coalesceKey });
    this.#compactIfNeeded();
  }

  // Removals apply in memory before they are buffered. On a full spool the
  // compaction that makes room for the record then already leaves the
  // removed events out, so an acknowledgement can always drain the spool.
  // A removal lost in a crash only sends the event again, so removals are
  // written lazily with the next group of records.
  override acknowledge(throughSequence: bigint): void {
    if (throughSequence <= this.metrics().acknowledged) return;
    super.acknowledge(throughSequence);
    this.#appendLine(JSON.stringify(this.#sequenceRecord("acknowledge", throughSequence)));
    this.#compactIfNeeded();
  }

  override discard(sequence: bigint): boolean {
    if (!this.pending().some((event) => event.sequence === sequence)) {
      return false;
    }
    const discarded = super.discard(sequence);
    this.#appendLine(JSON.stringify(this.#sequenceRecord("discard", sequence)));
    this.#compactIfNeeded();
    return discarded;
  }

  override reconcileAcknowledged(throughSequence: bigint): void {
    const acknowledged = this.metrics().acknowledged;
    if (throughSequence === acknowledged) return;
    // Moving forward is an acknowledgement like any other, appended.
    if (throughSequence > acknowledged) {
      this.acknowledge(throughSequence);
      return;
    }
    super.reconcileAcknowledged(throughSequence);
    this.#compact();
  }

  /**
   * Replaces queued events, as when a new workspace policy arrives on each
   * connection. Events it leaves as they were keep their stored records,
   * and when none changed the spool is not rewritten at all.
   */
  override replacePending(
    replace: (value: EventEnvelope) => EventEnvelope,
  ): void {
    let changed = false;
    super.replacePending((event) => {
      const replaced = replace(event);
      if (replaced === event || equals(EventEnvelopeSchema, replaced, event)) return event;
      validateEventScope(replaced, this.#requireScope(), event.sequence);
      changed = true;
      return replaced;
    });
    if (changed || this.#writeFailure !== undefined) this.#compact();
  }

  /** Applies one stored record; returns the event it held, if any. */
  #restoreRecord(
    record: SpoolRecord,
    target: BoundedEventQueue<EventEnvelope>,
    bytes: number,
    dropped: Set<bigint>,
  ): EventEnvelope | undefined {
    const sequence = parseSequence(record.sequence);
    if (record.operation === "acknowledge") {
      target.acknowledge(sequence);
      return undefined;
    }
    if (record.operation === "discard") {
      target.discard(sequence);
      dropped.delete(sequence);
      return undefined;
    }
    const event = this.#decrypt(record);
    if (
      sequence > target.metrics().acknowledged &&
      !target.canEnqueue(record.coalesce_key)
    ) {
      // A full queue makes room by leaving out its oldest event.
      const oldest = target.metrics().oldestSequence;
      if (oldest !== undefined) dropped.add(oldest);
    }
    target.enqueue(event, sequence, record.coalesce_key, bytes);
    return event;
  }

  #rememberLine(event: EventEnvelope, stored: StoredLine): void {
    if (this.#lineBytes + stored.line.length > maxRememberedLineBytes) return;
    this.#lines.set(event, stored);
    this.#lineBytes += stored.line.length;
  }

  /** Keeps the stored lines of `entries` only, from `known`. */
  #keepLines(entries: readonly QueuedEvent<EventEnvelope>[], known: ReadonlyMap<EventEnvelope, StoredLine>): void {
    this.#lines = new Map();
    this.#lineBytes = 0;
    for (const entry of entries) {
      const stored = known.get(entry.value);
      if (stored !== undefined && stored.sequence === entry.sequence && stored.coalesceKey === entry.coalesceKey) {
        this.#rememberLine(entry.value, stored);
      }
    }
  }

  /** Moves an unreadable spool aside so the queue can start empty. */
  #setAsideDamaged(): SpoolRestoreNotice {
    this.#size = undefined;
    removeSpoolFiles(this.#dataDirectory, false);
    const directory = moveAside(
      this.#dataDirectory,
      damagedSpoolsDirectory,
      "damaged",
      [spoolFileName],
    );
    if (directory === undefined) {
      throw new Error("Telemetry spool disappeared while it was being moved aside.");
    }
    return { reason: "damaged", directory };
  }

  #encryptedRecord(
    event: EventEnvelope,
    sequence: bigint,
    coalesceKey?: string,
  ): SpoolEvent {
    const scope = this.#requireScope();
    const nonce = randomBytes(12);
    const cipher = createCipheriv("aes-256-gcm", this.#requireKey(), nonce);
    cipher.setAAD(spoolAAD(scope, sequence));
    const encrypted = Buffer.concat([
      cipher.update(takeEncoding(event) ?? toBinary(EventEnvelopeSchema, event)),
      cipher.final(),
      cipher.getAuthTag(),
    ]);
    return {
      version: spoolVersion,
      tenant_id: scope.tenantID,
      machine_id: scope.machineID,
      operation: "event",
      sequence: sequence.toString(),
      ...(coalesceKey === undefined ? {} : { coalesce_key: coalesceKey }),
      nonce: nonce.toString("base64"),
      ciphertext: encrypted.toString("base64"),
    };
  }

  #decrypt(record: SpoolEvent): EventEnvelope {
    const sequence = parseSequence(record.sequence);
    const nonce = Buffer.from(record.nonce, "base64");
    const encrypted = Buffer.from(record.ciphertext, "base64");
    if (nonce.length !== 12 || encrypted.length < 17) {
      throw new Error("Telemetry spool encryption envelope is invalid.");
    }
    const ciphertext = encrypted.subarray(0, -16);
    const tag = encrypted.subarray(-16);
    const decipher = createDecipheriv("aes-256-gcm", this.#requireKey(), nonce);
    decipher.setAAD(spoolAAD(this.#requireScope(), sequence));
    decipher.setAuthTag(tag);
    let event: EventEnvelope;
    try {
      event = fromBinary(
        EventEnvelopeSchema,
        Buffer.concat([decipher.update(ciphertext), decipher.final()]),
      );
    } catch {
      throw new Error("Telemetry spool event could not be authenticated.");
    }
    validateEventScope(event, this.#requireScope(), sequence);
    return event;
  }

  #sequenceRecord(
    operation: "acknowledge" | "discard",
    sequence: bigint,
  ): SpoolSequenceRecord {
    const scope = this.#requireScope();
    return {
      version: spoolVersion,
      tenant_id: scope.tenantID,
      machine_id: scope.machineID,
      operation,
      sequence: sequence.toString(),
    };
  }

  /** Buffer one record for the next group write and return its stored size. */
  #appendLine(line: string): number {
    const encoded = `${line}\n`;
    const bytes = Buffer.byteLength(encoded);
    if (this.#storedBytes() + bytes > this.#maxBytes) {
      this.#compact();
    }
    if (this.#storedBytes() + bytes > this.#maxBytes) {
      throw new Error("Telemetry spool is full; collection stopped before data loss.");
    }
    this.#buffer.push(encoded);
    this.#bufferBytes += bytes;
    if (this.#bufferBytes >= flushAfterBytes) {
      this.#flushQuietly();
    } else {
      this.#flushTimer ??= setTimeout(() => {
        this.#flushTimer = undefined;
        this.#flushQuietly();
      }, flushDelayMs).unref();
    }
    return bytes;
  }

  /**
   * A write that runs outside a caller who could handle its failure. The
   * failure is kept: the next event is refused until a write succeeds, and
   * no source checkpoint moves past an unwritten event.
   */
  #flushQuietly(): void {
    try {
      this.flush();
    } catch {
      // Kept in #writeFailure; the next write retries.
    }
  }

  /** One flushed append of `encoded`. */
  #appendToFile(encoded: string): void {
    this.#prepareDirectory();
    if (this.#currentSize() === 0) this.#fileSecured = false;
    const options = {
      encoding: "utf8",
      mode: 0o600,
      flush: true,
    } as const;
    try {
      appendFileSync(this.#path, encoded, options);
    } catch (error) {
      if (!isNodeError(error) || error.code !== "ENOENT") throw error;
      // The data directory was removed while running: recreate it privately.
      this.#directoryPrepared = false;
      this.#fileSecured = false;
      this.#size = 0;
      this.#prepareDirectory();
      appendFileSync(this.#path, encoded, options);
    }
    if (!this.#fileSecured) {
      chmodSync(this.#path, 0o600);
      this.#fileSecured = true;
    }
  }

  /** The spool's size once the buffered records are written. */
  #storedBytes(): number {
    return this.#currentSize() + this.#bufferBytes;
  }

  #prepareDirectory(): void {
    if (this.#directoryPrepared) return;
    mkdirSync(this.#dataDirectory, { recursive: true, mode: 0o700 });
    makeDirectoryPrivateSync(this.#dataDirectory);
    this.#directoryPrepared = true;
  }

  #currentSize(): number {
    if (this.#size === undefined) {
      try {
        this.#size = statSync(this.#path).size;
      } catch (error) {
        if (!isNodeError(error) || error.code !== "ENOENT") throw error;
        this.#size = 0;
      }
    }
    return this.#size;
  }

  #compactIfNeeded(): void {
    // A compaction rewrites the queued events, so rewriting only once the
    // records it drops outweigh them keeps its cost proportional to the
    // records appended since the last one.
    const live = this.queuedBytes();
    const dead = this.#storedBytes() - live;
    if (dead >= this.#compactAfterDeadBytes && dead > live) this.#compact();
  }

  /** Rewrite the spool from memory, which also writes every buffered record. */
  #compact(): void {
    this.reweigh(this.#writeCompactedQueue(this));
  }

  /** Rewrite the spool as `queue` and return each queued event's stored size. */
  #writeCompactedQueue(queue: BoundedEventQueue<EventEnvelope>): number[] {
    this.#requireScope();
    mkdirSync(this.#dataDirectory, { recursive: true, mode: 0o700 });
    makeDirectoryPrivateSync(this.#dataDirectory);
    // An event whose stored line is known is written as it was: same
    // record, same nonce. Only the others are encrypted again.
    const entries = queue.entries();
    const written = new Map<EventEnvelope, StoredLine>();
    const lines = [JSON.stringify(this.#sequenceRecord("acknowledge", queue.metrics().acknowledged))];
    for (const entry of entries) {
      const known = this.#lines.get(entry.value);
      const line = known !== undefined && known.sequence === entry.sequence && known.coalesceKey === entry.coalesceKey
        ? known.line
        : JSON.stringify(this.#encryptedRecord(entry.value, entry.sequence, entry.coalesceKey));
      lines.push(line);
      written.set(entry.value, { line, sequence: entry.sequence, coalesceKey: entry.coalesceKey });
    }
    const encoded = `${lines.join("\n")}\n`;
    if (Buffer.byteLength(encoded) > this.#maxBytes) {
      throw new Error("Telemetry spool is full; collection stopped before data loss.");
    }
    const temporaryPath = `${this.#path}.${process.pid}.${randomBytes(8).toString("hex")}.tmp`;
    try {
      writeFileSync(temporaryPath, encoded, {
        encoding: "utf8",
        flag: "wx",
        mode: 0o600,
        flush: true,
      });
      this.#size = undefined;
      atomicReplaceSync(temporaryPath, this.#path);
      chmodSync(this.#path, 0o600);
      this.#directoryPrepared = true;
      this.#fileSecured = true;
      this.#size = Buffer.byteLength(encoded);
      // Memory already holds every buffered record's effect.
      this.#buffer = [];
      this.#bufferBytes = 0;
      this.#keepLines(entries, written);
      this.#writeFailure = undefined;
      if (this.#flushTimer !== undefined) {
        clearTimeout(this.#flushTimer);
        this.#flushTimer = undefined;
      }
    } catch (error) {
      try {
        unlinkSync(temporaryPath);
      } catch {
        // The temporary file may not have been created.
      }
      throw error;
    }
    // The first line is the acknowledgement; each event is one line.
    return lines.slice(1).map((line) => Buffer.byteLength(line) + 1);
  }

  #requireScope(): SpoolScope {
    if (this.#scope === undefined) {
      throw new Error("Telemetry spool must be restored before use.");
    }
    return this.#scope;
  }

  #requireKey(): Buffer {
    if (this.#key === undefined) {
      throw new Error("Telemetry spool key is unavailable.");
    }
    return this.#key;
  }
}

export function clearEventSpool(dataDirectory: string): void {
  removeSpoolFiles(dataDirectory, true);
}

/**
 * Moves what an earlier pairing of this data directory left behind out of
 * the way, so a computer paired again as a new machine starts with an empty
 * queue instead of refusing to read the old one. The encrypted spool, the
 * stream cursor and `extraFiles` (such as the old credential, the only key
 * that can still decrypt that spool) go to `retired-pairings/<time>-<machine>/`.
 * Only the newest few pairings are kept. Returns that directory, or
 * undefined when there was nothing to move.
 */
export function retirePairingState(
  dataDirectory: string,
  machineID: string | undefined,
  extraFiles: readonly string[] = [],
): string | undefined {
  removeSpoolFiles(dataDirectory, false);
  return moveAside(
    dataDirectory,
    retiredPairingsDirectory,
    machineID ?? "unknown",
    [spoolFileName, streamStateFileName, ...extraFiles],
  );
}

/**
 * Moves the `names` that exist into a new `<rootName>/<time>-<label>-*`
 * directory and keeps only the newest few such directories. Returns the new
 * directory, or undefined when there was nothing to move.
 */
function moveAside(
  dataDirectory: string,
  rootName: string,
  label: string,
  names: readonly string[],
): string | undefined {
  const present = names.filter((name) => existsSync(join(dataDirectory, name)));
  if (present.length === 0) return undefined;
  const root = join(dataDirectory, rootName);
  mkdirSync(root, { recursive: true, mode: 0o700 });
  chmodSync(root, 0o700);
  // The time first, so names sort oldest first; Windows refuses ":" in names.
  const stamp = new Date().toISOString().replace(/[:.]/gu, "-");
  const safeLabel = label.replace(/[^A-Za-z0-9._-]/gu, "_");
  const destination = mkdtempSync(join(root, `${stamp}-${safeLabel}-`));
  for (const name of present) {
    atomicReplaceSync(join(dataDirectory, name), join(destination, name));
  }
  const kept = readdirSync(root, { withFileTypes: true })
    .filter((entry) => entry.isDirectory())
    .map((entry) => entry.name)
    .sort();
  for (const name of kept.slice(0, -retainedRetiredPairings)) {
    rmSync(join(root, name), { recursive: true, force: true });
  }
  return destination;
}

function removeSpoolFiles(dataDirectory: string, includeSpool: boolean): void {
  let names: string[];
  try {
    names = readdirSync(dataDirectory);
  } catch (error) {
    if (!isNodeError(error) || error.code !== "ENOENT") throw error;
    return;
  }
  for (const name of names) {
    const temporary =
      name.startsWith(`${spoolFileName}.`) && name.endsWith(".tmp");
    if (!temporary && !(includeSpool && name === spoolFileName)) continue;
    try {
      unlinkSync(join(dataDirectory, name));
    } catch (error) {
      if (!isNodeError(error) || error.code !== "ENOENT") throw error;
    }
  }
}

/** The machine that wrote a spool, from its first record. */
function spoolOwner(
  raw: string,
): Readonly<{ tenantID: string; machineID: string }> | undefined {
  const end = raw.indexOf("\n");
  if (end < 0) return undefined;
  let value: unknown;
  try {
    value = JSON.parse(raw.slice(0, end));
  } catch {
    return undefined;
  }
  if (
    typeof value !== "object" || value === null ||
    !("version" in value) || value.version !== spoolVersion ||
    !("tenant_id" in value) || typeof value.tenant_id !== "string" ||
    !("machine_id" in value) || typeof value.machine_id !== "string" ||
    !scopedIDPattern.test(value.tenant_id) ||
    !scopedIDPattern.test(value.machine_id)
  ) {
    return undefined;
  }
  return { tenantID: value.tenant_id, machineID: value.machine_id };
}

function parseRecord(line: string, scope: SpoolScope): SpoolRecord {
  let value: unknown;
  try {
    value = JSON.parse(line);
  } catch {
    throw new Error("Telemetry spool contains an invalid record.");
  }
  if (
    typeof value !== "object" || value === null ||
    !("version" in value) || value.version !== spoolVersion ||
    !("tenant_id" in value) || value.tenant_id !== scope.tenantID ||
    !("machine_id" in value) || value.machine_id !== scope.machineID ||
    !("operation" in value) ||
    (value.operation !== "event" && value.operation !== "acknowledge" &&
      value.operation !== "discard") ||
    !("sequence" in value) || typeof value.sequence !== "string"
  ) {
    throw new Error("Telemetry spool scope or record shape is invalid.");
  }
  parseSequence(value.sequence);
  if (value.operation !== "event") return value as SpoolSequenceRecord;
  if (
    !("nonce" in value) || typeof value.nonce !== "string" ||
    !("ciphertext" in value) || typeof value.ciphertext !== "string" ||
    ("coalesce_key" in value && typeof value.coalesce_key !== "string")
  ) {
    throw new Error("Telemetry spool event shape is invalid.");
  }
  return value as SpoolEvent;
}

function parseSequence(value: string): bigint {
  if (!/^\d{1,20}$/u.test(value)) {
    throw new Error("Telemetry spool sequence is invalid.");
  }
  const sequence = BigInt(value);
  if (sequence > 18_446_744_073_709_551_615n) {
    throw new Error("Telemetry spool sequence is invalid.");
  }
  return sequence;
}

function spoolKey(scope: SpoolScope, credential: string): Buffer {
  return createHash("sha256")
    .update("phigon-observer-telemetry-spool-v1\0", "utf8")
    .update(scope.tenantID, "utf8")
    .update("\0", "utf8")
    .update(scope.machineID, "utf8")
    .update("\0", "utf8")
    .update(credential, "utf8")
    .digest();
}

function spoolAAD(scope: SpoolScope, sequence: bigint): Buffer {
  return Buffer.from(
    `phigon/spool/${scope.tenantID}/${scope.machineID}/${sequence}`,
    "utf8",
  );
}

function validateScope(tenantID: string, machineID: string): void {
  if (!scopedIDPattern.test(tenantID) || !scopedIDPattern.test(machineID)) {
    throw new Error("Telemetry spool scope is invalid.");
  }
}

function validateEventScope(
  event: EventEnvelope,
  scope: SpoolScope,
  sequence: bigint,
): void {
  if (
    event.tenantId !== scope.tenantID ||
    event.machineId !== scope.machineID ||
    event.sequence !== sequence
  ) {
    throw new Error("Telemetry spool event scope is invalid.");
  }
}

function isNodeError(error: unknown): error is NodeJS.ErrnoException {
  return error instanceof Error && "code" in error;
}
