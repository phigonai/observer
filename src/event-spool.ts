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
  readFileSync,
  readdirSync,
  statSync,
  unlinkSync,
  writeFileSync,
} from "node:fs";
import { join } from "node:path";
import { fromBinary, toBinary } from "@bufbuild/protobuf";
import { atomicReplaceSync } from "./atomic-replace.js";
import {
  EventEnvelopeSchema,
  type EventEnvelope,
} from "./generated/phigon/v1/telemetry_pb.js";
import { BoundedEventQueue, type QueueMetrics } from "./event-queue.js";

const spoolVersion = 1;
const spoolFileName = "telemetry-spool.jsonl";
const defaultMaxSpoolBytes = 64 << 20;
const compactAfterOperations = 1024;
const scopedIDPattern = /^[A-Za-z0-9._:-]{1,128}$/u;

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

/**
 * An encrypted append-only delivery spool. The in-memory queue remains the hot
 * path, while this log makes unacknowledged events recoverable after an
 * observer restart without writing prompt or tool content as plaintext.
 */
export class FileBackedEventQueue extends BoundedEventQueue<EventEnvelope> {
  readonly #dataDirectory: string;
  readonly #path: string;
  readonly #maxBytes: number;
  #scope: SpoolScope | undefined;
  #key: Buffer | undefined;
  #operations = 0;
  // Appends run synchronously on the event loop for every event and every
  // acknowledgement. Prepare the private directory and secure the file once,
  // and track the spool size here instead of stat-ing it before each append.
  #directoryPrepared = false;
  #fileSecured = false;
  #size: number | undefined;

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

  restore(tenantID: string, machineID: string, credential: string): void {
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
      return;
    }
    this.#scope = scope;
    this.#key = key;
    try {
      if (!existsSync(this.#path)) return;
      const metadata = statSync(this.#path);
      if (!metadata.isFile() || metadata.size > this.#maxBytes) {
        throw new Error("Telemetry spool exceeds its safe storage bound.");
      }
      const restored = new BoundedEventQueue<EventEnvelope>(this.metrics().capacity);
      const raw = readFileSync(this.#path, "utf8");
      const lines = raw.split("\n");
      const completeLines = lines.slice(0, -1);
      for (const line of completeLines) {
        if (line.length === 0) continue;
        const record = parseRecord(line, scope);
        this.#restoreRecord(record, restored, Buffer.byteLength(line) + 1);
      }
      if (!raw.endsWith("\n") && (lines.at(-1)?.length ?? 0) > 0) {
        // A crash can leave only the final append incomplete. It was never a
        // durable event, so ignore that tail and compact the verified prefix.
      }
      const sizes = this.#writeCompactedQueue(restored);
      this.replaceState(restored);
      this.reweigh(sizes);
      this.#operations = 0;
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
    const record = this.#encryptedRecord(value, sequence, coalesceKey);
    const bytes = this.#append(record);
    super.enqueue(value, sequence, coalesceKey, bytes);
    this.#compactIfNeeded();
  }

  // Removals apply in memory before they are appended. On a full spool the
  // compaction that makes room for the record then already leaves the
  // removed events out, so an acknowledgement can always drain the spool.
  // A removal lost in a crash only sends the event again.
  override acknowledge(throughSequence: bigint): void {
    if (throughSequence <= this.metrics().acknowledged) return;
    super.acknowledge(throughSequence);
    this.#append(this.#sequenceRecord("acknowledge", throughSequence));
    this.#compactIfNeeded();
  }

  override discard(sequence: bigint): boolean {
    if (!this.pending().some((event) => event.sequence === sequence)) {
      return false;
    }
    const discarded = super.discard(sequence);
    this.#append(this.#sequenceRecord("discard", sequence));
    this.#compactIfNeeded();
    return discarded;
  }

  override reconcileAcknowledged(throughSequence: bigint): void {
    if (throughSequence === this.metrics().acknowledged) return;
    super.reconcileAcknowledged(throughSequence);
    this.#compact();
  }

  override replacePending(
    replace: (value: EventEnvelope) => EventEnvelope,
  ): void {
    super.replacePending((event) => {
      const replaced = replace(event);
      validateEventScope(replaced, this.#requireScope(), event.sequence);
      return replaced;
    });
    this.#compact();
  }

  #restoreRecord(
    record: SpoolRecord,
    target: BoundedEventQueue<EventEnvelope>,
    bytes: number,
  ): void {
    const sequence = parseSequence(record.sequence);
    if (record.operation === "acknowledge") {
      target.acknowledge(sequence);
      return;
    }
    if (record.operation === "discard") {
      target.discard(sequence);
      return;
    }
    const event = this.#decrypt(record);
    if (!target.canEnqueue(record.coalesce_key)) {
      throw new Error("Telemetry spool contains more events than the configured queue capacity.");
    }
    target.enqueue(event, sequence, record.coalesce_key, bytes);
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
      cipher.update(toBinary(EventEnvelopeSchema, event)),
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

  /** Append one record and return its stored size. */
  #append(record: SpoolRecord): number {
    this.#prepareDirectory();
    const encoded = `${JSON.stringify(record)}\n`;
    const bytes = Buffer.byteLength(encoded);
    if (this.#currentSize() + bytes > this.#maxBytes) {
      this.#compact();
    }
    if (this.#currentSize() + bytes > this.#maxBytes) {
      throw new Error("Telemetry spool is full; collection stopped before data loss.");
    }
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
    this.#size = this.#currentSize() + bytes;
    this.#operations++;
    return bytes;
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
    if (this.#operations >= compactAfterOperations) this.#compact();
  }

  #compact(): void {
    this.reweigh(this.#writeCompactedQueue(this));
    this.#operations = 0;
  }

  /** Rewrite the spool as `queue` and return each queued event's stored size. */
  #writeCompactedQueue(queue: BoundedEventQueue<EventEnvelope>): number[] {
    this.#requireScope();
    mkdirSync(this.#dataDirectory, { recursive: true, mode: 0o700 });
    makeDirectoryPrivateSync(this.#dataDirectory);
    const records: SpoolRecord[] = [
      this.#sequenceRecord("acknowledge", queue.metrics().acknowledged),
      ...queue.entries().map((entry) =>
        this.#encryptedRecord(
          entry.value,
          entry.sequence,
          entry.coalesceKey,
        )
      ),
    ];
    const lines = records.map((record) => JSON.stringify(record));
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
    if (name !== spoolFileName && !temporary) continue;
    try {
      unlinkSync(join(dataDirectory, name));
    } catch (error) {
      if (!isNodeError(error) || error.code !== "ENOENT") throw error;
    }
  }
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
