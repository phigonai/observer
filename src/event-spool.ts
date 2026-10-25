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
  renameSync,
  statSync,
  unlinkSync,
  writeFileSync,
} from "node:fs";
import { join } from "node:path";
import { fromBinary, toBinary } from "@bufbuild/protobuf";
import {
  EventEnvelopeSchema,
  type EventEnvelope,
} from "./generated/phigon/v1/telemetry_pb.js";
import { BoundedEventQueue } from "./event-queue.js";

const spoolVersion = 1;
const spoolFileName = "telemetry-spool.jsonl";
const maxSpoolBytes = 64 << 20;
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
  #scope: SpoolScope | undefined;
  #key: Buffer | undefined;
  #operations = 0;

  constructor(dataDirectory: string, capacity = 2048) {
    super(capacity);
    this.#dataDirectory = dataDirectory;
    this.#path = join(dataDirectory, spoolFileName);
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
      if (!metadata.isFile() || metadata.size > maxSpoolBytes) {
        throw new Error("Telemetry spool exceeds its safe storage bound.");
      }
      const restored = new BoundedEventQueue<EventEnvelope>(this.metrics().capacity);
      const raw = readFileSync(this.#path, "utf8");
      const lines = raw.split("\n");
      const completeLines = lines.slice(0, -1);
      for (const line of completeLines) {
        if (line.length === 0) continue;
        const record = parseRecord(line, scope);
        this.#restoreRecord(record, restored);
      }
      if (!raw.endsWith("\n") && (lines.at(-1)?.length ?? 0) > 0) {
        // A crash can leave only the final append incomplete. It was never a
        // durable event, so ignore that tail and compact the verified prefix.
      }
      this.#writeCompactedQueue(restored);
      this.replaceState(restored);
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
    this.#append(record);
    super.enqueue(value, sequence, coalesceKey);
    this.#compactIfNeeded();
  }

  override acknowledge(throughSequence: bigint): void {
    if (throughSequence <= this.metrics().acknowledged) return;
    this.#append(this.#sequenceRecord("acknowledge", throughSequence));
    super.acknowledge(throughSequence);
    this.#compactIfNeeded();
  }

  override discard(sequence: bigint): boolean {
    if (!this.pending().some((event) => event.sequence === sequence)) {
      return false;
    }
    this.#append(this.#sequenceRecord("discard", sequence));
    const discarded = super.discard(sequence);
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
    target.enqueue(event, sequence, record.coalesce_key);
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

  #append(record: SpoolRecord): void {
    mkdirSync(this.#dataDirectory, { recursive: true, mode: 0o700 });
    chmodSync(this.#dataDirectory, 0o700);
    const encoded = `${JSON.stringify(record)}\n`;
    let size = existsSync(this.#path) ? statSync(this.#path).size : 0;
    if (size + Buffer.byteLength(encoded) > maxSpoolBytes) {
      this.#compact();
      size = statSync(this.#path).size;
    }
    if (size + Buffer.byteLength(encoded) > maxSpoolBytes) {
      throw new Error("Telemetry spool is full; collection stopped before data loss.");
    }
    appendFileSync(this.#path, encoded, {
      encoding: "utf8",
      mode: 0o600,
      flush: true,
    });
    chmodSync(this.#path, 0o600);
    this.#operations++;
  }

  #compactIfNeeded(): void {
    if (this.#operations >= compactAfterOperations) this.#compact();
  }

  #compact(): void {
    this.#writeCompactedQueue(this);
    this.#operations = 0;
  }

  #writeCompactedQueue(queue: BoundedEventQueue<EventEnvelope>): void {
    this.#requireScope();
    mkdirSync(this.#dataDirectory, { recursive: true, mode: 0o700 });
    chmodSync(this.#dataDirectory, 0o700);
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
    const encoded = `${records.map((record) => JSON.stringify(record)).join("\n")}\n`;
    if (Buffer.byteLength(encoded) > maxSpoolBytes) {
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
      renameSync(temporaryPath, this.#path);
      chmodSync(this.#path, 0o600);
    } catch (error) {
      try {
        unlinkSync(temporaryPath);
      } catch {
        // The temporary file may not have been created.
      }
      throw error;
    }
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
