import { makeDirectoryPrivate } from "./private-directory.js";
import {
  chmod,
  mkdir,
  readFile,
  unlink,
  writeFile,
} from "node:fs/promises";
import { randomUUID } from "node:crypto";
import { join } from "node:path";
import { atomicReplace } from "./atomic-replace.js";

export type StreamState = Readonly<{
  machineId: string;
  acknowledgedSequence: bigint;
  updatedAt: string;
  recoveryPending?: boolean;
}>;

export class StreamStateStore {
  readonly #dataDirectory: string;
  readonly #path: string;

  constructor(dataDirectory: string) {
    this.#dataDirectory = dataDirectory;
    this.#path = join(dataDirectory, "stream-state.json");
  }

  async load(machineId: string, spooledAcknowledgement?: bigint): Promise<StreamState> {
    validateMachineId(machineId);
    let raw: string;
    try {
      raw = await readFile(this.#path, "utf8");
    } catch (error) {
      if (isNodeError(error) && error.code === "ENOENT") {
        return {
          machineId,
          acknowledgedSequence: 0n,
          updatedAt: new Date(0).toISOString(),
        };
      }
      throw error;
    }
    let value: unknown;
    try {
      value = JSON.parse(raw);
    } catch {
      return this.#recoverFromSpool(machineId, raw, spooledAcknowledgement);
    }
    if (
      typeof value === "object" &&
      value !== null &&
      !("machineId" in value) &&
      "acknowledgedSequence" in value &&
      typeof value.acknowledgedSequence === "string" &&
      /^\d+$/u.test(value.acknowledgedSequence) &&
      "updatedAt" in value &&
      typeof value.updatedAt === "string"
    ) {
      return {
        machineId,
        acknowledgedSequence: 0n,
        updatedAt: new Date(0).toISOString(),
      };
    }
    if (
      typeof value !== "object" ||
      value === null ||
      !("machineId" in value) ||
      typeof value.machineId !== "string" ||
      !("acknowledgedSequence" in value) ||
      typeof value.acknowledgedSequence !== "string" ||
      !/^\d+$/.test(value.acknowledgedSequence) ||
      !("updatedAt" in value) ||
      typeof value.updatedAt !== "string" ||
      !Number.isFinite(Date.parse(value.updatedAt))
    ) {
      return this.#recoverFromSpool(machineId, raw, spooledAcknowledgement);
    }
    if (value.machineId !== machineId) {
      return {
        machineId,
        acknowledgedSequence: 0n,
        updatedAt: new Date(0).toISOString(),
      };
    }
    return {
      machineId,
      acknowledgedSequence: BigInt(value.acknowledgedSequence),
      updatedAt: value.updatedAt,
    };
  }

  async #recoverFromSpool(machineId: string, raw: string, acknowledgedSequence?: bigint): Promise<StreamState> {
    // Only a journal already restored for this machine and credential may
    // replace an unreadable cursor. With no checkpoint, the authenticated
    // server must establish the cursor before collection can resume.
    if (acknowledgedSequence === undefined || acknowledgedSequence < 0n) {
      throw new Error("Stored stream state is invalid and has no verified delivery checkpoint.");
    }
    await writeFile(`${this.#path}.${randomUUID()}.corrupt`, raw, {
      encoding: "utf8", flag: "wx", mode: 0o600, flush: true,
    });
    if (acknowledgedSequence === 0n) {
      return { machineId, acknowledgedSequence, updatedAt: new Date(0).toISOString(), recoveryPending: true };
    }
    await this.save(machineId, acknowledgedSequence);
    return { machineId, acknowledgedSequence, updatedAt: new Date().toISOString() };
  }

  async save(
    machineId: string,
    acknowledgedSequence: bigint,
  ): Promise<void> {
    validateMachineId(machineId);
    if (acknowledgedSequence < 0n) {
      throw new Error("Acknowledged sequence must not be negative.");
    }
    await mkdir(this.#dataDirectory, { recursive: true, mode: 0o700 });
    await makeDirectoryPrivate(this.#dataDirectory);
    const temporaryPath = `${this.#path}.${process.pid}.${randomUUID()}.tmp`;
    try {
      await writeFile(
        temporaryPath,
        `${JSON.stringify({
          machineId,
          acknowledgedSequence: acknowledgedSequence.toString(),
          updatedAt: new Date().toISOString(),
        })}\n`,
        { encoding: "utf8", flag: "wx", mode: 0o600, flush: true },
      );
      await atomicReplace(temporaryPath, this.#path);
      await chmod(this.#path, 0o600);
    } catch (error) {
      try {
        await unlink(temporaryPath);
      } catch {
        // The temporary file may not have been created.
      }
      throw error;
    }
  }
}

function validateMachineId(value: string): void {
  if (
    value.length < 1 ||
    value.length > 128 ||
    !/^[A-Za-z0-9._:-]+$/u.test(value)
  ) {
    throw new Error("Machine ID is invalid.");
  }
}

function isNodeError(error: unknown): error is NodeJS.ErrnoException {
  return error instanceof Error && "code" in error;
}
