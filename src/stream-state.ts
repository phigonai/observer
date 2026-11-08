import { makeDirectoryPrivate } from "./private-directory.js";
import {
  chmod,
  mkdir,
  readdir,
  readFile,
  rm,
  stat,
  unlink,
  writeFile,
} from "node:fs/promises";
import { createHash, randomUUID } from "node:crypto";
import { join } from "node:path";
import { atomicReplace } from "./atomic-replace.js";

export type StreamState = Readonly<{
  machineId: string;
  acknowledgedSequence: bigint;
  updatedAt: string;
  recoveryPending?: boolean;
}>;

/** The stream cursor's file name in the data directory. */
export const streamStateFileName = "stream-state.json";

/** How many copies of unreadable cursors are kept beside it, newest first. */
export const maxCorruptStreamStateCopies = 3;

export class StreamStateStore {
  readonly #dataDirectory: string;
  readonly #path: string;

  constructor(dataDirectory: string) {
    this.#dataDirectory = dataDirectory;
    this.#path = join(dataDirectory, streamStateFileName);
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
    await this.#keepCorruptCopy(raw);
    if (acknowledgedSequence === 0n) {
      return { machineId, acknowledgedSequence, updatedAt: new Date(0).toISOString(), recoveryPending: true };
    }
    await this.save(machineId, acknowledgedSequence);
    return { machineId, acknowledgedSequence, updatedAt: new Date().toISOString() };
  }

  /**
   * Keeps the unreadable cursor for whoever looks into it. While recovery
   * waits for the server, every reconnect reads the same file again, so a
   * copy is named after its content and written once; only the newest few
   * copies are kept.
   */
  async #keepCorruptCopy(raw: string): Promise<void> {
    const digest = createHash("sha256").update(raw, "utf8").digest("hex").slice(0, 32);
    const copy = `${this.#path}.${digest}.corrupt`;
    try {
      await writeFile(copy, raw, {
        encoding: "utf8", flag: "wx", mode: 0o600, flush: true,
      });
    } catch (error) {
      if (isNodeError(error) && error.code === "EEXIST") return;
      throw error;
    }
    await this.#pruneCorruptCopies(copy).catch(() => undefined);
  }

  /** Removes all but the newest copies; `kept`, just written, always stays. */
  async #pruneCorruptCopies(kept: string): Promise<void> {
    const prefix = `${streamStateFileName}.`;
    const copies = await Promise.all(
      (await readdir(this.#dataDirectory))
        .filter((name) => name.startsWith(prefix) && name.endsWith(".corrupt"))
        .map((name) => join(this.#dataDirectory, name))
        .filter((path) => path !== kept)
        .map(async (path) => {
          return { path, modified: (await stat(path).catch(() => undefined))?.mtimeMs ?? 0 };
        }),
    );
    copies.sort((a, b) => b.modified - a.modified);
    for (const older of copies.slice(maxCorruptStreamStateCopies - 1)) {
      await rm(older.path, { force: true });
    }
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
