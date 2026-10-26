import { makeDirectoryPrivate } from "./private-directory.js";
import {
  chmod,
  mkdir,
  readFile,
  rename,
  unlink,
  writeFile,
} from "node:fs/promises";
import { randomUUID } from "node:crypto";
import { join } from "node:path";

export type StoredMachineCredential = Readonly<{
  machineId: string;
  tenantId: string;
  credential: string;
  controlPlaneOrigin: string;
  grpcOrigin?: string;
  createdAt: string;
  consentProfile?: "metadata" | "full";
  consentPolicyVersion?: string;
  consentedAt?: string;
}>;

export interface CredentialStore {
  save(value: StoredMachineCredential): Promise<void>;
  load(): Promise<StoredMachineCredential | null>;
}

export class FileCredentialStore implements CredentialStore {
  readonly #dataDirectory: string;
  readonly #credentialPath: string;

  constructor(dataDirectory: string) {
    this.#dataDirectory = dataDirectory;
    this.#credentialPath = join(dataDirectory, "machine-credential.json");
  }

  async save(value: StoredMachineCredential): Promise<void> {
    validateCredential(value);
    await mkdir(this.#dataDirectory, { recursive: true, mode: 0o700 });
    await makeDirectoryPrivate(this.#dataDirectory);
    const temporaryPath = `${this.#credentialPath}.${process.pid}.${randomUUID()}.tmp`;
    try {
      await writeFile(
        temporaryPath,
        `${JSON.stringify(value)}\n`,
        { encoding: "utf8", flag: "wx", mode: 0o600 },
      );
      await rename(temporaryPath, this.#credentialPath);
      await chmod(this.#credentialPath, 0o600);
    } catch (error) {
      try {
        await unlink(temporaryPath);
      } catch {
        // The temporary file may not have been created.
      }
      throw error;
    }
  }

  async load(): Promise<StoredMachineCredential | null> {
    let raw: string;
    try {
      raw = await readFile(this.#credentialPath, "utf8");
    } catch (error) {
      if (isNodeError(error) && error.code === "ENOENT") {
        return null;
      }
      throw error;
    }
    let value: unknown;
    try {
      value = JSON.parse(raw);
    } catch {
      // SyntaxError can include part of the JSON, including a machine token.
      throw new Error("Stored machine pairing data is unreadable. Restore the credential file from a trusted backup; keep the existing data directory and queued activity.");
    }
    validateCredential(value);
    return value;
  }

  async clear(): Promise<boolean> {
    try {
      await unlink(this.#credentialPath);
      return true;
    } catch (error) {
      if (isNodeError(error) && error.code === "ENOENT") {
        return false;
      }
      throw error;
    }
  }
}

function validateCredential(
  value: unknown,
): asserts value is StoredMachineCredential {
  if (
    typeof value !== "object" ||
    value === null ||
    !("machineId" in value) ||
    typeof value.machineId !== "string" ||
    !("tenantId" in value) ||
    typeof value.tenantId !== "string" ||
    !("credential" in value) ||
    typeof value.credential !== "string" ||
    !value.credential.startsWith("phg_m_") ||
    !("controlPlaneOrigin" in value) ||
    typeof value.controlPlaneOrigin !== "string" ||
    !("createdAt" in value) ||
    typeof value.createdAt !== "string"
  ) {
    throw new Error("Stored machine credential is invalid.");
  }
  const hasConsent =
    "consentProfile" in value ||
    "consentPolicyVersion" in value ||
    "consentedAt" in value;
  if ("grpcOrigin" in value && typeof value.grpcOrigin !== "string") {
    throw new Error("Stored telemetry endpoint is invalid.");
  }
  if (
    hasConsent &&
    (!("consentProfile" in value) ||
      (value.consentProfile !== "metadata" && value.consentProfile !== "full") ||
      !("consentPolicyVersion" in value) ||
      value.consentPolicyVersion !== "observer-policy-v1" ||
      !("consentedAt" in value) ||
      typeof value.consentedAt !== "string")
  ) {
    throw new Error("Stored machine consent evidence is invalid.");
  }
}

function isNodeError(error: unknown): error is NodeJS.ErrnoException {
  return error instanceof Error && "code" in error;
}
