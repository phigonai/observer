import { makeDirectoryPrivate } from "./private-directory.js";
import {
  chmod,
  mkdir,
  readFile,
  rename,
  stat,
  unlink,
  writeFile,
} from "node:fs/promises";
import { randomUUID } from "node:crypto";
import { join } from "node:path";
import { atomicReplace } from "./atomic-replace.js";

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
  /**
   * Who consented: the computer's owner at pairing, or the company with an
   * enrollment code. Credentials saved before enrollment codes existed have
   * none and are the owner's.
   */
  consentSource?: ConsentSource;
  /** The enrollment code the company consented with, by ID and label. */
  enrollmentCodeId?: string;
  enrollmentCodeLabel?: string;
  /**
   * What whoever consented let the company's administrators do on this
   * computer: stop its AI agents, and also run the commands they approve.
   * Pairings made before it was asked have none, and allow neither.
   */
  remoteActions?: RemoteActionConsent;
  /**
   * The SHA-256 of the certificate authority pinned when this computer
   * paired (`--server-ca-sha256`). The key is issued under it and never
   * sent under any other; without it, the saved server-ca.pem decides, and
   * the system's authorities when there is none. Older observers ignore it.
   */
  serverAuthoritySha256?: string;
}>;

/** "none", "stop_agents" (stop and force-stop agents), or "all" (also run approved commands). */
export type RemoteActionConsent = "none" | "stop_agents" | "all";

export type ConsentSource = "owner" | "company";

/** Who consented for this computer; the owner unless the company did. */
export function consentSourceOf(credential: StoredMachineCredential): ConsentSource {
  return credential.consentSource ?? "owner";
}

/** The longest enrollment code label kept, in characters. */
export const maxEnrollmentCodeLabelLength = 100;

export interface CredentialStore {
  save(value: StoredMachineCredential): Promise<void>;
  load(): Promise<StoredMachineCredential | null>;
}

/** The machine credential's file name in the data directory. */
export const credentialFileName = "machine-credential.json";

export class FileCredentialStore implements CredentialStore {
  readonly #dataDirectory: string;
  readonly #credentialPath: string;
  readonly #rename: typeof rename;
  readonly #chmod: typeof chmod;

  constructor(
    dataDirectory: string,
    options: Readonly<{ rename?: typeof rename; chmod?: typeof chmod }> = {},
  ) {
    this.#dataDirectory = dataDirectory;
    this.#credentialPath = join(dataDirectory, credentialFileName);
    this.#rename = options.rename ?? rename;
    this.#chmod = options.chmod ?? chmod;
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
      // Windows refuses a rename while antivirus or an indexer holds the
      // file open; atomicReplace waits briefly and tries again.
      await atomicReplace(temporaryPath, this.#credentialPath, this.#rename);
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
    await this.#keepPrivate();
    return value;
  }

  /**
   * The key is kept in this file, and the queue's encryption key is derived
   * from it, so only its owner may read either. A directory restored from a
   * backup or copied by hand can come back readable by others; it is made
   * owner-only again on the first read instead of at the next pairing.
   * Windows restricts the data directory itself (private-directory.ts) on
   * every write.
   *
   * The operating system's key store is not used for it: a background
   * service must never wait on a keychain prompt (the macOS Keychain asks
   * again whenever Node.js is updated), libsecret needs a desktop session a
   * systemd user service often lacks, and DPAPI is reachable from Node.js
   * only through PowerShell, which managed computers often lock down, and
   * loses what it protected when an administrator resets the account's
   * password. Each would risk the key and the queue it decrypts.
   */
  async #keepPrivate(): Promise<void> {
    if (process.platform === "win32") return;
    // Both are made owner-only where possible. A key others can still read,
    // or one in a folder others can still write to (and so swap files in),
    // is not used: it may already be known to them.
    const file = await tightened(this.#credentialPath, 0o600, 0o077, this.#chmod);
    const directory = await tightened(this.#dataDirectory, 0o700, 0o022, this.#chmod);
    if (!file || !directory) {
      throw new Error(
        "This computer's Phigon machine key is readable by other users, or kept in a folder they can change, and its permissions could not be fixed. " +
          `Make ${this.#dataDirectory} and the files in it belong to the account the observer runs as, then run the observer again.`,
      );
    }
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
  if (
    ("consentSource" in value &&
      (value.consentSource !== "owner" && value.consentSource !== "company")) ||
    // The company's consent is recorded only with its profile.
    ("consentSource" in value && value.consentSource === "company" && !hasConsent) ||
    ("enrollmentCodeId" in value &&
      (typeof value.enrollmentCodeId !== "string" || value.enrollmentCodeId.length > 64)) ||
    ("enrollmentCodeLabel" in value &&
      (typeof value.enrollmentCodeLabel !== "string" ||
        value.enrollmentCodeLabel.length > maxEnrollmentCodeLabelLength)) ||
    ("remoteActions" in value &&
      (value.remoteActions !== "none" && value.remoteActions !== "stop_agents" && value.remoteActions !== "all"))
  ) {
    throw new Error("Stored machine consent evidence is invalid.");
  }
  if (
    "serverAuthoritySha256" in value &&
    (typeof value.serverAuthoritySha256 !== "string" || !/^[0-9a-f]{64}$/u.test(value.serverAuthoritySha256))
  ) {
    throw new Error("Stored server certificate authority is invalid.");
  }
}

/**
 * Sets `path` to `mode` when others have any access to it, and says whether
 * none of the `exposed` permission bits is set afterwards.
 */
async function tightened(path: string, mode: number, exposed: number, change: typeof chmod): Promise<boolean> {
  try {
    // Anything beyond the owner is taken away where it can be; only the
    // `exposed` bits make the key unusable when that is not permitted.
    if (((await stat(path)).mode & 0o077) !== 0) {
      await change(path, mode).catch(() => undefined);
    }
    return ((await stat(path)).mode & exposed) === 0;
  } catch {
    return false;
  }
}

function isNodeError(error: unknown): error is NodeJS.ErrnoException {
  return error instanceof Error && "code" in error;
}
