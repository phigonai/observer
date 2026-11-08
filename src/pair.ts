import { arch, hostname, platform } from "node:os";
import type { ObserverConfig } from "./config.js";
import {
  FileCredentialStore,
  credentialFileName,
  type CredentialStore,
  type RemoteActionConsent,
  type StoredMachineCredential,
} from "./credential-store.js";
import { retirePairingState } from "./event-spool.js";
import {
  adoptPendingInstallationID,
  installationFileName,
  loadOrCreateInstallationID,
  loadOrCreatePendingInstallationID,
  pairingAttempt,
  promotePendingInstallationID,
} from "./installation.js";
import { InstanceLock } from "./instance-lock.js";
import { serverFetch } from "./server-fetch.js";

export const OBSERVER_CONSENT_POLICY_VERSION = "observer-policy-v1";
export type ConsentProfile = "metadata" | "full";

export type PairingMachine = Readonly<{
  id: string;
  tenant_id: string;
  display_name: string;
  state: string;
}>;

/** What the pairing exchange and an enrollment both answer with. */
export type ConnectedMachine = Readonly<{
  machine: PairingMachine;
  credential: string;
}>;

export type PairResult = Readonly<{
  machineId: string;
  displayName: string;
  state: string;
  controlPlaneOrigin: string;
  credentialStored: true;
  /**
   * The earlier machine this computer was paired as, when the workspace no
   * longer accepted its key and the computer was paired as a new machine.
   */
  replacedMachineId?: string;
  /** Where this computer reached its server before, when it moved. */
  previousControlPlaneOrigin?: string;
  /**
   * The earlier machine was replaced because the server proves another
   * certificate authority than the one its key was issued under, so the
   * key was not sent.
   */
  newServerAuthority?: true;
}>;

/**
 * One exchange with the control plane. A failure other than a stored key
 * the server refused is `credentialRejected: false`, and its error is
 * thrown as is.
 */
export type ExchangeOutcome<T extends ConnectedMachine> =
  | Readonly<{ paired: T }>
  | Readonly<{ error: Error; credentialRejected: boolean }>;

/** The consent evidence a connection stores with the machine credential. */
export type ConsentEvidence = Pick<
  StoredMachineCredential,
  | "consentProfile"
  | "consentPolicyVersion"
  | "consentedAt"
  | "consentSource"
  | "enrollmentCodeId"
  | "enrollmentCodeLabel"
  | "remoteActions"
>;

export type PairOptions = Readonly<{
  config: ObserverConfig;
  code: string;
  displayName?: string;
  consentProfile: ConsentProfile;
  /** What the owner lets the company's administrators do on this computer. */
  remoteActions?: RemoteActionConsent;
  credentialStore?: CredentialStore;
  fetcher?: typeof fetch;
  /** See `ConnectOptions.serverMoved`. */
  serverMoved?: boolean;
  /** See `ConnectOptions.storedKeyAllowed`. */
  storedKeyAllowed?: boolean;
  /** See `ConnectOptions.serverAuthoritySha256`. */
  serverAuthoritySha256?: string | undefined;
}>;

/**
 * A one-time pairing code as the server compares it: upper case, without
 * spaces or hyphens (normalizePairingCode in the control plane).
 */
export function serverPairingCode(code: string): string {
  return code.trim().toUpperCase().replace(/[- ]/gu, "");
}

export async function pairMachine(options: PairOptions): Promise<PairResult> {
  const code = options.code.trim();
  if (code.length === 0) {
    throw new Error("Pairing code is required.");
  }
  if (
    options.config.observabilityProfile === "full" &&
    options.consentProfile !== "full"
  ) {
    throw new Error(
      "The configured full observability profile requires full-content consent.",
    );
  }
  const endpoint = new URL(
    "/v1/pairing/exchange",
    options.config.controlPlaneUrl,
  );
  const fetcher = options.fetcher ?? serverFetch;
  const connected = await connectMachine<ConnectedMachine>({
    config: options.config,
    endpoint,
    fetcher,
    ...(options.credentialStore === undefined ? {} : { credentialStore: options.credentialStore }),
    ...(options.serverMoved === true ? { serverMoved: true } : {}),
    ...(options.storedKeyAllowed === false ? { storedKeyAllowed: false } : {}),
    // The server reads ABCDE-FGHIJ and abcdefghij as one code, so a retry
    // spelled differently is still the same attempt.
    attempt: pairingAttempt(serverPairingCode(code)),
    serverAuthoritySha256: options.serverAuthoritySha256,
    exchange: (installationID, existingCredential) => exchangePairing(fetcher, endpoint, {
      code,
      installation_id: installationID,
      display_name: options.displayName?.trim() || hostname(),
      hostname: hostname(),
      operating_system: normalizedOperatingSystem(),
      architecture: arch(),
      consent: {
        granted: true,
        profile: options.consentProfile,
        policy_version: OBSERVER_CONSENT_POLICY_VERSION,
      },
      ...(existingCredential === undefined ? {} : { existing_credential: existingCredential }),
    }),
    evidence: (_paired, at) => ({
      consentProfile: options.consentProfile,
      consentPolicyVersion: OBSERVER_CONSENT_POLICY_VERSION,
      consentedAt: at,
      consentSource: "owner",
      ...(options.remoteActions === undefined ? {} : { remoteActions: options.remoteActions }),
    }),
  });
  return connected.result;
}

export type ConnectOptions<T extends ConnectedMachine> = Readonly<{
  config: ObserverConfig;
  endpoint: URL;
  fetcher: typeof fetch;
  credentialStore?: CredentialStore;
  /**
   * The server this computer is paired with now answers at the configured
   * address, so the stored key may go there: it holds a certificate from
   * the authority pinned at pairing, or both addresses are this computer's
   * own. Without it, a stored machine from another address is refused
   * before anything is sent.
   */
  serverMoved?: boolean;
  /**
   * False when the server proves another certificate authority than the
   * one the stored key was issued under: the key is never sent there, and
   * the computer connects as a new machine. Allowed unless said otherwise.
   */
  storedKeyAllowed?: boolean;
  /** The code this connection uses, as `pairingAttempt` identifies it. */
  attempt: string;
  /**
   * The authority the server proved, stored with the key in the same
   * write (`PairingAuthority.keyAuthority`); undefined for the system's.
   */
  serverAuthoritySha256?: string | undefined;
  /** Exchanges a code for this installation, with the stored key if any. */
  exchange: (installationID: string, existingCredential?: string) => Promise<ExchangeOutcome<T>>;
  /** The consent evidence to store with the credential `paired` returned. */
  evidence: (paired: T, at: string) => ConsentEvidence;
}>;

/**
 * Connects this computer with a code, keeping its machine when the server
 * still accepts its stored key: pairing again, or enrolling, renews consent
 * and keeps the same machine, so its queued activity stays deliverable.
 * When the server no longer accepts the key, the computer connects as a
 * new machine and its old queue moves aside.
 */
export async function connectMachine<T extends ConnectedMachine>(
  options: ConnectOptions<T>,
): Promise<Readonly<{ paired: T; result: PairResult }>> {
  const dataDirectory = options.config.dataDirectory;
  const credentialStore = options.credentialStore ??
    new FileCredentialStore(dataDirectory);
  const previous = await credentialStore.load();
  if (previous === null) await adoptPendingInstallationID(dataDirectory, options.attempt);
  const installationID = await loadOrCreateInstallationID(dataDirectory);
  const moved = previous !== null && previous.controlPlaneOrigin !== options.endpoint.origin;
  if (previous !== null && moved && options.serverMoved !== true) {
    throw new Error(otherServerMessage(previous.controlPlaneOrigin, options.endpoint.origin));
  }
  let paired: T | undefined;
  const newAuthority = previous !== null && options.storedKeyAllowed === false;
  if (previous !== null && !newAuthority) {
    const renewal = await options.exchange(installationID, previous.credential);
    if ("paired" in renewal) {
      paired = renewal.paired;
    } else if (!renewal.credentialRejected) {
      throw renewal.error;
    } else if (
      await credentialStillAccepted(
        options.fetcher,
        options.config.controlPlaneUrl,
        previous.credential,
      )
    ) {
      // The exchange also refuses a key that is valid in another workspace.
      throw new Error("This computer is paired with another workspace on this server. Use a separate data directory to pair another workspace.");
    }
  }

  let lock: InstanceLock | undefined;
  try {
    if (paired === undefined || !sameMachine(previous, paired)) {
      // A new machine. Its queue, stream cursor and credential start empty;
      // the observer must not be using the old ones while they move.
      lock = await InstanceLock.acquire(dataDirectory);
      if (newAuthority) {
        // The stored key still works at the server it was issued under, so
        // nothing moves until this server has paired the computer: a wrong
        // or expired code leaves the earlier pairing, its key and its queue
        // as they were. The new machine gets a new installation ID, kept
        // pending on disk so a retry after a lost response uses the same
        // one, and made current once the exchange succeeded.
        const pendingInstallationID = await loadOrCreatePendingInstallationID(dataDirectory, options.attempt);
        const fresh = await options.exchange(pendingInstallationID);
        if (!("paired" in fresh)) throw fresh.error;
        paired = fresh.paired;
        retirePairingState(dataDirectory, previous?.machineId, [credentialFileName, installationFileName]);
        await promotePendingInstallationID(dataDirectory);
      }
      // The old credential goes with its queue: it is the only key that can
      // decrypt it. Once it is gone, a retry after a lost response pairs
      // without it, and the server answers with the same new machine.
      //
      // A key the server no longer accepts also retires its installation ID:
      // a server can still hold that ID for the deleted machine, and the
      // built-in SQLite server refuses to pair it again. A new ID pairs
      // cleanly everywhere.
      const replacing = paired === undefined && previous !== null;
      if (!newAuthority) {
        retirePairingState(dataDirectory, previous?.machineId, [
          credentialFileName,
          ...(replacing ? [installationFileName] : []),
        ]);
      }
      if (paired === undefined) {
        const freshInstallationID = replacing
          ? await loadOrCreateInstallationID(dataDirectory)
          : installationID;
        const fresh = await options.exchange(freshInstallationID);
        if (!("paired" in fresh)) throw fresh.error;
        paired = fresh.paired;
      }
    }
    const pairedAt = new Date().toISOString();
    await credentialStore.save({
      machineId: paired.machine.id,
      tenantId: paired.machine.tenant_id,
      credential: paired.credential,
      controlPlaneOrigin: options.config.controlPlaneUrl.origin,
      grpcOrigin: options.config.grpcUrl.origin,
      createdAt: pairedAt,
      ...options.evidence(paired, pairedAt),
      ...(options.serverAuthoritySha256 === undefined ? {} : { serverAuthoritySha256: options.serverAuthoritySha256 }),
    });
  } finally {
    await lock?.release();
  }

  const replaced = previous !== null && previous.machineId !== paired.machine.id;
  return Object.freeze({
    paired,
    result: Object.freeze({
      machineId: paired.machine.id,
      displayName: paired.machine.display_name,
      state: paired.machine.state,
      controlPlaneOrigin: options.config.controlPlaneUrl.origin,
      credentialStored: true,
      ...(replaced ? { replacedMachineId: previous.machineId } : {}),
      ...(replaced && newAuthority ? { newServerAuthority: true as const } : {}),
      ...(previous !== null && moved ? { previousControlPlaneOrigin: previous.controlPlaneOrigin } : {}),
    }),
  });
}

/** Why a computer paired with the server at `stored` does not pair at `requested`. */
export function otherServerMessage(stored: string, requested: string): string {
  return `This computer is connected to the Phigon server at ${stored}. ` +
    `If that server moved to ${requested}, copy the whole command from Connect machine again, including --server-ca-sha256. ` +
    "To connect this computer to another workspace instead, run phigon-observer remove-machine first, or use a separate data directory (PHIGON_DATA_DIR).";
}

function sameMachine(
  previous: StoredMachineCredential | null,
  paired: ConnectedMachine,
): boolean {
  return previous !== null &&
    previous.machineId === paired.machine.id &&
    previous.tenantId === paired.machine.tenant_id &&
    previous.credential === paired.credential;
}

async function exchangePairing(
  fetcher: typeof fetch,
  endpoint: URL,
  body: Readonly<Record<string, unknown>>,
): Promise<ExchangeOutcome<ConnectedMachine>> {
  let response: Response;
  try {
    response = await fetcher(endpoint, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Accept: "application/json",
      },
      body: JSON.stringify(body),
      redirect: "error",
      signal: AbortSignal.timeout(10_000),
    });
  } catch (error) {
    if (error instanceof Error && error.name === "TimeoutError") {
      throw new Error(
        `Pairing timed out while contacting ${endpoint.origin}. Try again.`,
      );
    }
    throw new Error(
      `Could not reach ${endpoint.origin}. Check your internet connection and try again.`,
    );
  }

  if (!response.ok) {
    const failure = await apiError(response);
    return {
      error: new Error(failure.message ?? `Pairing failed with HTTP ${response.status}.`),
      credentialRejected: credentialRejected(response.status, failure),
    };
  }
  let value: unknown;
  try {
    value = await response.json();
  } catch {
    // A truncated response may contain a credential; parser errors must not
    // print fragments. The server supports retries for this installation.
    throw new Error("The pairing response was incomplete or invalid. Retry with the same code before it expires; keep the existing data directory.");
  }
  if (!isConnectedMachine(value)) {
    throw new Error("Control plane returned an invalid pairing response.");
  }
  return { paired: value };
}

/**
 * Whether a failed exchange refused the stored key. The server answers a
 * key it no longer accepts with HTTP 400 and "machine credential is
 * invalid".
 */
export function credentialRejected(
  status: number,
  failure: Readonly<{ code?: string; message?: string }>,
): boolean {
  return failure.code === "invalid_credential" ||
    (status === 400 &&
      /^machine credential is (?:invalid|revoked)\b/iu.test(failure.message ?? ""));
}

/**
 * Whether a server still accepts a stored key. Only a key the server
 * itself calls invalid or revoked, because an administrator removed the
 * computer or revoked the key, may be set aside for a new pairing.
 */
async function credentialStillAccepted(
  fetcher: typeof fetch,
  controlPlaneUrl: URL,
  credential: string,
): Promise<boolean> {
  const endpoint = new URL("/v1/machine/heartbeat", controlPlaneUrl);
  let response: Response;
  try {
    response = await fetcher(endpoint, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${credential}`,
        Accept: "application/json",
      },
      redirect: "error",
      signal: AbortSignal.timeout(10_000),
    });
  } catch {
    throw new Error(
      `Could not reach ${endpoint.origin} to check this computer's earlier pairing. Check your internet connection and try again.`,
    );
  }
  if (response.ok) {
    await response.body?.cancel();
    return true;
  }
  if (
    response.status === 401 &&
    (await apiError(response)).code === "invalid_credential"
  ) {
    return false;
  }
  throw new Error(
    `Could not check this computer's earlier pairing (HTTP ${response.status}). Try again.`,
  );
}

/** A response with a machine and a machine credential. */
export function isConnectedMachine(value: unknown): value is ConnectedMachine {
  return typeof value === "object" &&
    value !== null &&
    "credential" in value &&
    typeof value.credential === "string" &&
    value.credential.startsWith("phg_m_") &&
    "machine" in value &&
    typeof value.machine === "object" &&
    value.machine !== null &&
    "id" in value.machine &&
    typeof value.machine.id === "string" &&
    "tenant_id" in value.machine &&
    typeof value.machine.tenant_id === "string" &&
    "display_name" in value.machine &&
    typeof value.machine.display_name === "string" &&
    "state" in value.machine &&
    typeof value.machine.state === "string";
}

/** The `{ error: { code, message } }` body of a failed control-plane call. */
export async function apiError(
  response: Response,
): Promise<Readonly<{ code?: string; message?: string }>> {
  try {
    const value: unknown = await response.json();
    if (
      typeof value === "object" &&
      value !== null &&
      "error" in value &&
      typeof value.error === "object" &&
      value.error !== null
    ) {
      const error = value.error;
      return {
        ...("code" in error && typeof error.code === "string"
          ? { code: error.code }
          : {}),
        ...("message" in error && typeof error.message === "string"
          ? { message: error.message }
          : {}),
      };
    }
  } catch {
    // The status code still provides an actionable, non-sensitive failure.
  }
  return {};
}

export function normalizedOperatingSystem(): "macos" | "linux" | "windows" {
  const value = platform();
  if (value === "darwin") return "macos";
  if (value === "win32") return "windows";
  return "linux";
}
