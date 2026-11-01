import { arch, hostname, platform } from "node:os";
import type { ObserverConfig } from "./config.js";
import {
  FileCredentialStore,
  credentialFileName,
  type CredentialStore,
  type StoredMachineCredential,
} from "./credential-store.js";
import { retirePairingState } from "./event-spool.js";
import { installationFileName, loadOrCreateInstallationID } from "./installation.js";
import { InstanceLock } from "./instance-lock.js";

export const OBSERVER_CONSENT_POLICY_VERSION = "observer-policy-v1";
export type ConsentProfile = "metadata" | "full";

type PairingMachine = Readonly<{
  id: string;
  tenant_id: string;
  display_name: string;
  state: string;
}>;

type PairingResponse = Readonly<{
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
}>;

type ExchangeOutcome =
  | Readonly<{ paired: PairingResponse }>
  | Readonly<{ message: string; credentialRejected: boolean }>;

export type PairOptions = Readonly<{
  config: ObserverConfig;
  code: string;
  displayName?: string;
  consentProfile: ConsentProfile;
  credentialStore?: CredentialStore;
  fetcher?: typeof fetch;
}>;

export async function pairMachine(options: PairOptions): Promise<PairResult> {
  const code = options.code.trim();
  if (code.length === 0) {
    throw new Error("Pairing code is required.");
  }
  const installationID = await loadOrCreateInstallationID(
    options.config.dataDirectory,
  );
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
  const fetcher = options.fetcher ?? fetch;
  const credentialStore = options.credentialStore ??
    new FileCredentialStore(options.config.dataDirectory);
  const previous = await credentialStore.load();
  if (previous !== null && previous.controlPlaneOrigin !== endpoint.origin) {
    throw new Error("The stored machine belongs to a different control plane. Use a separate data directory to pair another workspace.");
  }
  const request = {
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
  };
  let paired: PairingResponse | undefined;
  if (previous !== null) {
    // Pairing again with the stored key renews consent and keeps the same
    // machine, so its queued activity stays deliverable.
    const renewal = await exchangePairing(fetcher, endpoint, {
      ...request,
      existing_credential: previous.credential,
    });
    if ("paired" in renewal) {
      paired = renewal.paired;
    } else if (!renewal.credentialRejected) {
      throw new Error(renewal.message);
    } else if (
      await credentialStillAccepted(
        fetcher,
        options.config.controlPlaneUrl,
        previous.credential,
      )
    ) {
      // The exchange also refuses a key that is valid in another workspace.
      throw new Error("This computer is paired with another workspace on this server. Use a separate data directory to pair another workspace.");
    }
  }

  const dataDirectory = options.config.dataDirectory;
  let lock: InstanceLock | undefined;
  try {
    if (paired === undefined || !sameMachine(previous, paired)) {
      // A new machine. Its queue, stream cursor and credential start empty;
      // the observer must not be using the old ones while they move.
      lock = await InstanceLock.acquire(dataDirectory);
      // The old credential goes with its queue: it is the only key that can
      // decrypt it. Once it is gone, a retry after a lost response pairs
      // without it, and the server answers with the same new machine.
      //
      // A key the server no longer accepts also retires its installation ID:
      // a server can still hold that ID for the deleted machine, and the
      // built-in SQLite server refuses to pair it again. A new ID pairs
      // cleanly everywhere.
      const replacing = paired === undefined && previous !== null;
      retirePairingState(dataDirectory, previous?.machineId, [
        credentialFileName,
        ...(replacing ? [installationFileName] : []),
      ]);
      if (paired === undefined) {
        const installation_id = replacing
          ? await loadOrCreateInstallationID(dataDirectory)
          : installationID;
        const fresh = await exchangePairing(fetcher, endpoint, { ...request, installation_id });
        if (!("paired" in fresh)) throw new Error(fresh.message);
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
      consentProfile: options.consentProfile,
      consentPolicyVersion: OBSERVER_CONSENT_POLICY_VERSION,
      consentedAt: pairedAt,
    });
  } finally {
    await lock?.release();
  }

  const replaced = previous !== null && previous.machineId !== paired.machine.id;
  return Object.freeze({
    machineId: paired.machine.id,
    displayName: paired.machine.display_name,
    state: paired.machine.state,
    controlPlaneOrigin: options.config.controlPlaneUrl.origin,
    credentialStored: true,
    ...(replaced ? { replacedMachineId: previous.machineId } : {}),
  });
}

function sameMachine(
  previous: StoredMachineCredential | null,
  paired: PairingResponse,
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
): Promise<ExchangeOutcome> {
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
      message: failure.message ?? `Pairing failed with HTTP ${response.status}.`,
      // The exchange answers a key it no longer accepts with HTTP 400 and
      // "machine credential is invalid".
      credentialRejected: failure.code === "invalid_credential" ||
        (response.status === 400 &&
          /^machine credential is (?:invalid|revoked)\b/iu.test(failure.message ?? "")),
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
  return { paired: parsePairingResponse(value) };
}

/**
 * Whether the server still accepts a stored key. Only a key the server
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

function parsePairingResponse(value: unknown): PairingResponse {
  if (
    typeof value !== "object" ||
    value === null ||
    !("credential" in value) ||
    typeof value.credential !== "string" ||
    !value.credential.startsWith("phg_m_") ||
    !("machine" in value) ||
    typeof value.machine !== "object" ||
    value.machine === null ||
    !("id" in value.machine) ||
    typeof value.machine.id !== "string" ||
    !("tenant_id" in value.machine) ||
    typeof value.machine.tenant_id !== "string" ||
    !("display_name" in value.machine) ||
    typeof value.machine.display_name !== "string" ||
    !("state" in value.machine) ||
    typeof value.machine.state !== "string"
  ) {
    throw new Error("Control plane returned an invalid pairing response.");
  }
  return value as PairingResponse;
}

/** The `{ error: { code, message } }` body of a failed control-plane call. */
async function apiError(
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

function normalizedOperatingSystem(): "macos" | "linux" | "windows" {
  const value = platform();
  if (value === "darwin") return "macos";
  if (value === "win32") return "windows";
  return "linux";
}
