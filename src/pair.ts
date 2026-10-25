import { arch, hostname, platform } from "node:os";
import type { ObserverConfig } from "./config.js";
import {
  FileCredentialStore,
  type CredentialStore,
} from "./credential-store.js";
import { loadOrCreateInstallationID } from "./installation.js";

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
}>;

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
  let response: Response;
  try {
    response = await fetcher(endpoint, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Accept: "application/json",
      },
      body: JSON.stringify({
        code,
        ...(previous === null ? {} : { existing_credential: previous.credential }),
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
      }),
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
    throw new Error(await pairingFailureMessage(response));
  }
  let value: unknown;
  try {
    value = await response.json();
  } catch {
    // A truncated response may contain a credential; parser errors must not
    // print fragments. The server supports retries for this installation.
    throw new Error("The pairing response was incomplete or invalid. Retry with the same code before it expires; keep the existing data directory.");
  }
  const paired = parsePairingResponse(value);
  await credentialStore.save({
    machineId: paired.machine.id,
    tenantId: paired.machine.tenant_id,
    credential: paired.credential,
    controlPlaneOrigin: options.config.controlPlaneUrl.origin,
    grpcOrigin: options.config.grpcUrl.origin,
    createdAt: new Date().toISOString(),
    consentProfile: options.consentProfile,
    consentPolicyVersion: OBSERVER_CONSENT_POLICY_VERSION,
    consentedAt: new Date().toISOString(),
  });

  return Object.freeze({
    machineId: paired.machine.id,
    displayName: paired.machine.display_name,
    state: paired.machine.state,
    controlPlaneOrigin: options.config.controlPlaneUrl.origin,
    credentialStored: true,
  });
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

async function pairingFailureMessage(response: Response): Promise<string> {
  try {
    const value: unknown = await response.json();
    if (
      typeof value === "object" &&
      value !== null &&
      "error" in value &&
      typeof value.error === "object" &&
      value.error !== null &&
      "message" in value.error &&
      typeof value.error.message === "string"
    ) {
      return value.error.message;
    }
  } catch {
    // The status code still provides an actionable, non-sensitive failure.
  }
  return `Pairing failed with HTTP ${response.status}.`;
}

function normalizedOperatingSystem(): "macos" | "linux" | "windows" {
  const value = platform();
  if (value === "darwin") return "macos";
  if (value === "win32") return "windows";
  return "linux";
}
