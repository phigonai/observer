import type { ObserverConfig } from "./config.js";
import { FileCredentialStore, type StoredMachineCredential } from "./credential-store.js";
import { consentHealth, type ObserverConsentHealth } from "./health.js";
import { InstanceLock, type InstanceLockHolder } from "./instance-lock.js";
import { machineRemovedMessage, removalConfirmed } from "./machine-removed.js";
import { OBSERVER_CONSENT_POLICY_VERSION } from "./pair.js";
import { inspectionMessage, relayHost, relayNotConnectedMessage } from "./server-authority.js";
import { serverFetch, trustedServerAuthority } from "./server-fetch.js";
import { StreamStateStore } from "./stream-state.js";

/**
 * Exit codes of `doctor --check`, for device management scripts. The first
 * failing check, in this order, decides the code.
 */
export const doctorCheckExitCodes = Object.freeze({
  ok: 0,
  notPaired: 3,
  consentMissing: 4,
  notRunning: 5,
  deliveryStale: 6,
  controlPlaneUnreachable: 7,
});

export const defaultMaxDeliveryAgeMinutes = 15;
const probeTimeoutMs = 5_000;

export type DoctorCheckName = "paired" | "consent" | "running" | "delivery" | "control_plane";

export type DoctorCheck = Readonly<{
  name: DoctorCheckName;
  status: "pass" | "fail" | "skip";
  detail: string;
}>;

export type DoctorCheckReport = Readonly<{
  ok: boolean;
  exitCode: number;
  observerVersion: string;
  dataDirectory: string;
  controlPlaneOrigin: string;
  maxDeliveryAgeMinutes: number;
  /** How this computer consented, when it is paired with this server. */
  consent?: ObserverConsentHealth;
  checks: readonly DoctorCheck[];
  checkedAt: string;
}>;

const exitCodeFor: Readonly<Record<DoctorCheckName, number>> = Object.freeze({
  paired: doctorCheckExitCodes.notPaired,
  consent: doctorCheckExitCodes.consentMissing,
  running: doctorCheckExitCodes.notRunning,
  delivery: doctorCheckExitCodes.deliveryStale,
  control_plane: doctorCheckExitCodes.controlPlaneUnreachable,
});

export type DoctorCheckOptions = Readonly<{
  config: ObserverConfig;
  observerVersion: string;
  maxDeliveryAgeMinutes?: number;
  now?: () => Date;
  fetcher?: typeof fetch;
  inspectLock?: (dataDirectory: string) => Promise<InstanceLockHolder>;
  probeTimeoutMs?: number;
}>;

/**
 * Checks, without sending any activity, that this computer is paired with
 * current consent, that an observer is running, that the workspace has
 * confirmed delivery recently, and that the control plane answers.
 */
export async function runDoctorCheck(options: DoctorCheckOptions): Promise<DoctorCheckReport> {
  const { config } = options;
  const now = (options.now ?? (() => new Date()))();
  const maxAge = options.maxDeliveryAgeMinutes ?? defaultMaxDeliveryAgeMinutes;
  const checks: DoctorCheck[] = [];

  let credential: StoredMachineCredential | null = null;
  try {
    credential = await new FileCredentialStore(config.dataDirectory).load();
    if (credential === null) {
      checks.push(fail("paired", "This computer is not paired. Run phigon-observer pair with a code from Connect machine."));
    } else if (credential.controlPlaneOrigin !== config.controlPlaneUrl.origin) {
      checks.push(fail(
        "paired",
        `This computer is paired with ${credential.controlPlaneOrigin}, but the observer is set up for ${config.controlPlaneUrl.origin}.`,
      ));
      credential = null;
    } else {
      checks.push(pass("paired", `Paired as machine ${credential.machineId} with ${credential.controlPlaneOrigin}.`));
    }
  } catch (error) {
    checks.push(fail("paired", error instanceof Error ? error.message : "Stored pairing data could not be read."));
  }

  const consent = credential === null ? undefined : consentHealth(credential);
  if (credential === null || consent === undefined) {
    checks.push(skip("consent", "Needs pairing first."));
  } else if (
    credential.consentProfile === undefined ||
    credential.consentPolicyVersion !== OBSERVER_CONSENT_POLICY_VERSION
  ) {
    // A company's consent is stored only with its profile, so this is an
    // owner's consent from before profiles, or from an older policy.
    checks.push(fail(
      "consent",
      "The owner's consent is missing or out of date. Pair again with --consent-profile metadata or --consent-profile full.",
    ));
  } else {
    const when = credential.consentedAt === undefined ? "" : ` on ${credential.consentedAt}`;
    checks.push(pass(
      "consent",
      consent.source === "company"
        ? `Your company consented for this computer to the ${credential.consentProfile} profile${
          consent.enrollmentCodeLabel === undefined ? " with an enrollment code" : ` with the enrollment code "${consent.enrollmentCodeLabel}"`
        }${when}.`
        : `The owner consented to the ${credential.consentProfile} profile${when}.`,
    ));
  }

  try {
    const holder = await (options.inspectLock ?? ((directory) => InstanceLock.inspect(directory)))(config.dataDirectory);
    checks.push(holder.running
      ? pass("running", `An observer is running with this data directory${holder.pid === undefined ? "" : ` (process ${holder.pid})`}.`)
      : credential !== null && await removalConfirmed(config.dataDirectory, credential)
        // Starting it again would only stop again: the workspace removed it.
        ? fail("running", machineRemovedMessage)
        : fail("running", "No observer is running with this data directory. Start it with phigon-observer service install, or run phigon-observer run."));
  } catch {
    checks.push(fail("running", "Could not tell whether an observer is running: its lock file could not be read."));
  }

  if (credential === null) {
    checks.push(skip("delivery", "Needs pairing first."));
  } else {
    try {
      const state = await new StreamStateStore(config.dataDirectory).load(credential.machineId);
      const confirmedAt = Date.parse(state.updatedAt);
      const minutes = Math.floor((now.getTime() - confirmedAt) / 60_000);
      if (confirmedAt <= 0) {
        checks.push(fail("delivery", "The workspace has not confirmed any delivery from this computer yet."));
      } else if (minutes > maxAge) {
        checks.push(fail(
          "delivery",
          `Nothing has been delivered to the workspace for ${minutes} minutes (last confirmed ${state.updatedAt}).`,
        ));
      } else {
        checks.push(pass("delivery", `The workspace last confirmed delivery ${Math.max(0, minutes)} minutes ago.`));
      }
    } catch {
      checks.push(fail("delivery", "The stored stream checkpoint could not be read."));
    }
  }

  checks.push(await probeControlPlane(config.controlPlaneUrl, options.fetcher ?? serverFetch, options.probeTimeoutMs ?? probeTimeoutMs));

  const failed = checks.find((check) => check.status === "fail");
  return Object.freeze({
    ok: failed === undefined,
    exitCode: failed === undefined ? doctorCheckExitCodes.ok : exitCodeFor[failed.name],
    observerVersion: options.observerVersion,
    dataDirectory: config.dataDirectory,
    controlPlaneOrigin: config.controlPlaneUrl.origin,
    maxDeliveryAgeMinutes: maxAge,
    ...(consent === undefined ? {} : { consent }),
    checks: Object.freeze(checks),
    checkedAt: now.toISOString(),
  });
}

/** GET /healthz, through the configured proxy and the pinned authority. */
async function probeControlPlane(url: URL, fetcher: typeof fetch, timeoutMs: number): Promise<DoctorCheck> {
  const endpoint = new URL("/healthz", url);
  const started = performance.now();
  try {
    const response = await fetcher(endpoint, {
      method: "GET",
      headers: { Accept: "application/json" },
      redirect: "error",
      signal: AbortSignal.timeout(timeoutMs),
    });
    await response.body?.cancel().catch(() => undefined);
    if (!response.ok) {
      return fail("control_plane", `The control plane at ${url.origin} answered HTTP ${response.status}.`);
    }
    return pass("control_plane", `The control plane at ${url.origin} answered in ${Math.round(performance.now() - started)} ms.`);
  } catch (error) {
    const timedOut = error instanceof Error && error.name === "TimeoutError";
    const code = errorCode(error);
    // The relay closes a connection for a server that is not connected to it.
    if (!timedOut && relayHost(url.hostname) && (code === "ECONNRESET" || code === "UND_ERR_SOCKET" || code === "EPIPE")) {
      return fail("control_plane", relayNotConnectedMessage);
    }
    // Only the pinned authority is trusted, so a certificate it did not
    // issue was re-signed on the way.
    if (!timedOut && trustedServerAuthority() !== undefined && code !== undefined && untrustedChainCodes.has(code)) {
      return fail("control_plane", inspectionMessage(url));
    }
    const reason = timedOut
      ? `no answer within ${Math.round(timeoutMs / 1_000)} seconds`
      : code ?? "the connection failed";
    return fail("control_plane", `Could not reach the control plane at ${url.origin} (${reason}).`);
  }
}

/** Node.js codes for a certificate chain that does not lead to a trusted authority. */
const untrustedChainCodes = new Set([
  "UNABLE_TO_VERIFY_LEAF_SIGNATURE",
  "UNABLE_TO_GET_ISSUER_CERT",
  "UNABLE_TO_GET_ISSUER_CERT_LOCALLY",
  "SELF_SIGNED_CERT_IN_CHAIN",
  "DEPTH_ZERO_SELF_SIGNED_CERT",
  "CERT_SIGNATURE_FAILURE",
]);

/** A system error code such as ENOTFOUND or a certificate error, never a message with data. */
function errorCode(error: unknown): string | undefined {
  for (let current: unknown = error, depth = 0; current instanceof Error && depth < 4; depth++) {
    const code = (current as NodeJS.ErrnoException).code;
    if (typeof code === "string" && /^[A-Z0-9_]{2,64}$/u.test(code)) return code;
    current = current.cause;
  }
  return undefined;
}

function pass(name: DoctorCheckName, detail: string): DoctorCheck {
  return Object.freeze({ name, status: "pass", detail });
}

function fail(name: DoctorCheckName, detail: string): DoctorCheck {
  return Object.freeze({ name, status: "fail", detail });
}

function skip(name: DoctorCheckName, detail: string): DoctorCheck {
  return Object.freeze({ name, status: "skip", detail });
}

export function formatDoctorCheck(report: DoctorCheckReport): string {
  const labels: Readonly<Record<DoctorCheckName, string>> = {
    paired: "Pairing",
    consent: "Consent",
    running: "Observer",
    delivery: "Delivery",
    control_plane: "Control plane",
  };
  return [
    report.ok
      ? "Phigon observer check passed."
      : `Phigon observer check found a problem (exit code ${report.exitCode}).`,
    ...report.checks.map((check) =>
      `${check.status === "pass" ? "ok  " : check.status === "fail" ? "FAIL" : "skip"}  ${labels[check.name].padEnd(13)} ${check.detail}`),
    "",
  ].join("\n");
}
