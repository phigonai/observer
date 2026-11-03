import { arch, hostname } from "node:os";
import { setTimeout as delay } from "node:timers/promises";
import type { ObserverConfig } from "./config.js";
import { redactSecrets } from "./content-redaction.js";
import {
  maxEnrollmentCodeLabelLength,
  type CredentialStore,
} from "./credential-store.js";
import {
  OBSERVER_CONSENT_POLICY_VERSION,
  apiError,
  connectMachine,
  credentialRejected,
  isConnectedMachine,
  normalizedOperatingSystem,
  type ConnectedMachine,
  type ConsentProfile,
  type ExchangeOutcome,
  type PairResult,
} from "./pair.js";
import { plainText } from "./user-notices.js";

/**
 * Enrollment with a company's reusable enrollment code. Unlike pairing, the
 * company gives consent for its computers: nobody at this computer is
 * asked, the server answers with the profile the company chose, and that
 * profile limits collection exactly as an owner's choice does.
 *
 * The code itself is never printed, logged or stored.
 */

/** The environment variable device management scripts pass the code in. */
export const enrollmentCodeVariable = "PHIGON_ENROLLMENT_CODE";

/**
 * Exit codes of `pair` with an enrollment code, for device management
 * scripts. Any other failure exits with 1.
 */
export const enrollmentExitCodes = Object.freeze({
  /** The server is busy, unavailable or unreachable: run it again later. */
  retryLater: 20,
  /** Expired, revoked, used up or outdated: the company needs a new code. */
  newCodeNeeded: 21,
  /** Not an enrollment code, or cut short. */
  invalidCode: 22,
  /** This computer enrolled with this code before and was removed since. */
  alreadyUsed: 23,
  /** This computer is already connected to the workspace. */
  alreadyConnected: 24,
});

const exitCodeForServerCode: Readonly<Record<string, number>> = Object.freeze({
  rate_limited: enrollmentExitCodes.retryLater,
  rate_limit_unavailable: enrollmentExitCodes.retryLater,
  enrollment_unavailable: enrollmentExitCodes.retryLater,
  enrollment_code_expired: enrollmentExitCodes.newCodeNeeded,
  enrollment_code_revoked: enrollmentExitCodes.newCodeNeeded,
  enrollment_code_used_up: enrollmentExitCodes.newCodeNeeded,
  enrollment_code_outdated: enrollmentExitCodes.newCodeNeeded,
  invalid_enrollment_code: enrollmentExitCodes.invalidCode,
  enrollment_code_already_used: enrollmentExitCodes.alreadyUsed,
  installation_already_paired: enrollmentExitCodes.alreadyConnected,
});

/** A failed enrollment: a plain sentence, the server's code and an exit code. */
export class EnrollmentError extends Error {
  readonly code: string;
  readonly exitCode: number;

  constructor(message: string, code: string, exitCode: number) {
    super(message);
    this.name = "EnrollmentError";
    this.code = code;
    this.exitCode = exitCode;
  }
}

/**
 * Retries for a busy server (HTTP 429 or 503): a few attempts, each after
 * the server's Retry-After plus a little jitter so a fleet behind one
 * address does not come back at the same second, within a bounded total.
 */
export const enrollmentRetry = Object.freeze({
  attempts: 4,
  defaultWaitMs: 30_000,
  maxWaitMs: 120_000,
  totalWaitMs: 300_000,
  jitterMs: 10_000,
});

const codePattern = /^phe_[A-Za-z0-9_-]{32}$/u;

/**
 * Checks an enrollment code's shape before it is sent, so a mistyped code
 * costs no request. Errors never repeat the code.
 */
export function checkedEnrollmentCode(value: string): string {
  const code = value.trim();
  if (!code.startsWith("phe_")) {
    throw new EnrollmentError(
      "This is not an enrollment code: enrollment codes start with phe_. For a one-time pairing code from Connect machine, use --code instead.",
      "invalid_enrollment_code",
      enrollmentExitCodes.invalidCode,
    );
  }
  if (!codePattern.test(code)) {
    throw new EnrollmentError(
      "This enrollment code is not valid. Check that it was copied in full, or ask your administrator for a new one.",
      "invalid_enrollment_code",
      enrollmentExitCodes.invalidCode,
    );
  }
  return code;
}

/** The consent the company gave, as the server reported it. */
export type CompanyConsent = Readonly<{
  source: "company";
  profile: ConsentProfile;
  policyVersion: string;
  grantedAt?: string;
  enrollmentCodeId?: string;
  enrollmentCodeLabel?: string;
}>;

export type EnrollResult = PairResult & Readonly<{ consent: CompanyConsent }>;

type EnrolledMachine = ConnectedMachine & Readonly<{ consent: CompanyConsent }>;

export type EnrollOptions = Readonly<{
  config: ObserverConfig;
  code: string;
  displayName?: string;
  observerVersion?: string;
  credentialStore?: CredentialStore;
  fetcher?: typeof fetch;
  /** See `ConnectOptions.serverMoved`. */
  serverMoved?: boolean;
  /** Called before each retry of a busy server, with the wait. */
  onRetry?: (waitMs: number, attempt: number) => void;
  sleep?: (ms: number) => Promise<void>;
  random?: () => number;
}>;

/**
 * Enrolls this computer with a company's enrollment code through
 * `POST /v1/machines/enroll`, and stores the machine credential with the
 * company's consent. A computer already paired with this server sends its
 * stored key and keeps its machine; its consent moves to the company's.
 */
export async function enrollMachine(options: EnrollOptions): Promise<EnrollResult> {
  const code = checkedEnrollmentCode(options.code);
  const endpoint = new URL("/v1/machines/enroll", options.config.controlPlaneUrl);
  const fetcher = options.fetcher ?? fetch;
  const version = reportableVersion(options.observerVersion);
  const connected = await connectMachine<EnrolledMachine>({
    config: options.config,
    endpoint,
    fetcher,
    ...(options.credentialStore === undefined ? {} : { credentialStore: options.credentialStore }),
    ...(options.serverMoved === true ? { serverMoved: true } : {}),
    exchange: (installationID, existingCredential) => exchangeWithRetries(options, fetcher, endpoint, {
      enrollment_code: code,
      installation_id: installationID,
      display_name: options.displayName?.trim() || hostname(),
      hostname: hostname(),
      operating_system: normalizedOperatingSystem(),
      architecture: arch(),
      ...(version === undefined ? {} : { observer_version: version }),
      ...(existingCredential === undefined ? {} : { existing_credential: existingCredential }),
    }),
    evidence: (enrolled, at) => ({
      consentProfile: enrolled.consent.profile,
      consentPolicyVersion: enrolled.consent.policyVersion,
      consentedAt: enrolled.consent.grantedAt ?? at,
      consentSource: "company",
      ...(enrolled.consent.enrollmentCodeId === undefined
        ? {}
        : { enrollmentCodeId: enrolled.consent.enrollmentCodeId }),
      ...(enrolled.consent.enrollmentCodeLabel === undefined
        ? {}
        : { enrollmentCodeLabel: enrolled.consent.enrollmentCodeLabel }),
    }),
  });
  return Object.freeze({ ...connected.result, consent: connected.paired.consent });
}

async function exchangeWithRetries(
  options: EnrollOptions,
  fetcher: typeof fetch,
  endpoint: URL,
  body: Readonly<Record<string, unknown>>,
): Promise<ExchangeOutcome<EnrolledMachine>> {
  const sleep = options.sleep ?? ((ms: number) => delay(ms));
  const random = options.random ?? Math.random;
  let waited = 0;
  for (let attempt = 1; ; attempt++) {
    const outcome = await exchangeEnrollment(fetcher, endpoint, body);
    if (!("retryAfterMs" in outcome)) return outcome;
    const waitMs = Math.round(outcome.retryAfterMs + random() * enrollmentRetry.jitterMs);
    if (attempt >= enrollmentRetry.attempts || waited + waitMs > enrollmentRetry.totalWaitMs) {
      return { error: outcome.error, credentialRejected: false };
    }
    options.onRetry?.(waitMs, attempt);
    await sleep(waitMs);
    waited += waitMs;
  }
}

type BusyOutcome = Readonly<{ error: EnrollmentError; retryAfterMs: number }>;

async function exchangeEnrollment(
  fetcher: typeof fetch,
  endpoint: URL,
  body: Readonly<Record<string, unknown>>,
): Promise<ExchangeOutcome<EnrolledMachine> | BusyOutcome> {
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
      signal: AbortSignal.timeout(15_000),
    });
  } catch (error) {
    throw new EnrollmentError(
      error instanceof Error && error.name === "TimeoutError"
        ? `Enrollment timed out while contacting ${endpoint.origin}. Run the same command again; within 10 minutes it gets the same machine back.`
        : `Could not reach ${endpoint.origin}. Check the network and the control-plane address, then try again.`,
      "unreachable",
      enrollmentExitCodes.retryLater,
    );
  }

  if (!response.ok) {
    const failure = await apiError(response);
    const code = failure.code ?? `http_${response.status}`;
    const error = new EnrollmentError(
      serverSentence(failure.message) ?? `Enrollment failed with HTTP ${response.status}. Try again later.`,
      code,
      exitCodeForServerCode[code] ??
        (response.status >= 500 ? enrollmentExitCodes.retryLater : 1),
    );
    if (response.status === 429 || response.status === 503) {
      return { error, retryAfterMs: retryAfterMs(response.headers.get("retry-after")) };
    }
    return { error, credentialRejected: credentialRejected(response.status, failure) };
  }
  let value: unknown;
  try {
    value = await response.json();
  } catch {
    // A truncated response may contain a credential; parser errors must not
    // print fragments. The server answers a repeat with the same machine.
    throw new EnrollmentError(
      "The enrollment response was incomplete. Run the same command again within 10 minutes and keep the data directory; the server answers with the same machine.",
      "invalid_response",
      enrollmentExitCodes.retryLater,
    );
  }
  const consent = companyConsent(value);
  if (!isConnectedMachine(value) || consent === undefined) {
    throw new EnrollmentError(
      "The control plane returned an enrollment this observer cannot use. Update the observer, then enroll again.",
      "invalid_response",
      1,
    );
  }
  return { paired: { machine: value.machine, credential: value.credential, consent } };
}

/**
 * The company's consent from an enrollment response. A consent this
 * observer cannot honour exactly, such as a newer policy version, is
 * refused rather than stored.
 */
function companyConsent(value: unknown): CompanyConsent | undefined {
  if (typeof value !== "object" || value === null || !("consent" in value)) return undefined;
  const consent = value.consent;
  if (
    typeof consent !== "object" ||
    consent === null ||
    !("source" in consent) || consent.source !== "company" ||
    !("profile" in consent) || (consent.profile !== "metadata" && consent.profile !== "full") ||
    !("policy_version" in consent) || consent.policy_version !== OBSERVER_CONSENT_POLICY_VERSION
  ) {
    return undefined;
  }
  const grantedAt = "granted_at" in consent && typeof consent.granted_at === "string" &&
      Number.isFinite(Date.parse(consent.granted_at))
    ? new Date(consent.granted_at).toISOString()
    : undefined;
  const codeId = "enrollment_code_id" in consent && typeof consent.enrollment_code_id === "string" &&
      /^[0-9A-Fa-f-]{1,64}$/u.test(consent.enrollment_code_id)
    ? consent.enrollment_code_id
    : undefined;
  const label = "enrollment_code_label" in consent && typeof consent.enrollment_code_label === "string"
    ? plainText(consent.enrollment_code_label, maxEnrollmentCodeLabelLength)
    : "";
  return Object.freeze({
    source: "company",
    profile: consent.profile,
    policyVersion: consent.policy_version,
    ...(grantedAt === undefined ? {} : { grantedAt }),
    ...(codeId === undefined ? {} : { enrollmentCodeId: codeId }),
    ...(label === "" ? {} : { enrollmentCodeLabel: label }),
  });
}

/** The server's plain sentence, one bounded line with any secret removed. */
function serverSentence(message: string | undefined): string | undefined {
  if (message === undefined) return undefined;
  const sentence = plainText(redactSecrets(message), 300);
  return sentence === "" ? undefined : sentence;
}

/** Retry-After in seconds or as an HTTP date, within the retry bounds. */
export function retryAfterMs(header: string | null, now: number = Date.now()): number {
  let wait = enrollmentRetry.defaultWaitMs;
  const value = header?.trim() ?? "";
  if (/^\d{1,6}$/u.test(value)) {
    wait = Number(value) * 1_000;
  } else if (value !== "" && Number.isFinite(Date.parse(value))) {
    wait = Date.parse(value) - now;
  }
  return Math.min(enrollmentRetry.maxWaitMs, Math.max(1_000, wait));
}

/** Printable ASCII of at most 64 bytes, as the server accepts. */
function reportableVersion(version: string | undefined): string | undefined {
  const value = version?.trim() ?? "";
  return /^[!-~]{1,64}$/u.test(value) ? value : undefined;
}
