import { arch, hostname, platform, release } from "node:os";
import type { ObserverConfig } from "./config.js";
import { consentSourceOf, type StoredMachineCredential } from "./credential-store.js";
import type { ObserverRuntimeHealth } from "./self-report.js";

const metadataOnlyCategories = new Set([
  "processMetadata",
  "fileMetadata",
  "networkMetadata",
  "browserMetadata",
]);

export type ObserverStreamCursorHealth = Readonly<{
  machineId: string;
  acknowledgedSequence: string;
  updatedAt: string;
}>;

/**
 * How this computer consented: its owner at pairing, or its company with an
 * enrollment code. `profile` is missing when no current consent is stored.
 */
export type ObserverConsentHealth = Readonly<{
  source: "owner" | "company";
  profile?: "metadata" | "full";
  policyVersion?: string;
  consentedAt?: string;
  enrollmentCodeLabel?: string;
}>;

/** The consent a stored credential records, for doctor. */
export function consentHealth(credential: StoredMachineCredential): ObserverConsentHealth {
  return Object.freeze({
    source: consentSourceOf(credential),
    ...(credential.consentProfile === undefined ? {} : { profile: credential.consentProfile }),
    ...(credential.consentPolicyVersion === undefined ? {} : { policyVersion: credential.consentPolicyVersion }),
    ...(credential.consentedAt === undefined ? {} : { consentedAt: credential.consentedAt }),
    ...(credential.enrollmentCodeLabel === undefined ? {} : { enrollmentCodeLabel: credential.enrollmentCodeLabel }),
  });
}

/** One line saying how the computer consented. */
export function describeConsent(consent: ObserverConsentHealth): string {
  const who = consent.source === "company"
    ? `your company, with the enrollment code${consent.enrollmentCodeLabel === undefined ? "" : ` "${consent.enrollmentCodeLabel}"`}`
    : "the computer's owner, at pairing";
  return consent.profile === undefined
    ? `none current (last given by ${who})`
    : `given by ${who}, for the ${consent.profile} profile`;
}

export type ObserverHealth = Readonly<{
  status: "ready" | "needs-pairing";
  observerVersion: string;
  controlPlaneOrigin: string;
  grpcOrigin: string;
  dataDirectory: string;
  heartbeatIntervalMs: number;
  discoveryIntervalMs: number;
  activityRateLimitPerMinute: number;
  activityQueueCapacity: number;
  machineTokenConfigured: boolean;
  observabilityProfile: string;
  enabledCollectionCategories: readonly string[];
  safeCollectionDefaults: boolean;
  host: Readonly<{
    architecture: string;
    hostname: string;
    platform: NodeJS.Platform;
    release: string;
  }>;
  runtime: Readonly<{
    node: string;
  }>;
  streamCursor?: ObserverStreamCursorHealth;
  streamCursorIssue?: string;
  /** How this computer consented, when it is paired. */
  consent?: ObserverConsentHealth;
  /** What the running observer last reported about itself (see self-report.ts). */
  runningObserver?: ObserverRuntimeHealth;
  checkedAt: string;
}>;

export function createHealthSnapshot(
  config: ObserverConfig,
  observerVersion: string,
  now: Date = new Date(),
  streamCursor?: ObserverStreamCursorHealth,
  streamCursorIssue?: string,
  consent?: ObserverConsentHealth,
  runningObserver?: ObserverRuntimeHealth,
): ObserverHealth {
  return Object.freeze({
    status: config.machineTokenConfigured ? "ready" : "needs-pairing",
    observerVersion,
    controlPlaneOrigin: config.controlPlaneUrl.origin,
    grpcOrigin: config.grpcUrl.origin,
    dataDirectory: config.dataDirectory,
    heartbeatIntervalMs: config.heartbeatIntervalMs,
    discoveryIntervalMs: config.discoveryIntervalMs,
    activityRateLimitPerMinute: config.activityRateLimitPerMinute,
    activityQueueCapacity: config.activityQueueCapacity,
    machineTokenConfigured: config.machineTokenConfigured,
    observabilityProfile: config.observabilityProfile,
    enabledCollectionCategories: Object.freeze(
      Object.entries(config.policy)
        .filter(([, enabled]) => enabled)
        .map(([category]) => category),
    ),
    safeCollectionDefaults: Object.entries(config.policy).every(
      ([category, enabled]) => !enabled || metadataOnlyCategories.has(category),
    ),
    host: Object.freeze({
      architecture: arch(),
      hostname: hostname(),
      platform: platform(),
      release: release(),
    }),
    runtime: Object.freeze({
      node: process.version,
    }),
    ...(streamCursor === undefined
      ? {}
      : { streamCursor: Object.freeze(streamCursor) }),
    ...(streamCursorIssue === undefined ? {} : { streamCursorIssue }),
    ...(consent === undefined ? {} : { consent }),
    ...(runningObserver === undefined ? {} : { runningObserver }),
    checkedAt: now.toISOString(),
  });
}
