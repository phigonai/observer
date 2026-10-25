import { arch, hostname, platform, release } from "node:os";
import type { ObserverConfig } from "./config.js";

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
  checkedAt: string;
}>;

export function createHealthSnapshot(
  config: ObserverConfig,
  observerVersion: string,
  now: Date = new Date(),
  streamCursor?: ObserverStreamCursorHealth,
  streamCursorIssue?: string,
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
    checkedAt: now.toISOString(),
  });
}
