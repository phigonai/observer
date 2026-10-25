import { createHash } from "node:crypto";

const maxProcessKeyBytes = 256;
const processKeyCapabilityPrefix = "process-key-sha256:";

/**
 * Accepts only opaque, bounded process-lifetime keys. Raw native start
 * material never leaves the local evidence provider.
 */
export function normalizedProcessKey(value: unknown): string | undefined {
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    value !== value.trim() ||
    Buffer.byteLength(value, "utf8") > maxProcessKeyBytes ||
    /[\u0000-\u001f\u007f]/u.test(value)
  ) {
    return undefined;
  }
  return value;
}

/**
 * Inventory carries only a short fingerprint of the process key. This lets
 * activity claims be compared with OS evidence without exposing native
 * process-lifetime material or treating a PID as identity.
 */
export function processKeyCapability(
  processKey: unknown,
): string | undefined {
  const normalized = normalizedProcessKey(processKey);
  if (normalized === undefined) return undefined;
  return `${processKeyCapabilityPrefix}${createHash("sha256")
    .update("phigon-process-key-capability-v1\0")
    .update(normalized)
    .digest("hex")
    .slice(0, 32)}`;
}

export function stableRuntimeAgentID(
  adapterID: string,
  processKey: unknown,
): string | undefined {
  const normalized = normalizedProcessKey(processKey);
  if (normalized === undefined || adapterID.length === 0) return undefined;
  const digest = createHash("sha256")
    .update("phigon-agent-process-v2\0")
    .update(adapterID)
    .update("\0")
    .update(normalized)
    .digest("hex")
    .slice(0, 32);
  return `agt_${digest}`;
}

/**
 * Converts complete local process-lifetime evidence into an opaque key. The
 * start identity, not the PID, prevents a reused PID from inheriting an old
 * runtime identity.
 */
export function observedProcessKey(
  platform: NodeJS.Platform,
  processID: number,
  nativeStartIdentity: string,
  executablePathDigest: string,
): string | undefined {
  if (
    !Number.isSafeInteger(processID) ||
    processID < 1 ||
    nativeStartIdentity.length === 0 ||
    executablePathDigest.length === 0
  ) {
    return undefined;
  }
  const hash = createHash("sha256");
  hash.update("phigon-observer-process-key-v1\0");
  for (const value of [
    platform,
    String(processID),
    nativeStartIdentity,
    executablePathDigest,
  ]) {
    hash.update(String(Buffer.byteLength(value, "utf8")));
    hash.update(":");
    hash.update(value);
    hash.update("\0");
  }
  return `prc_${hash.digest("hex")}`;
}
