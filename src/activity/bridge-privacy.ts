import { stat } from "node:fs/promises";
import { join } from "node:path";
import {
  COLLECTION_SETTINGS,
  consentedCollectionPolicy,
  loadConfig,
  type CollectionPolicy,
} from "../config.js";
import { FileCredentialStore, credentialFileName } from "../credential-store.js";
import { readServiceSettings, serviceSettingsPath } from "../service.js";
import { loadIdentifierKey } from "./identifier-key.js";
import type { StorableRecordOptions } from "./policy.js";

/**
 * The collection policy in force on this computer, judged where a bridge
 * record is written, outside the running observer: the profile whoever
 * consented agreed to, narrowed by the background service's settings when
 * it is installed (its profile and PHIGON_COLLECT_* switches). Without a
 * service the observer runs in a terminal whose settings are not known
 * here, and the full profile's defaults apply when full activity was
 * consented. Settings in `environment`, the environment of the program
 * writing the record, narrow it further: PHIGON_OBSERVABILITY_PROFILE=metadata
 * and PHIGON_COLLECT_*=false switch content off, and nothing there turns
 * anything on. Anything unreadable counts as the metadata profile.
 */
export async function bridgeCollectionPolicy(
  dataDirectory: string,
  environment: NodeJS.ProcessEnv = {},
): Promise<CollectionPolicy> {
  const stored = await storedCollectionPolicy(dataDirectory);
  return narrowedByEnvironment(stored, environment, dataDirectory);
}

function metadataPolicy(dataDirectory: string): CollectionPolicy {
  return consentedCollectionPolicy(loadConfig({ PHIGON_DATA_DIR: dataDirectory }).policy, undefined);
}

/** `policy` with every category the environment's own settings switch off turned off too. */
function narrowedByEnvironment(
  policy: CollectionPolicy,
  environment: NodeJS.ProcessEnv,
  dataDirectory: string,
): CollectionPolicy {
  const profile = environment["PHIGON_OBSERVABILITY_PROFILE"];
  const switches: Record<string, string> = {};
  for (const name of Object.values(COLLECTION_SETTINGS)) {
    const value = environment[name];
    if (value !== undefined) switches[name] = value;
  }
  if (profile === undefined && Object.keys(switches).length === 0) return policy;
  let requested: CollectionPolicy;
  try {
    requested = loadConfig({
      ...switches,
      // Read on top of the full profile, so only switches that turn
      // something off can matter; the intersection below never widens.
      PHIGON_OBSERVABILITY_PROFILE: profile ?? "full",
      PHIGON_DATA_DIR: dataDirectory,
    }).policy;
  } catch {
    return metadataPolicy(dataDirectory);
  }
  const narrowed = { ...policy } as Record<keyof CollectionPolicy, boolean>;
  for (const category of Object.keys(narrowed) as (keyof CollectionPolicy)[]) {
    narrowed[category] = policy[category] && requested[category];
  }
  return Object.freeze(narrowed);
}

async function storedCollectionPolicy(dataDirectory: string): Promise<CollectionPolicy> {
  const metadata = () => metadataPolicy(dataDirectory);
  try {
    const credential = await new FileCredentialStore(dataDirectory).load();
    if (credential?.consentProfile !== "full") return metadata();
  } catch {
    return metadata();
  }
  const settingsPath = serviceSettingsPath(dataDirectory);
  let environment: Record<string, string>;
  try {
    await stat(settingsPath);
    environment = await readServiceSettings(settingsPath);
  } catch (error) {
    if (!(error instanceof Error && "code" in error && error.code === "ENOENT")) return metadata();
    environment = { PHIGON_OBSERVABILITY_PROFILE: "full" };
  }
  try {
    const config = loadConfig({ ...environment, PHIGON_DATA_DIR: dataDirectory });
    if (config.observabilityProfile !== "full") return metadata();
    return consentedCollectionPolicy(config.policy, "full");
  } catch {
    return metadata();
  }
}

/**
 * Changes whenever a file bridgeCollectionPolicy reads changes (the pairing
 * credential that holds the consent, and the service settings), so a cached
 * policy can be checked with two stat calls. A file that cannot be examined
 * gives a value that never repeats, which forces the policy to be read again.
 */
export async function bridgePolicyFingerprint(dataDirectory: string): Promise<string> {
  const parts: string[] = [];
  for (const path of [join(dataDirectory, credentialFileName), serviceSettingsPath(dataDirectory)]) {
    try {
      const { size, mtimeMs, ctimeMs, ino } = await stat(path);
      parts.push(`${size}:${mtimeMs}:${ctimeMs}:${ino}`);
    } catch (error) {
      if (!(error instanceof Error && "code" in error && error.code === "ENOENT")) {
        return `unreadable:${++fingerprintSequence}`;
      }
      parts.push("missing");
    }
  }
  return parts.join("|");
}

let fingerprintSequence = 0;

/**
 * How records are written to bridge files in `dataDirectory` now (see
 * storableRecord), by a program with `environment` (see
 * bridgeCollectionPolicy). Call it once the directory exists, so the
 * installation's digest key is kept there.
 */
export async function bridgeStorageOptions(
  dataDirectory: string,
  environment: NodeJS.ProcessEnv = {},
): Promise<StorableRecordOptions> {
  return {
    policy: await bridgeCollectionPolicy(dataDirectory, environment),
    identifierKey: loadIdentifierKey(dataDirectory),
    pathPatterns: await bridgePathPatterns(dataDirectory, environment),
  };
}

/**
 * The private paths (PHIGON_REDACT_PATH_PATTERNS) the collector would replace:
 * those in the background service's settings and those in `environment`.
 */
async function bridgePathPatterns(
  dataDirectory: string,
  environment: NodeJS.ProcessEnv,
): Promise<readonly string[]> {
  const patterns = new Set<string>();
  const add = (value: string | undefined) => {
    if (value === undefined) return;
    try {
      const config = loadConfig({ PHIGON_REDACT_PATH_PATTERNS: value, PHIGON_DATA_DIR: dataDirectory });
      for (const pattern of config.redactionPathPatterns) patterns.add(pattern);
    } catch {
      // The observer refuses to start with such a setting.
    }
  };
  add(environment["PHIGON_REDACT_PATH_PATTERNS"]);
  try {
    const settingsPath = serviceSettingsPath(dataDirectory);
    await stat(settingsPath);
    add((await readServiceSettings(settingsPath))["PHIGON_REDACT_PATH_PATTERNS"]);
  } catch {
    // No service, or settings it cannot use either.
  }
  return [...patterns];
}
