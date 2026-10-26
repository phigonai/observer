import { makeDirectoryPrivate } from "./private-directory.js";
import { randomUUID } from "node:crypto";
import {
  chmod,
  mkdir,
  readFile,
  rename,
  stat,
  unlink,
  writeFile,
} from "node:fs/promises";
import { join } from "node:path";
import { create } from "@bufbuild/protobuf";
import {
  timestampDate,
  timestampFromDate,
} from "@bufbuild/protobuf/wkt";
import {
  AgentKind,
  AgentState,
} from "./generated/phigon/v1/common_pb.js";
import {
  AgentIdentitySchema,
  AgentInventorySchema,
  type AgentIdentity,
  type AgentInventory,
} from "./generated/phigon/v1/identity_pb.js";

const catalogVersion = 1;
const maxCatalogBytes = 1 << 20;
const maxHistoricalIdentities = 256;
const catalogFileName = "historical-agent-identities.json";
const processKeyCapabilityPattern =
  /^process-key-sha256:[a-f0-9]{32}$/u;
const capabilityPattern = /^[a-z0-9][a-z0-9:._+-]{0,63}$/u;
const scopedIDPattern = /^[A-Za-z0-9._:-]{1,128}$/u;

export type HistoricalIdentityScope = Readonly<{
  tenantId: string;
  machineId: string;
}>;

type StoredIdentity = Readonly<{
  agent_id: string;
  kind: number;
  display_name: string;
  version: string;
  runtime: string;
  state: number;
  process_id: string;
  started_at?: string;
  last_observed_at: string;
  capabilities: readonly string[];
  executable_path_digest: string;
}>;

type StoredCatalog = Readonly<{
  version: 1;
  tenant_id: string;
  machine_id: string;
  updated_at: string;
  identities: readonly StoredIdentity[];
}>;

/**
 * Stores only sanitized inventory metadata needed to keep stopped runtime and
 * unattributed source history targets addressable after observer restart.
 * Activity content, raw source IDs, raw process keys, credentials, and paths
 * are never accepted by this catalog.
 */
export class HistoricalIdentityStore {
  readonly #dataDirectory: string;
  readonly #path: string;
  readonly #scope: HistoricalIdentityScope;
  readonly #identities = new Map<string, AgentIdentity>();
  #loadPromise: Promise<readonly AgentIdentity[]> | undefined;
  #saveChain = Promise.resolve();
  #needsRewrite = false;

  constructor(
    dataDirectory: string,
    scope: HistoricalIdentityScope,
  ) {
    validateScope(scope);
    this.#dataDirectory = dataDirectory;
    this.#path = join(dataDirectory, catalogFileName);
    this.#scope = Object.freeze({ ...scope });
  }

  load(): Promise<readonly AgentIdentity[]> {
    this.#loadPromise ??= this.#loadOnce();
    return this.#loadPromise;
  }

  async remember(
    candidates: readonly AgentIdentity[],
  ): Promise<readonly AgentIdentity[]> {
    await this.load();
    const operation = this.#saveChain
      .catch(() => undefined)
      .then(async () => {
        let changed = this.#needsRewrite;
        for (const candidate of candidates) {
          const sanitized = sanitizedHistoricalIdentity(candidate);
          if (sanitized === undefined) continue;
          const previous = this.#identities.get(sanitized.agentId);
          if (
            previous === undefined ||
            serializedIdentity(previous) !== serializedIdentity(sanitized)
          ) {
            this.#identities.set(sanitized.agentId, sanitized);
            changed = true;
          }
        }
        if (this.#bound()) changed = true;
        if (changed) {
          await this.#save();
          this.#needsRewrite = false;
        }
        return this.identities();
      });
    this.#saveChain = operation.then(
      () => undefined,
      () => undefined,
    );
    return operation;
  }

  identities(): readonly AgentIdentity[] {
    return [...this.#identities.values()].sort((left, right) =>
      left.agentId.localeCompare(right.agentId)
    );
  }

  async #loadOnce(): Promise<readonly AgentIdentity[]> {
    let raw: string;
    try {
      const metadata = await stat(this.#path);
      if (!metadata.isFile() || metadata.size > maxCatalogBytes) {
        this.#needsRewrite = true;
        return [];
      }
      raw = await readFile(this.#path, "utf8");
    } catch (error) {
      if (isNodeError(error) && error.code === "ENOENT") return [];
      throw error;
    }

    let parsed: unknown;
    try {
      parsed = JSON.parse(raw);
    } catch {
      this.#needsRewrite = true;
      return [];
    }
    const catalog = parsedCatalog(parsed);
    if (
      catalog === undefined ||
      catalog.tenant_id !== this.#scope.tenantId ||
      catalog.machine_id !== this.#scope.machineId
    ) {
      this.#needsRewrite = true;
      return [];
    }
    for (const stored of catalog.identities) {
      const identity = parsedIdentity(stored);
      if (identity === undefined) {
        this.#identities.clear();
        this.#needsRewrite = true;
        return [];
      }
      this.#identities.set(identity.agentId, identity);
    }
    return this.identities();
  }

  #bound(): boolean {
    if (this.#identities.size <= maxHistoricalIdentities) return false;
    const retained = [...this.#identities.values()]
      .sort(recentIdentityFirst)
      .slice(0, maxHistoricalIdentities);
    this.#identities.clear();
    for (const identity of retained) {
      this.#identities.set(identity.agentId, identity);
    }
    return true;
  }

  async #save(): Promise<void> {
    await mkdir(this.#dataDirectory, { recursive: true, mode: 0o700 });
    await makeDirectoryPrivate(this.#dataDirectory);
    const temporaryPath =
      `${this.#path}.${process.pid}.${randomUUID()}.tmp`;
    const catalog: StoredCatalog = {
      version: catalogVersion,
      tenant_id: this.#scope.tenantId,
      machine_id: this.#scope.machineId,
      updated_at: new Date().toISOString(),
      identities: this.identities().map(storedIdentity),
    };
    try {
      await writeFile(
        temporaryPath,
        `${JSON.stringify(catalog)}\n`,
        { encoding: "utf8", flag: "wx", mode: 0o600 },
      );
      await rename(temporaryPath, this.#path);
      await chmod(this.#path, 0o600);
    } catch (error) {
      try {
        await unlink(temporaryPath);
      } catch {
        // The temporary file may not have been created.
      }
      throw error;
    }
  }
}

export function mergeInventoryWithHistoricalIdentities(
  inventory: AgentInventory,
  historical: readonly AgentIdentity[],
): AgentInventory {
  const byID = new Map<string, AgentIdentity>();
  for (const identity of historical) {
    const sanitized = sanitizedHistoricalIdentity(identity);
    if (sanitized !== undefined) byID.set(sanitized.agentId, sanitized);
  }
  // A fresh discovery observation is authoritative for the same lifetime.
  for (const identity of inventory.agents) {
    byID.set(identity.agentId, identity);
  }
  const candidates = [...byID.values()];
  const runtimeProducts = new Set(
    candidates
      .filter((identity) =>
        identity.capabilities.includes("process-instance")
      )
      .flatMap(agentProductCapabilities),
  );
  const combined = candidates.filter(
    (identity) =>
      identity.capabilities.includes("process-instance") ||
      !agentProductCapabilities(identity).some((capability) =>
        runtimeProducts.has(capability)
      ),
  );
  const selected = combined
    .sort(inventoryRetentionOrder)
    .slice(0, maxHistoricalIdentities)
    .sort((left, right) => left.agentId.localeCompare(right.agentId));
  const overflow = combined.length > selected.length;
  const overflowNotice =
    "Historical agent identities exceeded inventory capacity.";
  const notices = overflow && !inventory.notices.includes(overflowNotice)
    ? [...inventory.notices.slice(0, 31), overflowNotice]
    : [...inventory.notices];
  return create(AgentInventorySchema, {
    ...inventory,
    agents: selected,
    partial: inventory.partial || overflow,
    notices,
  });
}

function sanitizedHistoricalIdentity(
  value: AgentIdentity,
): AgentIdentity | undefined {
  const capabilities = validatedCapabilities(value.capabilities);
  if (
    !/^agt_[a-f0-9]{32}$/u.test(value.agentId) ||
    value.kind < AgentKind.CLAUDE ||
    value.kind > AgentKind.GENERIC ||
    !validBoundedText(value.displayName, 128, true) ||
    !validBoundedText(value.version, 64, false) ||
    !validBoundedText(value.runtime, 128, false) ||
    !validDigest(value.executablePathDigest) ||
    capabilities === undefined ||
    value.lastObservedAt === undefined
  ) {
    return undefined;
  }
  const processIdentity = capabilities.includes("process-instance");
  const sourceIdentity = capabilities.includes("source-isolated");
  if (processIdentity === sourceIdentity) return undefined;
  if (
    processIdentity &&
    capabilities.filter((capability) =>
      processKeyCapabilityPattern.test(capability)
    ).length !== 1
  ) {
    return undefined;
  }
  if (
    sourceIdentity &&
    (!capabilities.includes("unattributed") || value.processId !== 0n)
  ) {
    return undefined;
  }
  const lastObserved = validTimestamp(timestampDate(value.lastObservedAt));
  const startedAt = value.startedAt === undefined
    ? undefined
    : validTimestamp(timestampDate(value.startedAt));
  if (lastObserved === undefined ||
    (value.startedAt !== undefined && startedAt === undefined)) {
    return undefined;
  }
  return create(AgentIdentitySchema, {
    agentId: value.agentId,
    kind: value.kind,
    displayName: value.displayName,
    version: value.version,
    runtime: value.runtime,
    state: processIdentity ? AgentState.STOPPED : AgentState.UNKNOWN,
    processId: processIdentity ? value.processId : 0n,
    ...(startedAt === undefined
      ? {}
      : { startedAt: timestampFromDate(startedAt) }),
    lastObservedAt: timestampFromDate(lastObserved),
    capabilities,
    executablePathDigest: value.executablePathDigest,
  });
}

function storedIdentity(value: AgentIdentity): StoredIdentity {
  return {
    agent_id: value.agentId,
    kind: value.kind,
    display_name: value.displayName,
    version: value.version,
    runtime: value.runtime,
    state: value.state,
    process_id: value.processId.toString(),
    ...(value.startedAt === undefined
      ? {}
      : { started_at: timestampDate(value.startedAt).toISOString() }),
    last_observed_at: value.lastObservedAt === undefined
      ? new Date(0).toISOString()
      : timestampDate(value.lastObservedAt).toISOString(),
    capabilities: [...value.capabilities],
    executable_path_digest: value.executablePathDigest,
  };
}

function parsedCatalog(value: unknown): StoredCatalog | undefined {
  if (
    typeof value !== "object" ||
    value === null ||
    !("version" in value) ||
    value.version !== catalogVersion ||
    !("tenant_id" in value) ||
    typeof value.tenant_id !== "string" ||
    !("machine_id" in value) ||
    typeof value.machine_id !== "string" ||
    !("updated_at" in value) ||
    typeof value.updated_at !== "string" ||
    validDateString(value.updated_at) === undefined ||
    !("identities" in value) ||
    !Array.isArray(value.identities) ||
    value.identities.length > maxHistoricalIdentities
  ) {
    return undefined;
  }
  return value as StoredCatalog;
}

function parsedIdentity(value: unknown): AgentIdentity | undefined {
  if (
    typeof value !== "object" ||
    value === null ||
    !("agent_id" in value) ||
    typeof value.agent_id !== "string" ||
    !("kind" in value) ||
    typeof value.kind !== "number" ||
    !("display_name" in value) ||
    typeof value.display_name !== "string" ||
    !("version" in value) ||
    typeof value.version !== "string" ||
    !("runtime" in value) ||
    typeof value.runtime !== "string" ||
    !("state" in value) ||
    typeof value.state !== "number" ||
    !("process_id" in value) ||
    typeof value.process_id !== "string" ||
    !/^\d{1,20}$/u.test(value.process_id) ||
    !("last_observed_at" in value) ||
    typeof value.last_observed_at !== "string" ||
    !("capabilities" in value) ||
    !Array.isArray(value.capabilities) ||
    value.capabilities.some((capability) => typeof capability !== "string") ||
    !("executable_path_digest" in value) ||
    typeof value.executable_path_digest !== "string"
  ) {
    return undefined;
  }
  const startedAt = "started_at" in value
    ? typeof value.started_at === "string"
      ? validDateString(value.started_at)
      : undefined
    : null;
  const lastObservedAt = validDateString(value.last_observed_at);
  if (startedAt === undefined || lastObservedAt === undefined) {
    return undefined;
  }
  let processID: bigint;
  try {
    processID = BigInt(value.process_id);
  } catch {
    return undefined;
  }
  if (processID > 18_446_744_073_709_551_615n) return undefined;
  const candidate = create(AgentIdentitySchema, {
    agentId: value.agent_id,
    kind: value.kind,
    displayName: value.display_name,
    version: value.version,
    runtime: value.runtime,
    state: value.state,
    processId: processID,
    ...(startedAt === null
      ? {}
      : { startedAt: timestampFromDate(startedAt) }),
    lastObservedAt: timestampFromDate(lastObservedAt),
    capabilities: value.capabilities as string[],
    executablePathDigest: value.executable_path_digest,
  });
  return sanitizedHistoricalIdentity(candidate);
}

function validatedCapabilities(
  capabilities: readonly string[],
): string[] | undefined {
  if (
    capabilities.length === 0 ||
    capabilities.length > 64 ||
    capabilities.some((capability) => !capabilityPattern.test(capability))
  ) {
    return undefined;
  }
  return [...new Set(capabilities)].sort();
}

function agentProductCapabilities(identity: AgentIdentity): string[] {
  return identity.capabilities.filter((capability) =>
    capability.startsWith("agent-product:")
  );
}

function validBoundedText(
  value: string,
  maxBytes: number,
  required: boolean,
): boolean {
  return (
    (!required || value.length > 0) &&
    Buffer.byteLength(value, "utf8") <= maxBytes &&
    !/[\u0000-\u001f\u007f]/u.test(value)
  );
}

function validDigest(value: string): boolean {
  return value.length <= 128 && /^[A-Za-z0-9._:-]*$/u.test(value);
}

function validDateString(value: string): Date | undefined {
  if (value.length > 64) return undefined;
  return validTimestamp(new Date(value));
}

function validTimestamp(value: Date): Date | undefined {
  return Number.isNaN(value.getTime()) ? undefined : value;
}

function validateScope(scope: HistoricalIdentityScope): void {
  if (
    !scopedIDPattern.test(scope.tenantId) ||
    !scopedIDPattern.test(scope.machineId)
  ) {
    throw new Error("Historical identity scope is invalid.");
  }
}

function recentIdentityFirst(
  left: AgentIdentity,
  right: AgentIdentity,
): number {
  const leftObserved = left.lastObservedAt === undefined
    ? 0
    : timestampDate(left.lastObservedAt).getTime();
  const rightObserved = right.lastObservedAt === undefined
    ? 0
    : timestampDate(right.lastObservedAt).getTime();
  return rightObserved - leftObserved || left.agentId.localeCompare(right.agentId);
}

function inventoryRetentionOrder(
  left: AgentIdentity,
  right: AgentIdentity,
): number {
  const leftCurrent = left.state === AgentState.RUNNING ? 1 : 0;
  const rightCurrent = right.state === AgentState.RUNNING ? 1 : 0;
  if (leftCurrent !== rightCurrent) return rightCurrent - leftCurrent;
  const leftSource = left.capabilities.includes("source-isolated") ? 1 : 0;
  const rightSource = right.capabilities.includes("source-isolated") ? 1 : 0;
  if (leftSource !== rightSource) return rightSource - leftSource;
  return recentIdentityFirst(left, right);
}

function serializedIdentity(value: AgentIdentity): string {
  return JSON.stringify(storedIdentity(value));
}

function isNodeError(error: unknown): error is NodeJS.ErrnoException {
  return error instanceof Error && "code" in error;
}
