import { randomUUID } from "node:crypto";
import {
  chmod,
  mkdir,
  readFile,
  rename,
  unlink,
  writeFile,
} from "node:fs/promises";
import { homedir } from "node:os";
import {
  dirname,
  isAbsolute,
  join,
  relative,
  resolve,
  sep,
} from "node:path";

const registryVersion = 1;
const maxRegistrations = 128;
const maxRegistryBytes = 1 << 20;
const idPattern = /^[a-z0-9][a-z0-9-]{0,62}$/u;
const namePattern = /^[A-Za-z0-9][A-Za-z0-9._+-]{0,127}$/u;
const capabilityPattern = /^[a-z0-9][a-z0-9:._+-]{0,63}$/u;
const reservedCapabilities = new Set([
  "native-activity",
  "process-instance",
  "source-isolated",
  "unattributed",
]);
const reservedCapabilityPrefixes = ["agent-product:", "process-key:"];

export type CustomAgentRegistration = Readonly<{
  id: string;
  displayName: string;
  executableNames: readonly string[];
  processNames: readonly string[];
  configurationPaths: readonly string[];
  activityDirectories: readonly string[];
  capabilities: readonly string[];
}>;

type StoredRegistry = Readonly<{
  version: 1;
  agents: readonly CustomAgentRegistration[];
}>;

export class CustomAgentRegistry {
  readonly #dataDirectory: string;
  readonly #path: string;

  constructor(dataDirectory: string) {
    this.#dataDirectory = dataDirectory;
    this.#path = join(dataDirectory, "custom-agents.json");
  }

  async list(): Promise<readonly CustomAgentRegistration[]> {
    let raw: string;
    try {
      raw = await readFile(this.#path, "utf8");
    } catch (error) {
      if (isNodeError(error) && error.code === "ENOENT") return [];
      throw error;
    }
    if (Buffer.byteLength(raw, "utf8") > maxRegistryBytes) {
      throw new Error("Custom agent registry exceeds the 1 MiB safety limit.");
    }
    let value: unknown;
    try {
      value = JSON.parse(raw);
    } catch {
      throw new Error("Custom agent registry is not valid JSON.");
    }
    if (
      typeof value !== "object" ||
      value === null ||
      !("version" in value) ||
      value.version !== registryVersion ||
      !("agents" in value) ||
      !Array.isArray(value.agents) ||
      value.agents.length > maxRegistrations
    ) {
      throw new Error("Custom agent registry is invalid.");
    }
    const agents = value.agents.map(validatedRegistration);
    const ids = new Set(agents.map((agent) => agent.id));
    if (ids.size !== agents.length) {
      throw new Error("Custom agent registry contains duplicate IDs.");
    }
    validateClaimConflicts(agents);
    return agents.sort((left, right) => left.id.localeCompare(right.id));
  }

  async add(
    value: CustomAgentRegistration,
  ): Promise<CustomAgentRegistration> {
    const registration = validatedRegistration(value);
    const existing = await this.list();
    if (existing.some((agent) => agent.id === registration.id)) {
      throw new Error(
        `Custom agent ${registration.id} already exists; remove it before replacing its monitoring definition.`,
      );
    }
    if (existing.length >= maxRegistrations) {
      throw new Error(`Custom agent registry is limited to ${maxRegistrations} agents.`);
    }
    const agents = [...existing, registration];
    validateClaimConflicts(agents);
    await this.#save(agents);
    return registration;
  }

  async remove(id: string): Promise<CustomAgentRegistration | undefined> {
    const normalizedID = validatedID(id);
    const existing = await this.list();
    const removed = existing.find((agent) => agent.id === normalizedID);
    if (removed === undefined) return undefined;
    await this.#save(existing.filter((agent) => agent.id !== normalizedID));
    return removed;
  }

  async #save(agents: readonly CustomAgentRegistration[]): Promise<void> {
    await mkdir(this.#dataDirectory, { recursive: true, mode: 0o700 });
    await chmod(this.#dataDirectory, 0o700);
    const temporary = `${this.#path}.${process.pid}.${randomUUID()}.tmp`;
    const registry: StoredRegistry = {
      version: registryVersion,
      agents: [...agents].sort((left, right) => left.id.localeCompare(right.id)),
    };
    try {
      await writeFile(temporary, `${JSON.stringify(registry, null, 2)}\n`, {
        encoding: "utf8",
        flag: "wx",
        mode: 0o600,
      });
      await rename(temporary, this.#path);
      await chmod(this.#path, 0o600);
    } catch (error) {
      try {
        await unlink(temporary);
      } catch {
        // The temporary file may not have been created.
      }
      throw error;
    }
  }
}

export function customAgentRegistration(
  value: Readonly<{
    id: string;
    displayName: string;
    executableNames?: readonly string[];
    processNames?: readonly string[];
    configurationPaths?: readonly string[];
    activityDirectories?: readonly string[];
    capabilities?: readonly string[];
  }>,
): CustomAgentRegistration {
  return validatedRegistration({
    id: value.id,
    displayName: value.displayName,
    executableNames: value.executableNames ?? [],
    processNames: value.processNames ?? [],
    configurationPaths: value.configurationPaths ?? [],
    activityDirectories: value.activityDirectories ?? [],
    capabilities: value.capabilities ?? ["activity"],
  });
}

function validatedRegistration(value: unknown): CustomAgentRegistration {
  if (typeof value !== "object" || value === null) {
    throw new Error("Custom agent registration is invalid.");
  }
  const object = value as Record<string, unknown>;
  const id = validatedID(object["id"]);
  const displayName = validatedDisplayName(object["displayName"]);
  const executableNames = validatedList(
    object["executableNames"],
    "executable name",
    namePattern,
  );
  const processNames = validatedList(
    object["processNames"],
    "process name",
    namePattern,
  );
  const configurationPaths = validatedPaths(
    object["configurationPaths"],
    "configuration path",
  );
  const activityDirectories = validatedPaths(
    object["activityDirectories"],
    "activity directory",
    true,
  );
  const capabilities = validatedList(
    object["capabilities"],
    "capability",
    capabilityPattern,
  );
  if (capabilities.some(isReservedCapability)) {
    throw new Error(
      "Custom agent capabilities cannot claim Phigon-managed identity or evidence properties.",
    );
  }
  if (
    executableNames.length === 0 &&
    processNames.length === 0 &&
    configurationPaths.length === 0 &&
    activityDirectories.length === 0
  ) {
    throw new Error(
      "Custom agent requires at least one executable, process, configuration path, or activity directory.",
    );
  }
  return Object.freeze({
    id,
    displayName,
    executableNames,
    processNames,
    configurationPaths,
    activityDirectories,
    capabilities: capabilities.length === 0 ? ["activity"] : capabilities,
  });
}

function isReservedCapability(value: string): boolean {
  return reservedCapabilities.has(value) ||
    reservedCapabilityPrefixes.some((prefix) => value.startsWith(prefix));
}

function validatedID(value: unknown): string {
  if (typeof value !== "string" || !idPattern.test(value)) {
    throw new Error(
      "Custom agent ID must use 1-63 lowercase letters, digits, or hyphens.",
    );
  }
  return value;
}

function validatedDisplayName(value: unknown): string {
  if (
    typeof value !== "string" ||
    value !== value.trim() ||
    value.length === 0 ||
    Buffer.byteLength(value, "utf8") > 128 ||
    /[\u0000-\u001f\u007f]/u.test(value)
  ) {
    throw new Error("Custom agent display name must be 1-128 printable characters.");
  }
  return value;
}

function validatedList(
  value: unknown,
  label: string,
  pattern: RegExp,
): readonly string[] {
  if (!Array.isArray(value) || value.length > 32) {
    throw new Error(`Custom agent ${label} list is invalid.`);
  }
  const result = value.map((entry) => {
    if (typeof entry !== "string" || !pattern.test(entry)) {
      throw new Error(`Custom agent ${label} is invalid.`);
    }
    return entry;
  });
  return [...new Set(result)].sort();
}

function validatedPaths(
  value: unknown,
  label: string,
  scopedDirectory = false,
): readonly string[] {
  if (!Array.isArray(value) || value.length > 32) {
    throw new Error(`Custom agent ${label} list is invalid.`);
  }
  const result = value.map((entry) => {
    if (
      typeof entry !== "string" ||
      entry !== entry.trim() ||
      entry.length === 0 ||
      Buffer.byteLength(entry, "utf8") > 1024 ||
      /[\u0000-\u001f\u007f]/u.test(entry)
    ) {
      throw new Error(`Custom agent ${label} is invalid.`);
    }
    const normalized = normalizedRegistrationPath(entry);
    if (
      scopedDirectory &&
      (dirname(normalized) === normalized ||
        normalized === normalizedRegistrationPath("~"))
    ) {
      throw new Error(
        "Custom agent activity directory must be scoped below the filesystem root and home directory.",
      );
    }
    return entry;
  });
  return [...new Set(result)].sort();
}

function validateClaimConflicts(
  agents: readonly CustomAgentRegistration[],
): void {
  validateNamedClaims(agents, "executableNames", "executable name");
  validateNamedClaims(agents, "processNames", "process name");
  validateExactPathClaims(
    agents,
    "configurationPaths",
    "configuration path",
  );
  validateActivityDirectoryClaims(agents);
}

function validateNamedClaims(
  agents: readonly CustomAgentRegistration[],
  property: "executableNames" | "processNames",
  label: string,
): void {
  const owners = new Map<string, string>();
  for (const agent of agents) {
    for (const claim of agent[property]) {
      const normalized = claim.toLowerCase().replace(/\.exe$/u, "");
      const owner = owners.get(normalized);
      if (owner !== undefined) {
        throw conflictingClaimError(label, claim, owner, agent.id);
      }
      owners.set(normalized, agent.id);
    }
  }
}

function validateExactPathClaims(
  agents: readonly CustomAgentRegistration[],
  property: "configurationPaths",
  label: string,
): void {
  const owners = new Map<string, string>();
  for (const agent of agents) {
    for (const path of agent[property]) {
      const normalized = normalizedRegistrationPath(path);
      const owner = owners.get(normalized);
      if (owner !== undefined) {
        throw conflictingClaimError(label, path, owner, agent.id);
      }
      owners.set(normalized, agent.id);
    }
  }
}

function validateActivityDirectoryClaims(
  agents: readonly CustomAgentRegistration[],
): void {
  const claims: Array<Readonly<{
    id: string;
    path: string;
    normalized: string;
  }>> = [];
  for (const agent of agents) {
    for (const path of agent.activityDirectories) {
      const normalized = normalizedRegistrationPath(path);
      const overlap = claims.find((claim) =>
        pathsOverlap(claim.normalized, normalized)
      );
      if (overlap !== undefined) {
        throw conflictingClaimError(
          "activity directory",
          path,
          overlap.id,
          agent.id,
        );
      }
      claims.push({ id: agent.id, path, normalized });
    }
  }
}

function normalizedRegistrationPath(value: string): string {
  let expanded = value;
  if (value === "~") expanded = homedir();
  else if (value.startsWith("~/") || value.startsWith("~\\")) {
    expanded = join(homedir(), value.slice(2));
  } else if (value.startsWith("~")) {
    throw new Error(
      "Custom agent paths must be absolute or begin with ~/ for the current user's home directory.",
    );
  }
  if (!isAbsolute(expanded)) {
    throw new Error(
      "Custom agent paths must be absolute or begin with ~/ for the current user's home directory.",
    );
  }
  const normalized = resolve(expanded).normalize("NFC");
  return process.platform === "win32" || process.platform === "darwin"
    ? normalized.toLowerCase()
    : normalized;
}

function pathsOverlap(left: string, right: string): boolean {
  return isWithin(left, right) || isWithin(right, left);
}

function isWithin(root: string, candidate: string): boolean {
  const path = relative(root, candidate);
  return path === "" || (!path.startsWith(`..${sep}`) && path !== "..");
}

function conflictingClaimError(
  label: string,
  value: string,
  leftID: string,
  rightID: string,
): Error {
  const ownership = leftID === rightID
    ? `within ${leftID}`
    : `between ${leftID} and ${rightID}`;
  return new Error(
    `Custom agent ${label} ${JSON.stringify(value)} is ambiguous ${ownership}; monitoring definitions must use independent evidence.`,
  );
}

function isNodeError(error: unknown): error is NodeJS.ErrnoException {
  return error instanceof Error && "code" in error;
}
