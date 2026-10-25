import { create } from "@bufbuild/protobuf";
import {
  timestampDate,
  timestampFromDate,
} from "@bufbuild/protobuf/wkt";
import { AgentState } from "../generated/phigon/v1/common_pb.js";
import {
  AgentIdentitySchema,
  AgentInventorySchema,
  type AgentIdentity,
  type AgentInventory,
} from "../generated/phigon/v1/identity_pb.js";
import { claudeAdapter } from "./adapters/claude.js";
import { codexAdapter } from "./adapters/codex.js";
import { customAgentAdapter } from "./adapters/custom.js";
import { genericAdapter } from "./adapters/generic.js";
import { hermesAdapter } from "./adapters/hermes.js";
import { openClawAdapter } from "./adapters/openclaw.js";
import type { HostEvidenceProvider } from "./evidence.js";
import { sortAgentIdentities } from "./known-agent.js";
import { SystemEvidenceProvider } from "./system-evidence.js";
import type {
  AgentDiscoveryAdapter,
  DiscoverySnapshot,
} from "./types.js";
import type { CustomAgentRegistry } from "../custom-agent-registry.js";

const defaultAdapters: readonly AgentDiscoveryAdapter[] = [
  claudeAdapter,
  codexAdapter,
  hermesAdapter,
  openClawAdapter,
  genericAdapter,
];

export type DiscoveryEngineOptions = Readonly<{
  adapters?: readonly AgentDiscoveryAdapter[];
  customAgentRegistry?: CustomAgentRegistry;
  evidenceFactory?: () => HostEvidenceProvider;
  clock?: () => Date;
}>;

export class DiscoveryEngine {
  readonly #adapters: readonly AgentDiscoveryAdapter[];
  readonly #evidenceFactory: () => HostEvidenceProvider;
  readonly #clock: () => Date;
  #retainedMachineID: string | undefined;
  readonly #retainedRuntimes = new Map<string, AgentIdentity>();

  constructor(options: DiscoveryEngineOptions = {}) {
    this.#adapters = options.adapters ?? [
      ...defaultAdapters,
      ...(options.customAgentRegistry === undefined
        ? []
        : [customAgentAdapter(options.customAgentRegistry)]),
    ];
    this.#evidenceFactory =
      options.evidenceFactory ?? (() => new SystemEvidenceProvider());
    this.#clock = options.clock ?? (() => new Date());
  }

  async discover(machineId = ""): Promise<DiscoverySnapshot> {
    const observedAt = this.#clock();
    const evidence = this.#evidenceFactory();
    const results = await Promise.all(
      this.#adapters.map((adapter) =>
        adapter.discover(evidence, observedAt),
      ),
    );
    const discoveredAgents = results.flatMap((result) => result.agents);
    const conflictingProcessClaims = processClaimConflicts(discoveredAgents);
    const adapterHealth = [
      ...results.map((result) => result.health),
      ...(conflictingProcessClaims.size === 0
        ? []
        : [{
            adapterId: "attribution",
            status: "error" as const,
            notices: [
              `${conflictingProcessClaims.size} process-lifetime ` +
              "claim(s) matched multiple agent identities; affected " +
              "runtimes were not attributed.",
            ],
          }]),
    ];
    const notices = adapterHealth
      .flatMap((health) => [
        `adapter=${health.adapterId};status=${health.status}`,
        ...health.notices,
      ])
      .slice(0, 32)
      .map((notice) => notice.slice(0, 256));
    const partial = adapterHealth.some(
      (health) =>
        health.status === "permission_denied" ||
        health.status === "error",
    );
    const currentAgents = sortAgentIdentities(
      discoveredAgents.filter((agent) =>
        !agent.capabilities.some((capability) =>
          conflictingProcessClaims.has(capability)
        )
      ),
    );
    const agents = this.#retainRuntimeHistory(
      machineId,
      currentAgents,
      !partial,
    );
    const inventory: AgentInventory = create(AgentInventorySchema, {
      machineId,
      observedAt: timestampFromDate(observedAt),
      agents,
      partial,
      notices,
    });
    return Object.freeze({ inventory, adapterHealth });
  }

  #retainRuntimeHistory(
    machineID: string,
    currentAgents: readonly AgentIdentity[],
    coverageComplete: boolean,
  ): AgentIdentity[] {
    if (
      this.#retainedMachineID !== undefined &&
      this.#retainedMachineID !== machineID
    ) {
      this.#retainedRuntimes.clear();
    }
    this.#retainedMachineID = machineID;

    const currentByID = new Map(
      currentAgents.map((agent) => [agent.agentId, agent]),
    );
    for (const agent of currentAgents) {
      if (isRuntimeIdentity(agent)) {
        this.#retainedRuntimes.set(agent.agentId, agent);
      }
    }
    for (const [agentID, prior] of this.#retainedRuntimes) {
      if (currentByID.has(agentID)) continue;
      this.#retainedRuntimes.set(
        agentID,
        create(AgentIdentitySchema, {
          ...prior,
          state: coverageComplete
            ? AgentState.STOPPED
            : AgentState.UNKNOWN,
        }),
      );
    }

    const runtimes = [...this.#retainedRuntimes.values()].sort(
      compareRuntimeRetention,
    );
    const runtimeProducts = new Set(
      runtimes.flatMap((agent) => agentProductCapabilities(agent)),
    );
    const products = currentAgents.filter(
      (agent) =>
        !isRuntimeIdentity(agent) &&
        !agentProductCapabilities(agent).some((capability) =>
          runtimeProducts.has(capability)
        ),
    );
    const selected = [...runtimes, ...products].slice(0, 256);
    const selectedIDs = new Set(selected.map((agent) => agent.agentId));
    for (const agentID of this.#retainedRuntimes.keys()) {
      if (!selectedIDs.has(agentID)) this.#retainedRuntimes.delete(agentID);
    }
    return sortAgentIdentities(selected);
  }
}

function processClaimConflicts(
  agents: readonly AgentIdentity[],
): ReadonlySet<string> {
  const identitiesByClaim = new Map<string, Set<string>>();
  for (const agent of agents) {
    for (const capability of agent.capabilities) {
      if (!capability.startsWith("process-key-sha256:")) continue;
      const identities = identitiesByClaim.get(capability) ?? new Set();
      identities.add(agent.agentId);
      identitiesByClaim.set(capability, identities);
    }
  }
  return new Set(
    [...identitiesByClaim.entries()]
      .filter(([, identities]) => identities.size > 1)
      .map(([claim]) => claim),
  );
}

function isRuntimeIdentity(agent: AgentIdentity): boolean {
  return agent.capabilities.includes("process-instance");
}

function agentProductCapabilities(agent: AgentIdentity): string[] {
  return agent.capabilities.filter((capability) =>
    capability.startsWith("agent-product:")
  );
}

function compareRuntimeRetention(
  left: AgentIdentity,
  right: AgentIdentity,
): number {
  const leftRunning = left.state === AgentState.RUNNING ? 1 : 0;
  const rightRunning = right.state === AgentState.RUNNING ? 1 : 0;
  if (leftRunning !== rightRunning) return rightRunning - leftRunning;
  const leftObserved = left.lastObservedAt === undefined
    ? 0
    : timestampDate(left.lastObservedAt).getTime();
  const rightObserved = right.lastObservedAt === undefined
    ? 0
    : timestampDate(right.lastObservedAt).getTime();
  return rightObserved - leftObserved || left.agentId.localeCompare(right.agentId);
}

export async function runDiscoveryLoop(
  engine: DiscoveryEngine,
  machineId: string,
  intervalMs: number,
  signal: AbortSignal,
  publish: (inventory: AgentInventory) => void | Promise<void>,
): Promise<void> {
  while (!signal.aborted) {
    const snapshot = await engine.discover(machineId);
    await publish(snapshot.inventory);
    await abortableDelay(intervalMs, signal);
  }
}

async function abortableDelay(
  milliseconds: number,
  signal: AbortSignal,
): Promise<void> {
  if (signal.aborted) return;
  await new Promise<void>((resolve) => {
    const timeout = setTimeout(resolve, milliseconds);
    signal.addEventListener(
      "abort",
      () => {
        clearTimeout(timeout);
        resolve();
      },
      { once: true },
    );
  });
}
