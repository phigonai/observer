import { createHash } from "node:crypto";
import { create } from "@bufbuild/protobuf";
import { timestampFromDate } from "@bufbuild/protobuf/wkt";
import {
  AgentState,
  type AgentKind,
} from "../generated/phigon/v1/common_pb.js";
import {
  AgentIdentitySchema,
  type AgentIdentity,
} from "../generated/phigon/v1/identity_pb.js";
import type {
  HostEvidenceProvider,
  ProbeResult,
  ProcessEvidence,
} from "./evidence.js";
import {
  normalizedProcessKey,
  processKeyCapability,
  stableRuntimeAgentID,
} from "./process-identity.js";
import type {
  AdapterHealth,
  AdapterResult,
} from "./types.js";

export type KnownAgentSpec = Readonly<{
  id: string;
  kind: AgentKind;
  displayName: string;
  executableNames: readonly string[];
  processNames: readonly string[];
  configurationPaths: readonly string[];
  capabilities: readonly string[];
  /**
   * `agent` (default): each matching process is its own agent runtime.
   * `application`: a desktop application whose many helper processes share
   * one executable name. It is detected through its installation, and its
   * processes only report that it is running.
   */
  processModel?: "agent" | "application";
}>;

export async function discoverKnownAgent(
  spec: KnownAgentSpec,
  evidence: HostEvidenceProvider,
  observedAt: Date,
): Promise<AdapterResult> {
  // Finish the passive process snapshot before launching a bounded
  // `--version` probe so discovery never observes its own child process.
  const processProbe = await evidence.listProcesses();
  const [executableProbe, configurationProbe] = await Promise.all([
    evidence.inspectExecutable(spec.executableNames),
    evidence.inspectConfiguration(spec.configurationPaths),
  ]);
  const notices: string[] = [];
  collectProbeNotice(processProbe, notices);
  collectProbeNotice(executableProbe, notices);
  collectProbeNotice(configurationProbe, notices);

  const processMatches =
    processProbe.status === "ok"
      ? processProbe.value
          .filter((process) =>
            spec.processNames.includes(process.executableName),
          )
          .sort((left, right) => left.processId - right.processId)
      : [];
  const processKeyCounts = new Map<string, number>();
  for (const process of processMatches) {
    const processKey = normalizedProcessKey(process.processKey);
    if (processKey !== undefined) {
      processKeyCounts.set(
        processKey,
        (processKeyCounts.get(processKey) ?? 0) + 1,
      );
    }
  }
  const application = spec.processModel === "application";
  const runtimeMatches = application ? [] : processMatches.filter((process) => {
    const processKey = normalizedProcessKey(process.processKey);
    return (
      processKey !== undefined &&
      processKeyCounts.get(processKey) === 1 &&
      Number.isSafeInteger(process.processId) &&
      process.processId > 0 &&
      process.startedAt instanceof Date &&
      !Number.isNaN(process.startedAt.getTime()) &&
      process.startedAt.getTime() <= observedAt.getTime() + 5 * 60_000
    );
  });
  const processEvidenceIncomplete =
    !application && runtimeMatches.length !== processMatches.length;
  const executable =
    executableProbe.status === "ok" ? executableProbe.value : null;
  const configurations =
    configurationProbe.status === "ok"
      ? configurationProbe.value
      : [];
  const detected =
    (!application && processMatches.length > 0) ||
    executable !== null ||
    configurations.length > 0;

  if (!detected) {
    return {
      agents: [],
      health: health(spec.id, [
        processProbe,
        executableProbe,
        configurationProbe,
      ], notices),
    };
  }

  if (executable !== null && executable.version.length === 0) {
    notices.push(`${spec.displayName} version is unknown.`);
  }
  if (processEvidenceIncomplete) {
    notices.push(
      `${spec.displayName} process-lifetime evidence was incomplete; ` +
      "affected runtimes were not attributed.",
    );
  }
  const processMatch = processMatches[0];
  const state = agentState(
    runtimeMatches[0],
    executable !== null,
    configurations.length > 0,
    [processProbe, executableProbe, configurationProbe],
  );
  const executablePathDigest =
    executable?.executablePathDigest ??
    configurations[0]?.identifierDigest ??
    processMatch?.executablePathDigest ??
    "";
  const productCapability = `agent-product:${spec.id}`;
  const processIdentities = runtimeMatches.flatMap((process) => {
    const agentID = stableRuntimeAgentID(spec.id, process.processKey);
    const keyCapability = processKeyCapability(process.processKey);
    if (agentID === undefined || keyCapability === undefined) return [];
    return [create(AgentIdentitySchema, {
      agentId: agentID,
      kind: spec.kind,
      displayName: `${spec.displayName} · PID ${process.processId}`,
      version: executable?.version ?? "",
      runtime: "",
      state: AgentState.RUNNING,
      processId: BigInt(process.processId),
      startedAt: timestampFromDate(process.startedAt),
      lastObservedAt: timestampFromDate(observedAt),
      capabilities: [
        ...new Set([
          ...spec.capabilities,
          productCapability,
          "process-instance",
          keyCapability,
        ]),
      ].sort(),
      executablePathDigest:
        process.executablePathDigest || executablePathDigest,
    })];
  });
  const productIdentity = processIdentities.length === 0
    ? [create(AgentIdentitySchema, {
        agentId: stableAgentID(spec.id, executablePathDigest),
        kind: spec.kind,
        displayName: spec.displayName,
        version: executable?.version ?? "",
        runtime: "",
        state: processMatches.length === 0
          ? state
          : application
            ? AgentState.RUNNING
            : AgentState.UNKNOWN,
        processId: 0n,
        lastObservedAt: timestampFromDate(observedAt),
        capabilities: [...spec.capabilities, productCapability].sort(),
        executablePathDigest,
      })]
    : [];
  const measuredHealth = health(
    spec.id,
    [processProbe, executableProbe, configurationProbe],
    notices,
  );
  const adapterHealth = processEvidenceIncomplete
    ? { ...measuredHealth, status: "error" as const }
    : measuredHealth;

  return {
    agents: [...productIdentity, ...processIdentities],
    health: adapterHealth,
  };
}

export function combineAdapterResults(
  adapterId: string,
  results: readonly AdapterResult[],
): AdapterResult {
  const notices = results.flatMap((result) => result.health.notices);
  const statuses = results.map((result) => result.health.status);
  let status: AdapterHealth["status"] = "healthy";
  if (statuses.includes("error")) status = "error";
  else if (statuses.includes("permission_denied")) {
    status = "permission_denied";
  } else if (statuses.includes("degraded")) {
    status = "degraded";
  }
  return {
    agents: results.flatMap((result) => result.agents),
    health: {
      adapterId,
      status,
      notices: notices.slice(0, 32),
    },
  };
}

function agentState(
  process: ProcessEvidence | undefined,
  hasExecutable: boolean,
  hasConfiguration: boolean,
  probes: readonly ProbeResult<unknown>[],
): AgentState {
  if (process !== undefined) return AgentState.RUNNING;
  if (probes.some((probe) => probe.status === "permission_denied")) {
    return AgentState.PERMISSION_DENIED;
  }
  if (probes.some((probe) => probe.status === "unknown")) {
    return AgentState.UNKNOWN;
  }
  if (hasExecutable) return AgentState.STOPPED;
  if (hasConfiguration) return AgentState.INSTALLED;
  return AgentState.UNKNOWN;
}

function health(
  adapterId: string,
  probes: readonly ProbeResult<unknown>[],
  notices: readonly string[],
): AdapterHealth {
  let status: AdapterHealth["status"] = "healthy";
  if (probes.some((probe) => probe.status === "unknown")) {
    status = "error";
  } else if (
    probes.some((probe) => probe.status === "permission_denied")
  ) {
    status = "permission_denied";
  } else if (notices.length > 0) {
    status = "degraded";
  }
  return {
    adapterId,
    status,
    notices: notices.slice(0, 32),
  };
}

function collectProbeNotice(
  probe: ProbeResult<unknown>,
  notices: string[],
): void {
  if (probe.status !== "ok") notices.push(probe.notice.slice(0, 256));
}

function stableAgentID(adapterID: string, evidenceDigest: string): string {
  const digest = createHash("sha256")
    .update("phigon-agent-v1")
    .update("\0")
    .update(adapterID)
    .update("\0")
    .update(evidenceDigest)
    .digest("hex")
    .slice(0, 32);
  return `agt_${digest}`;
}

export function sortAgentIdentities(
  agents: readonly AgentIdentity[],
): AgentIdentity[] {
  return [...agents].sort((left, right) =>
    left.agentId.localeCompare(right.agentId),
  );
}
