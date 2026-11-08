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
  ExecutableEvidence,
  HostEvidenceProvider,
  ProbeResult,
  ProcessEvidence,
} from "./evidence.js";
import {
  normalizedProcessKey,
  processKeyCapability,
  stableRuntimeAgentID,
} from "./process-identity.js";
import { mayBeInterpreterName } from "./script-package.js";
import type {
  AdapterHealth,
  AdapterResult,
  AgentDetection,
  DetectionEvidence,
} from "./types.js";

export type KnownAgentSpec = Readonly<{
  id: string;
  kind: AgentKind;
  displayName: string;
  executableNames: readonly string[];
  processNames: readonly string[];
  /**
   * npm packages of the agent. A CLI installed with npm runs as `node` (or
   * bun or deno); an interpreter process running a script from one of these
   * packages is this agent's process too.
   */
  scriptPackages?: readonly string[];
  configurationPaths: readonly string[];
  capabilities: readonly string[];
  /**
   * `agent` (default): each matching process is its own agent runtime.
   * `application`: a desktop application whose many helper processes share
   * one executable name. It is detected through its installation, and its
   * processes only report that it is running.
   */
  processModel?: "agent" | "application";
  /**
   * Process and command names that other common programs also use, such as
   * kdb+'s `q`, the goose database migration tool or the AWS Copilot CLI.
   * Where the agent's own configuration exists, such a process or PATH
   * command is this agent, as any other. Elsewhere it identifies nothing:
   * the agent is reported only when a name of its own or its npm package
   * identifies it, and a process found by such a name alone is never
   * reported as a runtime Phigon can stop.
   */
  sharedNames?: readonly string[];
  /**
   * How the agent's own `--version` begins, so that a command with a shared
   * name that prints it gives the agent's version.
   */
  versionBanner?: RegExp;
}>;

// Bounds what `discover --explain` lists for one agent.
const maxExplainedProcesses = 8;

export async function discoverKnownAgent(
  spec: KnownAgentSpec,
  evidence: HostEvidenceProvider,
  observedAt: Date,
): Promise<AdapterResult> {
  // Finish the passive process snapshot before launching a bounded
  // `--version` probe so discovery never observes its own child process.
  const processProbe = await evidence.listProcesses();
  const [executableProbe, configurationProbes] = await Promise.all([
    evidence.inspectExecutable(spec.executableNames),
    // One probe for each path, so `discover --explain` can name what it found.
    Promise.all(spec.configurationPaths.map((path) => evidence.inspectConfiguration([path]))),
  ]);
  const configurationProbe = combinedProbe(configurationProbes);
  const notices: string[] = [];
  collectProbeNotice(processProbe, notices);
  collectProbeNotice(executableProbe, notices);
  collectProbeNotice(configurationProbe, notices);

  const configurations =
    configurationProbe.status === "ok"
      ? configurationProbe.value
      : [];
  // Where the agent's own configuration exists, a shared name is this agent
  // (a native install, such as WinGet's or Homebrew's copilot, has no npm
  // package to show); elsewhere it identifies nothing and is set aside.
  const shared = configurations.length > 0 ? new Set<string>() : new Set(spec.sharedNames ?? []);
  const namedProcesses =
    processProbe.status === "ok"
      ? processProbe.value
          .filter((process) => isAgentProcess(spec, process))
          .sort((left, right) => left.processId - right.processId)
      : [];
  const processMatches = namedProcesses.filter((process) => !sharedNameOnly(spec, shared, process));
  const unconfirmedProcesses = namedProcesses.filter((process) => sharedNameOnly(spec, shared, process));
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
  const executableFound =
    executableProbe.status === "ok" ? executableProbe.value : null;
  const executableShared =
    executableFound !== null && shared.has(executableFound.executableName);
  const foundConfigurationPaths = spec.configurationPaths.filter((_, index) => {
    const probe = configurationProbes[index];
    return probe?.status === "ok" && probe.value.length > 0;
  });
  const detected =
    (!application && processMatches.length > 0) ||
    (executableFound !== null && !executableShared) ||
    configurations.length > 0;
  const setAside: DetectionEvidence[] = [
    ...unconfirmedProcesses.slice(0, maxExplainedProcesses).map((process) => processEvidence(process, false)),
    ...(executableShared && executableFound !== null ? [executableEvidence(executableFound, false)] : []),
  ];

  if (!detected) {
    return {
      agents: [],
      health: health(spec.id, [
        processProbe,
        executableProbe,
        configurationProbe,
      ], notices),
      detections: setAside.length === 0
        ? []
        : [{
            adapterId: spec.id,
            displayName: spec.displayName,
            reported: false,
            confidence: "low",
            stoppable: false,
            evidence: setAside,
            notes: [
              `Not reported: other programs use the same name, and nothing on this computer identifies one as ${spec.displayName}` +
                ` (its configuration${spec.scriptPackages === undefined ? "" : " or npm package"} was not found).`,
            ],
          }],
    };
  }

  const executable = executableFound;
  // A command with a name other programs use may be one of them even where
  // the agent is installed. Its version is the agent's only when the
  // command shows it is the agent: it runs the agent's npm package, or its
  // `--version` names the agent.
  const sharedCommand = executable !== null && (spec.sharedNames ?? []).includes(executable.executableName);
  const ownCommand = executable !== null && (
    !sharedCommand ||
    (executable.packageName !== undefined && (spec.scriptPackages ?? []).includes(executable.packageName)) ||
    (executable.versionBanner !== undefined && spec.versionBanner?.test(executable.versionBanner) === true)
  );
  const version = executable !== null && ownCommand ? executable.version : "";
  if (executable !== null && ownCommand && executable.version.length === 0) {
    notices.push(`${spec.displayName} version is unknown.`);
  }
  if (processEvidenceIncomplete) {
    notices.push(
      `${spec.displayName} process-lifetime evidence was incomplete; ` +
      "affected runtimes were not attributed.",
    );
  }
  if (unconfirmedProcesses.length > 0) {
    notices.push(
      `${unconfirmedProcesses.length} running program(s) named like ${spec.displayName} ` +
      "were not attributed to it: other programs use the same name.",
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
      version,
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
        version,
        runtime: "",
        // A program that may be this agent, or another with its name, is
        // neither running nor stopped as far as discovery can tell.
        state: processMatches.length === 0
          ? unconfirmedProcesses.length === 0 ? state : AgentState.UNKNOWN
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

  // A command found by a shared name is listed with the evidence set aside.
  const installation: DetectionEvidence[] = [
    ...(executable === null || executableShared ? [] : [executableEvidence(executable, true)]),
    ...foundConfigurationPaths.map((path): DetectionEvidence => ({
      kind: "configuration",
      detail: `${path} exists`,
      identifying: true,
    })),
  ];
  const versionNote = !ownCommand && executable !== null
    ? [`Other programs are also called "${executable.executableName}", so the version of that command is not given as ${spec.displayName}'s.`]
    : [];
  const runtimeNotes = [
    ...(unconfirmedProcesses.length === 0
      ? []
      : [`${unconfirmedProcesses.length} other running program(s) with a name other programs also use were set aside.`]),
    ...versionNote,
  ];
  const detections: AgentDetection[] = [
    ...productIdentity.map((identity): AgentDetection => ({
      agentId: identity.agentId,
      adapterId: spec.id,
      displayName: spec.displayName,
      reported: true,
      confidence: setAside.length > 0 ? "low" : application && processMatches.length > 0 ? "high" : "medium",
      stoppable: false,
      evidence: [
        ...processMatches.slice(0, maxExplainedProcesses).map((process) => processEvidence(process, true)),
        ...installation,
        ...setAside,
      ],
      notes: [
        ...(unconfirmedProcesses.length === 0
          ? []
          : [
              `Running program(s) with a name other programs also use were not attributed to ${spec.displayName}, ` +
                "so Phigon cannot stop them.",
            ]),
        ...versionNote,
        ...(processEvidenceIncomplete
          ? ["Some of its processes had no complete start-time evidence and were not attributed."]
          : []),
        ...(application
          ? ["A desktop application: its processes show that it runs, and are not stopped one by one."]
          : processMatches.length === 0 ? ["Installed; no process of its own is running."] : []),
      ],
    })),
    ...runtimeMatches.flatMap((process): AgentDetection[] => {
      const agentId = stableRuntimeAgentID(spec.id, process.processKey);
      return agentId === undefined || processKeyCapability(process.processKey) === undefined
        ? []
        : [{
            agentId,
            adapterId: spec.id,
            displayName: `${spec.displayName} · PID ${process.processId}`,
            reported: true,
            confidence: "high",
            stoppable: true,
            evidence: [processEvidence(process, true), ...installation],
            notes: runtimeNotes,
          }];
    }),
  ];

  return {
    agents: [...productIdentity, ...processIdentities],
    health: adapterHealth,
    detections,
  };
}

/** Found only by a name other programs use, not by the agent's npm package. */
function sharedNameOnly(spec: KnownAgentSpec, shared: ReadonlySet<string>, process: ProcessEvidence): boolean {
  return shared.has(process.executableName) && !runsScriptPackage(spec, process);
}

function processEvidence(process: ProcessEvidence, identifying: boolean): DetectionEvidence {
  return process.scriptPackage !== undefined && mayBeInterpreterName(process.executableName)
    ? {
        kind: "package",
        detail: `${process.executableName} process running the npm package ${process.scriptPackage} (PID ${process.processId})`,
        identifying,
      }
    : {
        kind: "process",
        detail: `running process "${process.executableName}" (PID ${process.processId})`,
        identifying,
      };
}

function executableEvidence(executable: ExecutableEvidence, identifying: boolean): DetectionEvidence {
  return {
    kind: "executable",
    detail: `"${executable.executableName}" command on PATH, version ${executable.version || "unknown"}`,
    identifying,
  };
}

/** One result for several probes: the first failure, or everything found. */
function combinedProbe<T>(probes: readonly ProbeResult<readonly T[]>[]): ProbeResult<readonly T[]> {
  const failed = probes.find((probe) => probe.status !== "ok");
  if (failed !== undefined) return failed;
  return {
    status: "ok",
    value: probes.flatMap((probe) => probe.status === "ok" ? probe.value : []),
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
    detections: results.flatMap((result) => result.detections ?? []),
  };
}

function isAgentProcess(
  spec: KnownAgentSpec,
  process: ProcessEvidence,
): boolean {
  return spec.processNames.includes(process.executableName) || runsScriptPackage(spec, process);
}

function runsScriptPackage(
  spec: KnownAgentSpec,
  process: ProcessEvidence,
): boolean {
  // A package counts only for an interpreter process (node, bun, deno),
  // including one Linux lists by its main thread's name.
  return (
    process.scriptPackage !== undefined &&
    mayBeInterpreterName(process.executableName) &&
    (spec.scriptPackages?.includes(process.scriptPackage) ?? false)
  );
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
