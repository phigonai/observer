import type {
  AgentIdentity,
  AgentInventory,
} from "../generated/phigon/v1/identity_pb.js";
import type { HostEvidenceProvider } from "./evidence.js";

export type AdapterHealthStatus =
  | "healthy"
  | "degraded"
  | "permission_denied"
  | "error";

export type AdapterHealth = Readonly<{
  adapterId: string;
  status: AdapterHealthStatus;
  notices: readonly string[];
}>;

/**
 * How sure discovery is that the evidence is this agent. high: one of its
 * processes, by its own name or npm package. medium: its installation (its
 * own command on PATH, or its own configuration). low: it is installed, but
 * a running program with a name other programs also use was set aside.
 */
export type DetectionConfidence = "high" | "medium" | "low";

export type DetectionEvidence = Readonly<{
  kind: "process" | "package" | "executable" | "configuration";
  /** Plain description for the person at this computer; never sent. */
  detail: string;
  /** False for a name other programs also use, which identifies nothing alone. */
  identifying: boolean;
}>;

/**
 * Why discovery reported an agent, or set evidence aside. Kept on this
 * computer for `discover --explain`; the inventory does not carry it.
 */
export type AgentDetection = Readonly<{
  /** The inventory identity, when the agent was reported. */
  agentId?: string;
  adapterId: string;
  displayName: string;
  reported: boolean;
  confidence: DetectionConfidence;
  /** Whether an administrator could stop it from Phigon. */
  stoppable: boolean;
  evidence: readonly DetectionEvidence[];
  notes: readonly string[];
}>;

export type AdapterResult = Readonly<{
  agents: readonly AgentIdentity[];
  health: AdapterHealth;
  detections?: readonly AgentDetection[];
}>;

export interface AgentDiscoveryAdapter {
  readonly id: string;
  discover(
    evidence: HostEvidenceProvider,
    observedAt: Date,
  ): Promise<AdapterResult>;
}

export type DiscoverySnapshot = Readonly<{
  inventory: AgentInventory;
  adapterHealth: readonly AdapterHealth[];
  /** Why each agent was reported, and evidence set aside; local only. */
  detections: readonly AgentDetection[];
}>;
