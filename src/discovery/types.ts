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

export type AdapterResult = Readonly<{
  agents: readonly AgentIdentity[];
  health: AdapterHealth;
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
}>;
