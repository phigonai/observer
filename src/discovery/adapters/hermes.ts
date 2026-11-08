import { AgentKind } from "../../generated/phigon/v1/common_pb.js";
import {
  discoverKnownAgent,
  type KnownAgentSpec,
} from "../known-agent.js";
import type { AgentDiscoveryAdapter } from "../types.js";

const spec: KnownAgentSpec = {
  id: "hermes",
  kind: AgentKind.HERMES,
  displayName: "Hermes Agent",
  executableNames: ["hermes-agent", "hermes"],
  processNames: ["hermes", "hermes-agent"],
  // The Hermes JavaScript engine and the Hermes IBC relayer are also called
  // hermes, and the relayer keeps its config.toml in ~/.hermes too, so only
  // Hermes Agent's own files there identify it.
  sharedNames: ["hermes"],
  configurationPaths: ["~/.hermes/config.yaml", "~/.hermes/sessions"],
  capabilities: [
    "activity",
    "browser",
    "filesystem",
    "native-activity",
    "terminal",
  ],
};

export const hermesAdapter: AgentDiscoveryAdapter = {
  id: spec.id,
  discover: (evidence, observedAt) =>
    discoverKnownAgent(spec, evidence, observedAt),
};
