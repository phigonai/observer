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
  executableNames: ["hermes", "hermes-agent"],
  processNames: ["hermes", "hermes-agent"],
  configurationPaths: ["~/.hermes"],
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
