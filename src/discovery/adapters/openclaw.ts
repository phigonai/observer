import { AgentKind } from "../../generated/phigon/v1/common_pb.js";
import {
  discoverKnownAgent,
  type KnownAgentSpec,
} from "../known-agent.js";
import type { AgentDiscoveryAdapter } from "../types.js";

const spec: KnownAgentSpec = {
  id: "openclaw",
  kind: AgentKind.OPENCLAW,
  displayName: "OpenClaw",
  executableNames: ["openclaw", "openclaw-agent"],
  processNames: ["openclaw", "openclaw-agent"],
  configurationPaths: ["~/.openclaw"],
  capabilities: [
    "activity",
    "browser",
    "filesystem",
    "native-activity",
    "terminal",
  ],
};

export const openClawAdapter: AgentDiscoveryAdapter = {
  id: spec.id,
  discover: (evidence, observedAt) =>
    discoverKnownAgent(spec, evidence, observedAt),
};
