import { AgentKind } from "../../generated/phigon/v1/common_pb.js";
import {
  discoverKnownAgent,
  type KnownAgentSpec,
} from "../known-agent.js";
import type { AgentDiscoveryAdapter } from "../types.js";

const spec: KnownAgentSpec = {
  id: "codex",
  kind: AgentKind.CODEX,
  displayName: "OpenAI Codex",
  executableNames: ["codex"],
  processNames: ["codex"],
  configurationPaths: ["~/.codex"],
  capabilities: [
    "activity",
    "filesystem",
    "git",
    "mcp",
    "native-activity",
    "terminal",
  ],
};

export const codexAdapter: AgentDiscoveryAdapter = {
  id: spec.id,
  discover: (evidence, observedAt) =>
    discoverKnownAgent(spec, evidence, observedAt),
};
