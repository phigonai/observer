import { AgentKind } from "../../generated/phigon/v1/common_pb.js";
import {
  discoverKnownAgent,
  type KnownAgentSpec,
} from "../known-agent.js";
import type { AgentDiscoveryAdapter } from "../types.js";

const spec: KnownAgentSpec = {
  id: "claude",
  kind: AgentKind.CLAUDE,
  displayName: "Claude Code",
  executableNames: ["claude"],
  processNames: ["claude", "claude-code"],
  scriptPackages: ["@anthropic-ai/claude-code"],
  // Claude Code's own files. ~/Library/Application Support/Claude belongs
  // to the Claude desktop app, which is not Claude Code.
  configurationPaths: [
    "~/.claude",
    "~/.claude.json",
    "$CLAUDE_CONFIG_DIR",
  ],
  capabilities: [
    "activity",
    "filesystem",
    "git",
    "mcp",
    "native-activity",
    "terminal",
  ],
};

export const claudeAdapter: AgentDiscoveryAdapter = {
  id: spec.id,
  discover: (evidence, observedAt) =>
    discoverKnownAgent(spec, evidence, observedAt),
};
