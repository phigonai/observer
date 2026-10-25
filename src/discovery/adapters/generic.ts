import { AgentKind } from "../../generated/phigon/v1/common_pb.js";
import {
  combineAdapterResults,
  discoverKnownAgent,
  type KnownAgentSpec,
} from "../known-agent.js";
import type { AgentDiscoveryAdapter } from "../types.js";

const genericAgents: readonly KnownAgentSpec[] = [
  {
    id: "generic:aider",
    kind: AgentKind.GENERIC,
    displayName: "Aider",
    executableNames: ["aider"],
    processNames: ["aider"],
    configurationPaths: ["~/.aider"],
    capabilities: ["activity", "filesystem", "git", "terminal"],
  },
  {
    id: "generic:amp",
    kind: AgentKind.GENERIC,
    displayName: "Amp",
    executableNames: ["amp"],
    processNames: ["amp"],
    configurationPaths: ["~/.config/amp"],
    capabilities: ["activity", "filesystem", "git", "terminal"],
  },
  {
    id: "generic:cursor-agent",
    kind: AgentKind.GENERIC,
    displayName: "Cursor Agent",
    executableNames: ["cursor-agent"],
    processNames: ["cursor-agent"],
    configurationPaths: ["~/.cursor"],
    capabilities: ["activity", "filesystem", "git", "terminal"],
  },
  {
    id: "generic:gemini",
    kind: AgentKind.GENERIC,
    displayName: "Gemini CLI",
    executableNames: ["gemini"],
    processNames: ["gemini"],
    configurationPaths: ["~/.gemini"],
    capabilities: ["activity", "filesystem", "mcp", "terminal"],
  },
  {
    id: "generic:opencode",
    kind: AgentKind.GENERIC,
    displayName: "OpenCode",
    executableNames: ["opencode"],
    processNames: ["opencode"],
    configurationPaths: ["~/.config/opencode"],
    capabilities: ["activity", "filesystem", "git", "terminal"],
  },
  {
    id: "generic:goose",
    kind: AgentKind.GENERIC,
    displayName: "Goose",
    executableNames: ["goose"],
    processNames: ["goose"],
    configurationPaths: ["~/.config/goose"],
    capabilities: ["activity", "filesystem", "mcp", "terminal"],
  },
  {
    id: "generic:copilot",
    kind: AgentKind.GENERIC,
    displayName: "GitHub Copilot CLI",
    executableNames: ["copilot"],
    processNames: ["copilot"],
    configurationPaths: ["~/.copilot"],
    capabilities: [
      "activity",
      "filesystem",
      "git",
      "native-activity",
      "terminal",
    ],
  },
  {
    id: "generic:amazon-q",
    kind: AgentKind.GENERIC,
    displayName: "Amazon Q Developer CLI",
    executableNames: ["q"],
    processNames: ["q"],
    configurationPaths: ["~/.aws/amazonq"],
    capabilities: ["activity", "filesystem", "terminal"],
  },
  {
    id: "generic:openhands",
    kind: AgentKind.GENERIC,
    displayName: "OpenHands",
    executableNames: ["openhands"],
    processNames: ["openhands"],
    configurationPaths: ["~/.openhands"],
    capabilities: ["activity", "browser", "filesystem", "terminal"],
  },
  {
    id: "generic:cline",
    kind: AgentKind.GENERIC,
    displayName: "Cline",
    executableNames: [],
    processNames: [],
    configurationPaths: ["~/.cline"],
    capabilities: ["activity", "browser", "filesystem", "mcp", "terminal"],
  },
  {
    id: "generic:continue",
    kind: AgentKind.GENERIC,
    displayName: "Continue",
    executableNames: [],
    processNames: [],
    configurationPaths: ["~/.continue"],
    capabilities: ["activity", "filesystem", "mcp", "terminal"],
  },
  {
    id: "generic:jsonl",
    kind: AgentKind.GENERIC,
    displayName: "Generic JSONL agent",
    executableNames: [],
    processNames: [],
    configurationPaths: ["~/.phigon/agent-events"],
    capabilities: ["activity", "tools"],
  },
];

export const genericAdapter: AgentDiscoveryAdapter = {
  id: "generic",
  async discover(evidence, observedAt) {
    const results = await Promise.all(
      genericAgents.map((spec) =>
        discoverKnownAgent(spec, evidence, observedAt),
      ),
    );
    return combineAdapterResults("generic", results);
  },
};
