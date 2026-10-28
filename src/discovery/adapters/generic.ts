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
    id: "generic:cursor",
    kind: AgentKind.GENERIC,
    displayName: "Cursor",
    executableNames: ["cursor"],
    processNames: ["cursor"],
    configurationPaths: [
      "~/AppData/Roaming/Cursor",
      "~/Library/Application Support/Cursor",
      "~/.config/Cursor",
    ],
    capabilities: [
      "activity",
      "filesystem",
      "git",
      "mcp",
      "native-activity",
      "terminal",
    ],
    processModel: "application",
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
    id: "generic:copilot-chat",
    kind: AgentKind.GENERIC,
    displayName: "GitHub Copilot",
    executableNames: [],
    processNames: ["code", "code - insiders"],
    configurationPaths: [
      "~/AppData/Roaming/Code/User/globalStorage/github.copilot-chat",
      "~/Library/Application Support/Code/User/globalStorage/github.copilot-chat",
      "~/.config/Code/User/globalStorage/github.copilot-chat",
    ],
    capabilities: [
      "activity",
      "filesystem",
      "mcp",
      "native-activity",
      "terminal",
    ],
    processModel: "application",
  },
  {
    id: "generic:kiro",
    kind: AgentKind.GENERIC,
    displayName: "Kiro",
    executableNames: ["kiro"],
    processNames: ["kiro"],
    configurationPaths: [
      "~/AppData/Roaming/Kiro",
      "~/Library/Application Support/Kiro",
      "~/.config/Kiro",
    ],
    capabilities: ["activity", "filesystem", "mcp", "native-activity", "terminal"],
    processModel: "application",
  },
  {
    // Google Antigravity keeps agent conversations as undocumented protocol
    // buffer files (~/.gemini/antigravity/conversations/*.pb), so only the
    // application is discovered.
    id: "generic:antigravity",
    kind: AgentKind.GENERIC,
    displayName: "Antigravity",
    executableNames: ["antigravity"],
    processNames: ["antigravity"],
    configurationPaths: [
      "~/.gemini/antigravity",
      "~/AppData/Roaming/Antigravity",
      "~/Library/Application Support/Antigravity",
      "~/.config/Antigravity",
    ],
    capabilities: ["browser", "filesystem", "mcp", "terminal"],
    processModel: "application",
  },
  {
    // Trae keeps its agent history in an encrypted database
    // (ModularData/ai-agent/database.db has no SQLite header), so only the
    // application is discovered.
    id: "generic:trae",
    kind: AgentKind.GENERIC,
    displayName: "Trae",
    executableNames: ["trae"],
    processNames: ["trae"],
    configurationPaths: [
      "~/.trae",
      "~/AppData/Roaming/Trae",
      "~/Library/Application Support/Trae",
      "~/.config/Trae",
    ],
    capabilities: ["filesystem", "mcp", "terminal"],
    processModel: "application",
  },
  {
    // Zed stores agent threads compressed in threads/threads.db. No thread
    // could be inspected yet, so only the application is discovered.
    id: "generic:zed",
    kind: AgentKind.GENERIC,
    displayName: "Zed",
    executableNames: ["zed"],
    processNames: ["zed"],
    configurationPaths: [
      "~/AppData/Local/Zed",
      "~/AppData/Roaming/Zed",
      "~/Library/Application Support/Zed",
      "~/.config/zed",
    ],
    capabilities: ["filesystem", "mcp", "terminal"],
    processModel: "application",
  },
  {
    // No Factory Droid session could be inspected yet, so its CLI is
    // discovered without reading conversations.
    id: "generic:factory-droid",
    kind: AgentKind.GENERIC,
    displayName: "Factory Droid",
    executableNames: ["droid"],
    processNames: ["droid"],
    configurationPaths: ["~/.factory"],
    capabilities: ["filesystem", "git", "mcp", "terminal"],
  },
  {
    // The Roo Code extension's own storage. ~/.roo is not used as evidence:
    // other tools create it to share skills.
    id: "generic:roo-code",
    kind: AgentKind.GENERIC,
    displayName: "Roo Code",
    executableNames: [],
    processNames: [],
    configurationPaths: [
      "~/AppData/Roaming/Code/User/globalStorage/rooveterinaryinc.roo-cline",
      "~/AppData/Roaming/Cursor/User/globalStorage/rooveterinaryinc.roo-cline",
      "~/Library/Application Support/Code/User/globalStorage/rooveterinaryinc.roo-cline",
      "~/.config/Code/User/globalStorage/rooveterinaryinc.roo-cline",
    ],
    capabilities: ["browser", "filesystem", "mcp", "terminal"],
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
