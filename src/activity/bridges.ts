export type ActivityBridgeAgent = Readonly<{
  id: string;
  displayName: string;
}>;

export const activityBridgeAgents: readonly ActivityBridgeAgent[] =
  Object.freeze([
    { id: "generic", displayName: "Generic AI agent" },
    { id: "aider", displayName: "Aider" },
    { id: "amp", displayName: "Amp" },
    { id: "cursor", displayName: "Cursor Agent" },
    { id: "gemini", displayName: "Gemini CLI" },
    { id: "opencode", displayName: "OpenCode" },
    { id: "goose", displayName: "Goose" },
    { id: "amazon-q", displayName: "Amazon Q Developer CLI" },
    { id: "openhands", displayName: "OpenHands" },
    { id: "cline", displayName: "Cline" },
    { id: "continue", displayName: "Continue" },
  ]);

export function activityBridgeAgent(
  id: string,
): ActivityBridgeAgent | undefined {
  return activityBridgeAgents.find((agent) => agent.id === id);
}
