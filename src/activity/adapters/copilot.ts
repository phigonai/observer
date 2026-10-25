import { AgentKind } from "../../generated/phigon/v1/common_pb.js";
import { createOpenAICompatibleAdapter } from "./openai-compatible.js";

export const copilotActivityAdapter = createOpenAICompatibleAdapter(
  "copilot",
  AgentKind.GENERIC,
  "GitHub Copilot CLI",
);
