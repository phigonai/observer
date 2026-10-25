import { AgentKind } from "../../generated/phigon/v1/common_pb.js";
import { createOpenAICompatibleAdapter } from "./openai-compatible.js";

export const genericActivityAdapter = createOpenAICompatibleAdapter(
  "generic",
  AgentKind.GENERIC,
  "AI agent",
);
