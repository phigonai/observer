import {
  ActivityKind,
  AgentKind,
} from "../../generated/phigon/v1/common_pb.js";
import { ToolPhase } from "../../generated/phigon/v1/telemetry_pb.js";
import {
  activityDraft,
  errorDraft,
  toolDrafts,
} from "../normalize.js";
import {
  nestedField,
  objectValue,
  stringField,
} from "../record.js";
import type {
  ActivityDraft,
  ParseContext,
  VendorActivityAdapter,
} from "../types.js";

// VS Code ToolConfirmKind: Denied = 0, Skipped = 5.
const deniedConfirmations = new Set([0, 5]);

/**
 * GitHub Copilot chat in VS Code. VS Code saves each chat session as
 * `chatSessions/<id>.json` (or, since its operation-log storage, as an
 * equivalent `<id>.jsonl` log) under the workspace storage folder. Each
 * delivered record is one request: `message.text` is the prompt and
 * `response` holds the reply parts: markdown `{ value }`, `inlineReference`,
 * `thinking` and `toolInvocationSerialized`. `result.errorDetails` reports a
 * failed request.
 */
class CopilotChatActivityAdapter implements VendorActivityAdapter {
  readonly id = "copilot-chat";
  readonly agentKind = AgentKind.GENERIC;

  parse(record: unknown, context: ParseContext): readonly ActivityDraft[] {
    try {
      const request = objectValue(record);
      if (request === null) return [];
      const drafts: ActivityDraft[] = [];
      const prompt = stringField(objectValue(request["message"]), "text");
      if (prompt.trim() !== "") {
        drafts.push(activityDraft(
          this.agentKind,
          context,
          ActivityKind.PROMPT,
          "User prompt submitted.",
          prompt,
          "promptContent",
          "copilot_chat_request",
        ));
      }
      const parts = Array.isArray(request["response"])
        ? request["response"].slice(0, 1_024)
        : [];
      const reply: string[] = [];
      const reasoning: string[] = [];
      const tools: ActivityDraft[] = [];
      for (const part of parts) {
        const item = objectValue(part);
        if (item === null) continue;
        const kind = stringField(item, "kind");
        if (kind === "") {
          reply.push(stringField(item, "value"));
        } else if (kind === "inlineReference") {
          const name = referenceName(item);
          if (name !== "") reply.push(`\`${name}\``);
        } else if (kind === "thinking") {
          const value = item["value"];
          reasoning.push(
            Array.isArray(value)
              ? value.filter((entry) => typeof entry === "string").join("")
              : typeof value === "string" ? value : "",
          );
        } else if (kind === "toolInvocationSerialized") {
          tools.push(...toolInvocationDrafts(this.agentKind, context, item));
        }
      }
      const replyText = reply.join("").trim();
      if (replyText !== "") {
        drafts.push(activityDraft(
          this.agentKind,
          context,
          ActivityKind.RESPONSE,
          "Agent response produced.",
          replyText,
          "responseContent",
          "copilot_chat_response",
        ));
      }
      const reasoningText = reasoning
        .filter((value) => value.trim() !== "")
        .join("\n\n");
      if (reasoningText !== "") {
        drafts.push(activityDraft(
          this.agentKind,
          context,
          ActivityKind.REASONING,
          "Agent reasoning updated.",
          reasoningText,
          "reasoningContent",
          "thinking",
        ));
      }
      if (objectValue(nestedField(request, "result", "errorDetails")) !== null) {
        drafts.push(errorDraft(this.agentKind, context, "request_error"));
      }
      // One request is a whole agent turn; tools follow the conversation.
      drafts.push(...tools);
      return drafts;
    } catch {
      return [errorDraft(this.agentKind, context, "malformed_record")];
    }
  }
}

function toolInvocationDrafts(
  agentKind: AgentKind,
  context: ParseContext,
  item: Record<string, unknown>,
): readonly ActivityDraft[] {
  const specific = objectValue(item["toolSpecificData"]);
  const specificKind = stringField(specific, "kind");
  const confirmation = nestedField(item, "isConfirmed", "type");
  const denied = item["isConfirmed"] === false ||
    (typeof confirmation === "number" && deniedConfirmations.has(confirmation));
  let phase = denied
    ? ToolPhase.CANCELLED
    : item["isComplete"] === true
      ? ToolPhase.SUCCEEDED
      : ToolPhase.RUNNING;
  let input: unknown;
  let output: unknown;
  let exitCode: unknown;
  if (specificKind === "terminal") {
    const commandLine = objectValue(specific?.["commandLine"]);
    input = {
      command: stringField(commandLine, "userEdited") ||
        stringField(commandLine, "toolEdited") ||
        stringField(commandLine, "original"),
    };
    output = nestedField(specific, "terminalCommandOutput", "text");
    exitCode = nestedField(specific, "terminalCommandState", "exitCode");
    if (
      phase === ToolPhase.SUCCEEDED &&
      typeof exitCode === "number" &&
      exitCode !== 0
    ) {
      phase = ToolPhase.FAILED;
    }
  } else if (specificKind === "input") {
    input = specific?.["rawInput"];
  } else {
    // Built-in tools keep only their progress message; the files it names
    // identify what was read or changed.
    const path = messagePath(item["invocationMessage"]) ||
      messagePath(item["pastTenseMessage"]);
    input = {
      description: messageText(item["pastTenseMessage"]) ||
        messageText(item["invocationMessage"]),
      ...(path === "" ? {} : { path }),
    };
  }
  const details = objectValue(item["resultDetails"]);
  if (details !== null && "output" in details) {
    output = details["output"];
    if (details["isError"] === true) phase = ToolPhase.FAILED;
  }
  return toolDrafts(agentKind, context, {
    invocationId: stringField(item, "toolCallId"),
    toolName: toolName(stringField(item, "toolId")),
    phase,
    arguments: input,
    output,
    exitCode,
  });
}

/** `copilot_readFile` becomes `read_file`, the convention other agents use. */
function toolName(toolId: string): string {
  const name = toolId
    .replace(/^copilot_/u, "")
    .replace(/([a-z0-9])([A-Z])/gu, "$1_$2")
    .toLowerCase();
  return name || "tool";
}

function messageText(value: unknown): string {
  if (typeof value === "string") return value;
  return stringField(value, "value");
}

function messagePath(value: unknown): string {
  const uris = objectValue(objectValue(value)?.["uris"]);
  if (uris === null) return "";
  for (const uri of Object.values(uris).slice(0, 16)) {
    const path = stringField(uri, "fsPath") || stringField(uri, "path");
    if (path !== "") return path;
  }
  return "";
}

function referenceName(item: Record<string, unknown>): string {
  const explicit = stringField(item, "name");
  if (explicit !== "") return explicit;
  const reference = objectValue(item["inlineReference"]);
  const symbol = stringField(reference, "name");
  if (symbol !== "") return symbol;
  const path = stringField(reference, "path") ||
    stringField(nestedField(reference, "uri"), "path") ||
    stringField(nestedField(reference, "location", "uri"), "path");
  return path.split("/").filter(Boolean).at(-1) ?? "";
}

export const copilotChatActivityAdapter: VendorActivityAdapter =
  new CopilotChatActivityAdapter();
