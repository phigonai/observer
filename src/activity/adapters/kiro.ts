import {
  ActivityKind,
  AgentKind,
} from "../../generated/phigon/v1/common_pb.js";
import {
  activityDraft,
  errorDraft,
} from "../normalize.js";
import {
  objectValue,
  stringField,
} from "../record.js";
import type {
  ActivityDraft,
  ParseContext,
  VendorActivityAdapter,
} from "../types.js";

/**
 * Kiro chat sessions, saved per workspace as
 * `kiro.kiroagent/workspace-sessions/<workspace>/<session id>.json` in the
 * editor's global storage: `{ sessionId, title, history: [...] }`. Each
 * delivered record is one history item `{ message: { id, role, content },
 * contextItems, editorState, executionId? }`, where content is a string or
 * text parts `{ type: "text", text }`. Agent actions are kept in separate
 * execution files and are not read.
 */
class KiroActivityAdapter implements VendorActivityAdapter {
  readonly id = "kiro-session";
  readonly agentKind = AgentKind.GENERIC;

  parse(record: unknown, context: ParseContext): readonly ActivityDraft[] {
    try {
      const message = objectValue(objectValue(record)?.["message"]);
      if (message === null) return [];
      const role = stringField(message, "role");
      if (role !== "user" && role !== "assistant") return [];
      const text = messageText(message["content"]);
      if (text === "") return [];
      return [activityDraft(
        this.agentKind,
        context,
        role === "user" ? ActivityKind.PROMPT : ActivityKind.RESPONSE,
        role === "user" ? "User prompt submitted." : "Agent response produced.",
        text,
        role === "user" ? "promptContent" : "responseContent",
        `kiro_${role}`,
      )];
    } catch {
      return [errorDraft(this.agentKind, context, "malformed_record")];
    }
  }
}

function messageText(content: unknown): string {
  if (typeof content === "string") return content.trim();
  if (!Array.isArray(content)) return "";
  return content
    .slice(0, 256)
    .flatMap((part) =>
      stringField(part, "type") === "text" ? [stringField(part, "text")] : []
    )
    .filter((text) => text.trim() !== "")
    .join("\n")
    .trim();
}

export const kiroActivityAdapter: VendorActivityAdapter =
  new KiroActivityAdapter();
