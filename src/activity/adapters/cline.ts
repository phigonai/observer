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
  objectValue,
  stringField,
} from "../record.js";
import type {
  ActivityDraft,
  ParseContext,
  VendorActivityAdapter,
} from "../types.js";

/**
 * Cline CLI session messages
 * (~/.cline/data/sessions/<session>/<session>.messages.json). The document
 * is rewritten in place with `{ version, sessionId, messages: [...] }`; the
 * JSON document source delivers each message once. A message is
 * `{ id, role, content, ts }` where content is a string or Anthropic-style
 * blocks: text, thinking, tool_use `{id, name, input}`, and tool_result
 * `{tool_use_id, name, content, is_error?}` on user-role messages.
 */
class ClineActivityAdapter implements VendorActivityAdapter {
  readonly id = "cline-cli";
  readonly agentKind = AgentKind.GENERIC;

  parse(record: unknown, context: ParseContext): readonly ActivityDraft[] {
    try {
      const message = objectValue(record);
      if (message === null) return [];
      const role = stringField(message, "role");
      if (role !== "user" && role !== "assistant") return [];
      const observedContext = {
        ...context,
        observedAt: clineObservedAt(message["ts"], context.observedAt),
      };
      const content = message["content"];
      const blocks = Array.isArray(content) ? content : [content];
      const drafts: ActivityDraft[] = [];
      const texts: string[] = [];
      for (const block of blocks.slice(0, 256)) {
        if (typeof block === "string") {
          texts.push(block);
          continue;
        }
        const item = objectValue(block);
        if (item === null) continue;
        const type = stringField(item, "type");
        if (type === "text") {
          texts.push(stringField(item, "text"));
        } else if (type === "thinking" && role === "assistant") {
          const thinking = stringField(item, "thinking");
          if (thinking.trim() === "") continue;
          drafts.push(activityDraft(
            this.agentKind,
            observedContext,
            ActivityKind.REASONING,
            "Agent reasoning updated.",
            thinking,
            "reasoningContent",
            "thinking",
          ));
        } else if (type === "tool_use" && role === "assistant") {
          drafts.push(...toolDrafts(this.agentKind, observedContext, {
            invocationId: stringField(item, "id"),
            toolName: stringField(item, "name") || "tool",
            phase: ToolPhase.REQUESTED,
            arguments: item["input"],
          }));
        } else if (type === "tool_result") {
          drafts.push(...toolDrafts(this.agentKind, observedContext, {
            invocationId: stringField(item, "tool_use_id"),
            toolName: stringField(item, "name") || "tool",
            phase: clineToolFailed(item)
              ? ToolPhase.FAILED
              : ToolPhase.SUCCEEDED,
            output: item["content"],
          }));
        }
      }
      const text = texts.filter((value) => value.trim() !== "").join("\n");
      if (text !== "") {
        drafts.unshift(activityDraft(
          this.agentKind,
          observedContext,
          role === "user" ? ActivityKind.PROMPT : ActivityKind.RESPONSE,
          role === "user"
            ? "User prompt submitted."
            : "Agent response produced.",
          text,
          role === "user" ? "promptContent" : "responseContent",
          `cline_${role}`,
        ));
      }
      return drafts;
    } catch {
      return [errorDraft(this.agentKind, context, "malformed_record")];
    }
  }
}

/**
 * Built-in Cline tools return `[{ query, result, success, error? }]`; a
 * provider-level failure sets `is_error`.
 */
function clineToolFailed(block: Record<string, unknown>): boolean {
  if (block["is_error"] === true) return true;
  const content = block["content"];
  return Array.isArray(content) &&
    content.length > 0 &&
    content.every((entry) => objectValue(entry)?.["success"] === false);
}

function clineObservedAt(value: unknown, fallback: Date): Date {
  if (typeof value !== "number" || !Number.isFinite(value)) return fallback;
  const parsed = new Date(value);
  return Number.isNaN(parsed.getTime()) ? fallback : parsed;
}

export const clineActivityAdapter: VendorActivityAdapter =
  new ClineActivityAdapter();
