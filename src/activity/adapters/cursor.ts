import {
  ActivityKind,
  AgentKind,
} from "../../generated/phigon/v1/common_pb.js";
import {
  LifecyclePhase,
  ToolPhase,
} from "../../generated/phigon/v1/telemetry_pb.js";
import {
  activityDraft,
  errorDraft,
  lifecycleDraft,
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
 * Cursor agent transcripts, written by the Cursor editor's agent and the
 * `cursor-agent` CLI to
 * `~/.cursor/projects/<project>/agent-transcripts/<id>/<id>.jsonl`
 * (subagents in `<id>/subagents/<sub>.jsonl`). Each line is
 * `{ role, message: { content: [...] } }` with text blocks and tool_use
 * blocks `{ name, input }`; tool results are not recorded. Turn markers are
 * `{ type: "turn_ended", status, error? }` and `{ type: "error", error }`.
 */
class CursorActivityAdapter implements VendorActivityAdapter {
  readonly id = "cursor-transcript";
  readonly agentKind = AgentKind.GENERIC;

  parse(record: unknown, context: ParseContext): readonly ActivityDraft[] {
    try {
      const line = objectValue(record);
      if (line === null) return [];
      const type = stringField(line, "type");
      if (type === "turn_ended") {
        return stringField(line, "status") === "error"
          ? [errorDraft(this.agentKind, context, "turn_error")]
          : [lifecycleDraft(
              this.agentKind,
              context,
              LifecyclePhase.IDLE,
              "Cursor turn completed.",
            )];
      }
      if (type === "error") {
        return [errorDraft(this.agentKind, context, "agent_error")];
      }
      const role = stringField(line, "role");
      if (role !== "user" && role !== "assistant") return [];
      const content = objectValue(line["message"])?.["content"];
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
        const blockType = stringField(item, "type");
        if (blockType === "text") {
          texts.push(stringField(item, "text"));
        } else if (blockType === "tool_use" && role === "assistant") {
          const input = item["input"];
          drafts.push(...toolDrafts(this.agentKind, context, {
            toolName: stringField(item, "name") || "tool",
            phase: ToolPhase.REQUESTED,
            // ApplyPatch carries the patch text itself as its input.
            arguments: typeof input === "string" ? { patch: input } : input,
          }));
        }
      }
      const joined = texts.filter((value) => value.trim() !== "").join("\n");
      const text = role === "user" ? typedRequest(joined) : joined;
      if (text !== "") {
        drafts.unshift(activityDraft(
          this.agentKind,
          context,
          role === "user" ? ActivityKind.PROMPT : ActivityKind.RESPONSE,
          role === "user"
            ? "User prompt submitted."
            : "Agent response produced.",
          text,
          role === "user" ? "promptContent" : "responseContent",
          `cursor_${role}`,
        ));
      }
      return drafts;
    } catch {
      return [errorDraft(this.agentKind, context, "malformed_record")];
    }
  }
}

/**
 * Cursor wraps what the user typed in `<user_query>` and adds the context it
 * attached (open files, selections, a timestamp) around it. Only the typed
 * request is the prompt; a message without the wrapper is kept whole.
 */
function typedRequest(text: string): string {
  const queries = [...text.matchAll(/<user_query>([\s\S]*?)<\/user_query>/gu)]
    .map((match) => (match[1] ?? "").trim())
    .filter((query) => query !== "");
  return queries.length > 0 ? queries.join("\n\n") : text;
}

export const cursorActivityAdapter: VendorActivityAdapter =
  new CursorActivityAdapter();
