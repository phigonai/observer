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
  extractText,
  objectValue,
  recordObservedAt,
  stringField,
} from "../record.js";
import type {
  ActivityDraft,
  ParseContext,
  VendorActivityAdapter,
} from "../types.js";

class ClaudeActivityAdapter implements VendorActivityAdapter {
  readonly id = "claude";
  readonly agentKind = AgentKind.CLAUDE;
  readonly #toolNames = new Map<string, string>();

  parse(record: unknown, context: ParseContext): readonly ActivityDraft[] {
    try {
      const object = objectValue(record);
      if (object === null) return [];
      const observedContext = {
        ...context,
        observedAt: recordObservedAt(record, context.observedAt),
      };
      const type = stringField(object, "type");
      if (type === "system" || type === "summary") {
        // Claude Code transcripts write many system records per session
        // (turn timing, hook summaries, notices). Only the session start,
        // a finished turn, and an API failure carry lifecycle meaning.
        const subtype = stringField(object, "subtype");
        if (subtype === "turn_duration") {
          return [lifecycleDraft(
            this.agentKind,
            observedContext,
            LifecyclePhase.IDLE,
            "Claude turn completed.",
          )];
        }
        if (subtype === "api_error") {
          return [errorDraft(this.agentKind, observedContext, "api_error")];
        }
        if (type === "system" && subtype !== "" && subtype !== "init") {
          return [];
        }
        return [lifecycleDraft(
          this.agentKind,
          observedContext,
          LifecyclePhase.DISCOVERED,
          "Claude session discovered.",
        )];
      }
      if (type === "result") {
        return [
          object["is_error"] === true
            ? errorDraft(this.agentKind, observedContext, "result_error")
            : lifecycleDraft(
                this.agentKind,
                observedContext,
                LifecyclePhase.IDLE,
                "Claude task completed.",
              ),
        ];
      }
      if (type !== "user" && type !== "assistant") return [];
      const message = objectValue(object["message"]) ?? object;
      const role = stringField(message, "role") || type;
      const content = message["content"];
      const blocks = Array.isArray(content) ? content : [content];
      const drafts: ActivityDraft[] = [];
      const textBlocks: unknown[] = [];
      for (const block of blocks.slice(0, 256)) {
        const item = objectValue(block);
        if (item === null) {
          textBlocks.push(block);
          continue;
        }
        const blockType = stringField(item, "type");
        if (blockType === "tool_use") {
          const id = stringField(item, "id");
          const name = stringField(item, "name") || "tool";
          if (id !== "") this.#toolNames.set(id, name);
          drafts.push(...toolDrafts(this.agentKind, observedContext, {
            invocationId: id,
            toolName: name,
            phase: ToolPhase.REQUESTED,
            arguments: item["input"],
          }));
        } else if (blockType === "tool_result") {
          const id = stringField(item, "tool_use_id");
          drafts.push(...toolDrafts(this.agentKind, observedContext, {
            invocationId: id,
            toolName: this.#toolNames.get(id) ?? "tool",
            phase:
              item["is_error"] === true
                ? ToolPhase.FAILED
                : ToolPhase.SUCCEEDED,
            output: item["content"],
          }));
          this.#toolNames.delete(id);
        } else if (blockType === "thinking") {
          drafts.push(activityDraft(
            this.agentKind,
            observedContext,
            ActivityKind.REASONING,
            "Agent reasoning updated.",
            item["thinking"] ?? item["text"],
            "reasoningContent",
            "thinking",
          ));
        } else {
          textBlocks.push(item["text"] ?? block);
        }
      }
      // Claude Code marks text it injects into the user turn (command
      // caveats, reminders, compaction summaries). It was not typed by the
      // user, so it must not appear as a user prompt.
      const injected =
        type === "user" &&
        (object["isMeta"] === true || object["isCompactSummary"] === true);
      const text = injected ? "" : extractText(textBlocks);
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
          `${type}_message`,
        ));
      }
      return drafts;
    } catch {
      return [errorDraft(this.agentKind, context, "malformed_record")];
    }
  }
}

export const claudeActivityAdapter: VendorActivityAdapter =
  new ClaudeActivityAdapter();
