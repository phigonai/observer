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

const maxTrackedToolCalls = 4_096;

/**
 * Factory Droid sessions, appended to
 * `~/.factory/sessions/<project>/<session id>.jsonl`. The first line is
 * `{ type: "session_start", id, title, cwd }`; each message is an envelope
 * `{ type: "message", id, timestamp?, message: { role, content } }` whose
 * content holds Anthropic-style blocks: text, thinking, tool_use and (in
 * user messages) tool_result. `{ type: "session_event", data:
 * "session_ended" }` closes the session.
 */
class FactoryDroidActivityAdapter implements VendorActivityAdapter {
  readonly id = "factory-droid";
  readonly agentKind = AgentKind.GENERIC;
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
      if (type === "session_start") {
        return [lifecycleDraft(
          this.agentKind,
          observedContext,
          LifecyclePhase.DISCOVERED,
          "Droid session started.",
        )];
      }
      if (type === "session_event") {
        return stringField(object, "data") === "session_ended"
          ? [lifecycleDraft(
              this.agentKind,
              observedContext,
              LifecyclePhase.STOPPED,
              "Droid session ended.",
            )]
          : [];
      }
      if (type !== "message") return [];
      const message = objectValue(object["message"]);
      const role = stringField(message, "role");
      if (role !== "user" && role !== "assistant") return [];
      const content = message?.["content"];
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
        } else if (blockType === "thinking" && role === "assistant") {
          const thinking = stringField(item, "thinking") || stringField(item, "text");
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
        } else if (blockType === "tool_use" && role === "assistant") {
          drafts.push(...this.#toolUse(item, observedContext));
        } else if (blockType === "tool_result") {
          drafts.push(...this.#toolResult(item, observedContext));
        }
      }
      const text = (role === "user" ? texts.map(withoutReminders) : texts)
        .filter((value) => value.trim() !== "")
        .join("\n");
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
          `droid_${role}`,
        ));
      }
      return drafts;
    } catch {
      return [errorDraft(this.agentKind, context, "malformed_record")];
    }
  }

  #toolUse(
    item: Record<string, unknown>,
    context: ParseContext,
  ): readonly ActivityDraft[] {
    const id = stringField(item, "id");
    const name = stringField(item, "name") || "tool";
    if (id !== "") {
      this.#toolNames.set(`${context.sessionId}\u0000${id}`, name);
      if (this.#toolNames.size > maxTrackedToolCalls) {
        const oldest = this.#toolNames.keys().next().value;
        if (oldest !== undefined) this.#toolNames.delete(oldest);
      }
    }
    return toolDrafts(this.agentKind, context, {
      invocationId: id,
      toolName: name,
      phase: ToolPhase.REQUESTED,
      arguments: item["input"],
    });
  }

  #toolResult(
    item: Record<string, unknown>,
    context: ParseContext,
  ): readonly ActivityDraft[] {
    const id = stringField(item, "tool_use_id");
    const key = `${context.sessionId}\u0000${id}`;
    const name = this.#toolNames.get(key) ?? "tool";
    this.#toolNames.delete(key);
    const output = extractText(item["content"]);
    return toolDrafts(this.agentKind, context, {
      invocationId: id,
      toolName: name,
      phase: item["is_error"] === true ? ToolPhase.FAILED : ToolPhase.SUCCEEDED,
      ...(output === "" ? {} : { output }),
    });
  }
}

/**
 * Text the agent adds to a user turn for the model inside
 * `<system-reminder>` tags; the user did not type it.
 */
function withoutReminders(text: string): string {
  return text.replace(/<system-reminder>[\s\S]*?<\/system-reminder>/gu, "").trim();
}

export const factoryDroidActivityAdapter: VendorActivityAdapter =
  new FactoryDroidActivityAdapter();
