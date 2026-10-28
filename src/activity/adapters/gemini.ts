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
  arrayField,
  objectValue,
  recordObservedAt,
  stringField,
} from "../record.js";
import type {
  ActivityDraft,
  ParseContext,
  VendorActivityAdapter,
} from "../types.js";

const maxTrackedMessages = 8_192;

type MessageState = {
  text: boolean;
  thoughts: number;
  tools: Map<string, string>;
};

/**
 * Gemini CLI chat recordings
 * (~/.gemini/tmp/<project>/chats/session-*.jsonl, JSONL since v0.39).
 *
 * The first line holds session metadata; each message line is a complete
 * MessageRecord. The recorder appends the same message id again in full
 * when it adds token counts or merges completed tool calls into the last
 * model message, so emitted evidence is tracked per message id and only new
 * text, thoughts and tool-call states are reported. `$set`, `$patch` and
 * `$rewindTo` lines edit stored history and add no new activity.
 */
class GeminiActivityAdapter implements VendorActivityAdapter {
  readonly id = "gemini-cli";
  readonly agentKind = AgentKind.GENERIC;
  readonly #messages = new Map<string, MessageState>();

  parse(record: unknown, context: ParseContext): readonly ActivityDraft[] {
    try {
      const object = objectValue(record);
      if (object === null) return [];
      const observedContext = {
        ...context,
        observedAt: recordObservedAt(record, context.observedAt),
      };
      const type = stringField(object, "type");
      if (type === "") {
        if (
          stringField(object, "sessionId") !== "" &&
          stringField(object, "startTime") !== "" &&
          !("messages" in object)
        ) {
          return [lifecycleDraft(
            this.agentKind,
            { ...context, observedAt: startTime(object, context.observedAt) },
            LifecyclePhase.STARTED,
            "Gemini CLI session started.",
          )];
        }
        return [];
      }
      const messageID = stringField(object, "id");
      if (messageID === "") return [];
      if (type === "error") {
        if (this.#state(context.sessionId, messageID).text) return [];
        this.#state(context.sessionId, messageID).text = true;
        return [errorDraft(this.agentKind, observedContext, "gemini_error")];
      }
      if (type === "user") return this.#user(object, messageID, observedContext);
      if (type === "gemini") return this.#model(object, messageID, observedContext);
      return [];
    } catch {
      return [errorDraft(this.agentKind, context, "malformed_record")];
    }
  }

  #user(
    object: Record<string, unknown>,
    messageID: string,
    context: ParseContext,
  ): readonly ActivityDraft[] {
    const state = this.#state(context.sessionId, messageID);
    if (state.text) return [];
    // displayContent is what the user typed when the recorded content was
    // expanded (for example with @file includes). Tool responses sent back
    // to the model are function-response parts without text.
    const text = partsText(object["displayContent"]) ||
      partsText(object["content"]);
    if (text.trim() === "") return [];
    state.text = true;
    return [activityDraft(
      this.agentKind,
      context,
      ActivityKind.PROMPT,
      "User prompt submitted.",
      text,
      "promptContent",
      "user",
    )];
  }

  #model(
    object: Record<string, unknown>,
    messageID: string,
    context: ParseContext,
  ): readonly ActivityDraft[] {
    const state = this.#state(context.sessionId, messageID);
    const drafts: ActivityDraft[] = [];
    const thoughts = arrayField(object, "thoughts");
    for (const thought of thoughts.slice(state.thoughts, 64)) {
      const subject = stringField(thought, "subject").trim();
      const description = stringField(thought, "description").trim();
      const text = [subject, description].filter(Boolean).join("\n");
      if (text === "") continue;
      drafts.push(activityDraft(
        this.agentKind,
        context,
        ActivityKind.REASONING,
        "Agent reasoning updated.",
        text,
        "reasoningContent",
        "gemini_thought",
      ));
    }
    state.thoughts = Math.max(state.thoughts, Math.min(thoughts.length, 64));
    const text = partsText(object["content"]);
    if (!state.text && text.trim() !== "") {
      state.text = true;
      drafts.push(activityDraft(
        this.agentKind,
        context,
        ActivityKind.RESPONSE,
        "Agent response produced.",
        text,
        "responseContent",
        "gemini",
      ));
    }
    for (const call of arrayField(object, "toolCalls").slice(0, 32)) {
      const callID = stringField(call, "id");
      const status = stringField(call, "status");
      const key = callID || `${stringField(call, "name")}:${status}`;
      if (state.tools.get(key) === status) continue;
      state.tools.set(key, status);
      const toolCall = objectValue(call);
      const output = functionResponseOutput(toolCall?.["result"]) ??
        (typeof toolCall?.["resultDisplay"] === "string"
          ? toolCall["resultDisplay"]
          : undefined);
      drafts.push(...toolDrafts(this.agentKind, {
        ...context,
        observedAt: recordObservedAt(call, context.observedAt),
      }, {
        invocationId: callID,
        toolName: stringField(call, "name") || "tool",
        phase: geminiToolPhase(status),
        arguments: toolCall?.["args"],
        ...(output === undefined ? {} : { output }),
      }));
    }
    return drafts;
  }

  #state(sessionID: string, messageID: string): MessageState {
    const key = `${sessionID}\u0000${messageID}`;
    let state = this.#messages.get(key);
    if (state === undefined) {
      state = { text: false, thoughts: 0, tools: new Map() };
      this.#messages.set(key, state);
      if (this.#messages.size > maxTrackedMessages) {
        const oldest = this.#messages.keys().next().value;
        if (oldest !== undefined) this.#messages.delete(oldest);
      }
    }
    return state;
  }
}

function geminiToolPhase(status: string): ToolPhase {
  if (status === "success") return ToolPhase.SUCCEEDED;
  if (status === "error") return ToolPhase.FAILED;
  if (status === "cancelled") return ToolPhase.CANCELLED;
  if (status === "executing") return ToolPhase.RUNNING;
  return ToolPhase.REQUESTED;
}

/** Text of a @google/genai PartListUnion: a string, a Part, or Part[]. */
function partsText(value: unknown, depth = 0): string {
  if (depth > 2) return "";
  if (typeof value === "string") return value;
  if (Array.isArray(value)) {
    return value
      .slice(0, 256)
      .map((part) => partsText(part, depth + 1))
      .filter((text) => text !== "")
      .join("\n");
  }
  const part = objectValue(value);
  if (part === null || part["thought"] === true) return "";
  return typeof part["text"] === "string" ? part["text"] : "";
}

function functionResponseOutput(value: unknown): unknown {
  const parts = Array.isArray(value) ? value : [value];
  const outputs: unknown[] = [];
  for (const part of parts.slice(0, 32)) {
    const response = objectValue(
      objectValue(objectValue(part)?.["functionResponse"])?.["response"],
    );
    if (response === null) continue;
    outputs.push(response["output"] ?? response["error"] ?? response);
  }
  if (outputs.length === 0) return undefined;
  return outputs.length === 1 ? outputs[0] : outputs;
}

function startTime(object: Record<string, unknown>, fallback: Date): Date {
  const parsed = new Date(stringField(object, "startTime"));
  return Number.isNaN(parsed.getTime()) ? fallback : parsed;
}

export const geminiActivityAdapter: VendorActivityAdapter =
  new GeminiActivityAdapter();
