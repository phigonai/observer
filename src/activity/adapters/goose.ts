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

const maxTrackedToolCalls = 4_096;

/**
 * Goose session messages read from its sessions database. Each record is
 * `{ type: "goose_message", role, content, metadata }` where content holds
 * Goose's serialized MessageContent blocks: text, thinking, toolRequest
 * `{id, toolCall: {status, value: {name, arguments}}}` and toolResponse
 * `{id, toolResult: {status, value: {content, isError}} | {status, error}}`.
 */
class GooseActivityAdapter implements VendorActivityAdapter {
  readonly id = "goose-session";
  readonly agentKind = AgentKind.GENERIC;
  readonly #toolNames = new Map<string, string>();

  parse(record: unknown, context: ParseContext): readonly ActivityDraft[] {
    try {
      const object = objectValue(record);
      if (object === null || stringField(object, "type") !== "goose_message") {
        return [];
      }
      const role = stringField(object, "role");
      if (role !== "user" && role !== "assistant") return [];
      const observedContext = {
        ...context,
        observedAt: recordObservedAt(record, context.observedAt),
      };
      // Goose hides some messages from the user (for example context it
      // injects for the model); they were not typed or shown as chat.
      const userVisible =
        objectValue(object["metadata"])?.["userVisible"] !== false;
      const drafts: ActivityDraft[] = [];
      const texts: string[] = [];
      for (const block of arrayField(object, "content").slice(0, 256)) {
        const type = stringField(block, "type");
        if (type === "text") {
          texts.push(stringField(block, "text"));
        } else if (type === "thinking" && role === "assistant") {
          const thinking = stringField(block, "thinking");
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
        } else if (type === "toolRequest") {
          drafts.push(...this.#toolRequest(block, observedContext));
        } else if (type === "toolResponse") {
          drafts.push(...this.#toolResponse(block, observedContext));
        } else if (type === "error") {
          drafts.push(errorDraft(this.agentKind, observedContext, "goose_error"));
        }
      }
      const text = texts.filter((value) => value.trim() !== "").join("\n");
      if (text !== "" && userVisible) {
        drafts.unshift(activityDraft(
          this.agentKind,
          observedContext,
          role === "user" ? ActivityKind.PROMPT : ActivityKind.RESPONSE,
          role === "user"
            ? "User prompt submitted."
            : "Agent response produced.",
          text,
          role === "user" ? "promptContent" : "responseContent",
          `goose_${role}`,
        ));
      }
      return drafts;
    } catch {
      return [errorDraft(this.agentKind, context, "malformed_record")];
    }
  }

  #toolRequest(
    block: unknown,
    context: ParseContext,
  ): readonly ActivityDraft[] {
    const id = stringField(block, "id");
    const toolCall = objectValue(objectValue(block)?.["toolCall"]);
    if (stringField(toolCall, "status") !== "success") {
      return [errorDraft(this.agentKind, context, "goose_tool_request_error")];
    }
    const call = objectValue(toolCall?.["value"]);
    const name = stringField(call, "name") || "tool";
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
      arguments: call?.["arguments"],
    });
  }

  #toolResponse(
    block: unknown,
    context: ParseContext,
  ): readonly ActivityDraft[] {
    const id = stringField(block, "id");
    const key = `${context.sessionId}\u0000${id}`;
    const name = this.#toolNames.get(key) ?? "tool";
    this.#toolNames.delete(key);
    const result = objectValue(objectValue(block)?.["toolResult"]);
    const succeeded = stringField(result, "status") === "success";
    const value = objectValue(result?.["value"]);
    const output = succeeded
      ? arrayField(value, "content")
          .map((item) => stringField(item, "text"))
          .filter((text) => text !== "")
          .join("\n")
      : stringField(result, "error");
    return toolDrafts(this.agentKind, context, {
      invocationId: id,
      toolName: name,
      phase: succeeded && value?.["isError"] !== true
        ? ToolPhase.SUCCEEDED
        : ToolPhase.FAILED,
      ...(output === "" ? {} : { output }),
    });
  }
}

export const gooseActivityAdapter: VendorActivityAdapter =
  new GooseActivityAdapter();
