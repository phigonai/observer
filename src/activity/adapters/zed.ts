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
 * Zed agent threads read from its threads database (see
 * zed-sqlite-source.ts). Each record is one item of a thread:
 * `{ type: "zed_message", role: "user", content }` with Text and Mention
 * parts, `{ type: "zed_message", role: "assistant", content: [block] }`
 * with one Text, Thinking `{ text }` or ToolUse `{ id, name, input }` block,
 * or `{ type: "zed_tool_result", tool_use_id, tool_name, is_error, content }`.
 */
class ZedActivityAdapter implements VendorActivityAdapter {
  readonly id = "zed-thread";
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
      if (type === "zed_tool_result") {
        return this.#toolResult(object, observedContext);
      }
      if (type !== "zed_message") return [];
      const role = stringField(object, "role");
      if (role === "user") return this.#prompt(object, observedContext);
      if (role !== "assistant") return [];
      return arrayField(object, "content")
        .slice(0, 256)
        .flatMap((block) => this.#agentBlock(block, observedContext));
    } catch {
      return [errorDraft(this.agentKind, context, "malformed_record")];
    }
  }

  #prompt(
    object: Record<string, unknown>,
    context: ParseContext,
  ): readonly ActivityDraft[] {
    // Zed splits the prompt around each mention, so the parts join with
    // nothing between them.
    const text = arrayField(object, "content")
      .slice(0, 256)
      .map((part) => {
        const value = objectValue(part);
        if (typeof value?.["Text"] === "string") return value["Text"];
        const mention = objectValue(value?.["Mention"]);
        return mention === null ? "" : `@${mentionName(mention["uri"])}`;
      })
      .join("")
      .trim();
    if (text === "") return [];
    return [activityDraft(
      this.agentKind,
      context,
      ActivityKind.PROMPT,
      "User prompt submitted.",
      text,
      "promptContent",
      "zed_user",
    )];
  }

  #agentBlock(
    block: unknown,
    context: ParseContext,
  ): readonly ActivityDraft[] {
    const value = objectValue(block);
    if (value === null) return [];
    if (typeof value["Text"] === "string") {
      if (value["Text"].trim() === "") return [];
      return [activityDraft(
        this.agentKind,
        context,
        ActivityKind.RESPONSE,
        "Agent response produced.",
        value["Text"],
        "responseContent",
        "zed_assistant",
      )];
    }
    const thinking = stringField(objectValue(value["Thinking"]), "text");
    if (thinking.trim() !== "") {
      return [activityDraft(
        this.agentKind,
        context,
        ActivityKind.REASONING,
        "Agent reasoning updated.",
        thinking,
        "reasoningContent",
        "thinking",
      )];
    }
    const toolUse = objectValue(value["ToolUse"]);
    if (toolUse === null) return [];
    const id = stringField(toolUse, "id");
    const name = stringField(toolUse, "name") || "tool";
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
      arguments: toolUse["input"],
    });
  }

  #toolResult(
    object: Record<string, unknown>,
    context: ParseContext,
  ): readonly ActivityDraft[] {
    const id = stringField(object, "tool_use_id");
    const key = `${context.sessionId}\u0000${id}`;
    const name = stringField(object, "tool_name") ||
      this.#toolNames.get(key) ||
      "tool";
    this.#toolNames.delete(key);
    const output = stringField(object, "content");
    return toolDrafts(this.agentKind, context, {
      invocationId: id,
      toolName: name,
      phase: object["is_error"] === true ? ToolPhase.FAILED : ToolPhase.SUCCEEDED,
      ...(output === "" ? {} : { output }),
    });
  }
}

/**
 * What a mention points at, as Zed shows it: a symbol, thread or rule name,
 * a file or folder name, or a URL. Mentions are tagged values such as
 * `{ File: { abs_path } }` or `{ Fetch: { url } }`.
 */
function mentionName(uri: unknown): string {
  const variant = objectValue(uri);
  const fields = variant === null
    ? null
    : objectValue(Object.values(variant)[0]);
  for (const field of ["name", "abs_path", "path", "url"]) {
    const value = stringField(fields, field);
    if (value !== "") {
      return field === "abs_path" || field === "path"
        ? value.split(/[\\/]/u).filter(Boolean).at(-1) ?? value
        : value;
    }
  }
  return variant === null ? "mention" : Object.keys(variant)[0] ?? "mention";
}

export const zedActivityAdapter: VendorActivityAdapter =
  new ZedActivityAdapter();
