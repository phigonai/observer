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
  nestedField,
  objectValue,
  stringField,
} from "../record.js";
import type {
  ActivityDraft,
  ParseContext,
  VendorActivityAdapter,
} from "../types.js";

class OpenCodeActivityAdapter implements VendorActivityAdapter {
  readonly id = "opencode";
  readonly agentKind = AgentKind.GENERIC;
  readonly #startedSessions = new Set<string>();
  readonly #messageRoles = new Map<string, "user" | "assistant" | "conflict">();

  parse(record: unknown, context: ParseContext): readonly ActivityDraft[] {
    try {
      const object = objectValue(record);
      if (object === null) return [];
      const observedContext = {
        ...context,
        observedAt: openCodeObservedAt(object, context.observedAt),
      };
      const type = normalizeOpenCodeType(stringField(object, "type"));
      const part = objectValue(object["part"]);
      this.#rememberMessageRole(objectValue(object["message_info"]), context.sessionId);
      if (type === "message.updated") {
        this.#rememberMessageRole(objectValue(object["info"]), context.sessionId);
        return [];
      }
      const partType = normalizeOpenCodeType(stringField(part, "type"));
      const normalizedType = type === "message.part.updated"
        ? partType
        : type;

      if (normalizedType === "step_start") {
        if (this.#startedSessions.has(context.sessionId)) return [];
        this.#rememberStarted(context.sessionId);
        return [lifecycleDraft(
          this.agentKind,
          observedContext,
          LifecyclePhase.STARTED,
          "OpenCode task started.",
        )];
      }
      if (normalizedType === "step_finish") {
        const reason = stringField(part, "reason");
        if (reason !== "stop") return [];
        this.#startedSessions.delete(context.sessionId);
        return [lifecycleDraft(
          this.agentKind,
          observedContext,
          LifecyclePhase.IDLE,
          "OpenCode task completed.",
        )];
      }
      if (normalizedType === "text" && part !== null) {
        if (stringField(part, "text").trim() === "") {
          // OpenCode emits an empty text-part update before the completed
          // text update. Keep the native event, but do not invent an empty
          // chat bubble from an incomplete streaming part.
          return [];
        }
        const messageID = stringField(part, "messageID") ||
          stringField(part, "messageId");
        const messageRole = this.#messageRoles.get(`${context.sessionId}\u0000${messageID}`);
        if (type === "message.part.updated" && messageRole === "user") {
          return [activityDraft(
            this.agentKind,
            observedContext,
            ActivityKind.PROMPT,
            "User prompt submitted.",
            part["text"],
            "promptContent",
            "text",
          )];
        }
        if (
          type === "message.part.updated" &&
          (messageRole === undefined || messageRole === "conflict")
        ) {
          // A text part without a stable provider-reported message role is
          // preserved as vendor evidence but never guessed into a speaker.
          return [];
        }
        return [activityDraft(
          this.agentKind,
          observedContext,
          ActivityKind.RESPONSE,
          "Agent response produced.",
          part["text"],
          "responseContent",
          "text",
        )];
      }
      if (
        (normalizedType === "tool_use" || normalizedType === "tool") &&
        part !== null
      ) {
        const state = objectValue(part["state"]);
        const status = stringField(state, "status");
        return toolDrafts(this.agentKind, observedContext, {
          invocationId: part["callID"],
          toolName: part["tool"],
          phase: openCodeToolPhase(status),
          arguments: state?.["input"],
          output: state?.["output"],
          exitCode: nestedField(state, "metadata", "exitCode"),
        });
      }
      if (/error|failed|crash/iu.test(normalizedType)) {
        return [errorDraft(this.agentKind, observedContext, normalizedType)];
      }
      return [];
    } catch {
      return [errorDraft(this.agentKind, context, "malformed_record")];
    }
  }

  #rememberStarted(sessionId: string): void {
    this.#startedSessions.add(sessionId);
    if (this.#startedSessions.size <= 4_096) return;
    const oldest = this.#startedSessions.values().next().value;
    if (typeof oldest === "string") this.#startedSessions.delete(oldest);
  }

  #rememberMessageRole(info: Record<string, unknown> | null, sessionID: string): void {
    if (info === null) return;
    const messageID = stringField(info, "id");
    const role = stringField(info, "role");
    if (
      messageID === "" ||
      (role !== "user" && role !== "assistant")
    ) return;
    const key = `${sessionID}\u0000${messageID}`;
    const current = this.#messageRoles.get(key);
    this.#messageRoles.set(
      key,
      current === undefined || current === role ? role : "conflict",
    );
    if (this.#messageRoles.size <= 8_192) return;
    const oldest = this.#messageRoles.keys().next().value;
    if (typeof oldest === "string") this.#messageRoles.delete(oldest);
  }
}

function normalizeOpenCodeType(value: string): string {
  return value
    .replace(/\.\d+$/u, "")
    .replace(/-/gu, "_");
}

function openCodeObservedAt(
  object: Record<string, unknown>,
  fallback: Date,
): Date {
  const timestamp = object["timestamp"];
  if (typeof timestamp !== "number" || !Number.isFinite(timestamp)) {
    return fallback;
  }
  const parsed = new Date(timestamp);
  return Number.isNaN(parsed.getTime()) ? fallback : parsed;
}

function openCodeToolPhase(status: string): ToolPhase {
  if (status === "completed") return ToolPhase.SUCCEEDED;
  if (status === "error" || status === "failed") return ToolPhase.FAILED;
  if (status === "cancelled") return ToolPhase.CANCELLED;
  if (status === "running") return ToolPhase.RUNNING;
  return ToolPhase.REQUESTED;
}

export const openCodeActivityAdapter: VendorActivityAdapter =
  new OpenCodeActivityAdapter();
