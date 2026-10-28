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
import { createOpenAICompatibleAdapter } from "./openai-compatible.js";

const maxTrackedToolCalls = 4_096;
const maxRememberedCommandBytes = 64 << 10;

type ToolCallState = {
  name: string;
  command?: string;
};

/**
 * GitHub Copilot CLI session event log
 * (~/.copilot/session-state/<session>/events.jsonl). Each line is one
 * persisted session event `{id, timestamp, parentId, type, data}` as defined
 * by the Copilot SDK session event schema. Streaming deltas are ephemeral
 * and never written to the log.
 */
class CopilotActivityAdapter implements VendorActivityAdapter {
  readonly id = "copilot";
  readonly agentKind = AgentKind.GENERIC;
  readonly #toolCalls = new Map<string, ToolCallState>();
  // Records written by `phigon-observer ingest` or older bridges use the
  // OpenAI-compatible chat shape instead of the session event schema.
  readonly #compatible = createOpenAICompatibleAdapter(
    "copilot",
    AgentKind.GENERIC,
    "GitHub Copilot CLI",
  );

  parse(record: unknown, context: ParseContext): readonly ActivityDraft[] {
    try {
      const object = objectValue(record);
      if (object === null) return [];
      const type = stringField(object, "type");
      const data = objectValue(object["data"]);
      if (data === null || !/^[a-z_]+\.[a-z_.]+$|^abort$/u.test(type)) {
        return this.#compatible.parse(record, context);
      }
      const observedContext = {
        ...context,
        observedAt: recordObservedAt(record, context.observedAt),
      };
      return this.#parseEvent(type, data, observedContext);
    } catch {
      return [errorDraft(this.agentKind, context, "malformed_record")];
    }
  }

  #parseEvent(
    type: string,
    data: Record<string, unknown>,
    context: ParseContext,
  ): readonly ActivityDraft[] {
    switch (type) {
      case "session.start":
      case "session.resume":
        return [lifecycleDraft(
          this.agentKind,
          context,
          LifecyclePhase.STARTED,
          type === "session.start"
            ? "GitHub Copilot CLI session started."
            : "GitHub Copilot CLI session resumed.",
        )];
      case "session.error":
        return [errorDraft(
          this.agentKind,
          context,
          stringField(data, "errorType") || type,
        )];
      case "session.shutdown":
        return stringField(data, "shutdownType") === "error"
          ? [errorDraft(this.agentKind, context, type)]
          : [lifecycleDraft(
              this.agentKind,
              context,
              LifecyclePhase.STOPPED,
              "GitHub Copilot CLI session ended.",
            )];
      case "session.task_complete":
        return [lifecycleDraft(
          this.agentKind,
          context,
          LifecyclePhase.IDLE,
          "GitHub Copilot CLI task completed.",
        )];
      case "abort":
        return [lifecycleDraft(
          this.agentKind,
          context,
          LifecyclePhase.IDLE,
          "GitHub Copilot CLI turn stopped.",
        )];
      case "user.message":
        return this.#userMessage(data, context);
      case "assistant.message":
        return this.#assistantMessage(data, context);
      case "assistant.reasoning": {
        const content = stringField(data, "content");
        if (content.trim() === "") return [];
        return [activityDraft(
          this.agentKind,
          context,
          ActivityKind.REASONING,
          "Agent reasoning updated.",
          content,
          "reasoningContent",
          type,
        )];
      }
      case "tool.execution_start":
        return this.#toolStart(data, context);
      case "tool.execution_complete":
        return this.#toolComplete(data, context);
      default:
        return [];
    }
  }

  #userMessage(
    data: Record<string, unknown>,
    context: ParseContext,
  ): readonly ActivityDraft[] {
    const source = stringField(data, "source");
    // Autopilot continuations, hidden skill injections and inter-agent
    // prompts are reported on the same event but were not typed by a user.
    if (
      data["isAutopilotContinuation"] === true ||
      source.startsWith("skill-") ||
      source.startsWith("agent-")
    ) {
      return [];
    }
    const content = stringField(data, "content");
    if (content.trim() === "") return [];
    return [activityDraft(
      this.agentKind,
      context,
      ActivityKind.PROMPT,
      "User prompt submitted.",
      content,
      "promptContent",
      "user.message",
    )];
  }

  #assistantMessage(
    data: Record<string, unknown>,
    context: ParseContext,
  ): readonly ActivityDraft[] {
    const drafts: ActivityDraft[] = [];
    const content = stringField(data, "content");
    if (content.trim() !== "") {
      drafts.push(activityDraft(
        this.agentKind,
        context,
        ActivityKind.RESPONSE,
        "Agent response produced.",
        content,
        "responseContent",
        "assistant.message",
      ));
    }
    for (const request of arrayField(data, "toolRequests").slice(0, 64)) {
      const toolCallID = stringField(request, "toolCallId");
      const name = stringField(request, "name") || "tool";
      const args = objectValue(request)?.["arguments"];
      this.#remember(context.sessionId, toolCallID, name, args);
      drafts.push(...toolDrafts(this.agentKind, context, {
        invocationId: toolCallID,
        toolName: name,
        phase: ToolPhase.REQUESTED,
        arguments: args,
      }));
    }
    return drafts;
  }

  #toolStart(
    data: Record<string, unknown>,
    context: ParseContext,
  ): readonly ActivityDraft[] {
    const toolCallID = stringField(data, "toolCallId");
    const key = `${context.sessionId}\u0000${toolCallID}`;
    if (toolCallID !== "" && this.#toolCalls.has(key)) {
      // The assistant message already reported this request with its
      // arguments; starting it adds no new evidence.
      return [];
    }
    const name = stringField(data, "toolName") || "tool";
    const args = data["arguments"];
    this.#remember(context.sessionId, toolCallID, name, args);
    return toolDrafts(this.agentKind, context, {
      invocationId: toolCallID,
      toolName: name,
      phase: ToolPhase.RUNNING,
      arguments: args,
    });
  }

  #toolComplete(
    data: Record<string, unknown>,
    context: ParseContext,
  ): readonly ActivityDraft[] {
    const toolCallID = stringField(data, "toolCallId");
    const key = `${context.sessionId}\u0000${toolCallID}`;
    const state = this.#toolCalls.get(key);
    this.#toolCalls.delete(key);
    const result = objectValue(data["result"]);
    const detailed = stringField(result, "detailedContent");
    const concise = stringField(result, "content");
    const error = stringField(objectValue(data["error"]), "message");
    const exitCode = objectValue(data["shellExecution"])?.["exitCode"];
    return toolDrafts(this.agentKind, context, {
      invocationId: toolCallID,
      toolName: state?.name ?? "tool",
      phase: data["success"] === true
        ? ToolPhase.SUCCEEDED
        : data["success"] === false
          ? ToolPhase.FAILED
          : ToolPhase.UNSPECIFIED,
      // Only a shell command is repeated, so the terminal event can carry
      // its exit status; file arguments were reported with the request.
      ...(state?.command === undefined
        ? {}
        : { arguments: { command: state.command } }),
      output: detailed || concise || error || undefined,
      ...(typeof exitCode === "number" ? { exitCode } : {}),
    });
  }

  #remember(
    sessionID: string,
    toolCallID: string,
    name: string,
    args: unknown,
  ): void {
    if (toolCallID === "") return;
    const command = stringField(args, "command");
    this.#toolCalls.set(`${sessionID}\u0000${toolCallID}`, {
      name,
      ...(command !== "" &&
          Buffer.byteLength(command, "utf8") <= maxRememberedCommandBytes
        ? { command }
        : {}),
    });
    if (this.#toolCalls.size <= maxTrackedToolCalls) return;
    const oldest = this.#toolCalls.keys().next().value;
    if (oldest !== undefined) this.#toolCalls.delete(oldest);
  }
}

export const copilotActivityAdapter: VendorActivityAdapter =
  new CopilotActivityAdapter();
