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
  recordObservedAt,
  stringField,
} from "../record.js";
import type {
  ActivityDraft,
  ParseContext,
  VendorActivityAdapter,
} from "../types.js";

class CodexActivityAdapter implements VendorActivityAdapter {
  readonly id = "codex";
  readonly agentKind = AgentKind.CODEX;
  readonly #toolNames = new Map<string, string>();

  parse(record: unknown, context: ParseContext): readonly ActivityDraft[] {
    try {
      const object = objectValue(record);
      if (object === null) return [];
      const observedContext = {
        ...context,
        observedAt: recordObservedAt(record, context.observedAt),
      };
      const recordType = stringField(object, "type");
      const payload = objectValue(object["payload"]);
      if (recordType === "event_msg" && payload !== null) {
        return this.#parseEvent(payload, observedContext);
      }
      if (recordType === "response_item" && payload !== null) {
        return this.#parseResponseItem(payload, observedContext);
      }
      if (recordType === "session_meta") {
        return [
          lifecycleDraft(
            this.agentKind,
            observedContext,
            LifecyclePhase.DISCOVERED,
            "Codex session discovered.",
          ),
        ];
      }
      return [];
    } catch {
      return [errorDraft(this.agentKind, context, "malformed_record")];
    }
  }

  #parseEvent(
    payload: Record<string, unknown>,
    context: ParseContext,
  ): readonly ActivityDraft[] {
    const eventType = stringField(payload, "type");
    if (eventType === "user_message") {
      // Codex writes its persistent-goal continuation envelope to the same
      // source field as a real user message. Keep the vendor-native record,
      // but do not promote that orchestration envelope to a canonical prompt.
      if (isCodexContextOnlyMessage(payload["message"])) return [];
      return [activityDraft(
        this.agentKind,
        context,
        ActivityKind.PROMPT,
        "User prompt submitted.",
        payload["message"],
        "promptContent",
        eventType,
      )];
    }
    if (eventType === "agent_message") {
      return [activityDraft(
        this.agentKind,
        context,
        ActivityKind.RESPONSE,
        "Agent response produced.",
        payload["message"],
        "responseContent",
        eventType,
      )];
    }
    if (eventType === "agent_reasoning") {
      return [activityDraft(
        this.agentKind,
        context,
        ActivityKind.REASONING,
        "Agent reasoning updated.",
        payload["text"],
        "reasoningContent",
        eventType,
      )];
    }
    if (eventType === "task_started") {
      return [lifecycleDraft(
        this.agentKind,
        context,
        LifecyclePhase.STARTED,
        "Codex task started.",
      )];
    }
    if (eventType === "task_complete" || eventType === "turn_aborted") {
      return [lifecycleDraft(
        this.agentKind,
        context,
        LifecyclePhase.IDLE,
        eventType === "turn_aborted" ? "Codex turn stopped." : "Codex task completed.",
      )];
    }
    if (eventType === "patch_apply_end") {
      return toolDrafts(this.agentKind, context, {
        invocationId: payload["call_id"],
        toolName: "apply_patch",
        phase:
          payload["success"] === false
            ? ToolPhase.FAILED
            : ToolPhase.SUCCEEDED,
        arguments: { patch: payload["changes"] },
        output: payload["stderr"] || payload["stdout"],
      });
    }
    if (eventType === "item_completed") {
      return this.#parseCompletedItem(objectValue(payload["item"]), context);
    }
    if (eventType === "mcp_tool_call_end") {
      const outcome = codexReportedToolOutcome(payload);
      return toolDrafts(this.agentKind, context, {
        invocationId: payload["call_id"],
        toolName: nestedField(payload, "invocation", "tool"),
        phase: outcome.phase,
        output: payload["result"],
        ...(outcome.exitCode === undefined
          ? {}
          : { exitCode: outcome.exitCode }),
      });
    }
    if (/error|failed|crash/iu.test(eventType)) {
      return [errorDraft(this.agentKind, context, eventType)];
    }
    return [];
  }

  /**
   * Current Codex releases report the shell commands and file edits made by
   * a turn as completed thread items. The surrounding tool call (for example
   * a code-mode `exec` cell) does not carry the command line, exit code or
   * the edited paths, so these items are the only readable evidence.
   * Messages and reasoning items repeat response items and are skipped.
   */
  #parseCompletedItem(
    item: Record<string, unknown> | null,
    context: ParseContext,
  ): readonly ActivityDraft[] {
    if (item === null) return [];
    const itemType = stringField(item, "type");
    const itemID = stringField(item, "id");
    if (itemType === "CommandExecution") {
      const outcome = codexReportedToolOutcome(item);
      return toolDrafts(this.agentKind, context, {
        invocationId: itemID,
        toolName: "command_execution",
        phase: outcome.phase === ToolPhase.UNSPECIFIED
          ? codexItemPhase(stringField(item, "status"))
          : outcome.phase,
        arguments: {
          command: item["command"],
          ...(typeof item["cwd"] === "string" ? { cwd: item["cwd"] } : {}),
        },
        output: item["aggregated_output"],
        ...(outcome.exitCode === undefined
          ? {}
          : { exitCode: outcome.exitCode }),
      });
    }
    if (itemType === "FileChange") {
      const changes = objectValue(item["changes"]);
      if (changes === null) return [];
      const phase = codexItemPhase(stringField(item, "status"));
      return Object.entries(changes).slice(0, 15).flatMap(
        ([path, rawChange], index) => {
          const change = objectValue(rawChange);
          const changeType = stringField(change, "type");
          const movePath = stringField(change, "move_path");
          const diff = change?.["unified_diff"];
          const content = change?.["content"];
          return toolDrafts(this.agentKind, context, {
            invocationId: itemID === "" ? "" : `${itemID}:${index}`,
            toolName: changeType === "add"
              ? "create_file"
              : changeType === "delete"
                ? "delete_file"
                : movePath !== ""
                  ? "rename_file"
                  : "edit_file",
            phase,
            arguments: {
              path,
              ...(typeof diff === "string" ? { patch: diff } : {}),
              ...(typeof content === "string" ? { content } : {}),
            },
          });
        },
      );
    }
    return [];
  }

  #parseResponseItem(
    payload: Record<string, unknown>,
    context: ParseContext,
  ): readonly ActivityDraft[] {
    const itemType = stringField(payload, "type");
    if (itemType === "message") {
      const role = stringField(payload, "role");
      const content = codexResponseMessageContent(payload["content"], role);
      if (content === undefined) return [];
      if (role === "user") {
        if (isCodexContextOnlyMessage(content)) return [];
        return [activityDraft(
          this.agentKind,
          context,
          ActivityKind.PROMPT,
          "User prompt submitted.",
          content,
          "promptContent",
          "message",
        )];
      }
      if (role === "assistant") {
        return [activityDraft(
          this.agentKind,
          context,
          ActivityKind.RESPONSE,
          "Agent response produced.",
          content,
          "responseContent",
          "message",
        )];
      }
      return [];
    }
    if (itemType === "reasoning") {
      const summary = codexReasoningSummary(payload["summary"]);
      if (summary === undefined) return [];
      return [activityDraft(
        this.agentKind,
        context,
        ActivityKind.REASONING,
        "Agent reasoning summary produced.",
        summary,
        "reasoningContent",
        itemType,
      )];
    }
    if (itemType === "web_search_call") {
      const action = objectValue(payload["action"]);
      const actionType = action === null ? "" : stringField(action, "type");
      return toolDrafts(this.agentKind, context, {
        invocationId: stringField(payload, "id"),
        toolName: actionType === "" ? "web_search" : `web_search.${actionType}`,
        phase: codexCompletedToolPhase(stringField(payload, "status")),
        arguments: payload["action"],
      });
    }
    const callID =
      stringField(payload, "call_id") || stringField(payload, "id");
    const callKey = `${context.sessionId}\u0000${callID}`;
    if (
      itemType === "function_call" ||
      itemType === "custom_tool_call" ||
      itemType === "tool_search_call"
    ) {
      const name =
        stringField(payload, "name") ||
        (itemType === "tool_search_call" ? "tool_search" : "tool");
      if (callID !== "") {
        this.#toolNames.set(callKey, name);
        if (this.#toolNames.size > 4_096) {
          const oldest = this.#toolNames.keys().next().value;
          if (typeof oldest === "string") this.#toolNames.delete(oldest);
        }
      }
      return toolDrafts(this.agentKind, context, {
        invocationId: callID,
        toolName: name,
        phase: ToolPhase.REQUESTED,
        arguments:
          payload["arguments"] ??
          payload["input"] ??
          payload["execution"],
      });
    }
    if (
      itemType === "function_call_output" ||
      itemType === "custom_tool_call_output" ||
      itemType === "tool_search_output"
    ) {
      const name = this.#toolNames.get(callKey) ?? "tool";
      this.#toolNames.delete(callKey);
      const outcome = codexReportedToolOutcome(payload);
      return toolDrafts(this.agentKind, context, {
        invocationId: callID,
        toolName: name,
        phase: outcome.phase,
        output:
          payload["output"] ??
          payload["tools"] ??
          payload["execution"],
        ...(outcome.exitCode === undefined
          ? {}
          : { exitCode: outcome.exitCode }),
      });
    }
    return [];
  }
}

function codexReasoningSummary(value: unknown): string | undefined {
  if (!Array.isArray(value) || value.length === 0) return;
  const texts: string[] = [];
  for (const entry of value) {
    const block = objectValue(entry);
    if (
      block === null ||
      stringField(block, "type") !== "summary_text" ||
      typeof block["text"] !== "string" ||
      block["text"].trim() === ""
    ) {
      return;
    }
    texts.push(block["text"].trim());
  }
  return texts.join("\n\n");
}

function codexCompletedToolPhase(status: string): ToolPhase {
  if (status === "failed" || status === "error") return ToolPhase.FAILED;
  if (status === "completed" || status === "succeeded") {
    return ToolPhase.SUCCEEDED;
  }
  return ToolPhase.REQUESTED;
}

function codexItemPhase(status: string): ToolPhase {
  if (status === "completed") return ToolPhase.SUCCEEDED;
  if (status === "failed") return ToolPhase.FAILED;
  if (status === "declined") return ToolPhase.CANCELLED;
  if (status === "inProgress" || status === "in_progress") {
    return ToolPhase.RUNNING;
  }
  return ToolPhase.UNSPECIFIED;
}

function codexReportedToolOutcome(
  payload: Record<string, unknown>,
): Readonly<{ phase: ToolPhase; exitCode?: number }> {
  const evidence = new Set<ToolPhase>();
  const status = stringField(payload, "status").toLocaleLowerCase("en");
  if (status === "succeeded" || status === "success") {
    evidence.add(ToolPhase.SUCCEEDED);
  } else if (status === "failed" || status === "error") {
    evidence.add(ToolPhase.FAILED);
  } else if (status === "cancelled" || status === "canceled") {
    evidence.add(ToolPhase.CANCELLED);
  }

  if (payload["success"] === true) evidence.add(ToolPhase.SUCCEEDED);
  if (payload["success"] === false) evidence.add(ToolPhase.FAILED);

  const rawExitCode = payload["exit_code"] ?? payload["exitCode"];
  const exitCode =
    typeof rawExitCode === "number" && Number.isSafeInteger(rawExitCode)
      ? rawExitCode
      : undefined;
  if (exitCode !== undefined) {
    evidence.add(exitCode === 0 ? ToolPhase.SUCCEEDED : ToolPhase.FAILED);
  }

  if (evidence.size !== 1) return { phase: ToolPhase.UNSPECIFIED };
  const phase = evidence.values().next().value;
  if (phase === undefined) return { phase: ToolPhase.UNSPECIFIED };
  return {
    phase,
    ...(exitCode === undefined ? {} : { exitCode }),
  };
}

function codexResponseMessageContent(
  value: unknown,
  role: string,
): readonly Record<string, unknown>[] | undefined {
  if (role !== "user" && role !== "assistant") return;
  if (!Array.isArray(value) || value.length === 0) return;
  const expectedType = role === "user" ? "input_text" : "output_text";
  const blocks: Record<string, unknown>[] = [];
  for (const entry of value) {
    const block = objectValue(entry);
    // Keep the text in mixed image/text prompts without indexing image bytes.
    if (role === "user" && stringField(block, "type") === "input_image") {
      blocks.push({ type: "input_text", text: "[Image attachment]" });
      continue;
    }
    if (
      block === null ||
      stringField(block, "type") !== expectedType ||
      typeof block["text"] !== "string" ||
      block["text"].trim() === ""
    ) {
      return;
    }
    blocks.push(block);
  }
  return blocks;
}

const codexContextBlockTags = [
  "codex_internal_context",
  "environment_context",
  "recommended_plugins",
  "in-app-browser-context",
] as const;

function isCodexContextOnlyMessage(value: unknown): boolean {
  const texts = codexMessageTexts(value);
  return texts.length > 0 && texts.every(isCodexContextOnlyText);
}

function codexMessageTexts(value: unknown, depth = 0): string[] {
  if (typeof value === "string") return [value];
  if (depth >= 4) return [];
  if (Array.isArray(value)) {
    return value.flatMap((item) => codexMessageTexts(item, depth + 1));
  }
  const object = objectValue(value);
  if (object === null) return [];
  return ["text", "content", "message"].flatMap((field) =>
    codexMessageTexts(object[field], depth + 1)
  );
}

function isCodexContextOnlyText(value: string): boolean {
  let remainder = value.trim();
  for (const tag of codexContextBlockTags) {
    remainder = remainder.replace(
      new RegExp(`<${tag}\\b[^>]*>[\\s\\S]*?<\\/${tag}>`, "gu"),
      " ",
    );
  }
  return remainder.trim().length === 0;
}

export const codexActivityAdapter: VendorActivityAdapter =
  new CodexActivityAdapter();
