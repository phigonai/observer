import {
  ActivityKind,
  type AgentKind,
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
  extractText,
  nestedField,
  objectValue,
  recordObservedAt,
  stringField,
} from "../record.js";
import type {
  ActivityDraft,
  VendorActivityAdapter,
} from "../types.js";

export function createOpenAICompatibleAdapter(
  id: string,
  agentKind: AgentKind,
  displayName: string,
): VendorActivityAdapter {
  const toolNames = new Map<string, string>();
  return {
    id,
    agentKind,
    parse(record, context) {
      try {
        const object = objectValue(record);
        if (object === null) return [];
        const observedContext = {
          ...context,
          observedAt: recordObservedAt(record, context.observedAt),
        };
        const type = stringField(object, "type");
        if (type === "phigon_guardian_decision") {
          const decisionID = stringField(object, "decision_id");
          if (!/^[0-9a-f]{8}-[0-9a-f-]{27,}$/iu.test(decisionID)) {
            return [errorDraft(agentKind, observedContext, "malformed_guardian_decision")];
          }
          return toolDrafts(agentKind, observedContext, {
            invocationId: decisionID,
            toolName: "phigon.guardian.authorize_action",
            phase: ToolPhase.SUCCEEDED,
            output: object,
          });
        }
        if (type === "phigon_managed_command") {
          const invocationID = stringField(object, "invocation_id");
          const phase = stringField(object, "phase");
          if (!/^[0-9a-f]{8}-[0-9a-f-]{27,}$/iu.test(invocationID)) {
            return [errorDraft(agentKind, observedContext, "malformed_managed_command")];
          }
          return toolDrafts(agentKind, observedContext, {
            invocationId: invocationID,
            toolName: "terminal.exec",
            phase: phase === "requested"
              ? ToolPhase.REQUESTED
              : phase === "running"
                ? ToolPhase.RUNNING
                : phase === "succeeded"
                  ? ToolPhase.SUCCEEDED
                  : ToolPhase.FAILED,
            arguments: {
              executable: object["executable"],
              arguments: object["arguments"],
              stream: object["stream"],
            },
            output: object["output"],
            exitCode: object["exit_code"],
          });
        }
        if (/error|failed|crash/iu.test(type)) {
          return [errorDraft(agentKind, observedContext, type)];
        }
        if (/session_(?:start|created)|task_start/iu.test(type)) {
          return [lifecycleDraft(
            agentKind,
            observedContext,
            LifecyclePhase.STARTED,
            `${displayName} task started.`,
          )];
        }
        if (/session_(?:end|completed)|task_(?:end|complete)/iu.test(type)) {
          return [lifecycleDraft(
            agentKind,
            observedContext,
            LifecyclePhase.IDLE,
            `${displayName} task completed.`,
          )];
        }
        const message = objectValue(object["message"]) ?? object;
        const role =
          stringField(message, "role") || stringField(object, "role");
        const drafts: ActivityDraft[] = [];
        const toolCalls = [
          ...arrayField(message, "tool_calls"),
          ...arrayField(message, "toolCalls"),
        ];
        for (const call of toolCalls.slice(0, 128)) {
          const callID =
            stringField(call, "id") || stringField(call, "call_id");
          const name =
            stringField(call, "name") ||
            String(nestedField(call, "function", "name") ?? "tool");
          if (callID !== "") toolNames.set(callID, name);
          drafts.push(...toolDrafts(agentKind, observedContext, {
            invocationId: callID,
            toolName: name,
            phase: ToolPhase.REQUESTED,
            arguments:
              nestedField(call, "function", "arguments") ??
              nestedField(call, "function", "input") ??
              nestedField(call, "arguments"),
          }));
        }
        if (role === "tool") {
          const callID =
            stringField(message, "tool_call_id") ||
            stringField(object, "tool_call_id");
          drafts.push(...toolDrafts(agentKind, observedContext, {
            invocationId: callID,
            toolName: toolNames.get(callID) ?? "tool",
            phase: ToolPhase.SUCCEEDED,
            output: message["content"] ?? object["content"],
          }));
          toolNames.delete(callID);
          return drafts;
        }
        const content = extractText(
          message["content"] ?? object["content"],
        );
        if (content !== "" && (role === "user" || role === "assistant")) {
          drafts.unshift(activityDraft(
            agentKind,
            observedContext,
            role === "user"
              ? ActivityKind.PROMPT
              : ActivityKind.RESPONSE,
            role === "user"
              ? "User prompt submitted."
              : "Agent response produced.",
            content,
            role === "user" ? "promptContent" : "responseContent",
            `${id}_${role}`,
          ));
        }
        return drafts;
      } catch {
        return [errorDraft(agentKind, context, "malformed_record")];
      }
    },
  };
}
