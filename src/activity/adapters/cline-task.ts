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
  recordObservedAt,
  stringField,
} from "../record.js";
import type {
  ActivityDraft,
  ParseContext,
  VendorActivityAdapter,
} from "../types.js";

/** Set by the source on a task's first message: the user's request. */
export const clineTaskFirstMessageField = "phigon_first_message";

const maxTrackedSessions = 4_096;
// Older Cline appended this to a command that waits for approval.
const approvalMarker = "REQ_APP";

/**
 * Canonical names for the file tools Cline and its forks report, so they
 * become file events like other agents' read_file and edit_file.
 */
const fileToolNames: Readonly<Record<string, string>> = {
  appliedDiff: "edit_file",
  editedExistingFile: "edit_file",
  insertContent: "edit_file",
  searchAndReplace: "edit_file",
  newFileCreated: "create_file",
  fileDeleted: "delete_file",
  readFile: "read_file",
  listFilesTopLevel: "list_files",
  listFilesRecursive: "list_files",
  searchFiles: "search_files",
};

/**
 * Tasks of the Cline VS Code extension and its forks Roo Code and Kilo Code,
 * read from `<global storage>/tasks/<task id>/ui_messages.json`: the list of
 * messages the extension shows, each `{ ts, type: "say" | "ask", say?, ask?,
 * text?, partial? }`. The first message (or a `task` say) is the user's
 * request and `user_feedback` a later one; `text`, `completion_result` and
 * follow-up questions are the agent's replies. A `command` is followed by
 * `command_output` chunks, and a `tool` message carries JSON such as
 * `{ tool: "editedExistingFile", path }`.
 */
class ClineTaskActivityAdapter implements VendorActivityAdapter {
  readonly agentKind = AgentKind.GENERIC;
  // The last command per session, which later output belongs to.
  readonly #commands = new Map<string, string>();

  constructor(
    readonly id: string,
    readonly displayName: string,
  ) {}

  parse(record: unknown, context: ParseContext): readonly ActivityDraft[] {
    try {
      const message = objectValue(record);
      if (message === null) return [];
      const observedContext = {
        ...context,
        observedAt: recordObservedAt(record, context.observedAt),
      };
      const type = stringField(message, "type");
      const kind = type === "say"
        ? stringField(message, "say")
        : type === "ask"
          ? stringField(message, "ask")
          : "";
      const text = stringField(message, "text");
      const first = message[clineTaskFirstMessageField] === true;
      if ((first && kind === "text") || kind === "task" || kind === "user_feedback") {
        return this.#activity(observedContext, ActivityKind.PROMPT, text);
      }
      switch (kind) {
        case "text":
        case "completion_result":
          // The closing ask repeats nothing; the result itself is a say.
          return type === "say"
            ? this.#activity(observedContext, ActivityKind.RESPONSE, text)
            : [lifecycleDraft(
                this.agentKind,
                observedContext,
                LifecyclePhase.IDLE,
                `${this.displayName} task completed.`,
              )];
        case "followup":
        case "plan_mode_respond":
        case "act_mode_respond":
          return this.#activity(
            observedContext,
            ActivityKind.RESPONSE,
            jsonField(text, kind === "followup" ? "question" : "response") ?? text,
          );
        case "reasoning":
          return this.#activity(observedContext, ActivityKind.REASONING, text);
        case "command":
          return this.#command(observedContext, message, text);
        case "command_output":
          return this.#commandOutput(observedContext, text);
        case "tool":
          return this.#tool(observedContext, message, text);
        case "use_mcp_server":
          return this.#mcp(observedContext, message, text);
        case "error":
        case "api_req_failed":
        case "mistake_limit_reached":
        case "diff_error":
          return [errorDraft(this.agentKind, observedContext, kind)];
        default:
          return [];
      }
    } catch {
      return [errorDraft(this.agentKind, context, "malformed_record")];
    }
  }

  #activity(
    context: ParseContext,
    kind: ActivityKind,
    text: string,
  ): readonly ActivityDraft[] {
    if (text.trim() === "") return [];
    const prompt = kind === ActivityKind.PROMPT;
    const reasoning = kind === ActivityKind.REASONING;
    return [activityDraft(
      this.agentKind,
      context,
      kind,
      prompt
        ? "User prompt submitted."
        : reasoning
          ? "Agent reasoning updated."
          : "Agent response produced.",
      text,
      prompt ? "promptContent" : reasoning ? "reasoningContent" : "responseContent",
      prompt ? "cline_user" : reasoning ? "thinking" : "cline_assistant",
    )];
  }

  #command(
    context: ParseContext,
    message: Record<string, unknown>,
    text: string,
  ): readonly ActivityDraft[] {
    const command = text.endsWith(approvalMarker)
      ? text.slice(0, -approvalMarker.length).trimEnd()
      : text.trim();
    if (command === "") return [];
    const id = invocationId(message, "command");
    this.#remember(context.sessionId, id);
    return toolDrafts(this.agentKind, context, {
      invocationId: id,
      toolName: "execute_command",
      phase: ToolPhase.REQUESTED,
      arguments: { command },
    });
  }

  #commandOutput(
    context: ParseContext,
    text: string,
  ): readonly ActivityDraft[] {
    const id = this.#commands.get(context.sessionId);
    if (id === undefined || text === "") return [];
    // Output arrives in chunks without an outcome; each chunk is terminal
    // output of the command before it.
    return toolDrafts(this.agentKind, context, {
      invocationId: id,
      toolName: "execute_command",
      phase: ToolPhase.UNSPECIFIED,
      output: text,
    });
  }

  #tool(
    context: ParseContext,
    message: Record<string, unknown>,
    text: string,
  ): readonly ActivityDraft[] {
    const tool = parseObject(text);
    if (tool === null) return [];
    const name = stringField(tool, "tool");
    return toolDrafts(this.agentKind, context, {
      invocationId: invocationId(message, "tool"),
      toolName: fileToolNames[name] ?? (name || "tool"),
      phase: ToolPhase.REQUESTED,
      arguments: tool,
    });
  }

  #mcp(
    context: ParseContext,
    message: Record<string, unknown>,
    text: string,
  ): readonly ActivityDraft[] {
    const request = parseObject(text);
    if (request === null) return [];
    const server = stringField(request, "serverName");
    const tool = stringField(request, "toolName") || stringField(request, "uri");
    return toolDrafts(this.agentKind, context, {
      invocationId: invocationId(message, "mcp"),
      toolName: [server, tool].filter(Boolean).join("__") || "mcp",
      phase: ToolPhase.REQUESTED,
      arguments: request["arguments"] ?? request,
    });
  }

  #remember(sessionId: string, id: string): void {
    this.#commands.delete(sessionId);
    this.#commands.set(sessionId, id);
    if (this.#commands.size > maxTrackedSessions) {
      const oldest = this.#commands.keys().next().value;
      if (oldest !== undefined) this.#commands.delete(oldest);
    }
  }
}

/** A stable invocation id from the message's own timestamp. */
function invocationId(message: Record<string, unknown>, prefix: string): string {
  const ts = message["ts"];
  return typeof ts === "number" && Number.isSafeInteger(ts) ? `${prefix}_${ts}` : "";
}

function parseObject(text: string): Record<string, unknown> | null {
  if (!text.trimStart().startsWith("{")) return null;
  try {
    return objectValue(JSON.parse(text));
  } catch {
    return null;
  }
}

/** A string field of a JSON text, as Cline writes questions and plans. */
function jsonField(text: string, field: string): string | undefined {
  const value = parseObject(text)?.[field];
  return typeof value === "string" ? value : undefined;
}

export const clineExtensionActivityAdapter: VendorActivityAdapter =
  new ClineTaskActivityAdapter("cline-task", "Cline");
export const rooCodeActivityAdapter: VendorActivityAdapter =
  new ClineTaskActivityAdapter("roo-code-task", "Roo Code");
export const kiloCodeActivityAdapter: VendorActivityAdapter =
  new ClineTaskActivityAdapter("kilo-code-task", "Kilo Code");
