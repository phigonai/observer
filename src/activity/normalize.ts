import { createHash } from "node:crypto";
import { create } from "@bufbuild/protobuf";
import {
  ActivityKind,
  AgentKind,
  PrivacyClass,
  Severity,
} from "../generated/phigon/v1/common_pb.js";
import {
  ActivityEventSchema,
  BrowserEventSchema,
  BrowserOperation,
  FilesystemEventSchema,
  FilesystemOperation,
  GitEventSchema,
  GitOperation,
  LifecycleEventSchema,
  type LifecyclePhase,
  ResourceReferenceSchema,
  TerminalEventSchema,
  TerminalPhase,
  ToolEventSchema,
  ToolPhase,
  VendorEventSchema,
} from "../generated/phigon/v1/telemetry_pb.js";
import type { ActivityDraft, ParseContext } from "./types.js";

export function vendorDraft(
  agentKind: AgentKind,
  context: ParseContext,
  source: string,
  vendorType: string,
  record: unknown,
): ActivityDraft {
  const sanitized = context.policy.vendorRecord(record);
  return {
    agentKind,
    sessionId: context.sessionId,
    observedAt: context.observedAt,
    privacyClass:
      sanitized.value === undefined
        ? PrivacyClass.SYSTEM_METADATA
        : PrivacyClass.USER_CONTENT,
    payload: {
      case: "vendor",
      value: create(VendorEventSchema, {
        source: context.policy.safeName(source, "generic"),
        vendorType: context.policy.safeName(vendorType, "record"),
        sourceRecordDigest: sanitized.digest,
        ...(sanitized.value === undefined
          ? {}
          : { payloadJson: sanitized.value }),
        payloadRedacted: sanitized.redacted,
        payloadTruncated: sanitized.truncated,
        payloadOmitted: sanitized.value === undefined,
        redactedFields: sanitized.redactedFields.slice(0, 256),
      }),
    },
  };
}

export function activityDraft(
  agentKind: AgentKind,
  context: ParseContext,
  kind: ActivityKind,
  summary: string,
  content: unknown,
  category: "promptContent" | "responseContent" | "reasoningContent",
  vendorType: string,
  severity: Severity = Severity.INFO,
): ActivityDraft {
  const sanitized = context.policy.content(content, category);
  return {
    agentKind,
    sessionId: context.sessionId,
    observedAt: context.observedAt,
    privacyClass:
      sanitized.value === undefined
        ? PrivacyClass.SYSTEM_METADATA
        : PrivacyClass.USER_CONTENT,
    payload: {
      case: "activity",
      value: create(ActivityEventSchema, {
        kind,
        severity,
        summary: context.policy.summary(summary),
        ...(sanitized.value === undefined
          ? {}
          : { content: sanitized.value }),
        contentRedacted:
          sanitized.value === undefined ||
          sanitized.redacted ||
          sanitized.truncated,
        vendorType: context.policy.safeName(vendorType, "unknown"),
      }),
    },
  };
}

export function lifecycleDraft(
  agentKind: AgentKind,
  context: ParseContext,
  phase: LifecyclePhase,
  reason: string,
): ActivityDraft {
  return {
    agentKind,
    sessionId: context.sessionId,
    observedAt: context.observedAt,
    privacyClass: PrivacyClass.SYSTEM_METADATA,
    payload: {
      case: "lifecycle",
      value: create(LifecycleEventSchema, {
        phase,
        reason: context.policy.summary(reason),
      }),
    },
  };
}

export function errorDraft(
  agentKind: AgentKind,
  context: ParseContext,
  vendorType: string,
): ActivityDraft {
  return {
    ...activityDraft(
      agentKind,
      context,
      ActivityKind.ERROR,
      "Agent reported an error.",
      undefined,
      "responseContent",
      vendorType,
      Severity.ERROR,
    ),
    privacyClass: PrivacyClass.SYSTEM_METADATA,
  };
}

export function toolDrafts(
  agentKind: AgentKind,
  context: ParseContext,
  input: Readonly<{
    invocationId?: unknown;
    toolName?: unknown;
    phase: ToolPhase;
    arguments?: unknown;
    output?: unknown;
    exitCode?: unknown;
  }>,
): readonly ActivityDraft[] {
  const toolName = context.policy.safeName(input.toolName, "unknown-tool");
  const invocationId = context.policy.safeName(
    input.invocationId,
    `inv_${digest(`${context.sessionId}:${toolName}`).slice(0, 24)}`,
  );
  const argumentsValue = context.policy.json(
    parseMaybeJSON(input.arguments),
    "commandArguments",
  );
  const outputValue = context.policy.json(
    parseMaybeJSON(input.output),
    "toolOutput",
  );
  // Preserve permitted results whose provider does not report an outcome.
  if (input.phase === ToolPhase.UNSPECIFIED && outputValue.value === undefined) return [];
  const exitCode =
    typeof input.exitCode === "number" &&
    Number.isSafeInteger(input.exitCode)
      ? input.exitCode
      : undefined;
  const drafts: ActivityDraft[] = [{
    agentKind,
    sessionId: context.sessionId,
    observedAt: context.observedAt,
    privacyClass:
      argumentsValue.value === undefined && outputValue.value === undefined
        ? PrivacyClass.SYSTEM_METADATA
        : PrivacyClass.USER_CONTENT,
    payload: {
      case: "tool",
      value: create(ToolEventSchema, {
        invocationId,
        toolName,
        phase: input.phase,
        ...(argumentsValue.value === undefined
          ? {}
          : { argumentsJson: argumentsValue.value }),
        ...(outputValue.value === undefined
          ? {}
          : { output: outputValue.value }),
        argumentsRedacted:
          argumentsValue.value === undefined ||
          argumentsValue.redacted ||
          argumentsValue.truncated,
        outputRedacted:
          outputValue.value === undefined ||
          outputValue.redacted ||
          outputValue.truncated,
        ...(exitCode === undefined ? {} : { exitCode }),
      }),
    },
  }];

  const rawArguments = parseMaybeJSON(input.arguments);
  const editorCommand = fileEditorCommand(rawArguments);
  const terminalTool = editorCommand === "" &&
    (isTerminalTool(toolName) || hasCommandArgument(rawArguments));
  if (terminalTool) {
    drafts.push(
      terminalDraft(agentKind, context, {
        invocationId,
        phase:
          input.phase === ToolPhase.SUCCEEDED ||
          input.phase === ToolPhase.FAILED ||
          input.phase === ToolPhase.CANCELLED
            ? TerminalPhase.EXITED
            : input.output !== undefined
              ? TerminalPhase.OUTPUT
            : TerminalPhase.STARTED,
        arguments: rawArguments,
        output: input.output,
        ...(exitCode === undefined ? {} : { exitCode }),
      }),
    );
  }
  const git = gitDraft(
    agentKind,
    context,
    invocationId,
    rawArguments,
    input.output,
  );
  if (git !== null) drafts.push(git);
  const rawPath = pathFromArguments(rawArguments);
  // A result that carries no arguments (for example a Claude tool_result)
  // belongs to the file operation already reported with its request. Do not
  // add a second, unnamed file event for it.
  const argumentlessResult =
    input.arguments === undefined &&
    input.phase !== ToolPhase.REQUESTED &&
    input.phase !== ToolPhase.RUNNING;
  if (
    context.policy.allowsMetadata("fileMetadata") &&
    !argumentlessResult &&
    (isFilesystemTool(toolName) || (!terminalTool && rawPath !== ""))
  ) {
    drafts.push(
      filesystemDraft(
        agentKind,
        context,
        toolName,
        rawArguments,
      ),
    );
  }
  if (
    context.policy.allowsMetadata("browserMetadata") &&
    (isBrowserTool(toolName) ||
      stringProperty(rawArguments, ["url", "href"]) !== "")
  ) {
    drafts.push(browserDraft(agentKind, context, toolName, rawArguments));
  }
  return drafts;
}

function terminalDraft(
  agentKind: AgentKind,
  context: ParseContext,
  input: Readonly<{
    invocationId: string;
    phase: TerminalPhase;
    arguments: unknown;
    output: unknown;
    exitCode?: number;
  }>,
): ActivityDraft {
  const command = commandFromArguments(input.arguments);
  const executable = context.policy.safeName(
    executableFromCommand(command),
    "unknown",
  );
  const argumentsValue = context.policy.content(
    command,
    "commandArguments",
  );
  const outputValue = context.policy.content(
    input.output,
    "terminalOutput",
  );
  return {
    agentKind,
    sessionId: context.sessionId,
    observedAt: context.observedAt,
    privacyClass:
      argumentsValue.value === undefined && outputValue.value === undefined
        ? PrivacyClass.SYSTEM_METADATA
        : PrivacyClass.USER_CONTENT,
    payload: {
      case: "terminal",
      value: create(TerminalEventSchema, {
        commandId: input.invocationId,
        phase: input.phase,
        executable,
        ...(argumentsValue.value === undefined
          ? {}
          : { arguments: argumentsValue.value }),
        ...(outputValue.value === undefined
          ? {}
          : { output: Buffer.from(outputValue.value, "utf8") }),
        outputRedacted:
          outputValue.value === undefined ||
          outputValue.redacted ||
          outputValue.truncated,
        ...(input.exitCode === undefined
          ? {}
          : { exitCode: input.exitCode }),
      }),
    },
  };
}

function filesystemDraft(
  agentKind: AgentKind,
  context: ParseContext,
  toolName: string,
  rawArguments: unknown,
): ActivityDraft {
  const rawPath = pathFromArguments(rawArguments);
  const identifier =
    rawPath === ""
      ? {
          digest: digest(`${context.sessionId}:file`),
          redacted: true,
        }
      : context.policy.identifier(rawPath, "filePaths");
  const rawContent = stringProperty(rawArguments, [
    "content",
    "text",
    "patch",
  ]);
  const content = context.policy.content(rawContent, "fileContent");
  return {
    agentKind,
    sessionId: context.sessionId,
    observedAt: context.observedAt,
    privacyClass: PrivacyClass.RESOURCE_METADATA,
    payload: {
      case: "filesystem",
      value: create(FilesystemEventSchema, {
        operation: filesystemOperation(toolName, rawArguments),
        resource: create(ResourceReferenceSchema, {
          kind: "file",
          displayName: rawPath === "" ? "redacted file" : "file",
          identifierDigest: identifier.digest,
          ...(identifier.value === undefined
            ? {}
            : { identifier: identifier.value }),
        }),
        ...(content.value === undefined
          ? {}
          : {
              content: Buffer.from(content.value, "utf8"),
              byteCount: BigInt(Buffer.byteLength(content.value, "utf8")),
            }),
        contentRedacted:
          content.value === undefined ||
          content.redacted ||
          content.truncated,
      }),
    },
  };
}

function browserDraft(
  agentKind: AgentKind,
  context: ParseContext,
  toolName: string,
  rawArguments: unknown,
): ActivityDraft {
  const rawURL = stringProperty(rawArguments, ["url", "href"]);
  const identifier = context.policy.identifier(rawURL, "browserUrls");
  const target = context.policy.content(
    stringProperty(rawArguments, [
      "target",
      "selector",
      "accessible_name",
      "text",
    ]),
    "browserContent",
  );
  let operation = BrowserOperation.READ;
  if (toolName.includes("navigate") || toolName.includes("open")) {
    operation = BrowserOperation.NAVIGATE;
  } else if (toolName.includes("click")) operation = BrowserOperation.CLICK;
  else if (toolName.includes("type")) operation = BrowserOperation.TYPE;
  else if (toolName.includes("download")) {
    operation = BrowserOperation.DOWNLOAD;
  }
  return {
    agentKind,
    sessionId: context.sessionId,
    observedAt: context.observedAt,
    privacyClass: PrivacyClass.RESOURCE_METADATA,
    payload: {
      case: "browser",
      value: create(BrowserEventSchema, {
        operation,
        ...(identifier.value === undefined
          ? {}
          : { url: identifier.value }),
        urlDigest: identifier.digest,
        ...(target.value === undefined ? {} : { target: target.value }),
        contentRedacted:
          target.value === undefined ||
          target.redacted ||
          target.truncated,
      }),
    },
  };
}

function gitDraft(
  agentKind: AgentKind,
  context: ParseContext,
  invocationId: string,
  rawArguments: unknown,
  rawOutput: unknown,
): ActivityDraft | null {
  const command = commandFromArguments(rawArguments);
  const match = /(?:^|\s)git(?:\s+-C\s+\S+)?\s+(status|diff|commit|branch|switch|checkout|push|pull)\b/iu.exec(
    command,
  );
  const pullRequest =
    /(?:^|\s)gh\s+pr\s+(?:create|view|list|checks|merge|close|reopen)\b/iu.test(
      command,
    );
  if (match === null && !pullRequest) return null;
  const operationName = match?.[1]?.toLowerCase();
  const operation = pullRequest
    ? GitOperation.PULL_REQUEST
    : gitOperation(operationName);
  const patch =
    operation === GitOperation.DIFF
      ? context.policy.content(rawOutput, "gitPatchContent")
      : undefined;
  return {
    agentKind,
    sessionId: context.sessionId,
    observedAt: context.observedAt,
    privacyClass: PrivacyClass.RESOURCE_METADATA,
    payload: {
      case: "git",
      value: create(GitEventSchema, {
        operation,
        repositoryDigest: digest(
          stringProperty(rawArguments, ["workdir", "cwd"]) ||
            context.sessionId,
        ),
        revision: invocationId,
        ...(patch?.value === undefined ? {} : { patch: patch.value }),
        patchRedacted:
          patch === undefined ||
          patch.value === undefined ||
          patch.redacted ||
          patch.truncated,
      }),
    },
  };
}

function gitOperation(value: string | undefined): GitOperation {
  if (value === "status") return GitOperation.STATUS;
  if (value === "diff") return GitOperation.DIFF;
  if (value === "commit") return GitOperation.COMMIT;
  if (
    value === "branch" ||
    value === "switch" ||
    value === "checkout"
  ) {
    return GitOperation.BRANCH;
  }
  if (value === "push") return GitOperation.PUSH;
  return GitOperation.STATUS;
}

function isTerminalTool(value: string): boolean {
  return /(?:exec|shell|terminal|command)/iu.test(value);
}

function hasCommandArgument(value: unknown): boolean {
  if (typeof value !== "object" || value === null) return false;
  return commandFromArguments(value) !== "";
}

function isFilesystemTool(value: string): boolean {
  const normalized = value.toLowerCase().replace(/[^a-z0-9]+/gu, "_");
  return /^(?:read|write|edit|create|delete|remove|rename|move|search|find|glob|grep|touch|unlink)$/u.test(
    normalized,
  ) ||
    /(?:apply_patch|filesystem|(?:read|write|edit|create|delete|remove|rename|move|search|find|glob|grep)_file|(?:search|find|glob|grep)_files)/u.test(
      normalized,
    );
}

function filesystemOperation(
  toolName: string,
  rawArguments: unknown,
): FilesystemOperation {
  const editorCommand = fileEditorCommand(rawArguments);
  if (editorCommand === "view") return FilesystemOperation.READ;
  if (editorCommand === "create") return FilesystemOperation.CREATE;
  if (editorCommand !== "") return FilesystemOperation.WRITE;
  const normalized = toolName.toLowerCase().replace(/[^a-z0-9]+/gu, "_");
  if (/(?:^|_)(?:read|get|view)(?:_|$)/u.test(normalized)) {
    return FilesystemOperation.READ;
  }
  if (/(?:^|_)(?:search|find|glob|grep)(?:_|$)/u.test(normalized)) {
    return FilesystemOperation.SEARCH;
  }
  if (/(?:^|_)(?:delete|remove|unlink)(?:_|$)/u.test(normalized)) {
    return FilesystemOperation.DELETE;
  }
  if (/(?:^|_)(?:rename|move)(?:_|$)/u.test(normalized)) {
    return FilesystemOperation.RENAME;
  }
  if (/(?:^|_)(?:create|add|touch)(?:_|$)/u.test(normalized)) {
    return FilesystemOperation.CREATE;
  }
  if (normalized.includes("apply_patch")) {
    const patch = stringProperty(rawArguments, ["patch", "input"]);
    if (/^\*\*\* Add File:/mu.test(patch)) {
      return FilesystemOperation.CREATE;
    }
    if (/^\*\*\* Delete File:/mu.test(patch)) {
      return FilesystemOperation.DELETE;
    }
    if (/^\*\*\* Move to:/mu.test(patch)) {
      return FilesystemOperation.RENAME;
    }
  }
  return FilesystemOperation.WRITE;
}

// Text-editor tools (Anthropic str_replace_based_edit_tool, Goose
// text_editor, Copilot str_replace_editor) name their sub-command in a
// `command` field next to the file path. That is not a shell command.
const fileEditorCommands = new Set([
  "view",
  "create",
  "write",
  "str_replace",
  "insert",
  "undo_edit",
]);

function fileEditorCommand(value: unknown): string {
  const command = stringProperty(value, ["command"]);
  return fileEditorCommands.has(command) && pathFromArguments(value) !== ""
    ? command
    : "";
}

function isBrowserTool(value: string): boolean {
  return /(?:browser|chrome|playwright)/iu.test(value);
}

function parseMaybeJSON(value: unknown): unknown {
  if (typeof value !== "string") return value;
  if (Buffer.byteLength(value, "utf8") > 1 << 20) return "[OVERSIZED]";
  try {
    return JSON.parse(value);
  } catch {
    return value;
  }
}

function commandFromArguments(value: unknown): string {
  if (typeof value === "string") return value;
  const direct = stringProperty(value, ["cmd", "command", "script"]);
  if (direct !== "" || typeof value !== "object" || value === null) {
    return direct;
  }
  const object = value as Record<string, unknown>;
  // Agents also report argv arrays (["bash", "-lc", "git status"]) and
  // batches of shell commands; keep them readable as one command line.
  for (const name of ["command", "cmd", "argv"]) {
    const argv = stringArray(object[name]);
    if (argv.length > 0) return argv.join(" ");
  }
  const commands = object["commands"];
  if (typeof commands === "string") return commands;
  return stringArray(commands).join("\n");
}

function stringArray(value: unknown): readonly string[] {
  return Array.isArray(value) &&
      value.length > 0 &&
      value.length <= 256 &&
      value.every((item) => typeof item === "string")
    ? value as string[]
    : [];
}

function executableFromCommand(command: string): string {
  const first = command.trim().split(/\s+/u)[0] ?? "";
  return first.split(/[\\/]/u).pop() ?? "";
}

function pathFromArguments(value: unknown): string {
  const direct = stringProperty(value, [
    "path",
    "file",
    "filePath",
    "file_path",
    "targetPath",
    "target_path",
    "workdir",
  ]);
  if (direct !== "") return direct;
  const patch = stringProperty(value, ["patch", "input"]);
  const match = /^\*\*\* (?:Update|Add|Delete) File: (.+)$/mu.exec(patch);
  return match?.[1]?.trim() ?? "";
}

function stringProperty(
  value: unknown,
  names: readonly string[],
): string {
  if (typeof value !== "object" || value === null) return "";
  for (const name of names) {
    const candidate = (value as Record<string, unknown>)[name];
    if (typeof candidate === "string") return candidate;
  }
  return "";
}

function digest(value: string): string {
  return createHash("sha256").update(value).digest("hex");
}

export const NormalizedAgentKind = AgentKind;
