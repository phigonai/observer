import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { claudeActivityAdapter } from "../src/activity/adapters/claude.js";
import { clineActivityAdapter } from "../src/activity/adapters/cline.js";
import { codexActivityAdapter } from "../src/activity/adapters/codex.js";
import { copilotActivityAdapter } from "../src/activity/adapters/copilot.js";
import { copilotChatActivityAdapter } from "../src/activity/adapters/copilot-chat.js";
import { cursorActivityAdapter } from "../src/activity/adapters/cursor.js";
import { factoryDroidActivityAdapter } from "../src/activity/adapters/factory-droid.js";
import { geminiActivityAdapter } from "../src/activity/adapters/gemini.js";
import { gooseActivityAdapter } from "../src/activity/adapters/goose.js";
import { genericActivityAdapter } from "../src/activity/adapters/generic.js";
import { hermesActivityAdapter } from "../src/activity/adapters/hermes.js";
import { kiroActivityAdapter } from "../src/activity/adapters/kiro.js";
import { openClawActivityAdapter } from "../src/activity/adapters/openclaw.js";
import { openCodeActivityAdapter } from "../src/activity/adapters/opencode.js";
import { zedActivityAdapter } from "../src/activity/adapters/zed.js";
import { errorDraft, toolDrafts } from "../src/activity/normalize.js";
import { LocalPolicyEngine, truncateUTF8 } from "../src/activity/policy.js";
import type {
  ActivityDraft,
  VendorActivityAdapter,
} from "../src/activity/types.js";
import { loadConfig } from "../src/config.js";
import {
  ActivityKind,
  AgentKind,
  Severity,
} from "../src/generated/phigon/v1/common_pb.js";
import {
  FilesystemOperation,
  LifecyclePhase,
  TerminalPhase,
  ToolPhase,
} from "../src/generated/phigon/v1/telemetry_pb.js";

const fixtureRoot = new URL("../../test/fixtures/activity/", import.meta.url);
const observedAt = new Date("2026-07-24T10:00:00.000Z");

test("vendor fixtures match the normalized golden event matrix", async () => {
  const adapters: Readonly<Record<string, VendorActivityAdapter>> = {
    claude: claudeActivityAdapter,
    codex: codexActivityAdapter,
    hermes: hermesActivityAdapter,
    openclaw: openClawActivityAdapter,
  };
  const golden: unknown = JSON.parse(
    await readFile(new URL("golden.json", fixtureRoot), "utf8"),
  );
  const actual: Record<string, Record<string, number>> = {};
  const policy = metadataOnlyPolicy();

  for (const [name, adapter] of Object.entries(adapters)) {
    const drafts = await parseFixture(name, adapter, policy);
    actual[name] = countPayloads(drafts);
    assert.ok(drafts.length > 0);
    assertMetadataOnly(drafts);
  }

  assert.deepEqual(actual, golden);
});

test("enabled content is redacted locally before normalized output", async () => {
  const config = loadConfig({
    PHIGON_COLLECT_PROMPT_CONTENT: "true",
    PHIGON_COLLECT_RESPONSE_CONTENT: "true",
    PHIGON_COLLECT_REASONING_CONTENT: "true",
    PHIGON_COLLECT_COMMAND_ARGUMENTS: "true",
    PHIGON_COLLECT_TERMINAL_OUTPUT: "true",
    PHIGON_COLLECT_FILE_PATHS: "true",
    PHIGON_COLLECT_BROWSER_URLS: "true",
    PHIGON_COLLECT_TOOL_OUTPUT: "true",
    PHIGON_REDACT_PATH_PATTERNS: "/private/project",
  });
  const policy = new LocalPolicyEngine(
    config.policy,
    config.redactionPathPatterns,
  );
  const drafts = [
    ...(await parseFixture("codex", codexActivityAdapter, policy)),
    ...(await parseFixture("claude", claudeActivityAdapter, policy)),
  ];
  const serialized = serialize(drafts);

  assert.match(serialized, /\[REDACTED_PATH\]/u);
  assert.match(serialized, /\[REDACTED_SECRET\]/u);
  assert.doesNotMatch(serialized, /\/private\/project/u);
  assert.doesNotMatch(serialized, /sk-fixturesecret/u);
  assert.doesNotMatch(serialized, /ghp_012345/u);
  assert.doesNotMatch(serialized, /hunter2fixture/u);
});

test("OpenCode CLI JSON produces canonical tool and lifecycle events", async () => {
  const drafts = await parseFixture(
    "opencode",
    openCodeActivityAdapter,
    metadataOnlyPolicy(),
  );
  assert.deepEqual(countPayloads(drafts), {
    activity: 1,
    filesystem: 2,
    lifecycle: 2,
    tool: 2,
  });
  const tools = drafts.filter((draft) => draft.payload.case === "tool");
  assert.deepEqual(
    tools.map((draft) =>
      draft.payload.case === "tool"
        ? [draft.payload.value.toolName, draft.payload.value.phase]
        : []
    ),
    [["glob", ToolPhase.SUCCEEDED], ["read", ToolPhase.SUCCEEDED]],
  );
  assertMetadataOnly(drafts);
  const serialized = serialize(drafts);
  assert.doesNotMatch(serialized, /\/private\/project/u);
  assert.doesNotMatch(serialized, /fixturesecret/u);
});

test("OpenCode 2 session messages become prompts, reasoning, replies, tool calls and turn ends", () => {
  const policy = new LocalPolicyEngine(loadConfig({
    PHIGON_COLLECT_PROMPT_CONTENT: "true",
    PHIGON_COLLECT_RESPONSE_CONTENT: "true",
    PHIGON_COLLECT_REASONING_CONTENT: "true",
    PHIGON_COLLECT_COMMAND_ARGUMENTS: "true",
    PHIGON_COLLECT_TOOL_OUTPUT: "true",
  }).policy);
  const sessionID = "ses_opencode2_adapter";
  const context = { sessionId: sessionID, observedAt, policy };
  const parse = (record: Record<string, unknown>) =>
    openCodeActivityAdapter.parse({ sessionID, ...record }, context);
  const step = { id: "msg_step", sessionID, type: "assistant", agent: "build", time: { created: 1, completed: 9 } };

  const prompt = parse({
    type: "session_message.user",
    info: { id: "msg_prompt", sessionID, type: "user", text: "Rename the loader.", time: { created: 1 } },
  });
  assert.deepEqual(prompt.map(activityOf), [[ActivityKind.PROMPT, "Rename the loader."]]);

  const started = parse({
    type: "session_message.assistant",
    info: { ...step, tokens: { input: 120, output: 40, reasoning: 8, cache: { read: 0, write: 0 } } },
  });
  assert.deepEqual(started.map((draft) => draft.payload.case === "lifecycle" ? draft.payload.value.phase : draft.payload.case), [LifecyclePhase.STARTED]);
  assert.deepEqual(parse({ type: "session_message.assistant", info: step }), [], "a turn starts once");

  const reasoning = parse({
    type: "session_message.assistant.reasoning",
    messageID: "msg_step",
    part: { type: "reasoning", text: "Check the tests first.", time: { created: 2, completed: 3 } },
  });
  assert.deepEqual(reasoning.map(activityOf), [[ActivityKind.REASONING, "Check the tests first."]]);
  const reply = parse({
    type: "session_message.assistant.text",
    messageID: "msg_step",
    part: { type: "text", text: "The loader is renamed." },
  });
  assert.deepEqual(reply.map(activityOf), [[ActivityKind.RESPONSE, "The loader is renamed."]]);
  assert.deepEqual(parse({
    type: "session_message.assistant.text",
    messageID: "msg_step",
    part: { type: "text", text: "" },
  }), []);

  const tool = parse({
    type: "session_message.assistant.tool",
    messageID: "msg_step",
    part: {
      type: "tool",
      id: "call_tests",
      name: "bash",
      state: {
        status: "completed",
        input: { command: "npm test" },
        content: [{ type: "text", text: "All tests passed." }],
        metadata: { exit: 0 },
      },
      time: { created: 4, ran: 5, completed: 6 },
    },
  }).find((draft) => draft.payload.case === "tool");
  assert.ok(tool?.payload.case === "tool");
  assert.deepEqual(
    [tool.payload.value.invocationId, tool.payload.value.toolName, tool.payload.value.phase, tool.payload.value.exitCode],
    ["call_tests", "bash", ToolPhase.SUCCEEDED, 0],
  );
  assert.match(tool.payload.value.argumentsJson ?? "", /npm test/u);
  assert.match(tool.payload.value.output ?? "", /All tests passed\./u);
  const failed = parse({
    type: "session_message.assistant.tool",
    messageID: "msg_step",
    part: {
      type: "tool",
      id: "call_read",
      name: "read",
      state: { status: "error", input: { path: "missing.txt" }, error: { type: "tool", message: "File not found." } },
      time: { created: 7, completed: 8 },
    },
  }).find((draft) => draft.payload.case === "tool");
  assert.ok(failed?.payload.case === "tool");
  assert.equal(failed.payload.value.phase, ToolPhase.FAILED);
  assert.match(failed.payload.value.output ?? "", /File not found\./u);

  // Messages OpenCode adds itself stay vendor records only.
  assert.deepEqual(parse({
    type: "session_message.synthetic",
    info: { id: "msg_note", sessionID, type: "synthetic", text: "Continue.", time: { created: 9 } },
  }), []);

  const ended = parse({
    type: "session_message.idle",
    info: { id: "msg_idle", sessionID, type: "idle", outcome: "failed", time: { created: 10 } },
  });
  assert.deepEqual(
    ended.map((draft) => draft.payload.case === "lifecycle" ? draft.payload.value.phase : draft.payload.case),
    [LifecyclePhase.IDLE, "activity"],
  );
  assert.equal(ended[1]?.payload.case === "activity" ? ended[1].payload.value.kind : undefined, ActivityKind.ERROR);
  assert.equal(parse({ type: "session_message.assistant", info: step }).length, 1, "the next turn starts again");
});

/** An activity draft's kind and content. */
function activityOf(draft: ActivityDraft): readonly [ActivityKind | undefined, string | undefined] {
  return draft.payload.case === "activity"
    ? [draft.payload.value.kind, draft.payload.value.content]
    : [undefined, undefined];
}

test("OpenCode database events preserve speaker roles and fail closed on conflict", () => {
  const policy = new LocalPolicyEngine(loadConfig({
    PHIGON_COLLECT_PROMPT_CONTENT: "true",
    PHIGON_COLLECT_RESPONSE_CONTENT: "true",
  }).policy);
  const context = {
    sessionId: "session-opencode-sqlite",
    observedAt,
    policy,
  };
  assert.deepEqual(openCodeActivityAdapter.parse({
    type: "message.updated.1",
    info: { id: "message-user-sqlite", role: "user" },
  }, context), []);
  const prompt = openCodeActivityAdapter.parse({
    type: "message.part.updated.1",
    part: {
      messageID: "message-user-sqlite",
      type: "text",
      text: "Keep this OpenCode prompt isolated.",
    },
  }, context);
  assert.equal(prompt[0]?.payload.case, "activity");
  if (prompt[0]?.payload.case === "activity") {
    assert.equal(prompt[0].payload.value.kind, ActivityKind.PROMPT);
    assert.equal(
      prompt[0].payload.value.content,
      "Keep this OpenCode prompt isolated.",
    );
  }

  assert.deepEqual(openCodeActivityAdapter.parse({
    type: "message.updated.1",
    info: { id: "message-agent-sqlite", role: "assistant" },
  }, context), []);
  const response = openCodeActivityAdapter.parse({
    type: "message.part.updated.1",
    part: {
      messageID: "message-agent-sqlite",
      type: "text",
      text: "The OpenCode response is isolated.",
    },
  }, context);
  assert.equal(response[0]?.payload.case, "activity");
  if (response[0]?.payload.case === "activity") {
    assert.equal(response[0].payload.value.kind, ActivityKind.RESPONSE);
    assert.equal(
      response[0].payload.value.content,
      "The OpenCode response is isolated.",
    );
  }

  openCodeActivityAdapter.parse({
    type: "message.updated.1",
    info: { id: "message-role-conflict", role: "user" },
  }, context);
  openCodeActivityAdapter.parse({
    type: "message.updated.1",
    info: { id: "message-role-conflict", role: "assistant" },
  }, context);
  assert.deepEqual(openCodeActivityAdapter.parse({
    type: "message.part.updated.1",
    part: {
      messageID: "message-role-conflict",
      type: "text",
      text: "Never guess this speaker.",
    },
  }, context), []);
  assert.deepEqual(openCodeActivityAdapter.parse({
    type: "message.part.updated.1",
    part: {
      messageID: "message-role-missing",
      type: "text",
      text: "Never guess this missing speaker.",
    },
  }, context), []);
  assert.deepEqual(openCodeActivityAdapter.parse({
    type: "message.part.updated.1",
    part: {
      messageID: "message-agent-sqlite",
      type: "text",
      text: "",
    },
  }, context), []);
});

test("Codex goal continuation metadata is not emitted as a user prompt", () => {
  const context = {
    sessionId: "session-codex-goal",
    observedAt,
    policy: metadataOnlyPolicy(),
  };
  const continuation = codexActivityAdapter.parse({
    type: "event_msg",
    payload: {
      type: "user_message",
      message: [{
        type: "input_text",
        text:
          '<codex_internal_context source="goal">\nContinue working.' +
          "\n</codex_internal_context>",
      }],
    },
  }, context);
  const realPrompt = codexActivityAdapter.parse({
    type: "event_msg",
    payload: {
      type: "user_message",
      message: "continue bro",
    },
  }, context);
  const environmentContext = codexActivityAdapter.parse({
    type: "event_msg",
    payload: {
      type: "user_message",
      message: [{
        type: "input_text",
        text: "<environment_context>\n  <cwd>/workspace</cwd>\n</environment_context>",
      }],
    },
  }, context);
  const ambientRequest = codexActivityAdapter.parse({
    type: "event_msg",
    payload: {
      type: "user_message",
      message:
        "<in-app-browser-context source=\"ambient-ui-state\">context" +
        "</in-app-browser-context>\n\n## My request for Codex:\nshow the reply",
    },
  }, context);

  assert.deepEqual(continuation, []);
  assert.deepEqual(environmentContext, []);
  assert.ok(realPrompt.some((draft) => draft.payload.case === "activity"));
  assert.ok(ambientRequest.some((draft) => draft.payload.case === "activity"));
});

test("Codex response-item messages preserve explicitly reported speaker roles", () => {
  const policy = new LocalPolicyEngine(loadConfig({
    PHIGON_COLLECT_PROMPT_CONTENT: "true",
    PHIGON_COLLECT_RESPONSE_CONTENT: "true",
  }).policy);
  const context = {
    sessionId: "session-codex-response-message",
    observedAt,
    policy,
  };
  const prompt = codexActivityAdapter.parse({
    type: "response_item",
    payload: {
      type: "message",
      role: "user",
      content: [{ type: "input_text", text: "Show the saved chats." }],
    },
  }, context);
  const response = codexActivityAdapter.parse({
    type: "response_item",
    payload: {
      type: "message",
      role: "assistant",
      content: [{ type: "output_text", text: "Saved chats are visible." }],
    },
  }, context);

  assert.equal(prompt[0]?.payload.case, "activity");
  assert.equal(response[0]?.payload.case, "activity");
  if (prompt[0]?.payload.case === "activity") {
    assert.equal(prompt[0].payload.value.kind, ActivityKind.PROMPT);
    assert.match(prompt[0].payload.value.content ?? "", /Show the saved chats\./u);
  }
  if (response[0]?.payload.case === "activity") {
    assert.equal(response[0].payload.value.kind, ActivityKind.RESPONSE);
    assert.match(response[0].payload.value.content ?? "", /Saved chats are visible\./u);
  }
});

test("Codex response-item messages fail closed on conflict and missing coverage", () => {
  const context = {
    sessionId: "session-codex-response-message-invalid",
    observedAt,
    policy: metadataOnlyPolicy(),
  };
  const candidates = [
    {
      type: "response_item",
      payload: {
        type: "message",
        content: [{ type: "input_text", text: "Missing role." }],
      },
    },
    {
      type: "response_item",
      payload: {
        type: "message",
        role: "user",
        content: [{ type: "output_text", text: "Conflicting speaker claim." }],
      },
    },
    {
      type: "response_item",
      payload: {
        type: "message",
        role: "assistant",
        content: [{ type: "unknown", text: "Incomplete content coverage." }],
      },
    },
  ];

  for (const candidate of candidates) {
    assert.deepEqual(codexActivityAdapter.parse(candidate, context), []);
  }
});

test("Codex completed command and file-change items become terminal and file events", () => {
  const config = loadConfig({ PHIGON_OBSERVABILITY_PROFILE: "full" });
  const context = {
    sessionId: "session-codex-items",
    observedAt,
    policy: new LocalPolicyEngine(config.policy),
  };
  const command = codexActivityAdapter.parse({
    timestamp: "2026-07-24T10:00:01.000Z",
    type: "event_msg",
    payload: {
      type: "item_completed",
      thread_id: "thread-1",
      turn_id: "turn-1",
      item: {
        type: "CommandExecution",
        id: "item-command",
        command: ["/bin/bash", "-lc", "git status"],
        cwd: "/workspace",
        aggregated_output: "On branch main",
        exit_code: 0,
        status: "completed",
        source: "unified_exec_startup",
      },
    },
  }, context);
  const terminal = command.find((draft) => draft.payload.case === "terminal");
  assert.equal(terminal?.payload.case, "terminal");
  if (terminal?.payload.case === "terminal") {
    assert.equal(terminal.payload.value.phase, TerminalPhase.EXITED);
    assert.equal(terminal.payload.value.exitCode, 0);
    assert.equal(terminal.payload.value.executable, "bash");
    assert.equal(terminal.payload.value.arguments, "/bin/bash -lc git status");
  }
  assert.ok(command.some((draft) => draft.payload.case === "git"));
  const tool = command.find((draft) => draft.payload.case === "tool");
  if (tool?.payload.case === "tool") {
    assert.equal(tool.payload.value.phase, ToolPhase.SUCCEEDED);
  }

  const failed = codexActivityAdapter.parse({
    type: "event_msg",
    payload: {
      type: "item_completed",
      item: {
        type: "CommandExecution",
        id: "item-failed",
        command: ["/bin/bash", "-lc", "npm test"],
        aggregated_output: "1 failing",
        exit_code: 1,
        status: "failed",
      },
    },
  }, context).find((draft) => draft.payload.case === "tool");
  if (failed?.payload.case === "tool") {
    assert.equal(failed.payload.value.phase, ToolPhase.FAILED);
    assert.equal(failed.payload.value.exitCode, 1);
  } else {
    assert.fail("A failed command must produce a tool event.");
  }

  const files = codexActivityAdapter.parse({
    type: "event_msg",
    payload: {
      type: "item_completed",
      item: {
        type: "FileChange",
        id: "item-files",
        status: "completed",
        stdout: "",
        stderr: "",
        changes: {
          "/workspace/new.ts": { type: "add", content: "export {};\n" },
          "/workspace/app.ts": {
            type: "update",
            unified_diff: "@@ -1 +1 @@\n-old\n+new\n",
            move_path: null,
          },
          "/workspace/old.ts": { type: "delete" },
        },
      },
    },
  }, context).flatMap((draft) =>
    draft.payload.case === "filesystem"
      ? [[
          draft.payload.value.resource?.identifier,
          draft.payload.value.operation,
        ]]
      : []
  );
  assert.deepEqual(files, [
    ["/workspace/new.ts", FilesystemOperation.CREATE],
    ["/workspace/app.ts", FilesystemOperation.WRITE],
    ["/workspace/old.ts", FilesystemOperation.DELETE],
  ]);

  const repeatedMessage = codexActivityAdapter.parse({
    type: "event_msg",
    payload: {
      type: "item_completed",
      item: { type: "AgentMessage", id: "item-message", content: [{ type: "Text", text: "Done." }] },
    },
  }, context);
  assert.deepEqual(repeatedMessage, []);
});

test("Codex reasoning indexes only source-emitted readable summaries", () => {
  const policy = new LocalPolicyEngine(loadConfig({
    PHIGON_COLLECT_REASONING_CONTENT: "true",
  }).policy);
  const context = {
    sessionId: "session-codex-reasoning",
    observedAt,
    policy,
  };
  const drafts = codexActivityAdapter.parse({
    type: "response_item",
    payload: {
      type: "reasoning",
      encrypted_content: "opaque-private-model-state",
      summary: [
        { type: "summary_text", text: "Checking the source event path." },
        { type: "summary_text", text: "Confirming durable delivery." },
      ],
    },
  }, context);

  assert.equal(drafts.length, 1);
  assert.equal(drafts[0]?.payload.case, "activity");
  if (drafts[0]?.payload.case === "activity") {
    assert.equal(drafts[0].payload.value.kind, ActivityKind.REASONING);
    assert.equal(
      drafts[0].payload.value.content,
      "Checking the source event path.\n\nConfirming durable delivery.",
    );
    assert.doesNotMatch(
      drafts[0].payload.value.content ?? "",
      /opaque-private-model-state/u,
    );
  }

  for (const summary of [
    [],
    [{ type: "summary_text" }],
    [{ type: "unknown", text: "Unsupported coverage." }],
  ]) {
    assert.deepEqual(codexActivityAdapter.parse({
      type: "response_item",
      payload: {
        type: "reasoning",
        encrypted_content: "never-index-this",
        summary,
      },
    }, context), []);
  }
});

test("Codex web-search records preserve reported status and safe arguments", () => {
  const policy = new LocalPolicyEngine(loadConfig({
    PHIGON_COLLECT_COMMAND_ARGUMENTS: "true",
    PHIGON_COLLECT_BROWSER_URLS: "true",
  }).policy);
  const context = {
    sessionId: "session-codex-web-search",
    observedAt,
    policy,
  };
  const drafts = codexActivityAdapter.parse({
    type: "response_item",
    payload: {
      type: "web_search_call",
      id: "search-1",
      status: "completed",
      action: {
        type: "search",
        query: "portable observer setup",
      },
    },
  }, context);
  const tool = drafts.find((draft) => draft.payload.case === "tool");

  assert.equal(tool?.payload.case, "tool");
  if (tool?.payload.case === "tool") {
    assert.equal(tool.payload.value.invocationId, "search-1");
    assert.equal(tool.payload.value.toolName, "web_search.search");
    assert.equal(tool.payload.value.phase, ToolPhase.SUCCEEDED);
    assert.match(
      tool.payload.value.argumentsJson ?? "",
      /portable observer setup/u,
    );
  }
});

test("Codex tool outputs require explicit, consistent outcome evidence", () => {
  const context = {
    sessionId: "session-codex-tool-outcomes",
    observedAt,
    policy: metadataOnlyPolicy(),
  };
  const cases = [
    [{}, ToolPhase.UNSPECIFIED, undefined],
    [{ status: "succeeded" }, ToolPhase.SUCCEEDED, undefined],
    [{ success: false }, ToolPhase.FAILED, undefined],
    [{ exit_code: 0 }, ToolPhase.SUCCEEDED, 0],
    [{ exitCode: 17 }, ToolPhase.FAILED, 17],
    [
      { status: "succeeded", exit_code: 17 },
      ToolPhase.UNSPECIFIED,
      undefined,
    ],
  ] as const;

  for (const [outcome, expectedPhase, expectedExitCode] of cases) {
    codexActivityAdapter.parse({
      type: "response_item",
      payload: {
        type: "function_call",
        call_id: "call-outcome",
        name: "functions.exec_command",
        arguments: "{\"command\":\"git status\"}",
      },
    }, context);
    const drafts = codexActivityAdapter.parse({
      type: "response_item",
      payload: {
        type: "function_call_output",
        call_id: "call-outcome",
        output: "reported output",
        ...outcome,
      },
    }, context);
    const tool = drafts.find((draft) => draft.payload.case === "tool");
    const terminal = drafts.find((draft) => draft.payload.case === "terminal");

    if (expectedPhase === ToolPhase.UNSPECIFIED) {
      assert.deepEqual(drafts, []);
      continue;
    }
    assert.equal(tool?.payload.case, "tool");
    if (tool?.payload.case === "tool") {
      assert.equal(tool.payload.value.phase, expectedPhase);
      assert.equal(tool.payload.value.exitCode, expectedExitCode);
    }
    assert.equal(terminal?.payload.case, "terminal");
    if (terminal?.payload.case === "terminal") {
      assert.equal(
        terminal.payload.value.phase,
        TerminalPhase.EXITED,
      );
      assert.equal(terminal.payload.value.exitCode, expectedExitCode);
    }
  }
});

test("nested tool content obeys every subordinate consent category", () => {
  const policy = new LocalPolicyEngine(loadConfig({
    PHIGON_COLLECT_COMMAND_ARGUMENTS: "true",
    PHIGON_COLLECT_TOOL_OUTPUT: "true",
  }).policy);
  const tool = toolDrafts(AgentKind.CODEX, {
    sessionId: "session-policy",
    observedAt,
    policy,
  }, {
    toolName: "custom.deploy",
    phase: ToolPhase.SUCCEEDED,
    arguments: {
      env: { PUBLIC_VALUE: "must-not-leak" },
      nested: [{
        path: "/private/project/secret.ts",
        url: "https://internal.example.test/private",
        endpoint: "database.example.test:5432",
      }],
      target: "button[aria-label=Delete]",
      safe: "release-e2e",
    },
    output: {
      file_content: "private file body",
      patch: "private patch",
      safe: "completed",
    },
  }).find((draft) => draft.payload.case === "tool");

  assert.equal(tool?.payload.case, "tool");
  if (tool?.payload.case !== "tool") return;
  const serialized = JSON.stringify({
    arguments: JSON.parse(tool.payload.value.argumentsJson ?? "{}"),
    output: JSON.parse(tool.payload.value.output ?? "{}"),
  });
  assert.match(serialized, /\[REDACTED_POLICY\]/u);
  assert.match(serialized, /release-e2e/u);
  assert.match(serialized, /completed/u);
  for (const prohibited of [
    "must-not-leak",
    "/private/project",
    "internal.example.test",
    "database.example.test",
    "button[aria-label=Delete]",
    "private file body",
    "private patch",
  ]) {
    assert.doesNotMatch(serialized, new RegExp(prohibited.replace(
      /[.*+?^${}()|[\]\\]/gu,
      "\\$&",
    ), "u"));
  }
  assert.equal(tool.payload.value.argumentsRedacted, true);
  assert.equal(tool.payload.value.outputRedacted, true);
});

test("agent error records carry error severity", () => {
  const draft = errorDraft(AgentKind.CODEX, {
    sessionId: "session-error",
    observedAt,
    policy: metadataOnlyPolicy(),
  }, "response_item/error");
  assert.equal(draft.payload.case, "activity");
  if (draft.payload.case === "activity") {
    assert.equal(draft.payload.value.severity, Severity.ERROR);
  }
});

test("vendor-native records preserve source shape while removing secrets", () => {
  const config = loadConfig({
    PHIGON_COLLECT_COMMAND_ARGUMENTS: "true",
    PHIGON_COLLECT_FILE_PATHS: "true",
    PHIGON_COLLECT_TOOL_OUTPUT: "true",
    PHIGON_COLLECT_VENDOR_PAYLOAD: "true",
    PHIGON_REDACT_PATH_PATTERNS: "/private/project",
  });
  const policy = new LocalPolicyEngine(
    config.policy,
    config.redactionPathPatterns,
  );
  const result = policy.vendorRecord({
    type: "response_item",
    payload: {
      type: "function_call",
      arguments: {
        cmd: "git -C /private/project status",
        authorization: "Bearer fixture-token-value",
      },
      output: "sk-fixturesecret0123456789",
    },
  });

  assert.ok(result.value);
  const payload = JSON.parse(result.value);
  assert.equal(payload.type, "response_item");
  assert.equal(payload.payload.type, "function_call");
  assert.equal(
    payload.payload.arguments.authorization,
    "[REDACTED_SECRET]",
  );
  assert.match(payload.payload.arguments.cmd, /\[REDACTED_PATH\]/u);
  assert.equal(payload.payload.output, "[REDACTED_SECRET]");
  assert.equal(result.redacted, true);
  assert.ok(
    result.redactedFields.includes(
      "payload.arguments.authorization",
    ),
  );
  assert.doesNotMatch(result.value, /fixture-token|fixturesecret/u);
});

test("vendor payload requires its subordinate content consents", () => {
  const config = loadConfig({
    PHIGON_COLLECT_VENDOR_PAYLOAD: "true",
  });
  const result = new LocalPolicyEngine(config.policy).vendorRecord({
    type: "response_item",
    payload: {
      type: "function_call",
      name: "functions.exec_command",
      arguments: {
        cmd: "cat /private/vendor/path",
        env: { PUBLIC_VALUE: "vendor-private-env" },
      },
      output: "vendor-private-output",
    },
  });
  assert.ok(result.value);
  assert.match(result.value, /functions\.exec_command/u);
  assert.match(result.value, /\[REDACTED_POLICY\]/u);
  assert.doesNotMatch(
    result.value,
    /\/private\/vendor|vendor-private-env|vendor-private-output/u,
  );
  assert.equal(result.redacted, true);
});

test("vendor payload fails closed on unclassified free-form strings", () => {
  const config = loadConfig({
    PHIGON_COLLECT_VENDOR_PAYLOAD: "true",
  });
  const result = new LocalPolicyEngine(config.policy).vendorRecord({
    type: "custom",
    data: {
      name: "privateLabel",
      value: "private prompt that has no recognized vendor field",
      status: "running",
    },
  });
  assert.ok(result.value);
  const payload = JSON.parse(result.value);
  assert.equal(payload.type, "custom");
  assert.equal(payload.data.status, "running");
  assert.equal(payload.data.name, "[REDACTED_POLICY]");
  assert.equal(payload.data.value, "[REDACTED_POLICY]");
  assert.doesNotMatch(result.value, /private prompt/u);
  assert.equal(result.redacted, true);
});

test("vendor payload never bypasses reasoning consent through thinking blocks", () => {
  const config = loadConfig({
    PHIGON_COLLECT_RESPONSE_CONTENT: "true",
    PHIGON_COLLECT_VENDOR_PAYLOAD: "true",
  });
  const result = new LocalPolicyEngine(config.policy).vendorRecord({
    type: "assistant",
    message: {
      role: "assistant",
      content: [
        { type: "text", text: "visible response" },
        {
          type: "thinking",
          thinking: "private reasoning",
          text: "private alternate reasoning",
        },
      ],
    },
  });
  assert.ok(result.value);
  assert.match(result.value, /visible response/u);
  assert.match(result.value, /\[REDACTED_POLICY\]/u);
  assert.doesNotMatch(
    result.value,
    /private reasoning|private alternate reasoning/u,
  );
  assert.equal(result.redacted, true);
});

test("vendor-native payload collection fails closed when disabled", () => {
  const result = metadataOnlyPolicy().vendorRecord({
    type: "user",
    message: "private prompt",
  });
  assert.equal(result.value, undefined);
  assert.equal(result.redacted, true);
  assert.match(result.digest, /^[a-f0-9]{64}$/u);
});

test("generic OpenAI-compatible agent records preserve replies and tool calls", () => {
  const drafts = genericActivityAdapter.parse({
    type: "message",
    message: {
      role: "assistant",
      content: "Deploying now.",
      tool_calls: [{
        id: "call-generic",
        function: {
          name: "custom.deploy",
          arguments: JSON.stringify({ environment: "staging" }),
        },
      }],
    },
  }, {
    sessionId: "session-generic",
    observedAt,
    policy: metadataOnlyPolicy(),
  });

  assert.ok(drafts.some((draft) => draft.payload.case === "activity"));
  assert.ok(
    drafts.some(
      (draft) =>
        draft.payload.case === "tool" &&
        draft.payload.value.toolName === "custom.deploy",
    ),
  );
});

test("Codex keeps readable prompts containing images and isolates concurrent tool IDs", () => {
  const policy = new LocalPolicyEngine(loadConfig({PHIGON_OBSERVABILITY_PROFILE:"full"}).policy);
  const context = {sessionId:"mixed-image-test",observedAt,policy};
  const drafts = codexActivityAdapter.parse({type:"response_item",payload:{type:"message",role:"user",content:[
    {type:"input_text",text:"Inspect this screenshot."},
    {type:"input_image",image_url:"data:image/png;base64,never-copy-image-bytes"},
  ]}},context);
  assert.equal(drafts[0]?.payload.case,"activity");
  if(drafts[0]?.payload.case === "activity") {
    assert.match(drafts[0].payload.value.content ?? "",/Inspect this screenshot/);
    assert.match(drafts[0].payload.value.content ?? "",/Image attachment/);
    assert.doesNotMatch(drafts[0].payload.value.content ?? "",/base64|never-copy/);
  }
  for (const [sessionId,name] of [["thread-one","read_file"],["thread-two","search"]]) {
    codexActivityAdapter.parse({type:"response_item",payload:{type:"function_call",call_id:"same-call",name,arguments:"{}"}},{...context,sessionId:sessionId!});
  }
  const result=codexActivityAdapter.parse({type:"response_item",payload:{type:"function_call_output",call_id:"same-call",output:"result"}},{...context,sessionId:"thread-one"});
  const tool=result.find(draft=>draft.payload.case==="tool");
  if(tool?.payload.case!=="tool")assert.fail("missing tool");
  assert.equal(tool.payload.value.toolName,"read_file");
});

test("OpenCode resumes speaker attribution from source database evidence", () => {
  const context={sessionId:"restart-at-part",observedAt,policy:new LocalPolicyEngine(loadConfig({PHIGON_OBSERVABILITY_PROFILE:"full"}).policy)};
  const result=openCodeActivityAdapter.parse({type:"message.part.updated.1",message_info:{id:"message-after-restart",role:"user"},part:{type:"text",messageID:"message-after-restart",text:"Resume my saved conversation."}},context);
  if(result[0]?.payload.case!=="activity")assert.fail("missing restored prompt");
  assert.equal(result[0].payload.value.kind,ActivityKind.PROMPT);
  assert.match(result[0].payload.value.content ?? "",/Resume my saved conversation/);
});

test("Guardian decision journals become structured authorization telemetry", () => {
  const policy = new LocalPolicyEngine(loadConfig({
    PHIGON_COLLECT_TOOL_OUTPUT: "true",
  }).policy);
  const contract = "Do not let this agent delete project files.";
  const drafts = genericActivityAdapter.parse({
    type: "phigon_guardian_decision",
    decision_id: "4a529a6e-baf0-4cce-a8dd-2b5367c79df2",
    phigon_agent_name: "Phigon Guardian",
    session_id: "guardian:codex-worker",
    timestamp: observedAt.toISOString(),
    subject_agent_id: "codex:worker",
    action: "command.execute",
    resource: "Remove-Item project.txt",
    outcome: "denied",
    reason: "The proposed command would delete a project file.",
    admin_contract: contract,
    decision_source: "agentic_guardian",
    model: "gpt-5-mini",
    risk: "high",
    confidence: 0.98,
    latency_ms: 21,
    intervention: "block_action",
  }, {
    sessionId: "guardian:codex-worker",
    observedAt,
    policy,
  });

  const decision = drafts.find((draft) => draft.payload.case === "tool");
  assert.equal(decision?.payload.case, "tool");
  if (decision?.payload.case !== "tool") return;
  assert.equal(decision.payload.value.invocationId, "4a529a6e-baf0-4cce-a8dd-2b5367c79df2");
  assert.equal(decision.payload.value.toolName, "phigon.guardian.authorize_action");
  assert.equal(decision.payload.value.phase, ToolPhase.SUCCEEDED);
  const output = decision.payload.value.output;
  assert.equal(typeof output, "string");
  assert.match(output ?? "", /agentic_guardian/u);
  assert.match(output ?? "", /block_action/u);
  assert.match(output ?? "", new RegExp(contract.replaceAll(".", "\\."), "u"));
});

test("managed execution journals become correlated command telemetry", () => {
  const policy = new LocalPolicyEngine(loadConfig({
    PHIGON_COLLECT_COMMAND_ARGUMENTS: "true",
    PHIGON_COLLECT_TOOL_OUTPUT: "true",
    PHIGON_COLLECT_TERMINAL_OUTPUT: "true",
  }).policy);
  const drafts = genericActivityAdapter.parse({
    type: "phigon_managed_command",
    invocation_id: "f3b8b116-dff9-4ba0-a6e8-3b0529bfdb04",
    session_id: "task:test",
    agent_id: "codex:test",
    timestamp: observedAt.toISOString(),
    phase: "running",
    executable: "npm",
    arguments: ["test"],
    stream: "stdout",
    output: "tests passed",
    exit_code: null,
  }, {
    sessionId: "task:test",
    observedAt,
    policy,
  });
  const tool = drafts.find((draft) => draft.payload.case === "tool");
  const terminal = drafts.find((draft) => draft.payload.case === "terminal");
  assert.equal(tool?.payload.case, "tool");
  assert.equal(terminal?.payload.case, "terminal");
  if (tool?.payload.case === "tool") {
    assert.equal(tool.payload.value.phase, ToolPhase.RUNNING);
    assert.match(tool.payload.value.output ?? "", /tests passed/u);
  }
});

test("Claude system records map to turn lifecycle without repeated discovery", () => {
  const context = {
    sessionId: "session-claude-system",
    observedAt,
    policy: metadataOnlyPolicy(),
  };
  const kinds = (record: unknown) =>
    claudeActivityAdapter.parse(record, context).map((draft) =>
      draft.payload.case === "lifecycle"
        ? `lifecycle:${draft.payload.value.phase}`
        : draft.payload.case === "activity"
          ? `activity:${draft.payload.value.kind}`
          : String(draft.payload.case)
    );
  assert.deepEqual(kinds({ type: "system", subtype: "turn_duration", durationMs: 1200 }), [
    `lifecycle:${LifecyclePhase.IDLE}`,
  ]);
  assert.deepEqual(kinds({ type: "system", subtype: "stop_hook_summary" }), []);
  assert.deepEqual(kinds({ type: "system", subtype: "informational" }), []);
  assert.deepEqual(kinds({ type: "system", subtype: "compact_boundary" }), []);
  assert.deepEqual(kinds({ type: "system", subtype: "api_error" }), [
    `activity:${ActivityKind.ERROR}`,
  ]);
  assert.deepEqual(kinds({ type: "system", subtype: "init" }), [
    `lifecycle:${LifecyclePhase.DISCOVERED}`,
  ]);
});

test("Claude injected user-turn text is not reported as a user prompt", () => {
  const context = {
    sessionId: "session-claude-meta",
    observedAt,
    policy: metadataOnlyPolicy(),
  };
  const prompts = (record: unknown) =>
    claudeActivityAdapter.parse(record, context).filter((draft) =>
      draft.payload.case === "activity" &&
      draft.payload.value.kind === ActivityKind.PROMPT
    ).length;
  assert.equal(prompts({
    type: "user",
    isMeta: true,
    message: { role: "user", content: "<local-command-caveat>Caveat</local-command-caveat>" },
  }), 0);
  assert.equal(prompts({
    type: "user",
    isCompactSummary: true,
    message: { role: "user", content: "This session is being continued from a previous conversation." },
  }), 0);
  assert.equal(prompts({
    type: "user",
    message: { role: "user", content: "Run the release checks." },
  }), 1);
  const injectedResult = claudeActivityAdapter.parse({
    type: "user",
    isMeta: true,
    message: {
      role: "user",
      content: [{ type: "tool_result", tool_use_id: "toolu_meta", content: "ok" }],
    },
  }, context);
  assert.ok(injectedResult.some((draft) => draft.payload.case === "tool"));
});

test("Copilot CLI session events become prompts, replies, commands, and file events", () => {
  const config = loadConfig({ PHIGON_OBSERVABILITY_PROFILE: "full" });
  const context = {
    sessionId: "session-copilot-events",
    observedAt,
    policy: new LocalPolicyEngine(config.policy),
  };
  const event = (type: string, data: unknown, index: number) => ({
    id: `00000000-0000-4000-8000-00000000000${index}`,
    parentId: null,
    timestamp: `2026-07-24T10:00:0${index}.000Z`,
    type,
    data,
  });
  const drafts = [
    event("session.start", {
      sessionId: "copilot-session",
      version: 1,
      producer: "copilot-agent",
      copilotVersion: "1.0.0",
      startTime: "2026-07-24T10:00:00.000Z",
    }, 0),
    event("user.message", { content: "Fix the failing test.", attachments: [] }, 1),
    event("user.message", {
      content: "Continue working on the objective.",
      isAutopilotContinuation: true,
    }, 2),
    event("assistant.reasoning", { reasoningId: "r1", content: "Check the test first." }, 3),
    event("assistant.message", {
      messageId: "m1",
      content: "Running the tests.",
      toolRequests: [
        { toolCallId: "call-bash", name: "bash", arguments: { command: "npm test", description: "Run tests" } },
        { toolCallId: "call-edit", name: "edit", arguments: { path: "/workspace/a.ts", old_str: "a", new_str: "b" } },
      ],
    }, 4),
    event("tool.execution_start", {
      toolCallId: "call-bash",
      toolName: "bash",
      arguments: { command: "npm test" },
    }, 5),
    event("tool.execution_complete", {
      toolCallId: "call-bash",
      success: false,
      result: { content: "1 failing" },
      shellExecution: { exitCode: 1 },
    }, 6),
    event("tool.execution_complete", {
      toolCallId: "call-edit",
      success: true,
      result: { content: "Edited.", detailedContent: "@@ -1 +1 @@" },
    }, 7),
    event("session.task_complete", {}, 8),
  ].flatMap((record) => copilotActivityAdapter.parse(record, context));

  const activities = drafts.flatMap((draft) =>
    draft.payload.case === "activity"
      ? [[draft.payload.value.kind, draft.payload.value.content]]
      : []
  );
  assert.deepEqual(activities, [
    [ActivityKind.PROMPT, "Fix the failing test."],
    [ActivityKind.REASONING, "Check the test first."],
    [ActivityKind.RESPONSE, "Running the tests."],
  ]);
  const tools = drafts.flatMap((draft) =>
    draft.payload.case === "tool"
      ? [[draft.payload.value.toolName, draft.payload.value.phase]]
      : []
  );
  assert.deepEqual(tools, [
    ["bash", ToolPhase.REQUESTED],
    ["edit", ToolPhase.REQUESTED],
    ["bash", ToolPhase.FAILED],
    ["edit", ToolPhase.SUCCEEDED],
  ]);
  const exited = drafts.find((draft) =>
    draft.payload.case === "terminal" &&
    draft.payload.value.phase === TerminalPhase.EXITED
  );
  if (exited?.payload.case === "terminal") {
    assert.equal(exited.payload.value.exitCode, 1);
    assert.equal(exited.payload.value.arguments, "npm test");
  } else {
    assert.fail("The completed shell command must report its exit status.");
  }
  const files = drafts.filter((draft) => draft.payload.case === "filesystem");
  assert.equal(files.length, 1);
  const lifecycle = drafts.flatMap((draft) =>
    draft.payload.case === "lifecycle" ? [draft.payload.value.phase] : []
  );
  assert.deepEqual(lifecycle, [LifecyclePhase.STARTED, LifecyclePhase.IDLE]);
});

test("Copilot CLI user-requested tools are reported when they start", () => {
  const context = {
    sessionId: "session-copilot-user-tool",
    observedAt,
    policy: metadataOnlyPolicy(),
  };
  const started = copilotActivityAdapter.parse({
    id: "00000000-0000-4000-8000-000000000010",
    parentId: null,
    timestamp: "2026-07-24T10:00:10.000Z",
    type: "tool.execution_start",
    data: { toolCallId: "call-view", toolName: "view", arguments: { path: "/private/project/a.ts" } },
  }, context);
  const tool = started.find((draft) => draft.payload.case === "tool");
  if (tool?.payload.case === "tool") {
    assert.equal(tool.payload.value.phase, ToolPhase.RUNNING);
  } else {
    assert.fail("A tool started without a request must still be reported.");
  }
  const file = started.find((draft) => draft.payload.case === "filesystem");
  if (file?.payload.case === "filesystem") {
    assert.equal(file.payload.value.operation, FilesystemOperation.READ);
  } else {
    assert.fail("Viewing a file is a file read.");
  }
  assertMetadataOnly(started);
});

test("Gemini CLI chat recordings report each message, thought, and tool call once", () => {
  const config = loadConfig({ PHIGON_OBSERVABILITY_PROFILE: "full" });
  const context = {
    sessionId: "session-gemini",
    observedAt,
    policy: new LocalPolicyEngine(config.policy),
  };
  const shellCall = {
    id: "call-shell",
    name: "run_shell_command",
    args: { command: "npm test", description: "Run the tests" },
    result: [{
      functionResponse: {
        id: "call-shell",
        name: "run_shell_command",
        response: { output: "2 passing" },
      },
    }],
    status: "success",
    timestamp: "2026-07-24T10:00:05.000Z",
  };
  const editCall = {
    id: "call-edit",
    name: "replace",
    args: { file_path: "/workspace/a.ts", old_string: "a", new_string: "b" },
    result: null,
    status: "error",
    timestamp: "2026-07-24T10:00:06.000Z",
  };
  const answer = {
    id: "msg-model",
    timestamp: "2026-07-24T10:00:03.000Z",
    type: "gemini",
    content: "I will run the tests.",
    thoughts: [{
      subject: "Plan",
      description: "Run the tests first.",
      timestamp: "2026-07-24T10:00:02.000Z",
    }],
    model: "gemini-2.5-pro",
  };
  const lines = [
    {
      sessionId: "8f0f8a62-0000-4000-8000-000000000001",
      projectHash: "a".repeat(64),
      startTime: "2026-07-24T10:00:00.000Z",
      lastUpdated: "2026-07-24T10:00:00.000Z",
      kind: "main",
    },
    {
      id: "msg-user",
      timestamp: "2026-07-24T10:00:01.000Z",
      type: "user",
      content: [{ text: "Fix @a.ts" }, { text: "--- a.ts ---\nexport const a = 1;" }],
      displayContent: [{ text: "Fix @a.ts" }],
    },
    { $set: { lastUpdated: "2026-07-24T10:00:01.000Z" } },
    answer,
    // Token counts arrive later: the same message is appended again.
    { ...answer, tokens: { input: 10, output: 5, cached: 0, total: 15 } },
    {
      id: "msg-tools",
      timestamp: "2026-07-24T10:00:05.000Z",
      type: "gemini",
      content: "",
      toolCalls: [shellCall],
      thoughts: [],
      model: "gemini-2.5-pro",
    },
    // Completed tool calls are merged into the last model message.
    {
      id: "msg-tools",
      timestamp: "2026-07-24T10:00:05.000Z",
      type: "gemini",
      content: "",
      toolCalls: [shellCall, editCall],
      thoughts: [],
      model: "gemini-2.5-pro",
    },
    {
      id: "msg-tool-response",
      timestamp: "2026-07-24T10:00:07.000Z",
      type: "user",
      content: [{ functionResponse: { id: "call-shell", name: "run_shell_command", response: { output: "2 passing" } } }],
    },
    { id: "msg-info", timestamp: "2026-07-24T10:00:08.000Z", type: "info", content: "Checkpoint saved." },
    { id: "msg-error", timestamp: "2026-07-24T10:00:09.000Z", type: "error", content: "Quota exceeded." },
    { $patch: { updates: [{ id: "msg-tools", toolCalls: [{ id: "call-shell", result: [] }] }] } },
    { $rewindTo: "msg-error" },
  ];
  const drafts = lines.flatMap((line) => geminiActivityAdapter.parse(line, context));

  assert.deepEqual(
    drafts.flatMap((draft) =>
      draft.payload.case === "activity"
        ? [[draft.payload.value.kind, draft.payload.value.content ?? ""]]
        : []
    ),
    [
      [ActivityKind.PROMPT, "Fix @a.ts"],
      [ActivityKind.REASONING, "Plan\nRun the tests first."],
      [ActivityKind.RESPONSE, "I will run the tests."],
      [ActivityKind.ERROR, ""],
    ],
  );
  assert.deepEqual(
    drafts.flatMap((draft) =>
      draft.payload.case === "tool"
        ? [[draft.payload.value.toolName, draft.payload.value.phase]]
        : []
    ),
    [
      ["run_shell_command", ToolPhase.SUCCEEDED],
      ["replace", ToolPhase.FAILED],
    ],
  );
  const terminal = drafts.find((draft) => draft.payload.case === "terminal");
  if (terminal?.payload.case === "terminal") {
    assert.equal(terminal.payload.value.arguments, "npm test");
    assert.equal(
      Buffer.from(terminal.payload.value.output ?? []).toString("utf8"),
      "2 passing",
    );
  } else {
    assert.fail("The shell tool call must produce a terminal event.");
  }
  const file = drafts.find((draft) => draft.payload.case === "filesystem");
  if (file?.payload.case === "filesystem") {
    assert.equal(file.payload.value.resource?.identifier, "/workspace/a.ts");
  } else {
    assert.fail("The edit tool call must produce a file event.");
  }
  assert.deepEqual(
    drafts.flatMap((draft) =>
      draft.payload.case === "lifecycle" ? [draft.payload.value.phase] : []
    ),
    [LifecyclePhase.STARTED],
  );
});

test("Gemini CLI recordings stay metadata-only under the default policy", () => {
  const drafts = geminiActivityAdapter.parse({
    id: "msg-private",
    timestamp: "2026-07-24T10:00:01.000Z",
    type: "gemini",
    content: "Reading /private/project now.",
    toolCalls: [{
      id: "call-read",
      name: "read_file",
      args: { file_path: "/private/project/secret.ts" },
      result: [{ functionResponse: { response: { output: "fixturesecret" } } }],
      status: "success",
      timestamp: "2026-07-24T10:00:02.000Z",
    }],
  }, {
    sessionId: "session-gemini-private",
    observedAt,
    policy: metadataOnlyPolicy(),
  });
  assert.ok(drafts.some((draft) => draft.payload.case === "filesystem"));
  assertMetadataOnly(drafts);
});

test("Cline CLI session messages become prompts, replies, commands, and file edits", () => {
  const config = loadConfig({ PHIGON_OBSERVABILITY_PROFILE: "full" });
  const context = {
    sessionId: "session-cline",
    observedAt,
    policy: new LocalPolicyEngine(config.policy),
  };
  const messages = [
    {
      id: "msg-1",
      role: "user",
      content: [{ type: "text", text: "Add a health check." }],
      ts: Date.parse("2026-07-24T10:00:01.000Z"),
    },
    {
      id: "msg-2",
      role: "assistant",
      content: [
        { type: "thinking", thinking: "Inspect the server first." },
        { type: "text", text: "Adding the endpoint." },
        { type: "tool_use", id: "toolu_cmd", name: "run_commands", input: { commands: ["npm test"] } },
        {
          type: "tool_use",
          id: "toolu_edit",
          name: "editor",
          input: { path: "/workspace/server.ts", old_text: "a", new_text: "b" },
        },
      ],
      metrics: { inputTokens: 10, outputTokens: 5, cacheReadTokens: 0, cacheWriteTokens: 0 },
      modelInfo: { id: "model", provider: "provider" },
      ts: Date.parse("2026-07-24T10:00:02.000Z"),
    },
    {
      id: "msg-3",
      role: "user",
      content: [
        {
          type: "tool_result",
          tool_use_id: "toolu_cmd",
          name: "run_commands",
          content: [{ query: "npm test", result: "1 failing", success: false, error: "exit 1" }],
        },
        {
          type: "tool_result",
          tool_use_id: "toolu_edit",
          name: "editor",
          content: [{ query: "edit", result: "Edited.", success: true }],
        },
      ],
      ts: Date.parse("2026-07-24T10:00:03.000Z"),
    },
  ];
  const drafts = messages.flatMap((message) =>
    clineActivityAdapter.parse(message, context)
  );
  assert.deepEqual(
    drafts.flatMap((draft) =>
      draft.payload.case === "activity"
        ? [[draft.payload.value.kind, draft.payload.value.content]]
        : []
    ),
    [
      [ActivityKind.PROMPT, "Add a health check."],
      [ActivityKind.RESPONSE, "Adding the endpoint."],
      [ActivityKind.REASONING, "Inspect the server first."],
    ],
  );
  assert.deepEqual(
    drafts.flatMap((draft) =>
      draft.payload.case === "tool"
        ? [[draft.payload.value.toolName, draft.payload.value.phase]]
        : []
    ),
    [
      ["run_commands", ToolPhase.REQUESTED],
      ["editor", ToolPhase.REQUESTED],
      ["run_commands", ToolPhase.FAILED],
      ["editor", ToolPhase.SUCCEEDED],
    ],
  );
  const terminal = drafts.find((draft) => draft.payload.case === "terminal");
  if (terminal?.payload.case === "terminal") {
    assert.equal(terminal.payload.value.arguments, "npm test");
  } else {
    assert.fail("run_commands must produce a terminal event.");
  }
  const files = drafts.flatMap((draft) =>
    draft.payload.case === "filesystem"
      ? [draft.payload.value.resource?.identifier]
      : []
  );
  assert.deepEqual(files, ["/workspace/server.ts"]);
  assert.equal(
    drafts[0]?.observedAt.toISOString(),
    "2026-07-24T10:00:01.000Z",
  );
});

test("Cline CLI messages stay metadata-only under the default policy", () => {
  const drafts = clineActivityAdapter.parse({
    id: "msg-private",
    role: "assistant",
    content: [
      { type: "text", text: "Reading /private/project." },
      { type: "tool_use", id: "toolu_read", name: "editor", input: { path: "/private/project/a.ts", new_text: "fixturesecret" } },
    ],
    ts: Date.parse("2026-07-24T10:00:02.000Z"),
  }, {
    sessionId: "session-cline-private",
    observedAt,
    policy: metadataOnlyPolicy(),
  });
  assert.ok(drafts.some((draft) => draft.payload.case === "filesystem"));
  assertMetadataOnly(drafts);
});

test("Cursor agent transcripts become prompts, replies, commands, and file edits", () => {
  const config = loadConfig({ PHIGON_OBSERVABILITY_PROFILE: "full" });
  const context = {
    sessionId: "session-cursor",
    observedAt,
    policy: new LocalPolicyEngine(config.policy),
  };
  const lines = [
    {
      role: "user",
      message: {
        content: [{
          type: "text",
          text: "<attached_files>\n<file path=\"a.ts\" />\n</attached_files>\n<user_query>\nAdd a health check.\n</user_query>",
        }],
      },
    },
    {
      role: "assistant",
      message: {
        content: [
          { type: "text", text: "Adding the endpoint." },
          { type: "tool_use", name: "Shell", input: { command: "npm test", working_directory: "/workspace" } },
          { type: "tool_use", name: "StrReplace", input: { path: "/workspace/server.ts", old_string: "a", new_string: "b" } },
          { type: "tool_use", name: "ApplyPatch", input: "*** Begin Patch\n*** Add File: /workspace/health.ts\n+export {};\n*** End Patch" },
        ],
      },
    },
    { type: "turn_ended", status: "success" },
    { type: "turn_ended", status: "error", error: "provider unavailable" },
    { role: "user", message: { content: [{ type: "text", text: "No wrapper here." }] } },
  ];
  const drafts = lines.flatMap((line) => cursorActivityAdapter.parse(line, context));
  assert.deepEqual(
    drafts.flatMap((draft) =>
      draft.payload.case === "activity"
        ? [[draft.payload.value.kind, draft.payload.value.content ?? ""]]
        : []
    ),
    [
      [ActivityKind.PROMPT, "Add a health check."],
      [ActivityKind.RESPONSE, "Adding the endpoint."],
      [ActivityKind.ERROR, ""],
      [ActivityKind.PROMPT, "No wrapper here."],
    ],
  );
  assert.deepEqual(
    drafts.flatMap((draft) =>
      draft.payload.case === "tool"
        ? [[draft.payload.value.toolName, draft.payload.value.phase]]
        : []
    ),
    [
      ["Shell", ToolPhase.REQUESTED],
      ["StrReplace", ToolPhase.REQUESTED],
      ["ApplyPatch", ToolPhase.REQUESTED],
    ],
  );
  const terminal = drafts.find((draft) => draft.payload.case === "terminal");
  assert.equal(
    terminal?.payload.case === "terminal" ? terminal.payload.value.arguments : "",
    "npm test",
  );
  assert.deepEqual(
    drafts.flatMap((draft) =>
      draft.payload.case === "filesystem"
        ? [draft.payload.value.resource?.identifier]
        : []
    ),
    ["/workspace/server.ts", "/workspace/health.ts"],
  );
  assert.ok(drafts.some((draft) =>
    draft.payload.case === "lifecycle" &&
    draft.payload.value.phase === LifecyclePhase.IDLE
  ));
});

test("Cursor transcripts stay metadata-only under the default policy", () => {
  const drafts = cursorActivityAdapter.parse({
    role: "assistant",
    message: {
      content: [
        { type: "text", text: "Reading /private/project." },
        { type: "tool_use", name: "Write", input: { path: "/private/project/a.ts", contents: "fixturesecret" } },
      ],
    },
  }, {
    sessionId: "session-cursor-private",
    observedAt,
    policy: metadataOnlyPolicy(),
  });
  assert.ok(drafts.some((draft) => draft.payload.case === "filesystem"));
  assertMetadataOnly(drafts);
});

test("VS Code Copilot chat requests become prompts, replies, reasoning, and tool calls", () => {
  const config = loadConfig({ PHIGON_OBSERVABILITY_PROFILE: "full" });
  const context = {
    sessionId: "session-copilot-chat",
    observedAt,
    policy: new LocalPolicyEngine(config.policy),
  };
  const fileUri = { $mid: 1, scheme: "file", path: "/workspace/server.ts", fsPath: "/workspace/server.ts" };
  const drafts = copilotChatActivityAdapter.parse({
    requestId: "request_1",
    timestamp: Date.parse("2026-07-24T10:00:01.000Z"),
    message: { text: "Why does the build fail?", parts: [{ kind: "text", text: "Why does the build fail?" }] },
    response: [
      { kind: "thinking", value: "Check the server.", id: "t1" },
      { kind: "thinking", value: ["Then run ", "the tests."], id: "t2" },
      { kind: "prepareToolInvocation", toolName: "copilot_readFile" },
      {
        kind: "toolInvocationSerialized",
        toolId: "copilot_readFile",
        toolCallId: "call_read",
        invocationMessage: { value: "Reading [](file:///workspace/server.ts)", uris: { "file:///workspace/server.ts": fileUri } },
        pastTenseMessage: { value: "Read [](file:///workspace/server.ts)", uris: { "file:///workspace/server.ts": fileUri } },
        isConfirmed: { type: 1 },
        isComplete: true,
        source: { type: "internal" },
      },
      {
        kind: "toolInvocationSerialized",
        toolId: "run_in_terminal",
        toolCallId: "call_test",
        invocationMessage: "Running tests",
        toolSpecificData: {
          kind: "terminal",
          commandLine: { original: "npm test" },
          language: "sh",
          terminalCommandOutput: { text: "1 failing" },
          terminalCommandState: { exitCode: 1 },
        },
        isConfirmed: { type: 4 },
        isComplete: true,
      },
      {
        kind: "toolInvocationSerialized",
        toolId: "run_in_terminal",
        toolCallId: "call_denied",
        invocationMessage: "Running cleanup",
        toolSpecificData: { kind: "terminal", commandLine: { original: "rm -rf build" } },
        isConfirmed: { type: 0 },
        isComplete: true,
      },
      { value: "The test for ", supportThemeIcons: false, supportHtml: false },
      { kind: "inlineReference", inlineReference: fileUri },
      { value: " fails.", supportThemeIcons: false, supportHtml: false },
    ],
    result: { errorDetails: { message: "Rate limited", code: "rate" } },
  }, context);
  assert.deepEqual(
    drafts.flatMap((draft) =>
      draft.payload.case === "activity"
        ? [[draft.payload.value.kind, draft.payload.value.content ?? ""]]
        : []
    ),
    [
      [ActivityKind.PROMPT, "Why does the build fail?"],
      [ActivityKind.RESPONSE, "The test for `server.ts` fails."],
      [ActivityKind.REASONING, "Check the server.\n\nThen run the tests."],
      [ActivityKind.ERROR, ""],
    ],
  );
  assert.deepEqual(
    drafts.flatMap((draft) =>
      draft.payload.case === "tool"
        ? [[draft.payload.value.invocationId, draft.payload.value.toolName, draft.payload.value.phase]]
        : []
    ),
    [
      ["call_read", "read_file", ToolPhase.SUCCEEDED],
      ["call_test", "run_in_terminal", ToolPhase.FAILED],
      ["call_denied", "run_in_terminal", ToolPhase.CANCELLED],
    ],
  );
  const terminal = drafts.find((draft) =>
    draft.payload.case === "terminal" && draft.payload.value.commandId === "call_test"
  );
  if (terminal?.payload.case === "terminal") {
    assert.equal(terminal.payload.value.arguments, "npm test");
    assert.equal(terminal.payload.value.exitCode, 1);
  } else {
    assert.fail("run_in_terminal must produce a terminal event.");
  }
  const read = drafts.find((draft) => draft.payload.case === "filesystem");
  if (read?.payload.case === "filesystem") {
    assert.equal(read.payload.value.operation, FilesystemOperation.READ);
    assert.equal(read.payload.value.resource?.identifier, "/workspace/server.ts");
  } else {
    assert.fail("read_file must produce a filesystem event.");
  }
});

test("VS Code Copilot chat requests stay metadata-only under the default policy", () => {
  const drafts = copilotChatActivityAdapter.parse({
    requestId: "request_private",
    message: { text: "Read /private/project/a.ts" },
    response: [
      { value: "fixturesecret is in /private/project/a.ts" },
      {
        kind: "toolInvocationSerialized",
        toolId: "copilot_createFile",
        toolCallId: "call_create",
        invocationMessage: { value: "Creating", uris: { a: { path: "/private/project/a.ts" } } },
        isComplete: true,
      },
    ],
    result: {},
  }, {
    sessionId: "session-copilot-chat-private",
    observedAt,
    policy: metadataOnlyPolicy(),
  });
  assert.ok(drafts.some((draft) => draft.payload.case === "filesystem"));
  assertMetadataOnly(drafts);
});

test("Kiro chat history items become prompts and replies", () => {
  const config = loadConfig({ PHIGON_OBSERVABILITY_PROFILE: "full" });
  const context = {
    sessionId: "session-kiro",
    observedAt,
    policy: new LocalPolicyEngine(config.policy),
  };
  const items = [
    { message: { id: "m1", role: "user", content: "Add a health check." }, contextItems: [], editorState: { type: "doc" } },
    {
      message: { id: "m2", role: "assistant", content: [{ type: "text", text: "Adding the endpoint." }, { type: "imageUrl", imageUrl: { url: "data:" } }] },
      contextItems: [],
      executionId: "exec-1",
      promptLogs: [],
    },
    { message: { id: "m3", role: "system", content: "Injected instructions." } },
    { message: { id: "m4", role: "assistant", content: [] } },
  ];
  assert.deepEqual(
    items.flatMap((item) => kiroActivityAdapter.parse(item, context)).flatMap((draft) =>
      draft.payload.case === "activity"
        ? [[draft.payload.value.kind, draft.payload.value.content]]
        : []
    ),
    [
      [ActivityKind.PROMPT, "Add a health check."],
      [ActivityKind.RESPONSE, "Adding the endpoint."],
    ],
  );
  assertMetadataOnly(kiroActivityAdapter.parse(
    { message: { id: "m5", role: "user", content: "fixturesecret in /private/project" } },
    { sessionId: "session-kiro-private", observedAt, policy: metadataOnlyPolicy() },
  ));
});

test("Goose session messages become prompts, replies, commands, and file edits", () => {
  const config = loadConfig({ PHIGON_OBSERVABILITY_PROFILE: "full" });
  const context = {
    sessionId: "session-goose",
    observedAt,
    policy: new LocalPolicyEngine(config.policy),
  };
  const message = (role: string, content: unknown, metadata: unknown = { userVisible: true, agentVisible: true }) => ({
    type: "goose_message",
    role,
    content,
    created: 1785000000,
    timestamp: "2026-07-24T10:00:00.000Z",
    metadata,
  });
  const drafts = [
    message("user", [{ type: "text", text: "List the failing tests." }]),
    message("user", [{ type: "text", text: "Summary of earlier context." }], { userVisible: false, agentVisible: true }),
    message("assistant", [
      { type: "thinking", thinking: "Run the suite.", signature: "sig" },
      { type: "text", text: "Running them now." },
      {
        type: "toolRequest",
        id: "call_shell",
        toolCall: { status: "success", value: { name: "developer__shell", arguments: { command: "npm test" } } },
      },
      {
        type: "toolRequest",
        id: "call_edit",
        toolCall: {
          status: "success",
          value: {
            name: "developer__text_editor",
            arguments: { command: "str_replace", path: "/workspace/a.ts", old_str: "a", new_str: "b" },
          },
        },
      },
    ]),
    message("user", [
      {
        type: "toolResponse",
        id: "call_shell",
        toolResult: { status: "success", value: { content: [{ type: "text", text: "1 failing" }], isError: true } },
      },
      {
        type: "toolResponse",
        id: "call_edit",
        toolResult: { status: "success", value: { content: [{ type: "text", text: "Edited." }] } },
      },
    ]),
  ].flatMap((record) => gooseActivityAdapter.parse(record, context));

  assert.deepEqual(
    drafts.flatMap((draft) =>
      draft.payload.case === "activity"
        ? [[draft.payload.value.kind, draft.payload.value.content]]
        : []
    ),
    [
      [ActivityKind.PROMPT, "List the failing tests."],
      [ActivityKind.RESPONSE, "Running them now."],
      [ActivityKind.REASONING, "Run the suite."],
    ],
  );
  assert.deepEqual(
    drafts.flatMap((draft) =>
      draft.payload.case === "tool"
        ? [[draft.payload.value.toolName, draft.payload.value.phase]]
        : []
    ),
    [
      ["developer__shell", ToolPhase.REQUESTED],
      ["developer__text_editor", ToolPhase.REQUESTED],
      ["developer__shell", ToolPhase.FAILED],
      ["developer__text_editor", ToolPhase.SUCCEEDED],
    ],
  );
  assert.deepEqual(
    drafts.flatMap((draft) =>
      draft.payload.case === "terminal"
        ? [[
            draft.payload.value.phase,
            draft.payload.value.arguments ?? "",
            Buffer.from(draft.payload.value.output ?? []).toString("utf8"),
          ]]
        : []
    ),
    [
      [TerminalPhase.STARTED, "npm test", ""],
      [TerminalPhase.EXITED, "", "1 failing"],
    ],
  );
  assert.deepEqual(
    drafts.flatMap((draft) =>
      draft.payload.case === "filesystem"
        ? [[draft.payload.value.resource?.identifier, draft.payload.value.operation]]
        : []
    ),
    [["/workspace/a.ts", FilesystemOperation.WRITE]],
  );
});

test("Zed thread items become prompts, replies, reasoning, commands, and file edits", () => {
  const config = loadConfig({ PHIGON_OBSERVABILITY_PROFILE: "full" });
  const context = {
    sessionId: "session-zed",
    observedAt,
    policy: new LocalPolicyEngine(config.policy),
  };
  const timestamp = "2026-07-24T10:00:00.000Z";
  const reply = (block: unknown) => ({ type: "zed_message", role: "assistant", content: [block], thread_id: "t1", timestamp });
  const drafts = [
    {
      type: "zed_message",
      role: "user",
      content: [
        { Text: "Why does " },
        { Mention: { uri: { File: { abs_path: "/workspace/src/main.rs" } } } },
        { Text: " panic?" },
        { Image: {} },
      ],
      thread_id: "t1",
      timestamp,
    },
    reply({ Thinking: { text: "Check the unwrap." } }),
    reply({ Text: "It unwraps a missing value." }),
    reply({ ToolUse: { id: "tool_1", name: "terminal", input: { command: "cargo test", cd: "workspace" }, is_input_complete: true } }),
    reply({ ToolUse: { id: "tool_2", name: "edit_file", input: { path: "workspace/src/main.rs", mode: "edit", display_description: "Fix" }, is_input_complete: true } }),
    { type: "zed_tool_result", tool_use_id: "tool_1", tool_name: "", is_error: true, content: "1 failed", thread_id: "t1", timestamp },
    { type: "zed_tool_result", tool_use_id: "tool_2", tool_name: "edit_file", is_error: false, content: "Edited", thread_id: "t1", timestamp },
    { type: "zed_message", role: "user", content: [{ Image: {} }], thread_id: "t1", timestamp },
  ].flatMap((record) => zedActivityAdapter.parse(record, context));

  assert.deepEqual(
    drafts.flatMap((draft) =>
      draft.payload.case === "activity"
        ? [[draft.payload.value.kind, draft.payload.value.content]]
        : []
    ),
    [
      [ActivityKind.PROMPT, "Why does @main.rs panic?"],
      [ActivityKind.REASONING, "Check the unwrap."],
      [ActivityKind.RESPONSE, "It unwraps a missing value."],
    ],
  );
  assert.deepEqual(
    drafts.flatMap((draft) =>
      draft.payload.case === "tool"
        ? [[draft.payload.value.toolName, draft.payload.value.phase]]
        : []
    ),
    [
      ["terminal", ToolPhase.REQUESTED],
      ["edit_file", ToolPhase.REQUESTED],
      ["terminal", ToolPhase.FAILED],
      ["edit_file", ToolPhase.SUCCEEDED],
    ],
  );
  assert.deepEqual(
    drafts.flatMap((draft) =>
      draft.payload.case === "terminal"
        ? [[draft.payload.value.phase, draft.payload.value.arguments ?? ""]]
        : []
    ),
    [
      [TerminalPhase.STARTED, "cargo test"],
      [TerminalPhase.EXITED, ""],
    ],
  );
  assert.deepEqual(
    drafts.flatMap((draft) =>
      draft.payload.case === "filesystem"
        ? [[draft.payload.value.resource?.identifier, draft.payload.value.operation]]
        : []
    ),
    [["workspace/src/main.rs", FilesystemOperation.WRITE]],
  );
  assertMetadataOnly(zedActivityAdapter.parse(
    { type: "zed_message", role: "user", content: [{ Text: "fixturesecret in /private/project" }] },
    { sessionId: "session-zed-private", observedAt, policy: metadataOnlyPolicy() },
  ));
});

test("Factory Droid session lines become prompts, replies, reasoning, commands, and file edits", () => {
  const config = loadConfig({ PHIGON_OBSERVABILITY_PROFILE: "full" });
  const context = {
    sessionId: "session-droid",
    observedAt,
    policy: new LocalPolicyEngine(config.policy),
  };
  const message = (id: string, role: string, content: unknown) => ({
    type: "message",
    id,
    timestamp: "2026-07-24T10:00:00.000Z",
    message: { role, content },
  });
  const drafts = [
    { type: "session_start", id: "s1", title: "Fix tests", cwd: "/workspace" },
    message("m1", "user", [
      { type: "text", text: "<system-reminder>Context for the model.</system-reminder>" },
      { type: "text", text: "Fix the failing test." },
    ]),
    message("m2", "assistant", [
      { type: "thinking", thinking: "Run it first." },
      { type: "text", text: "Running the suite." },
      { type: "tool_use", id: "tu1", name: "Execute", input: { command: "npm test" } },
      { type: "tool_use", id: "tu2", name: "Edit", input: { file_path: "/workspace/a.ts", old_string: "a", new_string: "b" } },
    ]),
    message("m3", "user", [
      { type: "tool_result", tool_use_id: "tu1", content: "1 failing", is_error: true },
      { type: "tool_result", tool_use_id: "tu2", content: [{ type: "text", text: "Edited." }] },
    ]),
    { type: "session_event", data: "session_ended" },
  ].flatMap((record) => factoryDroidActivityAdapter.parse(record, context));

  assert.deepEqual(
    drafts.flatMap((draft) =>
      draft.payload.case === "activity"
        ? [[draft.payload.value.kind, draft.payload.value.content]]
        : []
    ),
    [
      [ActivityKind.PROMPT, "Fix the failing test."],
      [ActivityKind.RESPONSE, "Running the suite."],
      [ActivityKind.REASONING, "Run it first."],
    ],
  );
  assert.deepEqual(
    drafts.flatMap((draft) =>
      draft.payload.case === "tool"
        ? [[draft.payload.value.toolName, draft.payload.value.phase]]
        : []
    ),
    [
      ["Execute", ToolPhase.REQUESTED],
      ["Edit", ToolPhase.REQUESTED],
      ["Execute", ToolPhase.FAILED],
      ["Edit", ToolPhase.SUCCEEDED],
    ],
  );
  assert.deepEqual(
    drafts.flatMap((draft) =>
      draft.payload.case === "terminal"
        ? [[draft.payload.value.phase, draft.payload.value.arguments ?? ""]]
        : []
    ),
    [
      [TerminalPhase.STARTED, "npm test"],
      [TerminalPhase.EXITED, ""],
    ],
  );
  assert.deepEqual(
    drafts.flatMap((draft) =>
      draft.payload.case === "filesystem"
        ? [[draft.payload.value.resource?.identifier, draft.payload.value.operation]]
        : []
    ),
    [["/workspace/a.ts", FilesystemOperation.WRITE]],
  );
  assert.deepEqual(
    drafts.flatMap((draft) =>
      draft.payload.case === "lifecycle" ? [draft.payload.value.phase] : []
    ),
    [LifecyclePhase.DISCOVERED, LifecyclePhase.STOPPED],
  );
  assertMetadataOnly(factoryDroidActivityAdapter.parse(
    message("m4", "user", [{ type: "text", text: "fixturesecret in /private/project" }]),
    { sessionId: "session-droid-private", observedAt, policy: metadataOnlyPolicy() },
  ));
});

test("Copilot CLI compatible bridge records preserve prompts, replies, and tools", () => {
  const drafts = copilotActivityAdapter.parse({
    type: "assistant.message",
    message: {
      role: "assistant",
      content: "The checks passed.",
      tool_calls: [{
        id: "copilot-shell",
        function: {
          name: "shell",
          arguments: JSON.stringify({ command: "npm test" }),
        },
      }],
    },
  }, {
    sessionId: "session-copilot",
    observedAt,
    policy: metadataOnlyPolicy(),
  });

  assert.ok(
    drafts.some(
      (draft) =>
        draft.payload.case === "activity" &&
        draft.payload.value.vendorType === "copilot_assistant",
    ),
  );
  assert.ok(
    drafts.some(
      (draft) =>
        draft.payload.case === "tool" &&
        draft.payload.value.toolName === "shell",
    ),
  );
});

test("filesystem tool events preserve their real operation", () => {
  const context = {
    sessionId: "session-filesystem",
    observedAt,
    policy: metadataOnlyPolicy(),
  };
  const cases = [
    ["Read", { file_path: "/private/project/a.ts" }, FilesystemOperation.READ],
    ["Glob", { path: "/private/project" }, FilesystemOperation.SEARCH],
    ["delete_file", { path: "/private/project/a.ts" }, FilesystemOperation.DELETE],
    ["move_file", { path: "/private/project/a.ts" }, FilesystemOperation.RENAME],
    ["create_file", { path: "/private/project/a.ts" }, FilesystemOperation.CREATE],
    ["write_file", { path: "/private/project/a.ts" }, FilesystemOperation.WRITE],
    [
      "apply_patch",
      { patch: "*** Begin Patch\n*** Delete File: old.ts\n*** End Patch\n" },
      FilesystemOperation.DELETE,
    ],
  ] as const;

  for (const [toolName, args, expected] of cases) {
    const filesystem = toolDrafts(AgentKind.CODEX, context, {
      toolName,
      phase: ToolPhase.SUCCEEDED,
      arguments: args,
    }).find((draft) => draft.payload.case === "filesystem");
    assert.equal(filesystem?.payload.case, "filesystem");
    if (filesystem?.payload.case === "filesystem") {
      assert.equal(filesystem.payload.value.operation, expected);
    }
  }
});

test("a file tool result without arguments does not add an unnamed file event", () => {
  const context = {
    sessionId: "session-claude-edit",
    observedAt,
    policy: metadataOnlyPolicy(),
  };
  const drafts = [
    ...claudeActivityAdapter.parse({
      type: "assistant",
      message: {
        role: "assistant",
        content: [{
          type: "tool_use",
          id: "toolu_edit",
          name: "Edit",
          input: { file_path: "/private/project/a.ts", old_string: "a", new_string: "b" },
        }],
      },
    }, context),
    ...claudeActivityAdapter.parse({
      type: "user",
      message: {
        role: "user",
        content: [{ type: "tool_result", tool_use_id: "toolu_edit", content: "Updated." }],
      },
    }, context),
  ];
  assert.deepEqual(countPayloads(drafts), { filesystem: 1, tool: 2 });
});

test("text-editor sub-commands are file operations, not shell commands", () => {
  const context = {
    sessionId: "session-editor",
    observedAt,
    policy: metadataOnlyPolicy(),
  };
  const kinds = (toolName: string, args: unknown) =>
    toolDrafts(AgentKind.GENERIC, context, {
      toolName,
      phase: ToolPhase.REQUESTED,
      arguments: args,
    }).flatMap((draft) =>
      draft.payload.case === "filesystem"
        ? [`file:${draft.payload.value.operation}`]
        : draft.payload.case === "terminal"
          ? ["terminal"]
          : []
    );
  assert.deepEqual(
    kinds("str_replace_based_edit_tool", { command: "str_replace", path: "/private/project/a.ts", old_str: "a", new_str: "b" }),
    [`file:${FilesystemOperation.WRITE}`],
  );
  assert.deepEqual(
    kinds("developer__text_editor", { command: "view", path: "/private/project/a.ts" }),
    [`file:${FilesystemOperation.READ}`],
  );
  assert.deepEqual(
    kinds("str_replace_editor", { command: "create", path: "/private/project/b.ts", file_text: "x" }),
    [`file:${FilesystemOperation.CREATE}`],
  );
  assert.deepEqual(kinds("developer__shell", { command: "view logs" }), ["terminal"]);
});

test("command arrays and command batches become readable terminal commands", () => {
  const policy = new LocalPolicyEngine(loadConfig({
    PHIGON_COLLECT_COMMAND_ARGUMENTS: "true",
  }).policy);
  const context = { sessionId: "session-argv", observedAt, policy };
  const terminalArguments = (toolName: string, args: unknown) =>
    toolDrafts(AgentKind.GENERIC, context, {
      toolName,
      phase: ToolPhase.REQUESTED,
      arguments: args,
    }).flatMap((draft) =>
      draft.payload.case === "terminal"
        ? [[draft.payload.value.executable, draft.payload.value.arguments]]
        : []
    );
  assert.deepEqual(
    terminalArguments("local_shell", { command: ["bash", "-lc", "npm test"] }),
    [["bash", "bash -lc npm test"]],
  );
  assert.deepEqual(
    terminalArguments("run_commands", { commands: ["npm ci", "npm test"] }),
    [["npm", "npm ci\nnpm test"]],
  );
  const git = toolDrafts(AgentKind.GENERIC, context, {
    toolName: "process",
    phase: ToolPhase.REQUESTED,
    arguments: { argv: ["git", "status"] },
  }).find((draft) => draft.payload.case === "git");
  assert.equal(git?.payload.case, "git");
});

test("structured custom tools derive terminal, filesystem, browser, and Git signals", () => {
  const context = {
    sessionId: "session-custom-tools",
    observedAt,
    policy: metadataOnlyPolicy(),
  };
  const terminalAndGit = toolDrafts(AgentKind.CODEX, context, {
    toolName: "mcp_runner",
    phase: ToolPhase.SUCCEEDED,
    arguments: {
      command: "git status",
      cwd: "/private/project",
    },
  });
  assert.ok(terminalAndGit.some((draft) => draft.payload.case === "terminal"));
  assert.ok(terminalAndGit.some((draft) => draft.payload.case === "git"));

  const filesystem = toolDrafts(AgentKind.CODEX, context, {
    toolName: "workspace_resource",
    phase: ToolPhase.REQUESTED,
    arguments: { file_path: "/private/project/a.ts" },
  });
  assert.ok(filesystem.some((draft) => draft.payload.case === "filesystem"));

  const browser = toolDrafts(AgentKind.CODEX, context, {
    toolName: "web_action",
    phase: ToolPhase.REQUESTED,
    arguments: { url: "https://example.test/path" },
  });
  assert.ok(browser.some((draft) => draft.payload.case === "browser"));
});

test("metadata categories fail closed before canonical evidence is emitted", () => {
  const config = loadConfig({
    PHIGON_COLLECT_FILE_METADATA: "false",
    PHIGON_COLLECT_BROWSER_METADATA: "false",
  });
  const context = {
    sessionId: "session-disabled-metadata",
    observedAt,
    policy: new LocalPolicyEngine(config.policy),
  };
  const drafts = toolDrafts(AgentKind.CODEX, context, {
    toolName: "workspace_browser_action",
    phase: ToolPhase.REQUESTED,
    arguments: {
      file_path: "/private/project/a.ts",
      url: "https://example.test/private",
    },
  });
  assert.equal(drafts.some((draft) => draft.payload.case === "filesystem"), false);
  assert.equal(drafts.some((draft) => draft.payload.case === "browser"), false);
});

test("full profile carries approved file, browser, and Git detail", () => {
  const config = loadConfig({ PHIGON_OBSERVABILITY_PROFILE: "full" });
  const context = {
    sessionId: "session-full-detail",
    observedAt,
    policy: new LocalPolicyEngine(config.policy),
  };
  const filesystem = toolDrafts(AgentKind.CODEX, context, {
    toolName: "write_file",
    phase: ToolPhase.SUCCEEDED,
    arguments: {
      file_path: "/workspace/a.ts",
      content: "export const ready = true;",
    },
  }).find((draft) => draft.payload.case === "filesystem");
  assert.equal(filesystem?.payload.case, "filesystem");
  if (filesystem?.payload.case === "filesystem") {
    assert.equal(
      Buffer.from(filesystem.payload.value.content ?? []).toString("utf8"),
      "export const ready = true;",
    );
    assert.equal(filesystem.payload.value.contentRedacted, false);
  }

  const browser = toolDrafts(AgentKind.CODEX, context, {
    toolName: "web_action",
    phase: ToolPhase.REQUESTED,
    arguments: {
      url: "https://example.test/path",
      accessible_name: "Deploy release",
    },
  }).find((draft) => draft.payload.case === "browser");
  assert.equal(browser?.payload.case, "browser");
  if (browser?.payload.case === "browser") {
    assert.equal(browser.payload.value.url, "https://example.test/path");
    assert.equal(browser.payload.value.target, "Deploy release");
  }

  const git = toolDrafts(AgentKind.CODEX, context, {
    toolName: "mcp_runner",
    phase: ToolPhase.SUCCEEDED,
    arguments: { command: "git -C /workspace diff" },
    output: "diff --git a/a.ts b/a.ts",
  }).find((draft) => draft.payload.case === "git");
  assert.equal(git?.payload.case, "git");
  if (git?.payload.case === "git") {
    assert.equal(git.payload.value.patch, "diff --git a/a.ts b/a.ts");
    assert.equal(git.payload.value.patchRedacted, false);
  }
});

test("malformed, circular, and deeply nested vendor records never throw", () => {
  const policy = metadataOnlyPolicy();
  const circular: Record<string, unknown> = { type: "assistant" };
  circular["message"] = circular;
  let deep: Record<string, unknown> = { value: "end" };
  for (let index = 0; index < 32; index++) {
    deep = { content: deep };
  }
  const values: readonly unknown[] = [
    null,
    undefined,
    42,
    "{malformed",
    circular,
    deep,
    { type: "response_item", payload: { type: "function_call" } },
  ];
  const adapters = [
    claudeActivityAdapter,
    codexActivityAdapter,
    hermesActivityAdapter,
    openClawActivityAdapter,
    genericActivityAdapter,
  ];

  for (const adapter of adapters) {
    for (const value of values) {
      assert.doesNotThrow(() =>
        adapter.parse(value, {
          sessionId: "session-adversarial",
          observedAt,
          policy,
        }),
      );
    }
  }
});

test("UTF-8 truncation respects byte limits and code-point boundaries", () => {
  const result = truncateUTF8("abc🙂def", 6);
  assert.equal(result.value, "abc");
  assert.equal(result.truncated, true);
  assert.ok(Buffer.byteLength(result.value, "utf8") <= 6);
});

async function parseFixture(
  name: string,
  adapter: VendorActivityAdapter,
  policy: LocalPolicyEngine,
): Promise<ActivityDraft[]> {
  const raw = await readFile(new URL(`${name}.jsonl`, fixtureRoot), "utf8");
  return raw
    .trim()
    .split(/\r?\n/u)
    .flatMap((line) =>
      adapter.parse(JSON.parse(line), {
        sessionId: `session-${name}`,
        observedAt,
        policy,
      }),
    );
}

function metadataOnlyPolicy(): LocalPolicyEngine {
  return new LocalPolicyEngine(loadConfig({}).policy, [
    "/private/project",
  ]);
}

function countPayloads(
  drafts: readonly ActivityDraft[],
): Record<string, number> {
  const result: Record<string, number> = {};
  for (const draft of drafts) {
    const name = draft.payload.case ?? "unset";
    result[name] = (result[name] ?? 0) + 1;
  }
  return Object.fromEntries(
    Object.entries(result).sort(([left], [right]) =>
      left.localeCompare(right),
    ),
  );
}

function assertMetadataOnly(drafts: readonly ActivityDraft[]): void {
  const serialized = serialize(drafts);
  assert.doesNotMatch(serialized, /fixturesecret/u);
  assert.doesNotMatch(serialized, /\/private\/project/u);
  for (const draft of drafts) {
    if (draft.payload.case === "activity") {
      assert.equal(draft.payload.value.content, undefined);
      assert.equal(draft.payload.value.contentRedacted, true);
    }
    if (draft.payload.case === "tool") {
      assert.equal(draft.payload.value.argumentsJson, undefined);
      assert.equal(draft.payload.value.output, undefined);
    }
    if (draft.payload.case === "terminal") {
      assert.equal(draft.payload.value.arguments, undefined);
      assert.equal(draft.payload.value.output, undefined);
    }
    if (draft.payload.case === "browser") {
      assert.equal(draft.payload.value.url, undefined);
    }
    if (draft.payload.case === "filesystem") {
      assert.equal(draft.payload.value.resource?.identifier, undefined);
    }
  }
}

function serialize(value: unknown): string {
  return JSON.stringify(value, (_key, item: unknown) =>
    typeof item === "bigint" ? item.toString() : item,
  );
}
