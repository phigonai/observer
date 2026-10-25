import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { claudeActivityAdapter } from "../src/activity/adapters/claude.js";
import { codexActivityAdapter } from "../src/activity/adapters/codex.js";
import { copilotActivityAdapter } from "../src/activity/adapters/copilot.js";
import { genericActivityAdapter } from "../src/activity/adapters/generic.js";
import { hermesActivityAdapter } from "../src/activity/adapters/hermes.js";
import { openClawActivityAdapter } from "../src/activity/adapters/openclaw.js";
import { openCodeActivityAdapter } from "../src/activity/adapters/opencode.js";
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

test("Copilot CLI source records preserve prompts, replies, and tools", () => {
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
