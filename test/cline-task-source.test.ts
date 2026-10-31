import assert from "node:assert/strict";
import { mkdir, mkdtemp, rm, utimes, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import {
  clineTaskFirstMessageField,
  rooCodeActivityAdapter,
} from "../src/activity/adapters/cline-task.js";
import { LocalPolicyEngine } from "../src/activity/policy.js";
import { JSONLSourceReader } from "../src/activity/source-reader.js";
import { loadConfig } from "../src/config.js";
import { ActivityKind } from "../src/generated/phigon/v1/common_pb.js";
import {
  FilesystemOperation,
  LifecyclePhase,
  TerminalPhase,
  ToolPhase,
} from "../src/generated/phigon/v1/telemetry_pb.js";

type Scan = Awaited<ReturnType<JSONLSourceReader["scan"]>>;

const source = (root: string) => [{
  adapterId: "roo-code-task",
  roots: [root],
  format: "json-messages" as const,
  pathPattern: "^[^/]+/ui_messages[.]json$",
  messagesField: "",
  document: {
    directoryPattern: "^[^/]+$",
    messageIdField: "ts",
    pendingField: "partial",
    firstMessageField: clineTaskFirstMessageField,
  },
}];

const texts = (scan: Scan) =>
  scan.records.map((record) => {
    const value = record.value as { text?: string; [key: string]: unknown };
    return `${value[clineTaskFirstMessageField] === true ? "first:" : ""}${value.text ?? ""}`;
  });

test("Cline-style task messages are delivered once, the first one marked, a partial one held back", async () => {
  const directory = await mkdtemp(join(tmpdir(), "phigon-cline-task-"));
  const root = join(directory, "tasks");
  const task = join(root, "0b6f6c2e-task");
  const file = join(task, "ui_messages.json");
  await mkdir(task, { recursive: true });
  const reader = new JSONLSourceReader(join(directory, "data"), false);
  let modified = Date.now() / 1_000;
  const save = async (messages: readonly unknown[]) => {
    await writeFile(file, JSON.stringify(messages));
    modified += 2;
    await utimes(file, modified, modified);
  };
  try {
    // A task started after the observer: read from its first message.
    assert.deepEqual(texts(await reader.scan(source(root), 32)), []);
    const opening = [
      { ts: 1_785_000_000_000, type: "say", say: "text", text: "Add a login page" },
      { ts: 1_785_000_001_000, type: "say", say: "api_req_started", text: "{}" },
      { ts: 1_785_000_002_000, type: "say", say: "text", text: "I'll start", partial: true },
    ];
    await save(opening);
    const first = await reader.scan(source(root), 32);
    assert.deepEqual(texts(first), ["first:Add a login page", "{}"]);
    assert.equal(first.records[0]?.observedAt.getTime(), 1_785_000_000_000);
    await reader.commit(first.checkpoint);

    // The streamed reply is delivered once Cline marks it complete.
    await save([
      ...opening.slice(0, 2),
      { ts: 1_785_000_002_000, type: "say", say: "text", text: "I'll start with the form." },
      { ts: 1_785_000_003_000, type: "ask", ask: "command", text: "npm test" },
    ]);
    assert.deepEqual(texts(await reader.scan(source(root), 32)), ["I'll start with the form.", "npm test"]);
  } finally {
    reader.close();
    await rm(directory, { recursive: true, force: true });
  }
});

test("Cline, Roo Code and Kilo Code task messages become prompts, replies, commands, file edits and errors", () => {
  const context = {
    sessionId: "session-roo",
    observedAt: new Date("2026-07-24T10:00:00.000Z"),
    policy: new LocalPolicyEngine(loadConfig({ PHIGON_OBSERVABILITY_PROFILE: "full" }).policy),
  };
  const drafts = [
    { ts: 1, type: "say", say: "text", text: "Fix the failing test", [clineTaskFirstMessageField]: true },
    { ts: 2, type: "say", say: "api_req_started", text: "{\"tokensIn\":10}" },
    { ts: 3, type: "say", say: "reasoning", text: "Run the suite first." },
    { ts: 4, type: "say", say: "text", text: "Running the tests." },
    { ts: 5, type: "ask", ask: "command", text: "npm testREQ_APP" },
    { ts: 6, type: "say", say: "command_output", text: "1 failing" },
    { ts: 7, type: "ask", ask: "tool", text: JSON.stringify({ tool: "editedExistingFile", path: "src/a.ts", diff: "-a\n+b" }) },
    { ts: 8, type: "ask", ask: "followup", text: JSON.stringify({ question: "Keep the old test?", suggest: [] }) },
    { ts: 9, type: "say", say: "user_feedback", text: "Yes, keep it" },
    { ts: 10, type: "say", say: "error", text: "Rate limited" },
    { ts: 11, type: "say", say: "completion_result", text: "The test passes now." },
    { ts: 12, type: "ask", ask: "completion_result", text: "" },
  ].flatMap((record) => rooCodeActivityAdapter.parse(record, context));

  assert.deepEqual(
    drafts.flatMap((draft) =>
      draft.payload.case === "activity" && draft.payload.value.kind !== ActivityKind.ERROR
        ? [[draft.payload.value.kind, draft.payload.value.content]]
        : []
    ),
    [
      [ActivityKind.PROMPT, "Fix the failing test"],
      [ActivityKind.REASONING, "Run the suite first."],
      [ActivityKind.RESPONSE, "Running the tests."],
      [ActivityKind.RESPONSE, "Keep the old test?"],
      [ActivityKind.PROMPT, "Yes, keep it"],
      [ActivityKind.RESPONSE, "The test passes now."],
    ],
  );
  assert.deepEqual(
    drafts.flatMap((draft) =>
      draft.payload.case === "tool"
        ? [[draft.payload.value.toolName, draft.payload.value.phase, draft.payload.value.invocationId]]
        : []
    ),
    [
      ["execute_command", ToolPhase.REQUESTED, "command_5"],
      ["execute_command", ToolPhase.UNSPECIFIED, "command_5"],
      ["edit_file", ToolPhase.REQUESTED, "tool_7"],
    ],
  );
  assert.deepEqual(
    drafts.flatMap((draft) =>
      draft.payload.case === "terminal"
        ? [[draft.payload.value.phase, draft.payload.value.arguments ?? "", Buffer.from(draft.payload.value.output ?? []).toString("utf8")]]
        : []
    ),
    [
      [TerminalPhase.STARTED, "npm test", ""],
      [TerminalPhase.OUTPUT, "", "1 failing"],
    ],
  );
  assert.deepEqual(
    drafts.flatMap((draft) =>
      draft.payload.case === "filesystem"
        ? [[draft.payload.value.resource?.identifier, draft.payload.value.operation]]
        : []
    ),
    [["src/a.ts", FilesystemOperation.WRITE]],
  );
  assert.deepEqual(
    drafts.flatMap((draft) =>
      draft.payload.case === "lifecycle" ? [draft.payload.value.phase] : []
    ),
    [LifecyclePhase.IDLE],
  );
  assert.equal(
    drafts.filter((draft) => draft.payload.case === "activity" && draft.payload.value.kind === ActivityKind.ERROR).length,
    1,
  );
});
