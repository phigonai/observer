import assert from "node:assert/strict";
import test from "node:test";
import { LocalPolicyEngine } from "../src/activity/policy.js";
import { toolDrafts } from "../src/activity/normalize.js";
import { loadConfig } from "../src/config.js";
import { AgentKind } from "../src/generated/phigon/v1/common_pb.js";
import { ToolPhase } from "../src/generated/phigon/v1/telemetry_pb.js";

test("missing tool arguments and results remain absent instead of creating phantom records", () => {
  const policy = new LocalPolicyEngine(loadConfig({ PHIGON_OBSERVABILITY_PROFILE: "full" }).policy);
  const context = { sessionId: "missing-fields", observedAt: new Date(), policy };
  assert.equal(policy.json(undefined, "toolOutput").value, undefined);
  const [call] = toolDrafts(AgentKind.CODEX, context, {
    invocationId: "call", toolName: "shell_command", phase: ToolPhase.REQUESTED, arguments: { command: "npm test" },
  });
  assert.ok(call?.payload.case === "tool");
  assert.equal(call.payload.value.output, undefined);
  const [result] = toolDrafts(AgentKind.CODEX, context, {
    invocationId: "call", toolName: "shell_command", phase: ToolPhase.SUCCEEDED, output: "Tests passed",
  });
  assert.ok(result?.payload.case === "tool");
  assert.equal(result.payload.value.argumentsJson, undefined);
  assert.equal(result.payload.value.output, '"Tests passed"');
});
