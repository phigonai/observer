import assert from "node:assert/strict";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import type { StoredActionPolicy } from "../src/action-policy.js";
import {
  GuardianDecisionUnavailableError,
  HTTPGuardianDecisionClient,
  readGuardianActionContext,
} from "../src/agentic-guardian.js";
import { GuardianHostedClient } from "../src/guardian-hosted-client.js";

const ruleID = "72b1f93f-6317-46c7-bbba-6174d19c4119";
const policy: StoredActionPolicy = Object.freeze({
  machineId: "machine-guardian-test",
  policyDigest: "a".repeat(64),
  defaultEffect: "allow",
  receivedAt: "2026-09-03T00:00:00.000Z",
  rules: [Object.freeze({
    ruleId: ruleID,
    action: "command.execute",
    effect: "deny",
    intervention: "block_action",
    resourcePattern: "*",
    agentPattern: "",
    reason: "Protect deletion",
    sourceText: "Do not delete project files.",
    enabled: true,
  })],
});

test("semantic Guardian accepts the authoritative contract returned by the control plane", async () => {
  let submitted: Record<string, unknown> | undefined;
  const fetcher: typeof fetch = async (_input, init) => {
    submitted = JSON.parse(String(init?.body)) as Record<string, unknown>;
    return new Response(JSON.stringify({
      decision: "deny",
      reason: "This command deletes a project file.",
      risk: "high",
      confidence: 0.98,
      matched_contract_id: ruleID,
      admin_contract: "Do not delete project files.",
      intervention: "block_action",
      model: "gpt-5-mini",
      cached: false,
      latency_ms: 24,
    }), { status: 200 });
  };
  const client = new HTTPGuardianDecisionClient({
    controlPlaneURL: new URL("https://control.example.test"),
    credential: "machine-secret",
    timeoutMs: 1_000,
    fetcher,
  });

  const decision = await client.decide({
    policyDigest: policy.policyDigest,
    agentId: "codex:worker",
    processId: 4242,
    processStartedAt: "2026-09-05T10:00:00.000Z",
    action: "command.execute",
    resource: "Remove-Item project.txt",
    context: { userPrompt: "Clean temporary project files" },
  });
  assert.equal(decision.decision, "deny");
  assert.equal(decision.adminContract, "Do not delete project files.");
  assert.equal(decision.model, "gpt-5-mini");
  assert.equal(decision.approvalState, undefined);
  assert.equal(submitted?.["policy_digest"], policy.policyDigest);
  assert.equal(submitted?.["process_id"], 4242);
  assert.equal(submitted?.["process_started_at"], "2026-09-05T10:00:00.000Z");
  assert.equal((submitted?.["context"] as Record<string, unknown>)["user_prompt"], "Clean temporary project files");
});

test("semantic Guardian rejects a blocking decision without its authoritative contract", async () => {
  const fetcher = (async () => new Response(JSON.stringify({
    decision: "deny",
    reason: "Unsupported contract",
    risk: "high",
    confidence: 0.8,
    matched_contract_id: "not-a-local-rule",
    intervention: "block_action",
    model: "gpt-5-mini",
    cached: false,
    latency_ms: 3,
  }), { status: 200 })) as typeof fetch;
  const client = new HTTPGuardianDecisionClient({
    controlPlaneURL: new URL("https://control.example.test"),
    credential: "machine-secret",
    timeoutMs: 1_000,
    fetcher,
  });
  await assert.rejects(
    client.decide({
      policyDigest: policy.policyDigest,
      agentId: "",
      action: "command.execute",
      resource: "Remove-Item project.txt",
      context: {},
    }),
    GuardianDecisionUnavailableError,
  );
});

test("Guardian action context is structured and bounded", async () => {
  const directory = await mkdtemp(join(tmpdir(), "phigon-guardian-context-"));
  try {
    const contextPath = join(directory, "context.json");
    await writeFile(contextPath, JSON.stringify({
      task_id: "task-1",
      proposal_id: "proposal-1",
      plan_step_id: "step-2",
      user_prompt: "Update the app",
      agent_plan: "Inspect, edit, and test",
      expected_effect: "Only application source files change",
    }));
    assert.deepEqual(await readGuardianActionContext(contextPath), {
      taskId: "task-1",
      proposalId: "proposal-1",
      planStepId: "step-2",
      userPrompt: "Update the app",
      agentPlan: "Inspect, edit, and test",
      expectedEffect: "Only application source files change",
    });
    await writeFile(contextPath, JSON.stringify({ unknown: "field" }));
    await assert.rejects(readGuardianActionContext(contextPath), /unsupported field/u);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("a Guardian request that gets no answer says why, without anything it sent", async () => {
  const refused = (async () => {
    throw new TypeError("fetch failed", { cause: Object.assign(new Error("connect ECONNREFUSED 192.0.2.1:443"), { code: "ECONNREFUSED" }) });
  }) as typeof fetch;
  const proposal = { policyDigest: policy.policyDigest, agentId: "", action: "command.execute", resource: "Remove-Item project.txt", context: {} };
  const client = (fetcher: typeof fetch, timeoutMs = 1_000) => new HTTPGuardianDecisionClient({
    controlPlaneURL: new URL("https://control.example.test"), credential: "machine-secret", timeoutMs, fetcher,
  });
  await assert.rejects(client(refused).decide(proposal), { message: "Guardian semantic decision service was unavailable (ECONNREFUSED)." });
  const silent = ((_url: URL, init: RequestInit) => new Promise((_resolve, reject) => {
    init.signal?.addEventListener("abort", () => reject(new DOMException("aborted", "AbortError")), { once: true });
  })) as typeof fetch;
  await assert.rejects(client(silent, 5).decide(proposal), { message: "Guardian semantic decision service was unavailable (no answer in time)." });
  const odd = (async () => { throw new TypeError("fetch failed", { cause: { code: "not a code; secret=1" } }); }) as typeof fetch;
  await assert.rejects(client(odd).decide(proposal), { message: "Guardian semantic decision service was unavailable." });

  const hosted = (fetcher: typeof fetch) => new GuardianHostedClient({ controlPlaneURL: new URL("https://control.example.test"), credential: "machine-secret", fetcher });
  const conflict = (async () => new Response(JSON.stringify({ error: { message: "do not repeat me" } }), { status: 409 })) as typeof fetch;
  await assert.rejects(
    hosted(conflict).post("/v1/machine/guardian/coverage", {}),
    { message: "Phigon Guardian could not reach your company's Phigon server (the server returned 409); the action remains blocked." },
  );
  await assert.rejects(
    hosted(refused).post("/v1/machine/guardian/coverage", {}),
    { message: "Phigon Guardian could not reach your company's Phigon server (ECONNREFUSED); the action remains blocked." },
  );
});
