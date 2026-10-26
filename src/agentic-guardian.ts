import { readFile } from "node:fs/promises";
import { redactSecrets } from "./content-redaction.js";
import type { GuardianIntervention } from "./action-policy.js";

const maxResponseBytes = 64 << 10;

export type GuardianActionContext = Readonly<{
  taskId?: string;
  proposalId?: string;
  planStepId?: string;
  userPrompt?: string;
  agentPlan?: string;
  justification?: string;
  expectedEffect?: string;
  recentActivity?: string;
}>;

export type GuardianActionProposal = Readonly<{
  policyDigest: string;
  agentId: string;
  processId?: number;
  processStartedAt?: string;
  action: string;
  resource: string;
  context: GuardianActionContext;
}>;

export type GuardianSemanticDecision = Readonly<{
  decision: "allow" | "deny" | "require_approval";
  reason: string;
  risk: "low" | "medium" | "high" | "critical";
  confidence: number;
  matchedContractId?: string;
  adminContract?: string;
  intervention: "none" | GuardianIntervention;
  model: string;
  cached: boolean;
  latencyMs: number;
  approvalId?: string;
  approvalState?: "pending" | "approved" | "rejected" | "consumed" | "expired";
  approvalExpiresAt?: string;
}>;

export class GuardianDecisionUnavailableError extends Error {}

export class HTTPGuardianDecisionClient {
  readonly #controlPlaneURL: URL;
  readonly #credential: string;
  readonly #timeoutMs: number;
  readonly #fetch: typeof fetch;

  constructor(options: Readonly<{
    controlPlaneURL: URL;
    credential: string;
    timeoutMs: number;
    fetcher?: typeof fetch;
  }>) {
    this.#controlPlaneURL = options.controlPlaneURL;
    this.#credential = options.credential;
    this.#timeoutMs = options.timeoutMs;
    this.#fetch = options.fetcher ?? fetch;
  }

  async decide(
    proposal: GuardianActionProposal,
    signal?: AbortSignal,
  ): Promise<GuardianSemanticDecision> {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), this.#timeoutMs);
    const started = performance.now();
    try {
      const endpoint = new URL(
        "/v1/machine/guardian/decisions",
        this.#controlPlaneURL,
      );
      const response = await this.#fetch(endpoint, {
        method: "POST",
        headers: {
          Authorization: `Bearer ${this.#credential}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          policy_digest: proposal.policyDigest,
          agent_id: proposal.agentId,
          process_id: proposal.processId ?? 0,
          process_started_at: proposal.processStartedAt ?? "",
          action: proposal.action,
          resource: proposal.resource,
          context: {
            task_id: proposal.context.taskId ?? "",
            proposal_id: proposal.context.proposalId ?? "",
            plan_step_id: proposal.context.planStepId ?? "",
            user_prompt: proposal.context.userPrompt ?? "",
            agent_plan: proposal.context.agentPlan ?? "",
            justification: proposal.context.justification ?? "",
            expected_effect: proposal.context.expectedEffect ?? "",
            recent_activity: proposal.context.recentActivity ?? "",
          },
        }),
        signal: signal === undefined ? controller.signal : AbortSignal.any([controller.signal, signal]),
      });
      const raw = await response.text();
      if (Buffer.byteLength(raw, "utf8") > maxResponseBytes) {
        throw new GuardianDecisionUnavailableError("Guardian decision response was too large.");
      }
      if (!response.ok) {
        throw new GuardianDecisionUnavailableError(
          `Guardian decision service returned ${response.status}.`,
        );
      }
      let value: unknown;
      try {
        value = JSON.parse(raw);
      } catch {
        throw new GuardianDecisionUnavailableError("Guardian decision response was invalid.");
      }
      return semanticDecision(
        value,
        Math.max(0, Math.round(performance.now() - started)),
      );
    } catch (error) {
      if (error instanceof GuardianDecisionUnavailableError) throw error;
      throw new GuardianDecisionUnavailableError(
        "Guardian semantic decision service was unavailable.",
      );
    } finally {
      clearTimeout(timeout);
    }
  }
}

export async function readGuardianActionContext(
  path: string | undefined,
): Promise<GuardianActionContext> {
  if (path === undefined) return Object.freeze({});
  const raw = await readFile(path);
  if (raw.byteLength > 16 << 10) {
    throw new Error("Guardian context file must not exceed 16 KiB.");
  }
  let value: unknown;
  try {
    value = JSON.parse(raw.toString("utf8"));
  } catch {
    throw new Error("Guardian context file must contain valid UTF-8 JSON.");
  }
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("Guardian context file must contain a JSON object.");
  }
  const record = value as Record<string, unknown>;
  const allowed = new Set([
    "task_id",
    "proposal_id",
    "plan_step_id",
    "user_prompt",
    "agent_plan",
    "justification",
    "expected_effect",
    "recent_activity",
  ]);
  if (Object.keys(record).some((key) => !allowed.has(key))) {
    throw new Error("Guardian context file contains an unsupported field.");
  }
  return Object.freeze({
    ...optionalContext(record, "task_id", "taskId", 128, false),
    ...optionalContext(record, "proposal_id", "proposalId", 128, false),
    ...optionalContext(record, "plan_step_id", "planStepId", 128, false),
    ...optionalContext(record, "user_prompt", "userPrompt", 2_000),
    ...optionalContext(record, "agent_plan", "agentPlan", 2_000),
    ...optionalContext(record, "justification", "justification", 1_000),
    ...optionalContext(record, "expected_effect", "expectedEffect", 1_000),
    ...optionalContext(record, "recent_activity", "recentActivity", 2_000),
  });
}

function optionalContext(
  record: Record<string, unknown>,
  source: string,
  target: keyof GuardianActionContext,
  maximum: number,
  redact = true,
): Partial<Record<keyof GuardianActionContext, string>> {
  const value = record[source];
  if (value === undefined || value === "") return {};
  if (typeof value !== "string" || value.length > maximum || /[\u0000]/u.test(value)) {
    throw new Error(`Guardian context ${source} is invalid.`);
  }
  return { [target]: redact ? redactSecrets(value) : value };
}

export function semanticDecision(
  value: unknown,
  observedLatencyMs: number,
): GuardianSemanticDecision {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new GuardianDecisionUnavailableError("Guardian decision response was invalid.");
  }
  const record = value as Record<string, unknown>;
  const decision = record["decision"];
  const risk = record["risk"];
  const reason = record["reason"];
  const confidence = record["confidence"];
  const contractID = record["matched_contract_id"];
  const adminContract = record["admin_contract"];
  const model = record["model"];
  const intervention = record["intervention"];
  const approvalID = record["approval_id"];
  const approvalState = record["approval_state"];
  const approvalExpiresAt = record["approval_expires_at"];
  if (
    (decision !== "allow" && decision !== "deny" && decision !== "require_approval") ||
    (risk !== "low" && risk !== "medium" && risk !== "high" && risk !== "critical") ||
    typeof reason !== "string" || reason.trim().length < 1 || reason.length > 256 ||
    typeof confidence !== "number" || !Number.isFinite(confidence) || confidence < 0 || confidence > 1 ||
    typeof contractID !== "string" || contractID.length > 128 ||
    (adminContract !== undefined &&
      (typeof adminContract !== "string" || adminContract.trim().length < 1 || adminContract.length > 2_000)) ||
    typeof model !== "string" || !/^[a-z0-9][a-z0-9._-]{0,127}$/iu.test(model) ||
    (intervention !== "none" && intervention !== "block_action" &&
      intervention !== "stop_agent" && intervention !== "kill_agent") ||
    typeof record["cached"] !== "boolean"
  ) {
    throw new GuardianDecisionUnavailableError("Guardian decision response was invalid.");
  }
  if (
    approvalID !== undefined &&
    (typeof approvalID !== "string" ||
      !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu.test(approvalID))
  ) {
    throw new GuardianDecisionUnavailableError("Guardian approval ID was invalid.");
  }
  if (
    approvalState !== undefined && approvalState !== "pending" &&
    approvalState !== "approved" && approvalState !== "rejected" &&
    approvalState !== "consumed" && approvalState !== "expired"
  ) {
    throw new GuardianDecisionUnavailableError("Guardian approval state was invalid.");
  }
  if (
    approvalExpiresAt !== undefined &&
    (typeof approvalExpiresAt !== "string" || !Number.isFinite(Date.parse(approvalExpiresAt)))
  ) {
    throw new GuardianDecisionUnavailableError("Guardian approval expiry was invalid.");
  }
  const hasCompleteApproval = typeof approvalID === "string" &&
    typeof approvalState === "string" && typeof approvalExpiresAt === "string";
  if (
    (decision === "require_approval" &&
      (!hasCompleteApproval || approvalState === "approved")) ||
    (decision === "deny" &&
      (approvalID !== undefined || approvalState !== undefined || approvalExpiresAt !== undefined)) ||
    (decision === "allow" && approvalID !== undefined &&
      (!hasCompleteApproval || approvalState !== "consumed" || model !== "admin-approval")) ||
    ((approvalID === undefined) !== (approvalState === undefined) ||
      (approvalID === undefined) !== (approvalExpiresAt === undefined))
  ) {
    throw new GuardianDecisionUnavailableError("Guardian approval response was inconsistent.");
  }
  if (
    decision !== "allow" &&
    (contractID === "" || typeof adminContract !== "string")
  ) {
    throw new GuardianDecisionUnavailableError(
      "Guardian blocked an action without a verifiable administrator contract.",
    );
  }
  if (
    (decision === "allow" && intervention !== "none") ||
    (decision === "deny" && intervention === "none") ||
    (decision === "require_approval" && intervention !== "block_action")
  ) {
    throw new GuardianDecisionUnavailableError(
      "Guardian response contained an invalid enforcement decision.",
    );
  }
  if (
    decision === "allow" && approvalID === undefined &&
    (contractID !== "" || adminContract !== undefined)
  ) {
    throw new GuardianDecisionUnavailableError(
      "Guardian allow response claimed an unrelated administrator contract.",
    );
  }
  if (
    decision === "allow" && approvalID !== undefined &&
    (contractID === "" || typeof adminContract !== "string")
  ) {
    throw new GuardianDecisionUnavailableError(
      "Guardian approval response omitted its authoritative administrator contract.",
    );
  }
  return Object.freeze({
    decision,
    reason: reason.trim(),
    risk,
    confidence,
    intervention,
    ...(contractID === ""
      ? {}
      : {
          matchedContractId: contractID,
          adminContract: (adminContract as string).trim(),
        }),
    model,
    cached: record["cached"],
    latencyMs: typeof record["latency_ms"] === "number" &&
        Number.isSafeInteger(record["latency_ms"]) && record["latency_ms"] >= 0
      ? record["latency_ms"]
      : observedLatencyMs,
    ...(approvalID === undefined ? {} : { approvalId: approvalID }),
    ...(approvalState === undefined ? {} : { approvalState }),
    ...(approvalExpiresAt === undefined ? {} : { approvalExpiresAt }),
  });
}
