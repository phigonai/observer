import { randomUUID } from "node:crypto";
import { chmod, mkdir, open } from "node:fs/promises";
import { join } from "node:path";
import type { GuardianActionContext } from "./agentic-guardian.js";
import type { GuardianIntervention } from "./action-policy.js";
import type { GuardianContainmentResult } from "./guardian-containment.js";

export type GuardianDecisionRecord = Readonly<{
  agentId: string;
  action: string;
  resource: string;
  outcome: string;
  reason: string;
  adminContract?: string;
  decisionSource: string;
  model?: string;
  risk?: string;
  confidence?: number;
  latencyMs: number;
  policyDigest?: string;
  context: GuardianActionContext;
  intervention?: GuardianIntervention;
  containment?: GuardianContainmentResult;
  approvalId?: string;
  approvalState?: string;
  approvalExpiresAt?: string;
}>;

export class GuardianDecisionJournal {
  readonly #dataDirectory: string;

  constructor(dataDirectory: string) {
    this.#dataDirectory = dataDirectory;
  }

  async append(record: GuardianDecisionRecord): Promise<void> {
    const directory = join(this.#dataDirectory, "bridges", "generic");
    await mkdir(directory, { recursive: true, mode: 0o700 });
    await chmod(this.#dataDirectory, 0o700);
    await chmod(join(this.#dataDirectory, "bridges"), 0o700);
    await chmod(directory, 0o700);
    const path = join(directory, "guardian-decisions.jsonl");
    const value = JSON.stringify({
      type: "phigon_guardian_decision",
      decision_id: randomUUID(),
      phigon_agent_name: "Phigon Guardian",
      session_id: record.context.taskId || `guardian:${record.agentId || "unknown"}`,
      timestamp: new Date().toISOString(),
      subject_agent_id: record.agentId,
      action: record.action,
      resource: record.resource,
      outcome: record.outcome,
      reason: record.reason,
      admin_contract: record.adminContract ?? "",
      decision_source: record.decisionSource,
      model: record.model ?? "",
      risk: record.risk ?? "",
      confidence: record.confidence ?? null,
      latency_ms: record.latencyMs,
      policy_digest: record.policyDigest ?? "",
      context: record.context,
      intervention: record.intervention ?? "",
      containment: record.containment ?? null,
      approval_id: record.approvalId ?? "",
      approval_state: record.approvalState ?? "",
      approval_expires_at: record.approvalExpiresAt ?? "",
    });
    if (Buffer.byteLength(value, "utf8") > 32 << 10) {
      throw new Error("Guardian decision record exceeded its storage bound.");
    }
    const handle = await open(path, "a", 0o600);
    try {
      await handle.write(`${value}\n`);
      await handle.sync();
    } finally {
      await handle.close();
    }
    await chmod(path, 0o600);
  }
}
