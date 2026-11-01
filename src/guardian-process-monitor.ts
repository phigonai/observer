import { timestampDate, type Timestamp } from "@bufbuild/protobuf/wkt";
import { AgentState } from "./generated/phigon/v1/common_pb.js";
import type { AgentInventory } from "./generated/phigon/v1/identity_pb.js";
import type { ActionPolicyPersistence } from "./action-policy.js";
import type { HTTPGuardianDecisionClient } from "./agentic-guardian.js";
import type { GuardianContainmentExecutor } from "./guardian-containment.js";
import type { GuardianDecisionJournal } from "./guardian-decision-journal.js";
import type { GuardianHostedClient } from "./guardian-hosted-client.js";
import { noticeAgentName, type UserNotices } from "./user-notices.js";

// A running process the policy allowed is asked about again only after this
// long. An administrator's agent block does not change the policy digest,
// so an allow must expire for a new block to reach agents already running.
const allowCacheMs = 60_000;
// An unchanged coverage report is sent again after this long. The server
// shows coverage as stale two minutes after the last report.
const coverageRefreshMs = 60_000;

// Discovery is a detection boundary, not a pre-execution sandbox. It can contain
// agents launched outside the managed CLI only after a central admin decision.
export class GuardianProcessMonitor {
  #reviewOffset = 0;
  // Allowed process lifetimes under #allowedDigest, and when each was allowed.
  #allowed = new Map<string, number>();
  #allowedDigest: string | undefined;
  #lastCoverage: Readonly<{ report: string; at: number }> | undefined;
  readonly #now: () => number;
  constructor(private readonly options: Readonly<{
    machineId: string;
    policyStore: Pick<ActionPolicyPersistence, "load">;
    decisionClient: Pick<HTTPGuardianDecisionClient, "decide">;
    containment: Pick<GuardianContainmentExecutor, "execute">;
    journal: Pick<GuardianDecisionJournal, "append">;
    onStatus: (message: string) => void;
    coverageClient?: Pick<GuardianHostedClient, "post">;
    /** Tells the person at this computer when an agent was stopped. */
    notices?: Pick<UserNotices, "agentStopped" | "agentBlocked">;
    now?: () => number;
  }>) {
    this.#now = options.now ?? Date.now;
  }

  async review(inventory: AgentInventory, parentSignal: AbortSignal): Promise<void> {
    if (parentSignal.aborted) return;
    const deadline = new AbortController();
    const timer = setTimeout(() => deadline.abort(), 20_000);
    const signal = AbortSignal.any([parentSignal, deadline.signal]);
    try { await this.reviewWithinDeadline(inventory, signal, parentSignal); }
    finally { clearTimeout(timer); }
  }

  private async reviewWithinDeadline(inventory: AgentInventory, signal: AbortSignal, coverageSignal: AbortSignal): Promise<void> {
    const policy = await this.options.policyStore.load(this.options.machineId);
    if (policy === null) {
      this.options.onStatus("Guardian process review is waiting for its administrator policy.");
      return;
    }
    let reviewed = 0; let denied = 0; let containmentFailed = 0; let unverified = 0;
    if (inventory.partial) this.options.onStatus("Guardian discovery is incomplete; process protection coverage is degraded.");
    if (this.#allowedDigest !== policy.policyDigest) {
      this.#allowed.clear();
      this.#allowedDigest = policy.policyDigest;
    }
    const allowedRecently = (agent: Agent) => {
      const at = this.#allowed.get(lifetimeKey(agent));
      return at !== undefined && this.#now() - at < allowCacheMs;
    };
    const reviewAgent = async (agent: Agent) => {
      if (signal.aborted) return;
      if (!reviewable(agent)) { if (agent.state === AgentState.RUNNING) unverified++; return; }
      if (allowedRecently(agent)) { reviewed++; return; }
      const resource = JSON.stringify({
        claimed_agent_id: agent.agentId,
        display_name: agent.displayName,
        runtime: agent.runtime,
        executable_path_digest: agent.executablePathDigest,
        lifecycle: "already_running",
      });
      const context = {
        expectedEffect: "Continue running this discovered AI agent. This is a periodic process review; no proposed command or verified model selection is available.",
      };
      try {
        const decision = await abortable(this.options.decisionClient.decide({
          policyDigest: policy.policyDigest, agentId: agent.agentId,
          processId: Number(agent.processId), processStartedAt: timestampDate(agent.startedAt).toISOString(),
          action: "agent.start", resource, context,
        }, signal), signal);
        if (signal.aborted) return;
        reviewed++;
        if (decision.decision === "allow") this.#allowed.set(lifetimeKey(agent), this.#now());
        else this.#allowed.delete(lifetimeKey(agent));
        const containment = decision.decision === "deny" && decision.intervention !== "none" && decision.intervention !== "block_action"
          ? await this.options.containment.execute({
            intervention: decision.intervention, agentId: agent.agentId,
            processId: Number(agent.processId), expectedStartedAt: timestampDate(agent.startedAt).toISOString(),
          }) : undefined;
        // Allows are already audited centrally. Report denied running processes
        // even when the admin authorized only action blocking, never escalation.
        if (containment?.state === "succeeded") {
          const notice = { key: `${agent.agentId}:${agent.processId}`, agent: noticeAgentName(agent.displayName), reason: decision.reason };
          if (decision.model === "agent-block") this.options.notices?.agentBlocked(notice);
          else this.options.notices?.agentStopped({ ...notice, forced: decision.intervention === "kill_agent" });
        }
        if (decision.decision !== "allow") {
          denied++;
          if (containment !== undefined && containment.state !== "succeeded") containmentFailed++;
          const detail = containment?.detail ?? "The running process was not stopped: its policy did not authorize process containment.";
          this.options.onStatus(`Phigon Guardian: ${agent.agentId}. ${decision.reason} ${detail}`);
          await this.options.journal.append({
            agentId: agent.agentId, action: "agent.start", resource,
            outcome: decision.decision === "deny" ? "denied" : "approval_required",
            reason: decision.reason, decisionSource: "guardian_process_monitor",
            latencyMs: decision.latencyMs, policyDigest: policy.policyDigest, context,
            ...(decision.adminContract === undefined ? {} : { adminContract: decision.adminContract }),
            ...(decision.intervention === "none" ? {} : { intervention: decision.intervention }),
            ...(containment === undefined ? {} : { containment }),
            model: decision.model, risk: decision.risk, confidence: decision.confidence,
          });
        }
      } catch {
        unverified++;
        this.options.onStatus(`Guardian could not verify process ${agent.agentId}; containment coverage is unavailable for this review.`);
      }
    };
    const discovered = inventory.agents.filter(agent => agent.state === AgentState.RUNNING);
    const offset = discovered.length ? this.#reviewOffset % discovered.length : 0;
    const running = [...discovered.slice(offset), ...discovered.slice(0, offset)];
    // Publish degraded coverage before a potentially slow provider review.
    if (running.some((agent) => reviewable(agent) && !allowedRecently(agent))) {
      await this.#reportCoverage({
        policy_digest: policy.policyDigest, platform: process.platform,
        process_review: "degraded", discovery_partial: inventory.partial === true,
        reviewed: 0, denied: 0, containment_failed: 0, unverified: running.length,
      }, coverageSignal, "Guardian review coverage could not be delivered.");
    }
    let next = 0;
    await Promise.all(Array.from({ length: Math.min(4, running.length) }, async () => {
      while (!signal.aborted && next < running.length) {
        const agent = running[next++]!;
        await abortable(reviewAgent(agent), signal).catch(() => undefined);
      }
    }));
    this.#reviewOffset = running.length ? (offset + next) % running.length : 0;
    // Forget processes that are no longer running.
    const live = new Set(running.filter(reviewable).map(lifetimeKey));
    for (const key of this.#allowed.keys()) if (!live.has(key)) this.#allowed.delete(key);
    unverified = Math.max(unverified, running.length - reviewed);
    if (!coverageSignal.aborted) {
      await this.#reportCoverage({
        policy_digest: policy.policyDigest, platform: process.platform,
        process_review: inventory.partial || unverified > 0 || containmentFailed > 0 ? "degraded" : "active",
        discovery_partial: inventory.partial === true,
        reviewed, denied, containment_failed: containmentFailed, unverified,
      }, coverageSignal, "Guardian could not deliver its coverage report; central protection status will become stale.");
    }
  }

  /** Sends a coverage report that changed, or an unchanged one once a minute. */
  async #reportCoverage(report: Readonly<Record<string, unknown>>, signal: AbortSignal, failure: string): Promise<void> {
    if (this.options.coverageClient === undefined) return;
    const encoded = JSON.stringify(report);
    const now = this.#now();
    if (this.#lastCoverage?.report === encoded && now - this.#lastCoverage.at < coverageRefreshMs) return;
    try {
      await this.options.coverageClient.post("/v1/machine/guardian/coverage", report, signal, 5_000);
      this.#lastCoverage = { report: encoded, at: now };
    } catch { this.options.onStatus(failure); }
  }
}

type Agent = AgentInventory["agents"][number];

/** A running agent with an exact process lifetime that a decision can name. */
function reviewable(agent: Agent): agent is Agent & { startedAt: Timestamp } {
  return agent.state === AgentState.RUNNING && agent.startedAt !== undefined &&
    agent.processId >= 1n && agent.processId <= BigInt(Number.MAX_SAFE_INTEGER) &&
    agent.capabilities.includes("process-instance");
}

function lifetimeKey(agent: Agent): string {
  const startedAt = agent.startedAt === undefined ? "" : timestampDate(agent.startedAt).toISOString();
  return `${agent.agentId}\u0000${agent.processId}\u0000${startedAt}`;
}

function abortable<T>(work: Promise<T>, signal: AbortSignal): Promise<T> {
  if (signal.aborted) { void work.catch(() => undefined); return Promise.reject(signal.reason); }
  return new Promise((resolve, reject) => {
    const abort = () => reject(signal.reason);
    signal.addEventListener("abort", abort, { once: true });
    work.then(resolve, reject).finally(() => signal.removeEventListener("abort", abort));
  });
}
