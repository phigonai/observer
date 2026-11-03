import { timestampDate, type Timestamp } from "@bufbuild/protobuf/wkt";
import { AgentState } from "./generated/phigon/v1/common_pb.js";
import type { AgentInventory } from "./generated/phigon/v1/identity_pb.js";
import type { ActionPolicyPersistence } from "./action-policy.js";
import type { GuardianSemanticDecision, HTTPGuardianDecisionClient } from "./agentic-guardian.js";
import type { GuardianContainmentExecutor, GuardianContainmentResult } from "./guardian-containment.js";
import type { GuardianDecisionJournal } from "./guardian-decision-journal.js";
import type { GuardianHostedClient } from "./guardian-hosted-client.js";
import { errorSummary, RetryBackoff, StatusChanges } from "./quiet-retry.js";
import { noticeAgentName, type UserNotices } from "./user-notices.js";

// A running process the policy allowed is asked about again only after this
// long. An administrator's agent block does not change the policy digest,
// so an allow must expire for a new block to reach agents already running.
const allowCacheMs = 60_000;
// A running process the policy denied, or that waits for an administrator,
// is asked about again after this long or under a new policy. Until then it
// stays denied, and its decision is journaled and reported only once.
const blockedCacheMs = 10 * 60_000;
// Running processes on one computer are few; this only bounds the cache,
// whose entries hold a decision of at most a few kilobytes.
const maxCachedDecisions = 256;
// An unchanged coverage report is sent again after this long. The server
// shows coverage as stale two minutes after the last report.
const coverageRefreshMs = 60_000;
// After a failed decision or coverage call, the next one waits this long,
// doubling after each failure up to the maximum.
const retryInitialMs = 10_000;
const retryMaxMs = 5 * 60_000;
// A problem that lasts is written to the log again this often.
const statusRepeatMs = 30 * 60_000;

type CachedDecision = Readonly<{
  decision: GuardianSemanticDecision;
  at: number;
  containmentFailed: boolean;
  /**
   * Set while an authorized stop failed and the process may still be
   * running: the stop alone is tried again then, without a new decision.
   */
  containmentRetry?: Readonly<{ at: number; delayMs: number }>;
}>;

// Discovery is a detection boundary, not a pre-execution sandbox. It can contain
// agents launched outside the managed CLI only after a central admin decision.
export class GuardianProcessMonitor {
  #reviewOffset = 0;
  // Decisions for process lifetimes under #decisionsDigest.
  #decisions = new Map<string, CachedDecision>();
  #decisionsDigest: string | undefined;
  #lastCoverage: Readonly<{ report: string; at: number }> | undefined;
  readonly #decisionRetry = new RetryBackoff(retryInitialMs, retryMaxMs);
  readonly #coverageRetry = new RetryBackoff(retryInitialMs, retryMaxMs);
  readonly #status: StatusChanges;
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
    this.#status = new StatusChanges(options.onStatus, statusRepeatMs, this.#now);
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
      this.#status.report("policy", "Guardian process review is waiting for its administrator policy.");
      return;
    }
    this.#status.clear("policy");
    let reviewed = 0; let denied = 0; let containmentFailed = 0; let unverified = 0;
    if (inventory.partial) this.#status.report("discovery", "Guardian discovery is incomplete; process protection coverage is degraded.");
    else this.#status.clear("discovery");
    if (this.#decisionsDigest !== policy.policyDigest) {
      for (const key of [...this.#decisions.keys()]) this.#forget(key);
      this.#decisionsDigest = policy.policyDigest;
      // A new policy is checked against running agents at once, even while
      // waiting after a failed call.
      this.#decisionRetry.succeeded();
    }
    const cached = (agent: Agent) => {
      const entry = this.#decisions.get(lifetimeKey(agent));
      if (entry === undefined) return undefined;
      const lifetime = entry.decision.decision === "allow" ? allowCacheMs : blockedCacheMs;
      return this.#now() - entry.at < lifetime ? entry : undefined;
    };
    const count = (entry: CachedDecision) => {
      reviewed++;
      if (entry.decision.decision !== "allow") {
        denied++;
        if (entry.containmentFailed) containmentFailed++;
      }
    };
    const reviewAgent = async (agent: Agent) => {
      if (signal.aborted) return;
      if (!reviewable(agent)) { if (agent.state === AgentState.RUNNING) unverified++; return; }
      const known = cached(agent);
      const retryDue = known?.containmentRetry !== undefined && this.#now() >= known.containmentRetry.at;
      if (known !== undefined && !retryDue) { count(known); return; }
      // A stop that failed is tried again only under a decision asked for
      // now: an administrator may have lifted an agent block since, which
      // does not change the policy digest.
      const postpone = () => {
        if (known === undefined) return;
        // Still denied; its stop waits longer.
        const delayMs = nextRetryDelay(known);
        const entry = { ...known, containmentRetry: { at: this.#now() + delayMs, delayMs } };
        this.#remember(lifetimeKey(agent), entry);
        count(entry);
      };
      const decision = await this.#decide(agent, policy.policyDigest, signal);
      if (decision === undefined) { postpone(); return; }
      // The same decision with a stop that keeps failing is journaled once.
      const repeated = known !== undefined && sameEnforcement(known.decision, decision);
      try {
        const containment = await this.#enforce(agent, decision, policy.policyDigest, !repeated);
        const entry = cachedDecision(decision, this.#now(), containment, repeated ? nextRetryDelay(known) : retryInitialMs);
        // Each process has its own topic, so failing stops of several
        // processes are each logged once, not on every try.
        if (repeated && entry.containmentRetry !== undefined) {
          this.#status.report(
            containmentTopic(lifetimeKey(agent)),
            `Phigon Guardian could not stop ${agent.agentId} (${errorSummary(containment?.detail ?? "no detail")}); it tries again.`,
          );
        } else if (known !== undefined) {
          this.#status.clear(containmentTopic(lifetimeKey(agent)));
        }
        count(entry);
        this.#remember(lifetimeKey(agent), entry);
      } catch (error) {
        // Asked about again: on the next pass for a new process, after a
        // longer wait for one whose stop failed.
        postpone();
        this.#status.report(
          "record",
          `Guardian could not finish reviewing a running agent (${errorSummary(error)}); containment coverage is unavailable until it can.`,
        );
      }
    };
    const discovered = inventory.agents.filter(agent => agent.state === AgentState.RUNNING);
    const offset = discovered.length ? this.#reviewOffset % discovered.length : 0;
    const running = [...discovered.slice(offset), ...discovered.slice(0, offset)];
    // Publish degraded coverage before a potentially slow provider review.
    if (running.some((agent) => reviewable(agent) && cached(agent) === undefined)) {
      await this.#reportCoverage({
        policy_digest: policy.policyDigest, platform: process.platform,
        process_review: "degraded", discovery_partial: inventory.partial === true,
        reviewed: 0, denied: 0, containment_failed: 0, unverified: running.length,
      }, coverageSignal);
    }
    let next = 0;
    await Promise.all(Array.from({ length: Math.min(4, running.length) }, async () => {
      while (!signal.aborted && next < running.length) {
        const agent = running[next++]!;
        await abortable(reviewAgent(agent), signal).catch(() => undefined);
      }
    }));
    this.#reviewOffset = running.length ? (offset + next) % running.length : 0;
    // Forget processes that are no longer running. An incomplete discovery
    // can miss some that still run, so it forgets none; their decisions
    // still expire, and the cache is bounded.
    if (!inventory.partial) {
      const live = new Set(running.filter(reviewable).map(lifetimeKey));
      for (const key of this.#decisions.keys()) if (!live.has(key)) this.#forget(key);
    }
    unverified = Math.max(unverified, running.length - reviewed);
    if (!coverageSignal.aborted) {
      await this.#reportCoverage({
        policy_digest: policy.policyDigest, platform: process.platform,
        process_review: inventory.partial || unverified > 0 || containmentFailed > 0 ? "degraded" : "active",
        discovery_partial: inventory.partial === true,
        reviewed, denied, containment_failed: containmentFailed, unverified,
      }, coverageSignal);
    }
  }

  /**
   * Applies a decision to a running process: stops it when the policy
   * authorized that, tells the person at the computer, and reports and
   * journals a denial. `reportFailure` is false when only a failed stop is
   * tried again, so a stop that keeps failing is journaled once.
   */
  async #enforce(
    agent: ReviewableAgent,
    decision: GuardianSemanticDecision,
    policyDigest: string,
    reportFailure: boolean,
  ): Promise<GuardianContainmentResult | undefined> {
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
    if (decision.decision !== "allow" && (reportFailure || containment?.state === "succeeded")) {
      const { resource, context } = reviewProposal(agent);
      const detail = containment?.detail ?? "The running process was not stopped: its policy did not authorize process containment.";
      this.options.onStatus(`Phigon Guardian: ${agent.agentId}. ${decision.reason} ${detail}`);
      await this.options.journal.append({
        agentId: agent.agentId, action: "agent.start", resource,
        outcome: decision.decision === "deny" ? "denied" : "approval_required",
        reason: decision.reason, decisionSource: "guardian_process_monitor",
        latencyMs: decision.latencyMs, policyDigest, context,
        ...(decision.adminContract === undefined ? {} : { adminContract: decision.adminContract }),
        ...(decision.intervention === "none" ? {} : { intervention: decision.intervention }),
        ...(containment === undefined ? {} : { containment }),
        model: decision.model, risk: decision.risk, confidence: decision.confidence,
      });
    }
    return containment;
  }

  /**
   * Asks the decision service about a running process, or returns undefined
   * when it was not asked (waiting after a failed call), gave no answer, or
   * the review was cut short.
   */
  async #decide(agent: ReviewableAgent, policyDigest: string, signal: AbortSignal): Promise<GuardianSemanticDecision | undefined> {
    // After a failed call the decision service is not asked again until the
    // wait is over; the process counts as unverified meanwhile.
    if (!this.#decisionRetry.ready(this.#now())) return undefined;
    const { resource, context } = reviewProposal(agent);
    let decision: GuardianSemanticDecision;
    try {
      decision = await abortable(this.options.decisionClient.decide({
        policyDigest, agentId: agent.agentId,
        processId: Number(agent.processId), processStartedAt: timestampDate(agent.startedAt).toISOString(),
        action: "agent.start", resource, context,
      }, signal), signal);
    } catch (error) {
      // A review cut short by its deadline or by shutdown is not a failure
      // of the decision service.
      if (signal.aborted) return undefined;
      this.#decisionRetry.failed(this.#now());
      this.#status.report(
        "review",
        `Guardian could not review running agents (${errorSummary(error)}). It tries again later; until then they count as unverified.`,
      );
      return undefined;
    }
    if (signal.aborted) return undefined;
    this.#decisionRetry.succeeded();
    this.#status.clear("review", "Guardian reviews running agents again.");
    return decision;
  }

  #remember(key: string, decision: CachedDecision): void {
    this.#decisions.delete(key);
    this.#decisions.set(key, decision);
    // A Map keeps insertion order, so its first key is the oldest decision.
    while (this.#decisions.size > maxCachedDecisions) {
      const oldest = this.#decisions.keys().next().value;
      if (oldest === undefined) break;
      this.#forget(oldest);
    }
  }

  /** Forgets a process's decision and the status kept about its stop. */
  #forget(key: string): void {
    this.#decisions.delete(key);
    this.#status.clear(containmentTopic(key));
  }

  /**
   * Sends a coverage report that changed, or an unchanged one once a minute.
   * After a failed report the next one waits, longer after each failure.
   */
  async #reportCoverage(report: Readonly<Record<string, unknown>>, signal: AbortSignal): Promise<void> {
    if (this.options.coverageClient === undefined) return;
    const encoded = JSON.stringify(report);
    const now = this.#now();
    if (this.#lastCoverage?.report === encoded && now - this.#lastCoverage.at < coverageRefreshMs) return;
    if (!this.#coverageRetry.ready(now)) return;
    try {
      await this.options.coverageClient.post("/v1/machine/guardian/coverage", report, signal, 5_000);
      this.#lastCoverage = { report: encoded, at: now };
      this.#coverageRetry.succeeded();
      this.#status.clear("coverage", "Guardian delivers its coverage report again.");
    } catch (error) {
      if (signal.aborted) return;
      this.#coverageRetry.failed(now);
      this.#status.report(
        "coverage",
        `Guardian could not deliver its coverage report (${errorSummary(error)}); the workspace shows its protection status as stale until it can.`,
      );
    }
  }
}

type Agent = AgentInventory["agents"][number];
type ReviewableAgent = Agent & { startedAt: Timestamp };

/** A running agent with an exact process lifetime that a decision can name. */
function reviewable(agent: Agent): agent is ReviewableAgent {
  return agent.state === AgentState.RUNNING && agent.startedAt !== undefined &&
    agent.processId >= 1n && agent.processId <= BigInt(Number.MAX_SAFE_INTEGER) &&
    agent.capabilities.includes("process-instance");
}

/** What a periodic review asks about a running agent. */
function reviewProposal(agent: Agent) {
  return {
    resource: JSON.stringify({
      claimed_agent_id: agent.agentId,
      display_name: agent.displayName,
      runtime: agent.runtime,
      executable_path_digest: agent.executablePathDigest,
      lifecycle: "already_running",
    }),
    context: {
      expectedEffect: "Continue running this discovered AI agent. This is a periodic process review; no proposed command or verified model selection is available.",
    },
  };
}

/**
 * A decision to remember, with a retry of its stop when the stop failed
 * while the process was still running.
 */
function cachedDecision(
  decision: GuardianSemanticDecision,
  at: number,
  containment: GuardianContainmentResult | undefined,
  retryDelayMs: number,
): CachedDecision {
  const failed = containment !== undefined && containment.state !== "succeeded";
  return {
    decision, at, containmentFailed: failed,
    ...(failed && containment.targetStillRunning !== false
      ? { containmentRetry: { at: at + retryDelayMs, delayMs: retryDelayMs } }
      : {}),
  };
}

/** The wait before the next try of a stop that failed again: twice the last, up to five minutes. */
function nextRetryDelay(entry: CachedDecision): number {
  return Math.min((entry.containmentRetry?.delayMs ?? retryInitialMs / 2) * 2, retryMaxMs);
}

/** The status topic for a process's failing stop. */
function containmentTopic(key: string): string {
  return `containment\u0000${key}`;
}

/** Whether two decisions would be applied the same way. */
function sameEnforcement(a: GuardianSemanticDecision, b: GuardianSemanticDecision): boolean {
  return a.decision === b.decision && a.intervention === b.intervention && a.model === b.model;
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
