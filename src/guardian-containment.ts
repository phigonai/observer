import { timestampDate } from "@bufbuild/protobuf/wkt";
import { AgentState } from "./generated/phigon/v1/common_pb.js";
import type { AgentInventory } from "./generated/phigon/v1/identity_pb.js";
import type { GuardianIntervention } from "./action-policy.js";
import {
  defaultProcessTreeControl,
  describeTreeOutcome,
  type ProcessTreeControl,
  type TreeStopOutcome,
} from "./process-tree.js";

export type GuardianContainmentRequest = Readonly<{
  intervention: GuardianIntervention;
  agentId: string;
  processId?: number;
  expectedStartedAt?: string;
}>;

export type GuardianContainmentResult = Readonly<{
  state: "not_requested" | "succeeded" | "failed" | "rejected";
  code: string;
  detail: string;
  targetStillRunning?: boolean;
}>;

export class GuardianContainmentExecutor {
  readonly #enabled: boolean;
  readonly #inventory: () => Promise<AgentInventory>;
  readonly #observerProcessID: number;
  readonly #processes: ProcessTreeControl;

  constructor(options: Readonly<{
    enabled: boolean;
    inventory: () => Promise<AgentInventory>;
    observerProcessID?: number;
    processControl?: ProcessTreeControl;
  }>) {
    this.#enabled = options.enabled;
    this.#inventory = options.inventory;
    this.#observerProcessID = options.observerProcessID ?? process.pid;
    this.#processes = options.processControl ?? defaultProcessTreeControl();
  }

  async execute(request: GuardianContainmentRequest): Promise<GuardianContainmentResult> {
    if (!["block_action", "stop_agent", "kill_agent"].includes(request.intervention)) {
      return result("rejected", "invalid_intervention", "The administrator intervention is invalid.");
    }
    if (request.intervention === "block_action") {
      return result("not_requested", "action_blocked", "The proposed action was blocked; process containment was not authorized.");
    }
    if (!this.#enabled) {
      return result("rejected", "containment_disabled", "Guardian process containment is unavailable in this executor.", true);
    }
    if (
      request.agentId.trim() === "" || request.agentId.length > 128 ||
      !/^[A-Za-z0-9._:-]+$/u.test(request.agentId) ||
      !Number.isSafeInteger(request.processId) || (request.processId ?? 0) < 1 ||
      request.expectedStartedAt === undefined ||
      !Number.isFinite(Date.parse(request.expectedStartedAt))
    ) {
      return result("rejected", "exact_target_required", "Containment requires an exact agent ID, process ID, and process start time.", true);
    }
    const processID = request.processId as number;
    if (processID === this.#observerProcessID) {
      return result("rejected", "self_target_rejected", "Guardian refuses to terminate the observer process.", true);
    }
    const expectedStartedAt = Date.parse(request.expectedStartedAt as string);
    const inventory = await this.#inventory();
    const target = inventory.agents.find((agent) =>
      agent.agentId === request.agentId &&
      agent.processId === BigInt(processID) &&
      agent.state === AgentState.RUNNING &&
      agent.startedAt !== undefined &&
      timestampDate(agent.startedAt).getTime() === expectedStartedAt &&
      agent.capabilities.includes("process-instance")
    );
    if (target === undefined) {
      return result("rejected", "stale_target", "The exact discovered agent process lifetime is no longer running.", false);
    }

    // Same exact-lifetime, whole-tree controller as administrator actions.
    const graceful = request.intervention === "stop_agent";
    const outcome = await this.#processes.stop(
      { processId: processID, startedAt: new Date(expectedStartedAt) },
      graceful ? "stop" : "kill",
    ).catch((): TreeStopOutcome => ({ outcome: "failed", code: "unknown" }));
    const receipt = describeTreeOutcome(outcome, graceful);
    if (receipt.code === "process_stopped") {
      return result("succeeded", receipt.code, graceful
        ? "This agent was stopped by Phigon Guardian under administrator policy."
        : "This agent was force-stopped by Phigon Guardian under administrator policy.", false);
    }
    return result(receipt.state, receipt.code, receipt.detail, receipt.targetStillRunning);
  }
}

function result(
  state: GuardianContainmentResult["state"],
  code: string,
  detail: string,
  targetStillRunning?: boolean,
): GuardianContainmentResult {
  return Object.freeze({ state, code, detail, ...(targetStillRunning === undefined ? {} : { targetStillRunning }) });
}
