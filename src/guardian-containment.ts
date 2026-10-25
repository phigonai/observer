import { timestampDate } from "@bufbuild/protobuf/wkt";
import { AgentState } from "./generated/phigon/v1/common_pb.js";
import type { AgentInventory } from "./generated/phigon/v1/identity_pb.js";
import type { GuardianIntervention } from "./action-policy.js";
import { requestWindowsGracefulStop } from "./windows-process.js";
import { killVerifiedWindowsProcess } from "./guardian-native.js";

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

type ProcessSignal = "SIGTERM" | "SIGKILL";

export class GuardianContainmentExecutor {
  readonly #enabled: boolean;
  readonly #inventory: () => Promise<AgentInventory>;
  readonly #platform: NodeJS.Platform;
  readonly #observerProcessID: number;
  readonly #signal: (processID: number, signal: ProcessSignal | 0) => void;
  readonly #sleep: (milliseconds: number) => Promise<void>;
  readonly #windowsGracefulStop: (processID: number, startedAt: string) => Promise<void>;
  readonly #nativeKill: boolean;

  constructor(options: Readonly<{
    enabled: boolean;
    inventory: () => Promise<AgentInventory>;
    platform?: NodeJS.Platform;
    observerProcessID?: number;
    signal?: (processID: number, signal: ProcessSignal | 0) => void;
    sleep?: (milliseconds: number) => Promise<void>;
    windowsGracefulStop?: (processID: number, startedAt: string) => Promise<void>;
  }>) {
    this.#enabled = options.enabled;
    this.#nativeKill = options.signal === undefined && options.platform === undefined;
    this.#inventory = options.inventory;
    this.#platform = options.platform ?? process.platform;
    this.#observerProcessID = options.observerProcessID ?? process.pid;
    this.#signal = options.signal ?? ((processID, signal) => process.kill(processID, signal));
    this.#sleep = options.sleep ?? ((milliseconds) =>
      new Promise((resolve) => setTimeout(resolve, milliseconds))
    );
    this.#windowsGracefulStop = options.windowsGracefulStop ??
      requestWindowsGracefulStop;
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
    if (!this.#processAlive(processID)) {
      return result("rejected", "target_already_stopped", "The target process is no longer running.", false);
    }

    try {
      if (request.intervention === "stop_agent" && this.#platform === "win32") {
        await this.#windowsGracefulStop(processID, request.expectedStartedAt);
      } else if (request.intervention === "kill_agent" && this.#platform === "win32" && this.#nativeKill) {
        await killVerifiedWindowsProcess(processID, request.expectedStartedAt as string);
        return result("succeeded", "process_stopped", "This agent was force-stopped by Phigon Guardian under administrator policy.", false);
      } else {
        const signal: ProcessSignal = request.intervention === "stop_agent"
          ? "SIGTERM"
          : "SIGKILL";
        this.#signal(processID, signal);
      }
    } catch (error) {
      return result("failed", "os_dispatch_failed", safeSignalFailure(error), this.#processAlive(processID));
    }
    const stopped = await this.#waitForExit(
      processID,
      request.intervention === "stop_agent" ? 5_000 : 2_000,
    );
    return stopped
      ? result("succeeded", "process_stopped", request.intervention === "kill_agent"
        ? "This agent was force-stopped by Phigon Guardian under administrator policy."
        : "This agent was stopped by Phigon Guardian under administrator policy.", false)
      : result("failed", "process_still_running", "The containment request was sent without escalation, but the exact process still reports running.", true);
  }

  #processAlive(processID: number): boolean {
    try {
      this.#signal(processID, 0);
      return true;
    } catch (error) {
      return (error as NodeJS.ErrnoException).code === "EPERM";
    }
  }

  async #waitForExit(processID: number, timeoutMs: number): Promise<boolean> {
    const attempts = Math.ceil(timeoutMs / 100);
    for (let attempt = 0; attempt < attempts; attempt += 1) {
      if (!this.#processAlive(processID)) return true;
      await this.#sleep(100);
    }
    return !this.#processAlive(processID);
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

function safeSignalFailure(error: unknown): string {
  const code = error instanceof Error && "code" in error
    ? String((error as NodeJS.ErrnoException).code ?? "unknown")
    : "unknown";
  return `Operating system rejected the Guardian process signal (${code.slice(0, 32)}).`;
}
