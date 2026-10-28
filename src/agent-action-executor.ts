import { createHash } from "node:crypto";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { create, toBinary } from "@bufbuild/protobuf";
import { timestampDate, timestampFromDate } from "@bufbuild/protobuf/wkt";
import {
  AgentActionResultSchema,
  AgentActionCommandSchema,
  RemoteActionResultState,
  RemoteActionType,
  type AgentActionCommand,
  type AgentActionResult,
} from "./generated/phigon/v1/action_pb.js";
import { AgentState } from "./generated/phigon/v1/common_pb.js";
import type { AgentInventory } from "./generated/phigon/v1/identity_pb.js";
import { defaultProcessTreeControl, describeTreeOutcome, type ProcessTreeControl, type TreeStopOutcome } from "./process-tree.js";
import { MachineCommandExecutor, machineActionTypes, pruneCommandReceipts } from "./machine-command-executor.js";
import { atomicReplace } from "./atomic-replace.js";
import type { RunningAgents } from "./system-inspection.js";

const executorVersion = "observer-agent-actions-v3";
const receiptLimit = 256;
const discoveryTimeoutMs = 60_000;
// Periodic discovery runs every 10 seconds by default.
const recentInventoryMs = 60_000;
// Matches the retention of process claims and machine-command receipts.
const receiptRetentionMs = 30 * 86_400_000;

export type ActionInventoryProvider = () => Promise<AgentInventory>;

export class AgentActionExecutor {
  readonly #enabled: boolean;
  readonly #machineID: string;
  readonly #inventory: ActionInventoryProvider;
  readonly #receipts: ActionReceiptStore;
  readonly #commands: MachineCommandExecutor;
  readonly #commandsEnabled: boolean;
  #queue: Promise<unknown> = Promise.resolve();
  readonly #claimsDirectory: string;
  readonly #processes: ProcessTreeControl;
  #latestInventory: { inventory: AgentInventory; at: number } | undefined;

  constructor(options: {
    enabled: boolean;
    commandsEnabled?: boolean;
    machineID: string;
    dataDirectory: string;
    inventory: ActionInventoryProvider;
    processControl?: ProcessTreeControl;
  }) {
    this.#enabled = options.enabled;
    this.#processes = options.processControl ?? defaultProcessTreeControl();
    this.#machineID = options.machineID;
    this.#inventory = options.inventory;
    this.#commandsEnabled = options.commandsEnabled ?? false;
    this.#claimsDirectory = join(options.dataDirectory, "process-operation-claims");
    this.#commands = new MachineCommandExecutor({
      enabled: this.#commandsEnabled, machineID: options.machineID, dataDirectory: options.dataDirectory,
      agents: () => this.#runningAgents(),
    });
    this.#receipts = new ActionReceiptStore(
      join(options.dataDirectory, "agent-action-receipts.json"),
    );
  }

  /**
   * Records the observer's periodic discovery result. inspect_system reuses a
   * recent one instead of scanning again; stop and kill always rescan.
   */
  observeInventory(inventory: AgentInventory): void {
    this.#latestInventory = { inventory, at: Date.now() };
  }

  async #runningAgents(): Promise<RunningAgents> {
    const latest = this.#latestInventory;
    const inventory = latest !== undefined && Date.now() - latest.at < recentInventoryMs ? latest.inventory : await this.#inventory();
    return {
      complete: !inventory.partial,
      agents: inventory.agents.filter((agent) =>
        agent.state === AgentState.RUNNING && agent.startedAt !== undefined &&
        agent.processId > 0n && agent.processId <= BigInt(Number.MAX_SAFE_INTEGER) &&
        agent.capabilities.includes("process-instance"))
        .map((agent) => ({
          name: agent.displayName || agent.runtime || "Agent",
          processId: Number(agent.processId),
          startedAt: timestampDate(agent.startedAt!),
        })),
    };
  }

  capabilities(): readonly RemoteActionType[] {
    return [...(this.#enabled ? [RemoteActionType.STOP_AGENT, RemoteActionType.KILL_AGENT] : []), ...(this.#commandsEnabled ? machineActionTypes : [])];
  }

  async maintainReceipts(): Promise<void> {
    const processClaims = this.#queue.then(() => pruneCommandReceipts(this.#claimsDirectory));
    this.#queue = processClaims.catch(() => undefined);
    await Promise.all([processClaims, this.#commands.prune()]);
  }

  manifest() {
    return {
      enabled: this.#enabled || this.#commandsEnabled,
      executorVersion,
      actions: [...this.capabilities()],
    };
  }

  async execute(command: AgentActionCommand): Promise<AgentActionResult> {
    if (machineActionTypes.includes(command.action)) return this.#commands.execute(command);
    const task = this.#queue.then(() => this.#executeProcess(command)).catch((error: unknown) => create(AgentActionResultSchema, {
      actionId: command.actionId, idempotencyKey: command.idempotencyKey, machineId: this.#machineID,
      state: error instanceof Error && error.message === "idempotency_conflict" ? RemoteActionResultState.REJECTED : RemoteActionResultState.FAILED,
      resultCode: error instanceof Error && error.message === "idempotency_conflict" ? "idempotency_conflict" : "execution_journal_unavailable",
      detail: "Execution could not be confirmed from its durable record. Check the target state before issuing another request.",
      observedAt: timestampFromDate(new Date()), targetStillRunning: true,
    }));
    this.#queue = task;
    return task;
  }

  async #executeProcess(command: AgentActionCommand): Promise<AgentActionResult> {
    const digest = createHash("sha256").update(toBinary(AgentActionCommandSchema, command)).digest("hex");

    const base = {
      actionId: command.actionId,
      idempotencyKey: command.idempotencyKey,
      machineId: this.#machineID,
    };
    const reject = async (
      resultCode: string,
      detail: string,
      targetStillRunning = true,
      state = RemoteActionResultState.REJECTED,
    ) => {
      const receipt = create(AgentActionResultSchema, {
        ...base,
        state,
        resultCode,
        detail,
        observedAt: timestampFromDate(new Date()),
        targetStillRunning,
      });
      await this.#receipts.put(receipt, digest, command.expiresAt ? timestampDate(command.expiresAt).toISOString() : undefined);
      return receipt;
    };

    if (command.machineId !== this.#machineID ||
      !validUUID(command.actionId) || !validUUID(command.idempotencyKey) ||
      command.expectedStartedAt === undefined || command.expiresAt === undefined ||
      command.processId < 1n || command.processId > BigInt(Number.MAX_SAFE_INTEGER) ||
      ![RemoteActionType.STOP_AGENT, RemoteActionType.KILL_AGENT].includes(command.action)) {
      return create(AgentActionResultSchema, { ...base, state: RemoteActionResultState.REJECTED, resultCode: "invalid_command", detail: "Command identity or capability validation failed.", observedAt: timestampFromDate(new Date()), targetStillRunning: true });
    }
    const cached = await this.#receipts.get(command.idempotencyKey, digest);
    if (cached !== null) return cached;
    // A claim without a receipt means a signal may already have been sent.
    // Report that honestly instead of an expiry or a second attempt.
    const claim = await readClaim(join(this.#claimsDirectory, `${command.idempotencyKey}.claim`));
    if (claim !== null) {
      if (/^[0-9a-f]{64}$/u.test(claim) && claim !== digest) throw new Error("idempotency_conflict");
      return await reject(
        "execution_interrupted",
        "A process signal was claimed without a completion receipt. It will not be repeated automatically.",
        true,
        RemoteActionResultState.FAILED,
      );
    }
    if (!this.#enabled) return await reject("executor_disabled", "Machine owner has not enabled remote agent actions.");
    if (!Number.isFinite(timestampDate(command.expiresAt).getTime()) || timestampDate(command.expiresAt).getTime() > Date.now() + 330_000) return await reject("invalid_command", "Command expiry is outside the approved execution window.");
    if (timestampDate(command.expiresAt).getTime() <= Date.now()) {
      return await reject(
        "command_expired",
        "The approved command expired before local execution.",
        true,
        RemoteActionResultState.EXPIRED,
      );
    }

    // Discovery can be slow. The approval is only valid until expiresAt, so
    // the wait is bounded by it and expiry is checked again before dispatch.
    const expiresAt = timestampDate(command.expiresAt).getTime();
    const expired = () => reject(
      "command_expired",
      "The approved command expired while the observer verified the target process. Nothing was signalled.",
      true,
      RemoteActionResultState.EXPIRED,
    );
    let inventory: AgentInventory;
    try {
      inventory = await withDeadline(this.#inventory(), Math.min(expiresAt - Date.now(), discoveryTimeoutMs));
    } catch {
      if (Date.now() >= expiresAt) return await expired();
      return await reject(
        "target_unverified",
        "The observer could not list running agents, so the target could not be verified. Nothing was signalled.",
        true,
        RemoteActionResultState.FAILED,
      );
    }
    if (Date.now() >= expiresAt) return await expired();
    const target = inventory.agents.find((agent) =>
      agent.agentId === command.agentId &&
      agent.processId === command.processId &&
      agent.state === AgentState.RUNNING &&
      agent.startedAt !== undefined &&
      timestampDate(agent.startedAt).getTime() === timestampDate(command.expectedStartedAt!).getTime() &&
      agent.capabilities.includes("process-instance")
    );
    if (target === undefined) {
      return await reject("stale_target", "The exact observed process lifetime is no longer running.", false);
    }

    const pid = Number(command.processId);
    if (pid === process.pid) {
      return await reject("self_target_rejected", "Observer refuses to terminate its own process.");
    }

    await mkdir(this.#claimsDirectory, { recursive: true, mode: 0o700 });
    // Exclusive creation also prevents two observer processes from claiming
    // the same signal. A leftover claim must never trigger another signal.
    await writeFile(join(this.#claimsDirectory, `${command.idempotencyKey}.claim`), digest, { flag: "wx", mode: 0o600, flush: true });
    await this.#receipts.put(create(AgentActionResultSchema, {
      ...base, state: RemoteActionResultState.FAILED, resultCode: "execution_interrupted",
      detail: "A process signal was claimed without a completion receipt. It will not be repeated automatically.",
      observedAt: timestampFromDate(new Date()), targetStillRunning: true,
    }), digest, timestampDate(command.expiresAt).toISOString());
    // The controller re-verifies the exact lifetime immediately before any
    // signal and includes only verified descendants of that lifetime.
    const outcome = await this.#processes.stop(
      { processId: pid, startedAt: timestampDate(command.expectedStartedAt) },
      command.action === RemoteActionType.STOP_AGENT ? "stop" : "kill",
    ).catch((): TreeStopOutcome => ({ outcome: "failed", code: "unknown" }));
    const [state, resultCode, detail, targetStillRunning] = describeOutcome(outcome, command.action === RemoteActionType.STOP_AGENT);
    const receipt = create(AgentActionResultSchema, {
      ...base, state, resultCode, detail, targetStillRunning, observedAt: timestampFromDate(new Date()),
    });
    await this.#receipts.put(receipt, digest, timestampDate(command.expiresAt).toISOString());
    return receipt;
  }
}

/** Maps a process-tree outcome to the wire receipt fields. */
export function describeOutcome(outcome: TreeStopOutcome, graceful: boolean): [RemoteActionResultState, string, string, boolean] {
  const receipt = describeTreeOutcome(outcome, graceful);
  const state = { succeeded: RemoteActionResultState.SUCCEEDED, failed: RemoteActionResultState.FAILED, rejected: RemoteActionResultState.REJECTED }[receipt.state];
  return [state, receipt.code, receipt.detail, receipt.targetStillRunning];
}

async function readClaim(path: string): Promise<string | null> {
  try {
    return (await readFile(path, "utf8")).trim();
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return null;
    throw error;
  }
}

function withDeadline<T>(work: Promise<T>, milliseconds: number): Promise<T> {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error("deadline_exceeded")), Math.max(0, milliseconds));
    work.then(
      (value) => { clearTimeout(timer); resolve(value); },
      (error: unknown) => { clearTimeout(timer); reject(error instanceof Error ? error : new Error("discovery_failed")); },
    );
  });
}

function validUUID(value: string): boolean {
  return /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu.test(value);
}

type StoredReceipt = Readonly<{
  commandDigest?: string;
  expiresAt?: string;
  actionId: string;
  idempotencyKey: string;
  machineId: string;
  state: RemoteActionResultState;
  resultCode: string;
  detail: string;
  observedAt: string;
  targetStillRunning: boolean;
}>;

class ActionReceiptStore {
  readonly #path: string;

  constructor(path: string) {
    this.#path = path;
  }

  async get(idempotencyKey: string, digest: string): Promise<AgentActionResult | null> {
    const receipts = await this.#load();
    const receipt = receipts.find((entry) => entry.idempotencyKey === idempotencyKey);
    if (receipt === undefined) return null;
    if (receipt.commandDigest !== digest) throw new Error("idempotency_conflict");
    return create(AgentActionResultSchema, {
      ...receipt,
      observedAt: timestampFromDate(new Date(receipt.observedAt)),
    });
  }

  async put(receipt: AgentActionResult, commandDigest: string, expiresAt?: string): Promise<void> {
    const observedAt = receipt.observedAt === undefined
      ? new Date().toISOString()
      : timestampDate(receipt.observedAt).toISOString();
    // Receipts outlive their command: a replay after a long disconnect must
    // return what happened, not a false "expired". Expired receipts make
    // room first; the durable claim still blocks a second signal.
    const now = Date.now();
    const receipts = (await this.#load())
      .filter((entry) => entry.idempotencyKey !== receipt.idempotencyKey && receiptExpiry(entry) + receiptRetentionMs > now);
    while (receipts.length >= receiptLimit) {
      const oldestExpired = receipts.findIndex((entry) => receiptExpiry(entry) <= now);
      if (oldestExpired < 0) throw new Error("Execution journal capacity reached");
      receipts.splice(oldestExpired, 1);
    }
    receipts.push({
      commandDigest, ...(expiresAt ? { expiresAt } : {}),
      actionId: receipt.actionId,
      idempotencyKey: receipt.idempotencyKey,
      machineId: receipt.machineId,
      state: receipt.state,
      resultCode: receipt.resultCode,
      detail: receipt.detail,
      observedAt,
      targetStillRunning: receipt.targetStillRunning,
    });
    const bounded = receipts.slice(-receiptLimit);
    await mkdir(dirname(this.#path), { recursive: true, mode: 0o700 });
    const temporary = `${this.#path}.${createHash("sha256").update(JSON.stringify(bounded)).digest("hex").slice(0, 12)}.tmp`;
    await writeFile(temporary, `${JSON.stringify(bounded)}\n`, { encoding: "utf8", mode: 0o600, flush: true });
    await atomicReplace(temporary, this.#path);
  }

  async #load(): Promise<StoredReceipt[]> {
    try {
      const value: unknown = JSON.parse(await readFile(this.#path, "utf8"));
      if (!Array.isArray(value) || value.length > receiptLimit || !value.every(validStoredReceipt)) throw new Error("Invalid execution journal");
      return value;
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "ENOENT") return [];
      throw error;
    }
  }
}

function receiptExpiry(entry: StoredReceipt): number {
  return entry.expiresAt ? Date.parse(entry.expiresAt) : Date.parse(entry.observedAt) + 600_000;
}

function validStoredReceipt(value: unknown): value is StoredReceipt {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return false;
  const record = value as Record<string, unknown>;
  return (record["commandDigest"] === undefined || typeof record["commandDigest"] === "string" && /^[0-9a-f]{64}$/u.test(record["commandDigest"])) &&
    (record["expiresAt"] === undefined || typeof record["expiresAt"] === "string" && Number.isFinite(Date.parse(record["expiresAt"]))) &&
    typeof record["actionId"] === "string" && validUUID(record["actionId"]) &&
    typeof record["idempotencyKey"] === "string" && validUUID(record["idempotencyKey"]) &&
    typeof record["machineId"] === "string" && validUUID(record["machineId"]) &&
    typeof record["state"] === "number" &&
    typeof record["resultCode"] === "string" && record["resultCode"].length <= 64 &&
    typeof record["detail"] === "string" && record["detail"].length <= 256 &&
    typeof record["observedAt"] === "string" && Number.isFinite(Date.parse(record["observedAt"])) &&
    typeof record["targetStillRunning"] === "boolean";
}
