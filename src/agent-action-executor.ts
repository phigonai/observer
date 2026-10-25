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
import { requestWindowsGracefulStop } from "./windows-process.js";
import { killVerifiedWindowsProcess } from "./guardian-native.js";
import { MachineCommandExecutor, machineActionTypes, pruneCommandReceipts } from "./machine-command-executor.js";
import { atomicReplace } from "./atomic-replace.js";

const executorVersion = "observer-agent-actions-v2";
const receiptLimit = 256;

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

  constructor(options: {
    enabled: boolean;
    commandsEnabled?: boolean;
    machineID: string;
    dataDirectory: string;
    inventory: ActionInventoryProvider;
  }) {
    this.#enabled = options.enabled;
    this.#machineID = options.machineID;
    this.#inventory = options.inventory;
    this.#commandsEnabled = options.commandsEnabled ?? false;
    this.#claimsDirectory = join(options.dataDirectory, "process-operation-claims");
    this.#commands = new MachineCommandExecutor({ enabled: this.#commandsEnabled, machineID: options.machineID, dataDirectory: options.dataDirectory });
    this.#receipts = new ActionReceiptStore(
      join(options.dataDirectory, "agent-action-receipts.json"),
    );
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

    const inventory = await this.#inventory();
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
    if (!processAlive(pid)) {
      return await reject("target_already_stopped", "The target process is no longer running.", false);
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
    try {
      if (
        command.action === RemoteActionType.STOP_AGENT &&
        process.platform === "win32"
      ) {
        await requestWindowsGracefulStop(pid, timestampDate(command.expectedStartedAt).toISOString());
      } else if (process.platform === "win32") {
        await killVerifiedWindowsProcess(pid, timestampDate(command.expectedStartedAt).toISOString());
      } else {
        process.kill(
          pid,
          command.action === RemoteActionType.STOP_AGENT ? "SIGTERM" : "SIGKILL",
        );
      }
    } catch (error) {
      return await reject(
        "os_dispatch_failed",
        safeErrorDetail(error),
        processAlive(pid),
        RemoteActionResultState.FAILED,
      );
    }

    const stopped = await waitForExit(pid, command.action === RemoteActionType.STOP_AGENT ? 5_000 : 2_000);
    const receipt = create(AgentActionResultSchema, {
      ...base,
      state: stopped
        ? RemoteActionResultState.SUCCEEDED
        : RemoteActionResultState.FAILED,
      resultCode: stopped ? "process_stopped" : "process_still_running",
      detail: stopped
        ? "The exact observed process lifetime exited after the approved signal."
        : "The approved stop request was sent without escalation, but the target still reports running.",
      observedAt: timestampFromDate(new Date()),
      targetStillRunning: !stopped,
    });
    await this.#receipts.put(receipt, digest, timestampDate(command.expiresAt).toISOString());
    return receipt;
  }
}

function processAlive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch (error) {
    return (error as NodeJS.ErrnoException).code === "EPERM";
  }
}

async function waitForExit(pid: number, timeoutMs: number): Promise<boolean> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (!processAlive(pid)) return true;
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
  return !processAlive(pid);
}

function safeErrorDetail(error: unknown): string {
  const code = error instanceof Error && "code" in error
    ? String((error as NodeJS.ErrnoException).code ?? "unknown")
    : "unknown";
  return `Operating system rejected the approved process signal (${code.slice(0, 32)}).`;
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
    const receipts = (await this.#load())
      .filter((entry) => entry.idempotencyKey !== receipt.idempotencyKey &&
        (entry.expiresAt ? Date.parse(entry.expiresAt) : Date.parse(entry.observedAt) + 600_000) > Date.now());
    if (receipts.length >= receiptLimit) throw new Error("Execution journal capacity reached");
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
