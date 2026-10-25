import { randomUUID } from "node:crypto";
import { unlinkSync } from "node:fs";
import {
  chmod,
  mkdir,
  readFile,
  rename,
  unlink,
  writeFile,
} from "node:fs/promises";
import { join } from "node:path";
import {
  GuardrailEffect,
  GuardrailIntervention,
  ManagedAction,
  type ActionGuardrailPolicy,
} from "./generated/phigon/v1/policy_pb.js";

export const managedActionNames = Object.freeze([
  "file.read",
  "file.write",
  "file.delete",
  "command.execute",
  "process.launch",
  "network.connect",
  "browser.navigate",
  "credential.access",
  "agent.start",
  "model.use",
] as const);

const maxPolicyRules = 256;

export type ManagedActionName = typeof managedActionNames[number];
export type GuardianIntervention = "block_action" | "stop_agent" | "kill_agent";

export type StoredActionRule = Readonly<{
  ruleId: string;
  action: ManagedActionName;
  effect: "deny" | "require_approval";
  intervention: GuardianIntervention;
  resourcePattern: string;
  agentPattern: string;
  reason: string;
  sourceText: string;
}>;

export type StoredActionPolicy = Readonly<{
  machineId: string;
  policyDigest: string;
  defaultEffect: "allow";
  rules: readonly StoredActionRule[];
  receivedAt: string;
}>;

export interface ActionPolicyPersistence {
  invalidate(machineId: string): number;
  save(
    machineId: string,
    policy: ActionGuardrailPolicy,
    generation?: number,
  ): Promise<StoredActionPolicy>;
  load(machineId: string): Promise<StoredActionPolicy | null>;
}

export class ActionPolicySupersededError extends Error {}

export class FileActionPolicyStore implements ActionPolicyPersistence {
  readonly #dataDirectory: string;
  readonly #path: string;
  #generation = 0;

  constructor(dataDirectory: string) {
    this.#dataDirectory = dataDirectory;
    this.#path = join(dataDirectory, "action-policy.json");
  }

  async save(
    machineId: string,
    policy: ActionGuardrailPolicy,
    generation = this.#generation,
  ): Promise<StoredActionPolicy> {
    const value = policyForStorage(machineId, policy);
    this.#requireCurrentGeneration(generation);
    await mkdir(this.#dataDirectory, { recursive: true, mode: 0o700 });
    await chmod(this.#dataDirectory, 0o700);
    const temporaryPath = `${this.#path}.${process.pid}.${randomUUID()}.tmp`;
    let promoted = false;
    try {
      await writeFile(
        temporaryPath,
        `${JSON.stringify(value)}\n`,
        { encoding: "utf8", flag: "wx", mode: 0o600 },
      );
      this.#requireCurrentGeneration(generation);
      await rename(temporaryPath, this.#path);
      promoted = true;
      this.#requireCurrentGeneration(generation);
      await chmod(this.#path, 0o600);
    } catch (error) {
      try {
        await unlink(promoted ? this.#path : temporaryPath);
      } catch {
        // The temporary file may not exist or invalidation may have removed it.
      }
      throw error;
    }
    return value;
  }

  invalidate(machineId: string): number {
    validateMachineId(machineId);
    this.#generation += 1;
    try {
      unlinkSync(this.#path);
    } catch (error) {
      if (!isNodeError(error) || error.code !== "ENOENT") throw error;
    }
    return this.#generation;
  }

  async load(machineId: string): Promise<StoredActionPolicy | null> {
    let raw: string;
    try {
      raw = await readFile(this.#path, "utf8");
    } catch (error) {
      if (isNodeError(error) && error.code === "ENOENT") return null;
      throw error;
    }
    const value: unknown = JSON.parse(raw);
    upgradeStoredPolicy(value);
    validateStoredPolicy(value, machineId);
    return value;
  }

  #requireCurrentGeneration(generation: number): void {
    if (generation !== this.#generation) {
      throw new ActionPolicySupersededError(
        "Action policy was superseded before persistence completed.",
      );
    }
  }
}

export function policyForStorage(
  machineId: string,
  policy: ActionGuardrailPolicy,
): StoredActionPolicy {
  validateMachineId(machineId);
  if (!/^[a-f0-9]{64}$/u.test(policy.policyDigest)) {
    throw new Error("Action policy digest is invalid.");
  }
  if (policy.defaultEffect !== "allow") {
    throw new Error("Action policy default effect is invalid.");
  }
  if (policy.rules.length > maxPolicyRules) {
    throw new Error("Action policy contains too many rules.");
  }
  const seen = new Set<string>();
  const rules = policy.rules.map((rule): StoredActionRule => {
    if (!validRuleId(rule.ruleId) || seen.has(rule.ruleId)) {
      throw new Error("Action policy rule identity is invalid.");
    }
    seen.add(rule.ruleId);
    const action = actionName(rule.action);
    const effect = effectName(rule.effect);
    const intervention = interventionName(rule.intervention);
    if (effect === "require_approval" && intervention !== "block_action") {
      throw new Error("Action policy approval rule cannot terminate an agent.");
    }
    if (
      rule.resourcePattern.length < 1 ||
      Buffer.byteLength(rule.resourcePattern, "utf8") > 512 ||
      Buffer.byteLength(rule.agentPattern.trim(), "utf8") > 128 ||
      rule.reason.trim().length < 1 ||
      Buffer.byteLength(rule.reason, "utf8") > 256 ||
      Buffer.byteLength(rule.sourceText.trim(), "utf8") > 2_000
    ) {
      throw new Error("Action policy rule bounds are invalid.");
    }
    compileGlob(rule.resourcePattern);
    return Object.freeze({
      ruleId: rule.ruleId,
      action,
      effect,
      intervention,
      resourcePattern: rule.resourcePattern,
      agentPattern: rule.agentPattern.trim(),
      reason: rule.reason.trim(),
      sourceText: rule.sourceText.trim(),
    });
  });
  return Object.freeze({
    machineId,
    policyDigest: policy.policyDigest,
    defaultEffect: "allow",
    rules: Object.freeze(rules),
    receivedAt: new Date().toISOString(),
  });
}

export function actionName(action: ManagedAction): ManagedActionName {
  const values: Partial<Record<ManagedAction, ManagedActionName>> = {
    [ManagedAction.FILE_READ]: "file.read",
    [ManagedAction.FILE_WRITE]: "file.write",
    [ManagedAction.FILE_DELETE]: "file.delete",
    [ManagedAction.COMMAND_EXECUTE]: "command.execute",
    [ManagedAction.PROCESS_LAUNCH]: "process.launch",
    [ManagedAction.NETWORK_CONNECT]: "network.connect",
    [ManagedAction.BROWSER_NAVIGATE]: "browser.navigate",
    [ManagedAction.CREDENTIAL_ACCESS]: "credential.access",
    [ManagedAction.AGENT_START]: "agent.start",
    [ManagedAction.MODEL_USE]: "model.use",
  };
  const value = values[action];
  if (value === undefined) throw new Error("Action policy action is invalid.");
  return value;
}

function effectName(effect: GuardrailEffect): StoredActionRule["effect"] {
  if (effect === GuardrailEffect.DENY) return "deny";
  if (effect === GuardrailEffect.REQUIRE_APPROVAL) return "require_approval";
  throw new Error("Action policy effect is invalid.");
}

function validateStoredPolicy(
  value: unknown,
  machineId: string,
): asserts value is StoredActionPolicy {
  if (
    typeof value !== "object" || value === null ||
    !("machineId" in value) || value.machineId !== machineId ||
    !("policyDigest" in value) || typeof value.policyDigest !== "string" ||
    !/^[a-f0-9]{64}$/u.test(value.policyDigest) ||
    !("defaultEffect" in value) || value.defaultEffect !== "allow" ||
    !("receivedAt" in value) || typeof value.receivedAt !== "string" ||
    !Number.isFinite(Date.parse(value.receivedAt)) ||
    !("rules" in value) || !Array.isArray(value.rules) || value.rules.length > maxPolicyRules
  ) {
    throw new Error("Stored action policy is invalid.");
  }
  const seen = new Set<string>();
  for (const rule of value.rules) {
    if (
      typeof rule !== "object" || rule === null ||
      !("ruleId" in rule) || typeof rule.ruleId !== "string" ||
      !validRuleId(rule.ruleId) || seen.has(rule.ruleId) ||
      !("action" in rule) || typeof rule.action !== "string" ||
      !managedActionNames.includes(rule.action as ManagedActionName) ||
      !("effect" in rule) ||
      (rule.effect !== "deny" && rule.effect !== "require_approval") ||
      !("intervention" in rule) ||
      (rule.intervention !== "block_action" &&
        rule.intervention !== "stop_agent" &&
        rule.intervention !== "kill_agent") ||
      !("resourcePattern" in rule) || typeof rule.resourcePattern !== "string" ||
      rule.resourcePattern.length < 1 || Buffer.byteLength(rule.resourcePattern, "utf8") > 512 ||
      !("agentPattern" in rule) || typeof rule.agentPattern !== "string" ||
      Buffer.byteLength(rule.agentPattern, "utf8") > 128 ||
      !("reason" in rule) || typeof rule.reason !== "string" ||
      rule.reason.trim().length < 1 || Buffer.byteLength(rule.reason, "utf8") > 256 ||
      !("sourceText" in rule) || typeof rule.sourceText !== "string" ||
      Buffer.byteLength(rule.sourceText, "utf8") > 2_000
    ) {
      throw new Error("Stored action policy rule is invalid.");
    }
    if (rule.effect === "require_approval" && rule.intervention !== "block_action") {
      throw new Error("Stored action policy approval rule cannot terminate an agent.");
    }
    compileGlob(rule.resourcePattern);
    if (rule.agentPattern.trim() !== "") compileGlob(rule.agentPattern.trim());
    if (rule.agentPattern !== "") compileGlob(rule.agentPattern);
    seen.add(rule.ruleId);
  }
}

function interventionName(intervention: GuardrailIntervention): GuardianIntervention {
  if (intervention === GuardrailIntervention.STOP_AGENT) return "stop_agent";
  if (intervention === GuardrailIntervention.KILL_AGENT) return "kill_agent";
  if (
    intervention === GuardrailIntervention.BLOCK_ACTION ||
    intervention === GuardrailIntervention.UNSPECIFIED
  ) return "block_action";
  throw new Error("Action policy intervention is invalid.");
}

function upgradeStoredPolicy(value: unknown): void {
  if (typeof value !== "object" || value === null || !("rules" in value) ||
    !Array.isArray(value.rules)) return;
  for (const item of value.rules) {
    if (typeof item === "object" && item !== null && !("agentPattern" in item)) {
      (item as Record<string, unknown>)["agentPattern"] = "";
    }
    if (typeof item === "object" && item !== null && !("sourceText" in item)) {
      (item as Record<string, unknown>)["sourceText"] = "";
    }
    if (typeof item === "object" && item !== null && !("intervention" in item)) {
      (item as Record<string, unknown>)["intervention"] = "block_action";
    }
  }
}

function compileGlob(pattern: string): RegExp {
  let expression = "^";
  for (let index = 0; index < pattern.length; index++) {
    const character = pattern[index] as string;
    if (character === "*" && pattern[index + 1] === "*") {
      expression += ".*";
      index++;
    } else if (character === "*") {
      expression += "[^/]*";
    } else if (character === "?") {
      expression += "[^/]";
    } else if (character === "[") {
      throw new Error("Character classes are not supported in action policy globs.");
    } else {
      expression += character.replace(/[\\^$+?.()|{}]/gu, "\\$&");
    }
  }
  return new RegExp(`${expression}$`, "u");
}

function validRuleId(value: string): boolean {
  return /^[a-f0-9]{8}-[a-f0-9]{4}-[1-8][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/iu.test(value);
}

function validateMachineId(value: string): void {
  if (value.length < 1 || value.length > 128 || !/^[A-Za-z0-9._:-]+$/u.test(value)) {
    throw new Error("Machine ID is invalid.");
  }
}

function isNodeError(error: unknown): error is NodeJS.ErrnoException {
  return error instanceof Error && "code" in error;
}
