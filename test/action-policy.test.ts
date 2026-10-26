import { create } from "@bufbuild/protobuf";
import assert from "node:assert/strict";
import { mkdtemp, stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import {
  ActionPolicySupersededError,
  FileActionPolicyStore,
  policyForStorage,
} from "../src/action-policy.js";
import {
  ActionGuardrailPolicySchema,
  ActionGuardrailRuleSchema,
  GuardrailEffect,
  ManagedAction,
} from "../src/generated/phigon/v1/policy_pb.js";

const machineId = "68fd2b0b-7e8c-4b0d-890d-7f2d8e94dc2f";
const policyDigest = "a".repeat(64);

test("action policy store persists a validated machine-bound policy", async () => {
  const directory = await mkdtemp(join(tmpdir(), "phigon-action-policy-"));
  const store = new FileActionPolicyStore(directory);
  const wire = create(ActionGuardrailPolicySchema, {
    policyDigest,
    defaultEffect: "allow",
    rules: [create(ActionGuardrailRuleSchema, {
      ruleId: "72b1f93f-6317-46c7-bbba-6174d19c4119",
      action: ManagedAction.NETWORK_CONNECT,
      effect: GuardrailEffect.DENY,
      resourcePattern: "*.internal.example:443",
      reason: "Internal endpoints are restricted.",
      sourceText: "Do not connect to internal endpoints.",
    })],
  });
  await store.save(machineId, wire);
  const stored = await store.load(machineId);
  assert.equal(stored?.policyDigest, policyDigest);
  assert.equal(stored?.rules[0]?.action, "network.connect");
  assert.equal(stored?.rules[0]?.sourceText, "Do not connect to internal endpoints.");
  if (process.platform !== "win32") {
    assert.equal((await stat(join(directory, "action-policy.json"))).mode & 0o777, 0o600);
  }
  await assert.rejects(
    store.load("different-machine"),
    /Stored action policy is invalid/u,
  );
});

test("action policy rejects unsupported rules before replacing local state", () => {
  assert.throws(
    () => policyForStorage(machineId, create(ActionGuardrailPolicySchema, {
      policyDigest,
      defaultEffect: "allow",
      rules: [create(ActionGuardrailRuleSchema, {
        ruleId: "72b1f93f-6317-46c7-bbba-6174d19c4119",
        action: ManagedAction.FILE_READ,
        effect: GuardrailEffect.DENY,
        resourcePattern: "[invalid]",
        reason: "Invalid glob syntax.",
      })],
    })),
    /Character classes are not supported/u,
  );
});

test("action policy invalidation fails closed and rejects superseded writes", async () => {
  const directory = await mkdtemp(join(tmpdir(), "phigon-action-generation-"));
  const store = new FileActionPolicyStore(directory);
  const first = create(ActionGuardrailPolicySchema, {
    policyDigest: "b".repeat(64),
    defaultEffect: "allow",
  });
  const second = create(ActionGuardrailPolicySchema, {
    policyDigest: "c".repeat(64),
    defaultEffect: "allow",
  });
  const firstGeneration = store.invalidate(machineId);
  const secondGeneration = store.invalidate(machineId);
  await assert.rejects(
    store.save(machineId, first, firstGeneration),
    ActionPolicySupersededError,
  );
  assert.equal(await store.load(machineId), null);
  await store.save(machineId, second, secondGeneration);
  assert.equal((await store.load(machineId))?.policyDigest, "c".repeat(64));
  store.invalidate(machineId);
  assert.equal(await store.load(machineId), null);
});

test("a pattern with a closing bracket is accepted like the server accepts it", () => {
  const stored = policyForStorage(machineId, create(ActionGuardrailPolicySchema, {
    policyDigest,
    defaultEffect: "allow",
    rules: [create(ActionGuardrailRuleSchema, {
      ruleId: "72b1f93f-6317-46c7-bbba-6174d19c4119",
      action: ManagedAction.FILE_READ,
      effect: GuardrailEffect.DENY,
      resourcePattern: "**/report].txt",
      reason: "Bracketed file names are restricted.",
    })],
  }));
  assert.equal(stored.rules[0]?.resourcePattern, "**/report].txt");
});
