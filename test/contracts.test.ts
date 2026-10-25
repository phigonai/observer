import assert from "node:assert/strict";
import test from "node:test";
import { create, fromBinary, toBinary } from "@bufbuild/protobuf";
import {
  PrivacyClass,
} from "../src/generated/phigon/v1/common_pb.js";
import {
  CollectionPolicySchema,
} from "../src/generated/phigon/v1/policy_pb.js";
import {
  EventEnvelopeSchema,
  LifecycleEventSchema,
  LifecyclePhase,
} from "../src/generated/phigon/v1/telemetry_pb.js";

test("generated telemetry bindings round-trip an event", () => {
  const lifecycle = create(LifecycleEventSchema, {
    phase: LifecyclePhase.STARTED,
    reason: "process detected",
  });
  const original = create(EventEnvelopeSchema, {
    tenantId: "tenant-0001",
    machineId: "machine-0001",
    agentId: "agent-0001",
    sessionId: "session-0001",
    sequence: 1n,
    schemaVersion: 1,
    privacyClass: PrivacyClass.SYSTEM_METADATA,
    payload: {
      case: "lifecycle",
      value: lifecycle,
    },
  });

  const decoded = fromBinary(
    EventEnvelopeSchema,
    toBinary(EventEnvelopeSchema, original),
  );

  assert.equal(decoded.machineId, original.machineId);
  assert.equal(decoded.sequence, 1n);
  assert.equal(decoded.payload.case, "lifecycle");
  assert.equal(decoded.payload.value?.reason, "process detected");
});

test("generated collection policy defaults every content switch off", () => {
  const policy = create(CollectionPolicySchema);

  assert.deepEqual(
    {
      promptContent: policy.promptContent,
      responseContent: policy.responseContent,
      reasoningContent: policy.reasoningContent,
      commandArguments: policy.commandArguments,
      terminalOutput: policy.terminalOutput,
      filePaths: policy.filePaths,
      fileContent: policy.fileContent,
      browserUrls: policy.browserUrls,
      browserContent: policy.browserContent,
      networkEndpoints: policy.networkEndpoints,
      gitPatchContent: policy.gitPatchContent,
      environmentValues: policy.environmentValues,
      toolOutput: policy.toolOutput,
    },
    {
      promptContent: false,
      responseContent: false,
      reasoningContent: false,
      commandArguments: false,
      terminalOutput: false,
      filePaths: false,
      fileContent: false,
      browserUrls: false,
      browserContent: false,
      networkEndpoints: false,
      gitPatchContent: false,
      environmentValues: false,
      toolOutput: false,
    },
  );
});
