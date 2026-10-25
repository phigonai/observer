import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import {
  mkdtemp,
  readFile,
  readdir,
  rm,
  symlink,
  writeFile,
} from "node:fs/promises";
import { createServer } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Readable } from "node:stream";
import { promisify } from "node:util";
import test from "node:test";
import { fileURLToPath } from "node:url";
import {
  isCliEntryPoint,
  run,
  settleObserverTasks,
} from "../src/cli.js";
import { FileActionPolicyStore } from "../src/action-policy.js";
import { FileCredentialStore } from "../src/credential-store.js";
import { CustomAgentRegistry } from "../src/custom-agent-registry.js";
import { StreamStateStore } from "../src/stream-state.js";
import { create } from "@bufbuild/protobuf";
import {
  ActionGuardrailPolicySchema,
  ActionGuardrailRuleSchema,
  GuardrailEffect,
  ManagedAction,
} from "../src/generated/phigon/v1/policy_pb.js";

const execFileAsync = promisify(execFile);

test("CLI startup does not eagerly load experimental SQLite", async () => {
  const cli = fileURLToPath(new URL("../src/cli.js", import.meta.url));
  const environment = { ...process.env };
  delete environment["NODE_NO_WARNINGS"];
  const { stderr } = await execFileAsync(process.execPath, [cli, "help"], {
    env: environment,
  });

  assert.doesNotMatch(stderr, /ExperimentalWarning|node:sqlite|SQLite/u);
});

test("top-level help aliases succeed without configuration", async () => {
  for (const alias of ["help", "--help", "-h"]) {
    let stdout = "";
    let stderr = "";
    const code = await run([alias], {}, {
      stdout: (value) => { stdout += value; },
      stderr: (value) => { stderr += value; },
    });
    assert.equal(code, 0, alias);
    assert.equal(stderr, "", alias);
    assert.match(stdout, /Usage:\s+phigon-observer/u);
  }
});

test("doctor emits a JSON diagnostic without credential values", async () => {
  let stdout = "";
  let stderr = "";

  const exitCode = await run(
    ["doctor", "--json"],
    {
      PHIGON_CONTROL_PLANE_URL: "https://control.example.test",
      PHIGON_MACHINE_TOKEN: "secret-value",
      PHIGON_DATA_DIR: "/tmp/phigon-test",
    },
    {
      stdout: (value) => {
        stdout += value;
      },
      stderr: (value) => {
        stderr += value;
      },
    },
  );

  assert.equal(exitCode, 0);
  assert.equal(stderr, "");
  assert.match(stdout, /"status": "ready"/);
  assert.doesNotMatch(stdout, /secret-value/);
});

test("doctor accepts the same portable observability profile as run", async () => {
  let stdout = "";
  let stderr = "";

  const exitCode = await run(
    ["doctor", "--profile", "full", "--json"],
    {
      PHIGON_CONTROL_PLANE_URL: "https://control.example.test",
      PHIGON_DATA_DIR: "/tmp/phigon-test-profile",
    },
    {
      stdout: (value) => {
        stdout += value;
      },
      stderr: (value) => {
        stderr += value;
      },
    },
  );

  assert.equal(exitCode, 0);
  assert.equal(stderr, "");
  const health = JSON.parse(stdout) as {
    observabilityProfile?: string;
    enabledCollectionCategories?: string[];
  };
  assert.equal(health.observabilityProfile, "full");
  assert.ok((health.enabledCollectionCategories?.length ?? 0) > 4);
});

test("portable profile flags fail closed outside doctor and run", async () => {
  let stderr = "";
  const exitCode = await run(
    ["discover", "--profile", "full"],
    { PHIGON_CONTROL_PLANE_URL: "https://control.example.test" },
    {
      stdout: () => undefined,
      stderr: (value) => {
        stderr += value;
      },
    },
  );

  assert.equal(exitCode, 1);
  assert.match(stderr, /supported only by doctor and run/u);
});

test("authorize-action rejects a credential from another control-plane origin", async () => {
  const directory = await mkdtemp(join(tmpdir(), "phigon-cli-action-origin-"));
  let stdout = "";
  let stderr = "";
  try {
    await new FileCredentialStore(directory).save({
      machineId: "machine-action-origin",
      tenantId: "tenant-action-origin",
      credential: `phg_m_${"o".repeat(43)}`,
      controlPlaneOrigin: "https://other-control.example.test",
      createdAt: "2026-08-22T00:00:00.000Z",
    });
    const exitCode = await run(
      [
        "authorize-action",
        "--action", "file.read",
        "--resource", "/workspace/readme.md",
        "--json",
      ],
      {
        PHIGON_CONTROL_PLANE_URL: "https://control.example.test",
        PHIGON_DATA_DIR: directory,
      },
      {
        stdout: (value) => { stdout += value; },
        stderr: (value) => { stderr += value; },
      },
    );
    assert.equal(exitCode, 1);
    assert.equal(stdout, "");
    assert.match(stderr, /different control plane|failed closed/u);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("Guardian is centrally managed and rejects all removed local controls", async () => {
  const directory = await mkdtemp(join(tmpdir(), "phigon-cli-central-guardian-"));
  const environment = { PHIGON_CONTROL_PLANE_URL: "https://control.example.test", PHIGON_DATA_DIR: directory };
  try {
    await writeFile(join(directory, "guardian-control.json"), JSON.stringify({ enabled: false, containmentEnabled: false }));
    let stdout = "";
    assert.equal(await run(["guardian", "status", "--json"], environment, {
      stdout: (value) => { stdout += value; }, stderr: () => undefined,
    }), 0);
    assert.deepEqual(JSON.parse(stdout), {
      enabled: true, decisionAuthority: "control_plane", containmentAuthority: "admin_policy", localOverrides: false,
      paired: false, policyDelivered: false, nativeRunner: true, machineWidePrevention: "not_attested", managedExecution: "unavailable",
    });
    for (const flags of [["off"], ["on"], ["containment", "off"], ["containment", "on"]]) {
      let stderr = "";
      assert.equal(await run(["guardian", ...flags], environment, {
        stdout: () => undefined, stderr: (value) => { stderr += value; },
      }), 1);
      assert.match(stderr, /Local Guardian controls have been removed/u);
    }
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("blocked managed action tells the agent the exact administrator contract", async () => {
  const directory = await mkdtemp(join(tmpdir(), "phigon-cli-guardian-message-"));
  const machineId = "5f1b4cb4-a77d-4f53-af66-197e184683f4";
  const contract = "Do not delete any file on this machine.";
  const ruleId = "72b1f93f-6317-46c7-bbba-6174d19c4119";
  let stdout = "";
  let stderr = "";
  let requests = 0;
  const server = createServer((_request, response) => {
    requests++;
    response.writeHead(200, { "Content-Type": "application/json" });
    response.end(JSON.stringify({
      decision: "deny",
      reason: "Deletion conflicts with the administrator contract.",
      risk: "high",
      confidence: 0.99,
      matched_contract_id: ruleId,
      admin_contract: contract,
      intervention: "block_action",
      model: "gpt-5-mini",
      cached: false,
      latency_ms: 10,
    }));
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  try {
    const address = server.address();
    assert.ok(address !== null && typeof address === "object");
    const origin = `http://127.0.0.1:${address.port}`;
    await new FileCredentialStore(directory).save({
      machineId,
      tenantId: "7d1b4cb4-a77d-4f53-af66-197e184683f4",
      credential: `phg_m_${"g".repeat(43)}`,
      controlPlaneOrigin: origin,
      createdAt: "2026-09-03T00:00:00.000Z",
    });
    await new FileActionPolicyStore(directory).save(machineId, create(
      ActionGuardrailPolicySchema,
      {
        policyDigest: "a".repeat(64),
        defaultEffect: "allow",
        rules: [create(ActionGuardrailRuleSchema, {
          ruleId,
          action: ManagedAction.FILE_DELETE,
          effect: GuardrailEffect.DENY,
          resourcePattern: "**",
          reason: "Deletion is prohibited by the administrator.",
          sourceText: contract,
        })],
      },
    ));

    const exitCode = await run(
      [
        "authorize-action",
        "--action", "file.delete",
        "--resource", "C:/workspace/important.txt",
        "--agent", "codex:worker",
        "--json",
      ],
      {
        PHIGON_CONTROL_PLANE_URL: origin,
        PHIGON_DATA_DIR: directory,
      },
      {
        stdout: (value) => { stdout += value; },
        stderr: (value) => { stderr += value; },
      },
    );
    assert.equal(exitCode, 77);
    assert.equal(stderr, "");
    assert.equal(requests, 1);
    const decision = JSON.parse(stdout) as {
      outcome: string;
      adminContract: string;
      agentMessage: string;
    };
    assert.equal(decision.outcome, "denied");
    assert.equal(decision.adminContract, contract);
    assert.match(decision.agentMessage, /blocked by Phigon Guardian/u);
    assert.match(decision.agentMessage, new RegExp(contract.replaceAll(".", "\\."), "u"));

    const journal = await readFile(
      join(directory, "bridges", "generic", "guardian-decisions.jsonl"),
      "utf8",
    );
    assert.match(journal, /phigon_guardian_decision/u);
    assert.match(journal, /Do not delete any file/u);
  } finally {
    await new Promise<void>((resolve, reject) => {
      server.close((error) => error ? reject(error) : resolve());
    });
    await rm(directory, { recursive: true, force: true });
  }
});

test("plain-language contracts are decided by hosted Guardian even when the local catch-all matches", async () => {
  const directory = await mkdtemp(join(tmpdir(), "phigon-cli-semantic-contract-"));
  const machineId = "5f1b4cb4-a77d-4f53-af66-197e184683f4";
  const ruleId = "16ae52f1-bb89-4d0f-bd7e-145cc8466c1d";
  let requests = 0;
  const server = createServer((request, response) => {
    requests++;
    assert.equal(request.url, "/v1/machine/guardian/decisions");
    response.writeHead(200, { "Content-Type": "application/json" });
    response.end(JSON.stringify({
      decision: "allow",
      reason: "The read-only command is consistent with the administrator contract.",
      risk: "low",
      confidence: 0.99,
      matched_contract_id: "",
      intervention: "none",
      model: "gpt-5-mini",
      cached: false,
      latency_ms: 12,
    }));
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  try {
    const address = server.address();
    assert.ok(address !== null && typeof address === "object");
    const origin = `http://127.0.0.1:${address.port}`;
    await new FileCredentialStore(directory).save({
      machineId,
      tenantId: "7d1b4cb4-a77d-4f53-af66-197e184683f4",
      credential: `phg_m_${"s".repeat(43)}`,
      controlPlaneOrigin: origin,
      createdAt: "2026-09-05T00:00:00.000Z",
    });
    await new FileActionPolicyStore(directory).save(machineId, create(
      ActionGuardrailPolicySchema,
      {
        policyDigest: "c".repeat(64),
        defaultEffect: "allow",
        rules: [create(ActionGuardrailRuleSchema, {
          ruleId,
          action: ManagedAction.COMMAND_EXECUTE,
          effect: GuardrailEffect.DENY,
          resourcePattern: "**",
          reason: "Interpret the administrator contract at runtime.",
          sourceText: "Do not execute destructive commands.",
        })],
      },
    ));
    let stdout = "";
    let stderr = "";
    const exitCode = await run([
      "authorize-action", "--action", "command.execute",
      "--resource", "git status", "--agent", "codex:worker", "--json",
    ], {
      PHIGON_CONTROL_PLANE_URL: origin,
      PHIGON_DATA_DIR: directory,
    }, {
      stdout: (value) => { stdout += value; },
      stderr: (value) => { stderr += value; },
    });
    assert.equal(exitCode, 0);
    assert.equal(stderr, "");
    assert.equal(requests, 1);
    const decision = JSON.parse(stdout) as { outcome: string; decisionSource: string };
    assert.equal(decision.outcome, "allowed");
    assert.equal(decision.decisionSource, "agentic_guardian");
  } finally {
    await new Promise<void>((resolve, reject) => {
      server.close((error) => error ? reject(error) : resolve());
    });
    await rm(directory, { recursive: true, force: true });
  }
});

test("managed agent launcher checks model policy before creating a process", async () => {
  const directory = await mkdtemp(join(tmpdir(), "phigon-cli-guardian-launch-"));
  const machineId = "5f1b4cb4-a77d-4f53-af66-197e184683f4";
  const marker = join(directory, "agent-started.txt");
  const ruleId = "871ce414-12b9-42a4-88e8-3d30ff2f244d";
  const contract = "Claude Code may not use Opus models on this machine.";
  let stdout = "";
  let stderr = "";
  let requests = 0;
  const server = createServer((_request, response) => {
    if (_request.url?.endsWith("/execution-profile")) { response.setHeader("Content-Type", "application/json"); response.end(JSON.stringify({ sandbox: "", policy_digest: "b".repeat(64) })); return; }
    requests++;
    response.writeHead(200, { "Content-Type": "application/json" });
    response.end(JSON.stringify({ action: "model.use", decision: {
      decision: "deny",
      reason: "This model conflicts with the administrator contract.",
      risk: "high",
      confidence: 0.99,
      matched_contract_id: ruleId,
      admin_contract: contract,
      intervention: "block_action",
      model: "gpt-5-mini",
      cached: false,
      latency_ms: 9,
    } }));
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  try {
    const address = server.address();
    assert.ok(address !== null && typeof address === "object");
    const origin = `http://127.0.0.1:${address.port}`;
    await new FileCredentialStore(directory).save({
      machineId,
      tenantId: "7d1b4cb4-a77d-4f53-af66-197e184683f4",
      credential: `phg_m_${"m".repeat(43)}`,
      controlPlaneOrigin: origin,
      createdAt: "2026-09-05T00:00:00.000Z",
    });
    await new FileActionPolicyStore(directory).save(machineId, create(
      ActionGuardrailPolicySchema,
      {
        policyDigest: "b".repeat(64),
        defaultEffect: "allow",
        rules: [create(ActionGuardrailRuleSchema, {
          ruleId,
          action: ManagedAction.MODEL_USE,
          effect: GuardrailEffect.DENY,
          resourcePattern: "anthropic:claude-opus-*",
          agentPattern: "claude-code:*",
          reason: "Use the approved standard model.",
          sourceText: contract,
        })],
      },
    ));

    const exitCode = await run(
      [
        "guardian", "launch",
        "--agent", "claude-code:worker-1",
        "--model", "anthropic:claude-opus-4-1",
        "--", process.execPath, "-e",
        `require('node:fs').writeFileSync(${JSON.stringify(marker)}, 'started')`,
      ],
      {
        PHIGON_CONTROL_PLANE_URL: origin,
        PHIGON_DATA_DIR: directory,
      },
      {
        stdout: (value) => { stdout += value; },
        stderr: (value) => { stderr += value; },
      },
    );
    assert.equal(exitCode, 77);
    assert.equal(stderr, "");
    assert.equal(requests, 1);
    assert.match(stdout, /Action: model\.use/u);
    assert.match(stdout, /Claude Code may not use Opus models/u);
    await assert.rejects(readFile(marker, "utf8"), { code: "ENOENT" });
    await assert.rejects(
      readFile(join(directory, "bridges", "generic", "guardian-managed-commands.jsonl"), "utf8"),
      { code: "ENOENT" },
    );
  } finally {
    await new Promise<void>((resolve, reject) => {
      server.close((error) => error ? reject(error) : resolve());
    });
    await rm(directory, { recursive: true, force: true });
  }
});

test("managed agent launcher cannot omit the model policy boundary", async () => {
  const directory = await mkdtemp(join(tmpdir(), "phigon-cli-guardian-model-required-"));
  const marker = join(directory, "agent-started.txt");
  let stderr = "";
  try {
    const exitCode = await run([
      "guardian", "launch", "--agent", "agt_claimed", "--",
      process.execPath, "-e",
      `require('node:fs').writeFileSync(${JSON.stringify(marker)}, 'started')`,
    ], { PHIGON_DATA_DIR: directory }, {
      stdout: () => undefined,
      stderr: (value) => { stderr += value; },
    });
    assert.equal(exitCode, 1);
    assert.match(stderr, /requires --model/u);
    await assert.rejects(readFile(marker, "utf8"), { code: "ENOENT" });
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("local approval rule always reaches the hosted exact-approval boundary", async () => {
  const directory = await mkdtemp(join(tmpdir(), "phigon-cli-guardian-approval-"));
  const machineId = "5f1b4cb4-a77d-4f53-af66-197e184683f4";
  const ruleId = "f3303823-6c43-4ad8-9320-ee80c8bd61a2";
  const approvalId = "2a0c7a49-f596-4e13-8bb5-da2921f26547";
  let requests = 0;
  const server = createServer((request, response) => {
    requests++;
    assert.equal(request.method, "POST");
    assert.equal(request.url, "/v1/machine/guardian/decisions");
    response.writeHead(200, { "Content-Type": "application/json" });
    response.end(JSON.stringify({
      decision: "require_approval",
      reason: "An administrator must approve this exact command.",
      risk: "high",
      confidence: 1,
      matched_contract_id: ruleId,
      admin_contract: "Approve source-control commands.",
      intervention: "block_action",
      model: "policy-gateway",
      cached: false,
      latency_ms: 0,
      approval_id: approvalId,
      approval_state: "pending",
      approval_expires_at: "2026-09-04T12:05:00Z",
    }));
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  try {
    const address = server.address();
    assert.ok(address !== null && typeof address === "object");
    const origin = `http://127.0.0.1:${address.port}`;
    await new FileCredentialStore(directory).save({
      machineId,
      tenantId: "7d1b4cb4-a77d-4f53-af66-197e184683f4",
      credential: `phg_m_${"a".repeat(43)}`,
      controlPlaneOrigin: origin,
      createdAt: "2026-09-03T00:00:00.000Z",
    });
    await new FileActionPolicyStore(directory).save(machineId, create(
      ActionGuardrailPolicySchema,
      {
        policyDigest: "a".repeat(64),
        defaultEffect: "allow",
        rules: [create(ActionGuardrailRuleSchema, {
          ruleId,
          action: ManagedAction.COMMAND_EXECUTE,
          effect: GuardrailEffect.REQUIRE_APPROVAL,
          resourcePattern: "git *",
          reason: "Approve source-control commands.",
        })],
      },
    ));

    let stdout = "";
    let stderr = "";
    const exitCode = await run(
      [
        "authorize-action",
        "--action", "command.execute",
        "--resource", "git push origin main",
        "--agent", "codex:worker",
        "--json",
      ],
      {
        PHIGON_CONTROL_PLANE_URL: origin,
        PHIGON_DATA_DIR: directory,
      },
      {
        stdout: (value) => { stdout += value; },
        stderr: (value) => { stderr += value; },
      },
    );
    assert.equal(exitCode, 77);
    assert.equal(stderr, "");
    assert.equal(requests, 1);
    const decision = JSON.parse(stdout) as {
      outcome: string;
      approvalId: string;
      approvalState: string;
      adminContract: string;
    };
    assert.equal(decision.outcome, "approval_required");
    assert.equal(decision.approvalId, approvalId);
    assert.equal(decision.approvalState, "pending");
    assert.equal(decision.adminContract, "Approve source-control commands.");
  } finally {
    await new Promise<void>((resolve, reject) => {
      server.close((error) => error ? reject(error) : resolve());
    });
    await rm(directory, { recursive: true, force: true });
  }
});

test("doctor reports the stored stream cursor without exposing credentials", async () => {
  const directory = await mkdtemp(join(tmpdir(), "phigon-cli-doctor-"));
  const machineId = "machine-doctor-1";
  const credential = ["phg", "m", "fixture-doctor-credential"].join("_");
  let stdout = "";
  let stderr = "";
  try {
    await new FileCredentialStore(directory).save({
      machineId,
      tenantId: "tenant-doctor-1",
      credential,
      controlPlaneOrigin: "https://control.example.test",
      createdAt: "2026-07-24T00:00:00.000Z",
    });
    await new StreamStateStore(directory).save(machineId, 42n);

    const exitCode = await run(
      ["doctor", "--json"],
      {
        PHIGON_CONTROL_PLANE_URL: "https://control.example.test",
        PHIGON_DATA_DIR: directory,
      },
      {
        stdout: (value) => {
          stdout += value;
        },
        stderr: (value) => {
          stderr += value;
        },
      },
    );

    assert.equal(exitCode, 0);
    assert.equal(stderr, "");
    const health = JSON.parse(stdout) as {
      machineTokenConfigured?: boolean;
      streamCursor?: {
        machineId?: string;
        acknowledgedSequence?: string;
        updatedAt?: string;
      };
    };
    assert.equal(health.machineTokenConfigured, true);
    assert.equal(health.streamCursor?.machineId, machineId);
    assert.equal(health.streamCursor?.acknowledgedSequence, "42");
    assert.match(health.streamCursor?.updatedAt ?? "", /^\d{4}-/u);
    assert.doesNotMatch(stdout, new RegExp(credential, "u"));
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("doctor reports a broken stream cursor without failing", async () => {
  const directory = await mkdtemp(join(tmpdir(), "phigon-cli-doctor-"));
  const machineId = "machine-doctor-2";
  const credential = ["phg", "m", "fixture-doctor-credential"].join("_");
  let stdout = "";
  let stderr = "";
  try {
    await new FileCredentialStore(directory).save({
      machineId,
      tenantId: "tenant-doctor-2",
      credential,
      controlPlaneOrigin: "https://control.example.test",
      createdAt: "2026-07-24T00:00:00.000Z",
    });
    await writeFile(join(directory, "stream-state.json"), "not json\n", {
      encoding: "utf8",
      mode: 0o600,
    });

    const exitCode = await run(
      ["doctor", "--json"],
      {
        PHIGON_CONTROL_PLANE_URL: "https://control.example.test",
        PHIGON_DATA_DIR: directory,
      },
      {
        stdout: (value) => {
          stdout += value;
        },
        stderr: (value) => {
          stderr += value;
        },
      },
    );

    assert.equal(exitCode, 0);
    assert.equal(stderr, "");
    const health = JSON.parse(stdout) as {
      machineTokenConfigured?: boolean;
      streamCursor?: unknown;
      streamCursorIssue?: string;
    };
    assert.equal(health.machineTokenConfigured, true);
    assert.equal(health.streamCursor, undefined);
    assert.equal(
      health.streamCursorIssue,
      "Stored stream cursor could not be read.",
    );
    assert.doesNotMatch(stdout, new RegExp(credential, "u"));
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("unknown commands fail with actionable usage", async () => {
  let stderr = "";
  const exitCode = await run(
    ["observe"],
    {},
    {
      stdout: () => undefined,
      stderr: (value) => {
        stderr += value;
      },
    },
  );

  assert.equal(exitCode, 2);
  assert.match(stderr, /Unknown command: observe/);
  assert.match(stderr, /phigon-observer doctor/);
});

test("ingest command accepts exact Cursor NDJSON without printing content", async () => {
  const directory = await mkdtemp(join(tmpdir(), "phigon-cli-ingest-"));
  let stdout = "";
  let stderr = "";
  try {
    const exitCode = await run(
      ["ingest", "--agent", "cursor", "--json"],
      { PHIGON_DATA_DIR: directory },
      {
        stdout: (value) => {
          stdout += value;
        },
        stderr: (value) => {
          stderr += value;
        },
      },
      Readable.from([
        `${JSON.stringify({
          type: "user",
          message: { role: "user", content: "private prompt" },
        })}\n`,
      ]),
    );
    assert.equal(exitCode, 0);
    assert.equal(stderr, "");
    assert.match(stdout, /"records": 1/u);
    assert.doesNotMatch(stdout, /private prompt/u);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("ingest registers any custom agent without a hardcoded bridge", async () => {
  const directory = await mkdtemp(join(tmpdir(), "phigon-cli-custom-"));
  let stdout = "";
  let stderr = "";
  try {
    const exitCode = await run(
      ["ingest", "--agent", "custom", "--name", "Local Build Bot", "--json"],
      { PHIGON_DATA_DIR: directory },
      {
        stdout: (value) => {
          stdout += value;
        },
        stderr: (value) => {
          stderr += value;
        },
      },
      Readable.from([
        `${JSON.stringify({
          type: "message",
          role: "assistant",
          content: "private custom response",
        })}\n`,
      ]),
    );
    assert.equal(exitCode, 0);
    assert.equal(stderr, "");
    const result = JSON.parse(stdout) as {
      agent?: string;
      agentName?: string;
      records?: number;
    };
    assert.deepEqual(result, {
      agent: "generic",
      agentName: "Local Build Bot",
      records: 1,
      malformed: 0,
      oversized: 0,
    });
    const bridgeDirectory = join(directory, "bridges", "generic");
    const files = await readdir(bridgeDirectory);
    assert.equal(files.length, 1);
    const stored = await readFile(join(bridgeDirectory, files[0] ?? ""), "utf8");
    assert.match(stored, /"phigon_agent_name":"Local Build Bot"/u);
    assert.doesNotMatch(stdout, /private custom response/u);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("agent commands manage dynamic monitoring definitions with readable output", async () => {
  const directory = await mkdtemp(join(tmpdir(), "phigon-cli-agents-"));
  const environment = {
    PHIGON_CONTROL_PLANE_URL: "https://control.example.test",
    PHIGON_DATA_DIR: directory,
  };
  try {
    let stdout = "";
    let stderr = "";
    const added = await run(
      [
        "agent",
        "add",
        "--id",
        "release-bot",
        "--name",
        "Release Bot",
        "--process",
        "release-bot",
        "--activity-dir",
        "~/.release-bot/sessions",
        "--json",
      ],
      environment,
      {
        stdout: (value) => {
          stdout += value;
        },
        stderr: (value) => {
          stderr += value;
        },
      },
    );
    assert.equal(added, 0);
    assert.equal(stderr, "");
    assert.deepEqual(JSON.parse(stdout), {
      status: "added",
      agent: {
        id: "release-bot",
        displayName: "Release Bot",
        executableNames: [],
        processNames: ["release-bot"],
        configurationPaths: [],
        activityDirectories: ["~/.release-bot/sessions"],
        capabilities: ["activity"],
      },
    });

    stdout = "";
    const listed = await run(
      ["agent", "list"],
      environment,
      {
        stdout: (value) => {
          stdout += value;
        },
        stderr: (value) => {
          stderr += value;
        },
      },
    );
    assert.equal(listed, 0);
    assert.match(stdout, /Custom agents: 1/u);
    assert.match(stdout, /Release Bot \(release-bot\): process, activity/u);

    stdout = "";
    const removed = await run(
      ["agent", "remove", "--id", "release-bot", "--yes", "--json"],
      environment,
      {
        stdout: (value) => {
          stdout += value;
        },
        stderr: (value) => {
          stderr += value;
        },
      },
    );
    assert.equal(removed, 0);
    assert.equal(JSON.parse(stdout).status, "removed");
    assert.deepEqual(await new CustomAgentRegistry(directory).list(), []);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("remove-machine unregisters the paired machine before clearing its credential", async () => {
  const directory = await mkdtemp(join(tmpdir(), "phigon-cli-remove-"));
  const credential = `phg_m_${"r".repeat(43)}`;
  let authorization = "";
  let method = "";
  const server = createServer((request, response) => {
    authorization = request.headers.authorization ?? "";
    method = request.method ?? "";
    assert.equal(request.url, "/v1/machine");
    response.writeHead(204);
    response.end();
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  try {
    const address = server.address();
    assert.ok(address !== null && typeof address === "object");
    const origin = `http://127.0.0.1:${address.port}`;
    const store = new FileCredentialStore(directory);
    await store.save({
      machineId: "machine-remove-1",
      tenantId: "tenant-remove-1",
      credential,
      controlPlaneOrigin: origin,
      createdAt: "2026-08-09T00:00:00.000Z",
    });
    const spoolPath = join(directory, "telemetry-spool.jsonl");
    const spoolTemporaryPath = `${spoolPath}.123.fixture.tmp`;
    await writeFile(spoolPath, "encrypted fixture\n", "utf8");
    await writeFile(spoolTemporaryPath, "encrypted fixture\n", "utf8");
    let stdout = "";
    let stderr = "";
    const exitCode = await run(
      ["remove-machine", "--yes", "--json"],
      {
        PHIGON_CONTROL_PLANE_URL: origin,
        PHIGON_DATA_DIR: directory,
      },
      {
        stdout: (value) => {
          stdout += value;
        },
        stderr: (value) => {
          stderr += value;
        },
      },
    );
    assert.equal(exitCode, 0);
    assert.equal(stderr, "");
    assert.equal(method, "DELETE");
    assert.equal(authorization, `Bearer ${credential}`);
    assert.equal(await store.load(), null);
    await assert.rejects(readFile(spoolPath, "utf8"), (error: unknown) =>
      error instanceof Error && "code" in error && error.code === "ENOENT");
    await assert.rejects(
      readFile(spoolTemporaryPath, "utf8"),
      (error: unknown) =>
        error instanceof Error && "code" in error && error.code === "ENOENT",
    );
    assert.deepEqual(JSON.parse(stdout), {
      status: "removed",
      machineId: "machine-remove-1",
      controlPlaneOrigin: origin,
      credentialRemoved: true,
    });
  } finally {
    await new Promise<void>((resolve, reject) => {
      server.close((error) => error ? reject(error) : resolve());
    });
    await rm(directory, { recursive: true, force: true });
  }
});

test("remove-machine keeps the local credential when the control plane fails", async () => {
  const directory = await mkdtemp(join(tmpdir(), "phigon-cli-remove-"));
  const credential = `phg_m_${"f".repeat(43)}`;
  const server = createServer((_request, response) => {
    response.writeHead(503, { "Content-Type": "application/json" });
    response.end(JSON.stringify({
      error: { message: "Machine removal is temporarily unavailable." },
    }));
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  try {
    const address = server.address();
    assert.ok(address !== null && typeof address === "object");
    const origin = `http://127.0.0.1:${address.port}`;
    const store = new FileCredentialStore(directory);
    await store.save({
      machineId: "machine-remove-2",
      tenantId: "tenant-remove-2",
      credential,
      controlPlaneOrigin: origin,
      createdAt: "2026-08-09T00:00:00.000Z",
    });
    let stderr = "";
    const exitCode = await run(
      ["remove-machine", "--yes", "--json"],
      {
        PHIGON_CONTROL_PLANE_URL: origin,
        PHIGON_DATA_DIR: directory,
      },
      {
        stdout: () => undefined,
        stderr: (value) => {
          stderr += value;
        },
      },
    );
    assert.equal(exitCode, 1);
    assert.match(stderr, /temporarily unavailable/u);
    assert.match(stderr, /local credential was kept/u);
    assert.equal((await store.load())?.credential, credential);
    assert.doesNotMatch(stderr, new RegExp(credential, "u"));
  } finally {
    await new Promise<void>((resolve, reject) => {
      server.close((error) => error ? reject(error) : resolve());
    });
    await rm(directory, { recursive: true, force: true });
  }
});

test(
  "npm bin symlinks are recognized as CLI entry points",
  { skip: process.platform === "win32" },
  async () => {
    const directory = await mkdtemp(join(tmpdir(), "phigon-cli-test-"));
    const link = join(directory, "phigon-observer");
    const cli = fileURLToPath(new URL("../src/cli.js", import.meta.url));
    try {
      await symlink(cli, link);
      assert.equal(isCliEntryPoint(link), true);
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  },
);

test("observer task coordination propagates acknowledgement persistence failures", async () => {
  const controller = new AbortController();
  const persistenceError = new Error("cursor store is read-only");

  await assert.rejects(
    settleObserverTasks(
      [Promise.resolve(), Promise.resolve(), Promise.resolve()],
      controller,
      () => persistenceError,
    ),
    /cursor store is read-only/u,
  );
  assert.equal(controller.signal.aborted, true);
});
