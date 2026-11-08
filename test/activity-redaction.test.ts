import assert from "node:assert/strict";
import { createHash, createHmac } from "node:crypto";
import { mkdtemp, readFile, rm, stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { clineExtensionActivityAdapter } from "../src/activity/adapters/cline-task.js";
import { identifierKeyFileName, loadIdentifierKey } from "../src/activity/identifier-key.js";
import { toolDrafts } from "../src/activity/normalize.js";
import { LocalPolicyEngine } from "../src/activity/policy.js";
import { credentialFieldName } from "../src/content-redaction.js";
import { loadConfig } from "../src/config.js";
import { AgentKind } from "../src/generated/phigon/v1/common_pb.js";
import { ToolPhase } from "../src/generated/phigon/v1/telemetry_pb.js";
import { loadContentConfig } from "./content-config.js";

// Token-shaped values are assembled at runtime so secret scanners do not
// flag this file.
const githubToken = ["gh", "p_", "Q".repeat(20), "7".repeat(16)].join("");
const metadata = () => new LocalPolicyEngine(loadConfig({}).policy);

function executable(command: unknown, policy = metadata()): string {
  const drafts = toolDrafts(AgentKind.GENERIC, {
    sessionId: "session-redaction",
    observedAt: new Date("2026-11-08T10:00:00.000Z"),
    policy,
  }, {
    invocationId: "call_1",
    toolName: "shell",
    phase: ToolPhase.REQUESTED,
    arguments: { command },
  });
  const terminal = drafts.find((draft) => draft.payload.case === "terminal");
  assert.ok(terminal?.payload.case === "terminal");
  return terminal.payload.value.executable;
}

test("a command's program name skips assignments and wrappers and never carries a secret", () => {
  for (const [command, expected] of [
    [`GITHUB_TOKEN=${githubToken} gh pr create`, "gh"],
    [`GITHUB_TOKEN="${githubToken}" OTHER='a b' git push`, "git"],
    [`env -u HOME API_KEY=${githubToken} /usr/bin/python3 tool.py`, "python3"],
    [`sudo -E -u root nice -n 5 nohup command time -p npm test`, "npm"],
    [`timeout -s KILL 30s git status`, "git"],
    [`/usr/bin/env node script.js`, "node"],
    [`$env:GITHUB_TOKEN="${githubToken}"; gh pr view`, "gh"],
    [`export TOKEN=${githubToken}; TOKEN2=x && cargo build`, "export"],
    [`TOKEN=${githubToken}; cargo build`, "cargo"],
    [`"C:\\Program Files\\nodejs\\node.exe" app.js`, "node.exe"],
    [`C:\\tools\\git.exe status`, "git.exe"],
    ["env", "env"],
    ["bash -lc 'git status'", "bash"],
  ] as const) {
    const name = executable(command);
    assert.equal(name, expected, command.replace(githubToken, "<token>"));
  }
  // A program word that is itself a secret is never sent.
  for (const command of [`${githubToken} --help`, `"${githubToken}"`, `TOKEN=x ${githubToken}`]) {
    const name = executable(command);
    assert.equal(name, "unknown");
  }
});

test("names fall back when they held a secret or a private path", () => {
  const policy = new LocalPolicyEngine(loadConfig({}).policy, ["/private/project"]);
  assert.equal(policy.safeName(`TOKEN=${githubToken}`, "fallback"), "fallback");
  assert.equal(policy.safeName(githubToken, "fallback"), "fallback");
  assert.equal(policy.safeName("postgres://admin:hunter2pass@db.internal/app", "fallback"), "fallback");
  assert.equal(policy.safeName("/private/project/tool", "fallback"), "fallback");
  assert.equal(policy.safeName("x".repeat(2_000), "fallback"), "fallback");
  assert.equal(policy.safeName("mcp__github__create_pull_request", "fallback"), "mcp__github__create_pull_request");
  assert.equal(policy.safeName("call_AbC123-xyz", "fallback"), "call_AbC123-xyz");
  assert.equal(policy.safeName("read file", "fallback"), "read-file");

  const drafts = toolDrafts(AgentKind.GENERIC, {
    sessionId: "session-redaction",
    observedAt: new Date("2026-11-08T10:00:00.000Z"),
    policy,
  }, {
    invocationId: `id-${githubToken}`,
    toolName: `tool ${githubToken}`,
    phase: ToolPhase.REQUESTED,
  });
  const tool = drafts.find((draft) => draft.payload.case === "tool");
  assert.ok(tool?.payload.case === "tool");
  assert.equal(tool.payload.value.toolName, "unknown-tool");
  assert.match(tool.payload.value.invocationId, /^inv_[0-9a-f]{24}$/u);
});

test("a name that holds a folder path is sent only where paths are collected", () => {
  const policy = metadata();
  for (const name of [
    "/home/alice/bin/deploy", "server__/home/alice/x", "C:\\tools\\payroll.exe", "tool ~/notes/plan", "\\\\fileserver\\share",
    // Embedded anywhere in the name.
    "session-/home/alice/proj", "run against db.payroll.internal:5432", "call-10.0.0.7:8080",
  ]) {
    assert.equal(policy.safeName(name, "fallback"), "fallback", name);
  }
  for (const name of [
    "github/create_issue", "/compact", "functions.exec_command", "mcp-resource:file",
    "anthropic/claude-3.5-sonnet", "guardian:codex-worker", "2026-11-08T10:00:00.000Z", "call_abc-123",
  ]) {
    assert.notEqual(policy.safeName(name, "fallback"), "fallback", name);
  }
  const full = new LocalPolicyEngine(loadConfig({ PHIGON_OBSERVABILITY_PROFILE: "full" }).policy);
  assert.equal(full.safeName("/home/alice/bin/deploy", "fallback"), "/home/alice/bin/deploy");

  const drafts = toolDrafts(AgentKind.GENERIC, {
    sessionId: "session-path-name",
    observedAt: new Date("2026-11-08T10:00:00.000Z"),
    policy,
  }, {
    invocationId: "call_path",
    toolName: "/home/alice/scripts/deploy.sh",
    phase: ToolPhase.REQUESTED,
  });
  const tool = drafts.find((draft) => draft.payload.case === "tool");
  assert.ok(tool?.payload.case === "tool");
  assert.equal(tool.payload.value.toolName, "unknown-tool");
  assert.doesNotMatch(JSON.stringify(drafts, (_key, value: unknown) => typeof value === "bigint" ? value.toString() : value), /alice/u);
});

test("an MCP resource address is never sent as a tool name", () => {
  const password = "q".repeat(14);
  const drafts = clineExtensionActivityAdapter.parse({
    ts: 1_762_600_000_000,
    type: "ask",
    ask: "use_mcp_server",
    text: JSON.stringify({
      type: "access_mcp_resource",
      serverName: "postgres",
      uri: `postgres://admin:${password}@db.internal.example:5432/app`,
    }),
  }, {
    sessionId: "session-mcp",
    observedAt: new Date("2026-11-08T10:00:00.000Z"),
    policy: metadata(),
  });
  const tool = drafts.find((draft) => draft.payload.case === "tool");
  assert.ok(tool?.payload.case === "tool");
  assert.equal(tool.payload.value.toolName, "postgres__mcp-resource:postgres");
  const serialized = JSON.stringify(drafts, (_key, value: unknown) => typeof value === "bigint" ? value.toString() : value);
  assert.doesNotMatch(serialized, /db\.internal|admin|qqqqqqqq/u);

  // Any name that holds an address keeps only its scheme.
  assert.equal(metadata().safeName("server__https://intranet.example/files/plan", "tool"), "server__https");
  assert.equal(metadata().safeName("file:///home/someone/notes.md", "tool"), "file");
});

test("tool output JSON hides .env contents exactly as terminal output does, and stays valid JSON", () => {
  const policy = new LocalPolicyEngine(loadConfig({ PHIGON_OBSERVABILITY_PROFILE: "full" }).policy);
  const values = ["plainapivalue1", "hunter2hunter2", "correcthorse99", githubToken];
  const dotenv = [
    `API_KEY=${values[0]}`,
    `PASSWORD="${values[1]}"`,
    `DB_PASSWORD='${values[2]}'`,
    `GITHUB_TOKEN=${values[3]}`,
    "NODE_ENV=production",
  ].join("\n");
  const drafts = toolDrafts(AgentKind.GENERIC, {
    sessionId: "session-dotenv",
    observedAt: new Date("2026-11-08T10:00:00.000Z"),
    policy,
  }, {
    invocationId: "call_env",
    toolName: "shell",
    phase: ToolPhase.SUCCEEDED,
    arguments: { command: "cat .env" },
    output: { stdout: dotenv, exit_code: 0 },
  });
  const tool = drafts.find((draft) => draft.payload.case === "tool");
  const terminal = drafts.find((draft) => draft.payload.case === "terminal");
  assert.ok(tool?.payload.case === "tool" && tool.payload.value.output !== undefined);
  assert.ok(terminal?.payload.case === "terminal" && terminal.payload.value.output !== undefined);
  const output = JSON.parse(tool.payload.value.output);
  assert.match(output.stdout, /NODE_ENV=production/u);
  assert.equal(tool.payload.value.outputRedacted, true);
  const terminalText = Buffer.from(terminal.payload.value.output).toString("utf8");
  for (const value of values) {
    assert.ok(!tool.payload.value.output.includes(value), "tool output kept a secret");
    assert.ok(!terminalText.includes(value), "terminal output kept a secret");
  }

  for (const input of [dotenv, [dotenv], { nested: { text: dotenv } }]) {
    const result = policy.json(input, "toolOutput");
    assert.ok(result.value !== undefined);
    assert.doesNotThrow(() => JSON.parse(result.value ?? ""));
    for (const value of values) assert.ok(!result.value.includes(value));
  }
});

test("values under credential-named keys are masked whatever their type, and JSON stays valid", () => {
  const policy = new LocalPolicyEngine(loadConfig({ PHIGON_OBSERVABILITY_PROFILE: "full" }).policy);
  const result = policy.json({
    token: "x",
    accessToken: 48_151_623_420,
    nested: { password: 123_456_789, "x-api-key": "plainheader" },
    credentials: { user: "someone", value: "plaincredential" },
    [`key-${githubToken}`]: true,
    password_set: true,
    refresh_token: "",
    max_tokens: 100,
    tokenCount: 5,
    note: "token=",
  }, "toolOutput");
  assert.ok(result.value !== undefined);
  const parsed = JSON.parse(result.value);
  assert.equal(parsed.token, "[REDACTED_SECRET]");
  assert.equal(parsed.accessToken, "[REDACTED_SECRET]");
  assert.equal(parsed.nested.password, "[REDACTED_SECRET]");
  assert.equal(parsed.nested["x-api-key"], "[REDACTED_SECRET]");
  assert.deepEqual(parsed.credentials, { user: "[REDACTED_SECRET]", value: "[REDACTED_SECRET]" });
  assert.equal(parsed["[REDACTED_SECRET]"], true);
  assert.equal(parsed.password_set, true);
  assert.equal(parsed.refresh_token, "");
  assert.equal(parsed.max_tokens, 100);
  assert.equal(parsed.tokenCount, 5);
  assert.equal(result.redacted, true);
  assert.doesNotMatch(result.value, /48151623420|123456789|plainheader|plaincredential|someone/u);
  assert.ok(!result.value.includes(githubToken));

  // Running the policy again on its own output changes nothing, as when
  // queued events are checked against a newer policy.
  const again = policy.json(parsed, "toolOutput");
  assert.deepEqual(JSON.parse(again.value ?? ""), parsed);

  const content = policy.content({ role: "tool", text: `PASSWORD="${"hunter2hunter2"}"\nB=1` }, "toolOutput");
  assert.ok(content.value !== undefined);
  assert.ok(!content.value.includes("hunter2hunter2"));
  assert.doesNotThrow(() => JSON.parse(content.value ?? ""));
});

test("a tool result the structure bounds shortened is reported as truncated", () => {
  const policy = new LocalPolicyEngine(loadConfig({ PHIGON_OBSERVABILITY_PROFILE: "full" }).policy);
  let deep: unknown = "bottom";
  for (let depth = 0; depth < 10; depth++) deep = { level: deep };
  for (const [name, value] of [
    ["items", Array.from({ length: 300 }, (_, index) => index)],
    ["keys", Object.fromEntries(Array.from({ length: 200 }, (_, index) => [`key${index}`, index]))],
    ["string", { stdout: "y ".repeat(40_000) }],
    ["key", { [`k${"e".repeat(200)}`]: 1 }],
    ["depth", deep],
  ] as const) {
    const result = policy.json(value, "toolOutput");
    assert.ok(result.value !== undefined, name);
    assert.equal(result.truncated, true, name);
    assert.ok(Buffer.byteLength(result.value) <= 128 << 10, name);
    assert.equal(policy.content(value, "toolOutput").truncated, true, name);
  }
  assert.equal(policy.json({ items: [1, 2, 3], stdout: "complete" }, "toolOutput").truncated, false);

  const drafts = toolDrafts(AgentKind.GENERIC, {
    sessionId: "session-bounds",
    observedAt: new Date("2026-11-08T10:00:00.000Z"),
    policy,
  }, {
    invocationId: "call_list",
    toolName: "list_files",
    phase: ToolPhase.SUCCEEDED,
    output: Array.from({ length: 300 }, (_, index) => `file${index}.ts`),
  });
  const tool = drafts.find((draft) => draft.payload.case === "tool");
  assert.ok(tool?.payload.case === "tool");
  assert.ok(tool.payload.value.output !== undefined);
  assert.equal(tool.payload.value.outputRedacted, true);
});

test("text is redacted before it is cut to its limit", () => {
  const policy = new LocalPolicyEngine(loadContentConfig({
    PHIGON_COLLECT_TOOL_OUTPUT: "true",
    PHIGON_COLLECT_TERMINAL_OUTPUT: "true",
    PHIGON_COLLECT_VENDOR_PAYLOAD: "true",
  }).policy);
  const password = "hunterpass";
  const secrets = [
    `postgres://admin:${password}@db.internal/app`,
    `Server=db;Pwd=${password};`,
    `DB_PASSWORD=${password}`,
  ];
  for (const secret of secrets) {
    for (const [limit, check] of [
      [64 << 10, (text: string) => policy.json({ stdout: text }, "toolOutput").value ?? ""],
      [256 << 10, (text: string) => policy.vendorRecord({ type: "tool_result", output: text }).value ?? ""],
    ] as const) {
      // The limit falls at points throughout the credential; the corpus test
      // tries every point with smaller limits.
      for (let cut = 1; cut < secret.length; cut += 4) {
        const text = `${"x".repeat(limit - cut - 1)} ${secret} tail`;
        const output = check(text);
        assert.ok(output.length > 0);
        assert.ok(!output.includes(password.slice(0, 4)), `${secret} cut at ${cut} kept part of the password`);
      }
    }
  }
});

test("withheld paths and addresses are sent as keyed digests that guesses cannot match", async () => {
  const directory = await mkdtemp(join(tmpdir(), "phigon-identifier-key-"));
  try {
    const key = loadIdentifierKey(directory);
    const stored = (await readFile(join(directory, identifierKeyFileName), "utf8")).trim();
    assert.match(stored, /^[0-9a-f]{64}$/u);
    assert.equal(key.toString("hex"), stored);
    // The same key on every later start.
    assert.deepEqual(loadIdentifierKey(directory), key);
    if (process.platform !== "win32") {
      assert.equal((await stat(join(directory, identifierKeyFileName))).mode & 0o777, 0o600);
    }
    // No data directory: a key for this process, and nothing created.
    const missing = join(directory, "missing");
    assert.equal(loadIdentifierKey(missing).length, 32);
    await assert.rejects(stat(missing), { code: "ENOENT" });

    const path = "/home/someone/projects/payroll/src/main.ts";
    const policy = new LocalPolicyEngine(loadConfig({}).policy, [], undefined, key);
    const drafts = toolDrafts(AgentKind.GENERIC, {
      sessionId: "session-digest",
      observedAt: new Date("2026-11-08T10:00:00.000Z"),
      policy,
    }, {
      invocationId: "call_read",
      toolName: "read_file",
      phase: ToolPhase.REQUESTED,
      arguments: { path, cwd: "/home/someone/projects/payroll", command: "git status" },
    });
    const plain = (value: string) => createHash("sha256").update(value).digest("hex");
    const file = drafts.find((draft) => draft.payload.case === "filesystem");
    assert.ok(file?.payload.case === "filesystem");
    const resource = file.payload.value.resource;
    assert.equal(resource?.identifier, undefined);
    assert.equal(resource?.identifierDigest, createHmac("sha256", key).update(path).digest("hex"));
    assert.notEqual(resource?.identifierDigest, plain(path));
    const git = drafts.find((draft) => draft.payload.case === "git");
    assert.ok(git?.payload.case === "git");
    assert.notEqual(git.payload.value.repositoryDigest, plain("/home/someone/projects/payroll"));
    assert.equal(git.payload.value.repositoryDigest, policy.digestIdentifier("/home/someone/projects/payroll"));

    const record = { type: "user", message: "yes" };
    assert.notEqual(policy.vendorRecord(record).digest, plain(JSON.stringify(record)));
    // Another computer's key gives other digests.
    const other = new LocalPolicyEngine(loadConfig({}).policy);
    assert.notEqual(other.identifier(path, "filePaths").digest, policy.identifier(path, "filePaths").digest);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("camelCase and hyphenated field names that hold credentials are masked", () => {
  for (const name of [
    "accessToken", "clientSecret", "x-api-key", "refreshToken", "apiKey", "APIKey", "XApiKey",
    "idToken", "X-Amz-Security-Token", "Set-Cookie", "Proxy-Authorization", "client_secret",
    "password", "dbPassword", "authorization", "privateKey", "sessionToken", "cookies", "secrets",
  ]) {
    assert.equal(credentialFieldName(name), true, name);
  }
  for (const name of [
    "max_tokens", "maxTokens", "tokenCount", "token_count", "input_tokens", "primaryKey",
    "cacheKey", "publicKey", "sortKey", "sessionId", "keyId", "monkey", "hotkey", "tokenizer", "authType",
  ]) {
    assert.equal(credentialFieldName(name), false, name);
  }

  const config = loadContentConfig({
    PHIGON_COLLECT_COMMAND_ARGUMENTS: "true",
    PHIGON_COLLECT_VENDOR_PAYLOAD: "true",
  });
  const result = new LocalPolicyEngine(config.policy).vendorRecord({
    type: "function_call",
    arguments: {
      accessToken: 48_151_623_420,
      clientSecret: "plainclientvalue",
      "x-api-key": "plainheadervalue",
      refreshToken: { value: "plainrefreshvalue" },
      tokenCount: 5,
      maxTokens: 4096,
    },
  });
  assert.ok(result.value !== undefined);
  const payload = JSON.parse(result.value);
  for (const name of ["accessToken", "clientSecret", "x-api-key", "refreshToken"]) {
    assert.equal(payload.arguments[name], "[REDACTED_SECRET]", name);
    assert.ok(result.redactedFields.includes(`arguments.${name}`), name);
  }
  assert.equal(payload.arguments.tokenCount, 5);
  assert.equal(payload.arguments.maxTokens, 4096);
  assert.doesNotMatch(result.value, /48151623420|plainclientvalue|plainheadervalue|plainrefreshvalue/u);
});
