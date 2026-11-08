import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { mkdtemp, readFile, readdir, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Readable } from "node:stream";
import test from "node:test";
import { createOpenAICompatibleAdapter } from "../src/activity/adapters/openai-compatible.js";
import { openCodeActivityAdapter } from "../src/activity/adapters/opencode.js";
import { ingestActivityJSONL } from "../src/activity/ingest.js";
import { LocalPolicyEngine } from "../src/activity/policy.js";
import type { ActivityDraft, VendorActivityAdapter } from "../src/activity/types.js";
import { SegmentedJournal, guardianDecisionJournal, managedCommandJournal } from "../src/bridge-journal.js";
import { loadConfig } from "../src/config.js";
import { credentialFieldName } from "../src/content-redaction.js";
import { FileCredentialStore } from "../src/credential-store.js";
import { AgentKind } from "../src/generated/phigon/v1/common_pb.js";
import { writeServiceSettings } from "../src/service.js";

// Token-shaped values are assembled at runtime so secret scanners do not
// flag this file.
const githubToken = ["gh", "p_", "Z".repeat(20), "4".repeat(16)].join("");
const leaks = [githubToken, "payroll", "someone", "intranet", "plainapivalue1", "hunter2hunter2", "Deploy", "fixturesecret", "Rate limit"];

const records: readonly unknown[] = [
  { type: "session_start", session_id: "ses-bridge", timestamp: "2026-11-08T10:00:00.000Z" },
  { type: "message", session_id: "ses-bridge", message: { role: "user", content: `Deploy the payroll service with ${githubToken}` } },
  {
    type: "message",
    session_id: "ses-bridge",
    message: {
      role: "assistant",
      content: "Running it.",
      tool_calls: [
        {
          id: "call_push",
          type: "function",
          function: {
            name: "shell",
            arguments: JSON.stringify({
              command: `GITHUB_TOKEN=${githubToken} git -C /home/someone/payroll push origin main`,
              cwd: "/home/someone/payroll",
            }),
          },
        },
        { id: "call_read", type: "function", function: { name: "read_file", arguments: JSON.stringify({ path: "/home/someone/payroll/.env" }) } },
        { id: "call_open", type: "function", function: { name: "browser_navigate", arguments: JSON.stringify({ url: "https://intranet.example/payroll?user=someone" }) } },
        { id: "call_argv", type: "function", function: { name: "exec", arguments: { argv: ["bash", "-lc", "git status --short /home/someone/payroll"] } } },
      ],
    },
  },
  { type: "message", session_id: "ses-bridge", message: { role: "tool", tool_call_id: "call_read", content: "API_KEY=plainapivalue1\nDB_PASSWORD=hunter2hunter2" } },
  { type: "error", session_id: "ses-bridge", message: "Rate limit reached for /home/someone/payroll" },
  { type: "session_end", session_id: "ses-bridge" },
];

/** Drafts without the digests, which differ by design once paths are stored as digests. */
function comparable(drafts: readonly ActivityDraft[]): unknown {
  return JSON.parse(JSON.stringify(drafts, (key, value: unknown) =>
    /Digest$/u.test(key) ? undefined : typeof value === "bigint" ? value.toString() : value));
}

function parseAll(adapter: VendorActivityAdapter, lines: readonly unknown[]): ActivityDraft[] {
  const context = {
    sessionId: "ses-bridge",
    observedAt: new Date("2026-11-08T10:00:00.000Z"),
    policy: new LocalPolicyEngine(loadConfig({}).policy),
  };
  return lines.flatMap((line) => adapter.parse(line, context));
}

async function storedLines(directory: string, agent: string): Promise<{ text: string; values: unknown[] }> {
  const root = join(directory, "bridges", agent);
  let text = "";
  for (const name of (await readdir(root)).sort()) text += await readFile(join(root, name), "utf8");
  return { text, values: text.trim().split("\n").map((line) => JSON.parse(line) as unknown) };
}

async function consent(directory: string, profile: "metadata" | "full"): Promise<void> {
  await new FileCredentialStore(directory).save({
    machineId: randomUUID(),
    tenantId: randomUUID(),
    credential: `phg_m_${"0".repeat(43)}`,
    controlPlaneOrigin: "http://127.0.0.1:8080",
    createdAt: "2026-11-08T00:00:00.000Z",
    consentProfile: profile,
    consentPolicyVersion: "observer-policy-v1",
    consentedAt: "2026-11-08T00:00:00.000Z",
  });
}

test("without full consent a bridge file keeps only what the metadata profile reads", async () => {
  const directory = await mkdtemp(join(tmpdir(), "phigon-bridge-metadata-"));
  try {
    for (const setup of [
      async () => undefined,
      async () => consent(directory, "metadata"),
    ]) {
      await rm(join(directory, "bridges"), { recursive: true, force: true });
      await setup();
      const result = await ingestActivityJSONL({
        agent: "cursor",
        dataDirectory: directory,
        input: Readable.from(records.map((record) => `${JSON.stringify(record)}\n`)),
      });
      assert.equal(result.records, records.length);
      const stored = await storedLines(directory, "cursor");
      for (const leak of leaks) assert.ok(!stored.text.includes(leak), `bridge file kept ${leak}`);

      // The collector finds the same metadata in the stored records as in
      // the records the agent wrote.
      const adapter = () => createOpenAICompatibleAdapter("cursor", AgentKind.GENERIC, "Cursor Agent");
      const fromRaw = parseAll(adapter(), records);
      const fromStored = parseAll(adapter(), stored.values);
      assert.ok(fromRaw.length >= 10);
      assert.deepEqual(comparable(fromStored), comparable(fromRaw));
    }

    // OpenCode's CLI records, read by its own adapter.
    const fixture = (await readFile(new URL("../../test/fixtures/activity/opencode.jsonl", import.meta.url), "utf8"))
      .trim().split(/\r?\n/u);
    await ingestActivityJSONL({ agent: "opencode", dataDirectory: directory, input: Readable.from(fixture.map((line) => `${line}\n`)) });
    const opencode = await storedLines(directory, "opencode");
    assert.doesNotMatch(opencode.text, /fixturesecret|private\/project|calculated result/u);
    assert.deepEqual(
      comparable(parseAll(openCodeActivityAdapter, opencode.values)),
      comparable(parseAll(openCodeActivityAdapter, fixture.map((line) => JSON.parse(line) as unknown))),
    );
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("without full consent a short word-like value is not kept either", async () => {
  const directory = await mkdtemp(join(tmpdir(), "phigon-bridge-words-"));
  try {
    const record = {
      type: "message",
      session_id: "ses-words",
      data: "ConfidentialProject",
      label: "Payroll2027",
      tags: ["AcquisitionAlpha", "x1"],
      reason: "stop",
      status: "Merger with Initech approved",
      message: { role: "assistant", content: "ok" },
    };
    await ingestActivityJSONL({ agent: "cursor", dataDirectory: directory, input: Readable.from([`${JSON.stringify(record)}\n`]) });
    const stored = await storedLines(directory, "cursor");
    assert.doesNotMatch(stored.text, /ConfidentialProject|Payroll2027|AcquisitionAlpha|x1|Initech/u);
    // What identifies the record, and one-word kinds and states, stay.
    assert.deepEqual(stored.values[0], {
      type: "message",
      session_id: "ses-words",
      data: "[REDACTED_POLICY]",
      label: "[REDACTED_POLICY]",
      tags: ["[REDACTED_POLICY]", "[REDACTED_POLICY]"],
      reason: "stop",
      status: "[REDACTED_POLICY]",
      message: { role: "assistant", content: "[REDACTED_POLICY]" },
    });
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("with full consent a bridge file keeps content but never a secret", async () => {
  const directory = await mkdtemp(join(tmpdir(), "phigon-bridge-full-"));
  try {
    await consent(directory, "full");
    const prompt = { type: "message", message: { role: "user", content: `Deploy the payroll service with ${githubToken}` } };
    const output = { type: "message", message: { role: "tool", tool_call_id: "call_read", content: "API_KEY=plainapivalue1\nDB_PASSWORD=hunter2hunter2" } };
    const ingest = () => ingestActivityJSONL({
      agent: "cursor",
      dataDirectory: directory,
      input: Readable.from([`${JSON.stringify(prompt)}\n`, `${JSON.stringify(output)}\n`]),
    });
    await ingest();
    let stored = await storedLines(directory, "cursor");
    assert.match(stored.text, /Deploy the payroll service with \[REDACTED_SECRET\]/u);
    for (const leak of [githubToken, "plainapivalue1", "hunter2hunter2"]) assert.ok(!stored.text.includes(leak));

    // A background service installed for the metadata profile collects no
    // content, so none is kept.
    await rm(join(directory, "bridges"), { recursive: true, force: true });
    await writeServiceSettings(directory, { PHIGON_OBSERVABILITY_PROFILE: "metadata" });
    await ingest();
    stored = await storedLines(directory, "cursor");
    assert.doesNotMatch(stored.text, /Deploy|payroll/u);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("with full consent a bridge file still keeps nothing in a category the policy leaves off", async () => {
  const directory = await mkdtemp(join(tmpdir(), "phigon-bridge-categories-"));
  try {
    await consent(directory, "full");
    const record = {
      type: "message",
      session_id: "ses-categories",
      message: { role: "user", content: "Summarise the quarterly numbers" },
      tool_input: {
        command: "npm test",
        env: { DATABASE_HOST: "db.payroll.internal", SESSION_ID: "envsessionvalue", HOME: "/home/someone" },
      },
      tool_output: "All 42 tests passed in the payroll suite",
    };
    const ingest = async () => {
      await rm(join(directory, "bridges"), { recursive: true, force: true });
      await ingestActivityJSONL({ agent: "cursor", dataDirectory: directory, input: Readable.from([`${JSON.stringify(record)}\n`]) });
      return storedLines(directory, "cursor");
    };
    // The full profile still leaves environment values off.
    let stored = await ingest();
    assert.match(stored.text, /Summarise the quarterly numbers/u);
    assert.match(stored.text, /All 42 tests passed/u);
    assert.doesNotMatch(stored.text, /payroll\.internal|envsessionvalue|\/home\/someone/u);

    // A service that turns tool output off keeps none of it.
    await writeServiceSettings(directory, {
      PHIGON_OBSERVABILITY_PROFILE: "full",
      PHIGON_COLLECT_TOOL_OUTPUT: "false",
    });
    stored = await ingest();
    assert.match(stored.text, /Summarise the quarterly numbers/u);
    assert.doesNotMatch(stored.text, /All 42 tests passed|payroll\.internal|envsessionvalue/u);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("a field's own category never reopens one the policy leaves off above it", async () => {
  const directory = await mkdtemp(join(tmpdir(), "phigon-bridge-nested-"));
  try {
    // Full consent: file paths are collected, environment values are not.
    await consent(directory, "full");
    const record = {
      type: "message",
      session_id: "ses-nested",
      tool_input: { path: "/workspace/app/readme.md", env: { PATH: "/opt/payroll-tools/bin", HOME: "/home/someone" } },
    };
    await ingestActivityJSONL({ agent: "cursor", dataDirectory: directory, input: Readable.from([`${JSON.stringify(record)}\n`]) });
    const stored = await storedLines(directory, "cursor");
    assert.match(stored.text, /\/workspace\/app\/readme\.md/u);
    assert.doesNotMatch(stored.text, /payroll-tools|\/home\/someone/u);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("text no field names is kept only where every kind of text it could be is collected", async () => {
  const directory = await mkdtemp(join(tmpdir(), "phigon-bridge-unclassified-"));
  try {
    await consent(directory, "full");
    const record = {
      type: "message",
      session_id: "ses-unclassified",
      data: "Draft the acquisition announcement for Initech",
      tool_output: "Build finished in 12 seconds",
    };
    const ingest = async () => {
      await rm(join(directory, "bridges"), { recursive: true, force: true });
      await ingestActivityJSONL({ agent: "cursor", dataDirectory: directory, input: Readable.from([`${JSON.stringify(record)}\n`]) });
      return storedLines(directory, "cursor");
    };
    assert.match((await ingest()).text, /acquisition announcement/u);
    // With prompts off, text that could be a prompt is not kept; output,
    // which a field names and the policy collects, still is.
    await writeServiceSettings(directory, {
      PHIGON_OBSERVABILITY_PROFILE: "full",
      PHIGON_COLLECT_PROMPT_CONTENT: "false",
    });
    const stored = await ingest();
    assert.doesNotMatch(stored.text, /acquisition announcement|Initech/u);
    assert.match(stored.text, /Build finished in 12 seconds/u);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("a withheld address is never kept for its key, a name or a model included", async () => {
  const directory = await mkdtemp(join(tmpdir(), "phigon-bridge-addresses-"));
  try {
    const record = {
      type: "tool_call",
      session_id: "ses-addresses",
      name: "/home/alice/.env",
      model: "https://intranet.example/models/payroll",
      status: "https://intranet.example/status",
      source: "db.payroll.internal:5432",
      message: { role: "assistant", content: "/home/alice/notes/plan.md" },
    };
    const ingest = async () => {
      await rm(join(directory, "bridges"), { recursive: true, force: true });
      await ingestActivityJSONL({ agent: "cursor", dataDirectory: directory, input: Readable.from([`${JSON.stringify(record)}\n`]) });
      return storedLines(directory, "cursor");
    };
    // Metadata only: no address stays, however it is named.
    let stored = await ingest();
    assert.doesNotMatch(stored.text, /alice|intranet|payroll/u);
    assert.match(stored.text, /"session_id":"ses-addresses"/u);
    // Full consent with file paths, addresses and endpoints turned off.
    await consent(directory, "full");
    await writeServiceSettings(directory, {
      PHIGON_OBSERVABILITY_PROFILE: "full",
      PHIGON_COLLECT_FILE_PATHS: "false",
      PHIGON_COLLECT_BROWSER_URLS: "false",
      PHIGON_COLLECT_NETWORK_ENDPOINTS: "false",
    });
    stored = await ingest();
    assert.doesNotMatch(stored.text, /alice|intranet|payroll/u);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("collection settings of the program that ingests narrow what a bridge file keeps", async () => {
  const directory = await mkdtemp(join(tmpdir(), "phigon-bridge-foreground-"));
  try {
    await consent(directory, "full");
    const record = {
      type: "message",
      session_id: "ses-foreground",
      message: { role: "user", content: "Summarise the quarterly numbers" },
      tool_output: "All 42 tests passed in the payroll suite",
      env: { REGION: "eu-payroll-west" },
    };
    const ingest = async (environment: NodeJS.ProcessEnv) => {
      await rm(join(directory, "bridges"), { recursive: true, force: true });
      await ingestActivityJSONL({
        agent: "cursor",
        dataDirectory: directory,
        input: Readable.from([`${JSON.stringify(record)}\n`]),
        environment,
      });
      return (await storedLines(directory, "cursor")).text;
    };
    // No service is installed, so only the caller's settings say more.
    let stored = await ingest({ PHIGON_COLLECT_TOOL_OUTPUT: "false" });
    assert.match(stored, /Summarise the quarterly numbers/u);
    assert.doesNotMatch(stored, /All 42 tests passed/u);
    stored = await ingest({ PHIGON_OBSERVABILITY_PROFILE: "metadata" });
    assert.doesNotMatch(stored, /Summarise|All 42 tests/u);
    // A setting can switch content off, never on.
    stored = await ingest({ PHIGON_COLLECT_ENVIRONMENT_VALUES: "true" });
    assert.doesNotMatch(stored, /eu-payroll-west/u);
    // A setting that cannot be read keeps only metadata.
    stored = await ingest({ PHIGON_COLLECT_TOOL_OUTPUT: "sometimes" });
    assert.doesNotMatch(stored, /Summarise|All 42 tests/u);
    // Without such settings the consented full profile applies.
    stored = await ingest({});
    assert.match(stored, /All 42 tests passed/u);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("configured private paths are replaced in bridge files", async () => {
  const directory = await mkdtemp(join(tmpdir(), "phigon-bridge-paths-"));
  try {
    await consent(directory, "full");
    const record = {
      type: "message",
      session_id: "ses-paths",
      message: { role: "user", content: "Open /srv/acme-payroll/config.yml and C:\\Clients\\Initech\\notes.txt" },
      files: { "/srv/acme-payroll/config.yml": 1 },
      tool_input: { command: "cat /srv/acme-payroll/config.yml" },
    };
    const ingest = async (environment: NodeJS.ProcessEnv) => {
      await rm(join(directory, "bridges"), { recursive: true, force: true });
      await ingestActivityJSONL({
        agent: "cursor",
        dataDirectory: directory,
        input: Readable.from([`${JSON.stringify(record)}\n`]),
        environment,
      });
      return (await storedLines(directory, "cursor")).text;
    };
    // From the ingesting program's settings.
    let stored = await ingest({ PHIGON_REDACT_PATH_PATTERNS: "/srv/acme-payroll" });
    assert.doesNotMatch(stored, /acme-payroll/u);
    assert.match(stored, /\[REDACTED_PATH\]\/config\.yml/u);
    // From the background service's settings.
    await writeServiceSettings(directory, {
      PHIGON_OBSERVABILITY_PROFILE: "full",
      PHIGON_REDACT_PATH_PATTERNS: "/srv/acme-payroll,C:\\Clients\\Initech",
    });
    stored = await ingest({});
    assert.doesNotMatch(stored, /acme-payroll|Initech/u);
    assert.match(stored, /Open \[REDACTED_PATH\]/u);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("an ID or name holding a withheld address anywhere is kept only as a digest", async () => {
  const directory = await mkdtemp(join(tmpdir(), "phigon-bridge-embedded-"));
  try {
    const record = {
      type: "message",
      name: "project at /home/alice/.env",
      session_id: "session-/home/alice/proj",
      agent: "bot via https://internal.example/x",
      provider: "relay db.payroll.internal:5432",
      status: "postgres://payroll",
      // Ordinary IDs, names and times stay readable.
      call_id: "call_abc-123",
      thread_id: "guardian:codex-worker",
      model: "anthropic/claude-3.5-sonnet",
      timestamp: "2026-11-08T10:00:00.000Z",
      tool_name: "github/create_issue",
    };
    await ingestActivityJSONL({ agent: "cursor", dataDirectory: directory, input: Readable.from([`${JSON.stringify(record)}\n`]) });
    const stored = await storedLines(directory, "cursor");
    assert.doesNotMatch(stored.text, /alice|internal\.example|payroll/u);
    const value = stored.values[0] as Record<string, string>;
    for (const key of ["name", "session_id", "agent", "provider", "status"]) {
      assert.match(value[key] ?? "", /^phigon-digest:[0-9a-f]{64}$/u, key);
    }
    for (const key of ["call_id", "thread_id", "model", "timestamp", "tool_name", "type"]) {
      assert.equal(value[key], record[key as keyof typeof record], key);
    }
    // The same value gives the same digest, so records still group.
    await ingestActivityJSONL({ agent: "cursor", dataDirectory: directory, input: Readable.from([`${JSON.stringify(record)}\n`]) });
    const again = (await storedLines(directory, "cursor")).values.map((line) => (line as Record<string, string>)["session_id"]);
    assert.equal(new Set(again).size, 1);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("a number in a category the policy leaves off is withheld like text", async () => {
  const directory = await mkdtemp(join(tmpdir(), "phigon-bridge-numbers-"));
  try {
    const record = {
      type: "message",
      ts: 1_762_600_000_000,
      timestamp: 1_762_600_000,
      exit_code: 3,
      env: { PORT: 54_329, WORKERS: 17, DEBUG: true },
      tool_output: 987_654_321,
      data: 4_111_111_111_111_111,
      usage: { input_tokens: 128 },
    };
    const ingest = async () => {
      await rm(join(directory, "bridges"), { recursive: true, force: true });
      await ingestActivityJSONL({ agent: "cursor", dataDirectory: directory, input: Readable.from([`${JSON.stringify(record)}\n`]) });
      return (await storedLines(directory, "cursor")).values[0] as Record<string, unknown>;
    };
    // Metadata only: times, codes and counts stay, other numbers do not.
    let stored = await ingest();
    assert.deepEqual(stored, {
      type: "message",
      ts: 1_762_600_000_000,
      timestamp: 1_762_600_000,
      exit_code: 3,
      env: { PORT: "[REDACTED_POLICY]", WORKERS: "[REDACTED_POLICY]", DEBUG: true },
      tool_output: "[REDACTED_POLICY]",
      data: "[REDACTED_POLICY]",
      usage: { input_tokens: 128 },
    });
    // Full consent leaves environment values off: none of them stays.
    await consent(directory, "full");
    stored = await ingest();
    assert.deepEqual(stored["env"], { PORT: "[REDACTED_POLICY]", WORKERS: "[REDACTED_POLICY]", DEBUG: true });
    assert.equal(stored["tool_output"], 987_654_321);
    assert.equal(stored["data"], 4_111_111_111_111_111);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("a key holding a withheld address, or data in a withheld object, is kept only as a digest", async () => {
  const directory = await mkdtemp(join(tmpdir(), "phigon-bridge-keys-"));
  try {
    const record = {
      type: "message",
      hosts: { "db.payroll.internal:5432": "up", "10.0.0.7:8080": "down" },
      caches: { "cache-/home/alice/proj": 1 },
      plans: { "Quarterly plan for Initech": true },
      message: { role: "assistant", content: "ok" },
    };
    const ingest = async () => {
      await rm(join(directory, "bridges"), { recursive: true, force: true });
      await ingestActivityJSONL({ agent: "cursor", dataDirectory: directory, input: Readable.from([`${JSON.stringify(record)}\n`]) });
      return storedLines(directory, "cursor");
    };
    // Metadata only.
    let stored = await ingest();
    assert.doesNotMatch(stored.text, /payroll|10\.0\.0\.7|alice|Initech/u);
    const value = stored.values[0] as Record<string, Record<string, unknown>>;
    for (const group of ["hosts", "caches", "plans"]) {
      assert.ok(Object.keys(value[group] ?? {}).every((key) => key.startsWith("phigon-digest:")), group);
    }
    // Field names stay.
    assert.deepEqual(Object.keys(value["message"] ?? {}).sort(), ["content", "role"]);
    // Full consent with endpoints off: endpoint keys go, content keys stay.
    await consent(directory, "full");
    await writeServiceSettings(directory, { PHIGON_OBSERVABILITY_PROFILE: "full", PHIGON_COLLECT_NETWORK_ENDPOINTS: "false" });
    stored = await ingest();
    assert.doesNotMatch(stored.text, /payroll|10\.0\.0\.7/u);
    assert.match(stored.text, /Quarterly plan for Initech/u);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("text no field names is withheld when any content switch is off, vendor payloads included", async () => {
  const directory = await mkdtemp(join(tmpdir(), "phigon-bridge-vendor-"));
  try {
    await consent(directory, "full");
    const record = {
      type: "message",
      data: "Draft the acquisition announcement for Initech",
      tool_output: "Build finished in 12 seconds",
    };
    for (const setting of ["PHIGON_COLLECT_VENDOR_PAYLOAD", "PHIGON_COLLECT_MCP_OUTPUT", "PHIGON_COLLECT_MODEL_PROMPTS"]) {
      await rm(join(directory, "bridges"), { recursive: true, force: true });
      await writeServiceSettings(directory, { PHIGON_OBSERVABILITY_PROFILE: "full", [setting]: "false" });
      await ingestActivityJSONL({ agent: "cursor", dataDirectory: directory, input: Readable.from([`${JSON.stringify(record)}\n`]) });
      const stored = (await storedLines(directory, "cursor")).text;
      assert.doesNotMatch(stored, /acquisition|Initech/u, setting);
      assert.match(stored, /Build finished in 12 seconds/u, setting);
    }
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("JSON text and IDs inside a collected record still follow the address rules", async () => {
  const directory = await mkdtemp(join(tmpdir(), "phigon-bridge-json-text-"));
  try {
    await consent(directory, "full");
    await writeServiceSettings(directory, { PHIGON_OBSERVABILITY_PROFILE: "full", PHIGON_COLLECT_FILE_PATHS: "false" });
    const record = {
      type: "message",
      name: "project at /home/alice/.env",
      message: {
        role: "assistant",
        tool_calls: [{
          id: "call_read",
          type: "function",
          function: { name: "read_file", arguments: JSON.stringify({ path: "/home/alice/notes.md", pattern: "TODO", limit: 20 }) },
        }],
      },
    };
    await ingestActivityJSONL({ agent: "cursor", dataDirectory: directory, input: Readable.from([`${JSON.stringify(record)}\n`]) });
    const stored = await storedLines(directory, "cursor");
    assert.doesNotMatch(stored.text, /alice/u);
    const value = stored.values[0] as { name: string; message: { tool_calls: Array<{ function: { arguments: string } }> } };
    assert.match(value.name, /^phigon-digest:[0-9a-f]{64}$/u);
    const argumentsValue = JSON.parse(value.message.tool_calls[0]?.function.arguments ?? "{}") as Record<string, unknown>;
    assert.match(String(argumentsValue["path"]), /^phigon-digest:/u);
    assert.equal(argumentsValue["pattern"], "TODO");
    assert.equal(argumentsValue["limit"], 20);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("one-time codes and PINs are secrets, and only listed numbers count as metadata", async () => {
  for (const name of ["otp_code", "otpCode", "verification_code", "auth_code", "mfa_code", "mfaToken", "pin", "card_pin", "passcode", "totp", "authorization_code", "sms_code"]) {
    assert.equal(credentialFieldName(name), true, name);
  }
  for (const name of ["status_code", "exit_code", "spin", "mapping", "zip_code", "country_code", "line_code"]) {
    assert.equal(credentialFieldName(name), false, name);
  }
  const directory = await mkdtemp(join(tmpdir(), "phigon-bridge-codes-"));
  try {
    const record = {
      type: "message",
      otp_code: 123_456,
      verification_code: 987_650,
      pin: 1_234,
      status_code: 404,
      exit_code: 1,
      line_code: 77,
      timestamp: 1_762_600_000,
      // Numeric IDs identify the record and stay; a number whose name only
      // ends in the letters "id" is not one.
      id: 42,
      session_id: 17,
      sessionId: 9,
      callID: 3,
      amount_paid: 30,
    };
    const ingest = async () => {
      await rm(join(directory, "bridges"), { recursive: true, force: true });
      await ingestActivityJSONL({ agent: "cursor", dataDirectory: directory, input: Readable.from([`${JSON.stringify(record)}\n`]) });
      return (await storedLines(directory, "cursor")).values[0];
    };
    assert.deepEqual(await ingest(), {
      type: "message",
      otp_code: "[REDACTED_SECRET]",
      verification_code: "[REDACTED_SECRET]",
      pin: "[REDACTED_SECRET]",
      status_code: 404,
      exit_code: 1,
      line_code: "[REDACTED_POLICY]",
      timestamp: 1_762_600_000,
      id: 42,
      session_id: 17,
      sessionId: 9,
      callID: 3,
      amount_paid: "[REDACTED_POLICY]",
    });
    // A code is a secret even where content is collected.
    await consent(directory, "full");
    const full = await ingest() as Record<string, unknown>;
    assert.equal(full["otp_code"], "[REDACTED_SECRET]");
    assert.equal(full["line_code"], 77);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("nothing inside a withheld category is reopened by a field's own category", async () => {
  const directory = await mkdtemp(join(tmpdir(), "phigon-bridge-nested-withheld-"));
  try {
    await consent(directory, "full");
    const nested = { prompt: "nested prompt words", response: "nested reply words", stdout: "nested output words", content: "nested file words" };
    for (const [key, setting] of [
      ["tool_output", "PHIGON_COLLECT_TOOL_OUTPUT"],
      ["arguments", "PHIGON_COLLECT_COMMAND_ARGUMENTS"],
      ["stdout", "PHIGON_COLLECT_TERMINAL_OUTPUT"],
      ["reasoning", "PHIGON_COLLECT_REASONING_CONTENT"],
      ["patch", "PHIGON_COLLECT_GIT_PATCH_CONTENT"],
      ["prompt", "PHIGON_COLLECT_PROMPT_CONTENT"],
    ] as const) {
      await rm(join(directory, "bridges"), { recursive: true, force: true });
      await writeServiceSettings(directory, { PHIGON_OBSERVABILITY_PROFILE: "full", [setting]: "false" });
      // As an object and as JSON text.
      const records = [{ type: "message", [key]: nested }, { type: "message", [key]: JSON.stringify(nested) }];
      await ingestActivityJSONL({
        agent: "cursor",
        dataDirectory: directory,
        input: Readable.from(records.map((record) => `${JSON.stringify(record)}\n`)),
      });
      const stored = (await storedLines(directory, "cursor")).text;
      assert.doesNotMatch(stored, /nested (?:prompt|reply|output|file) words/u, key);
    }
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("JSON text and numbers keep their exact text through bridge storage", async () => {
  const directory = await mkdtemp(join(tmpdir(), "phigon-bridge-lossless-"));
  try {
    await consent(directory, "full");
    const unchangedText = `{"order": 9007199254740993,  "ratio": 1.50, "note": "kept as is"}`;
    // Assembled at runtime so secret scanners do not flag this file.
    const tokenValue = ["abcdef", "ghij123"].join("");
    const changedText = `{"order":9007199254740993, "token": "${tokenValue}"}`;
    const unchangedLine = `{"type": "message",  "order": 9007199254740993, "ratio": 1.50, "message": {"role": "user", "content": ${JSON.stringify(unchangedText)}}}`;
    const changedLine = `{"type":"message","order":9007199254740993,"message":{"role":"user","content":${JSON.stringify(changedText)}},"token":"${tokenValue}"}`;
    await ingestActivityJSONL({
      agent: "cursor",
      dataDirectory: directory,
      input: Readable.from([`${unchangedLine}\n`, `${changedLine}\n`]),
    });
    const lines = (await storedLines(directory, "cursor")).text.trim().split("\n");
    // Nothing to withhold: the line as it came, byte for byte.
    assert.equal(lines[0], unchangedLine);
    // A secret masked: every number is still exact.
    assert.match(lines[1] ?? "", /"order":9007199254740993/u);
    const inner = (JSON.parse(lines[1] ?? "{}") as { message: { content: string } }).message.content;
    assert.match(inner, /^\{"order":9007199254740993,"token":"\[REDACTED_SECRET\]"\}$/u);
    assert.ok(!(lines[1] ?? "").includes(tokenValue));

    // Without full consent, a number kept as metadata is exact too.
    await consent(directory, "metadata");
    await rm(join(directory, "bridges"), { recursive: true, force: true });
    await ingestActivityJSONL({
      agent: "cursor",
      dataDirectory: directory,
      input: Readable.from([`{"type":"message","seq":9007199254740993,"data":12345678901234567890}\n`]),
    });
    assert.equal(
      (await storedLines(directory, "cursor")).text.trim(),
      `{"type":"message","seq":9007199254740993,"data":"[REDACTED_POLICY]"}`,
    );
    // A bare number is still not a record a custom agent may write.
    const custom = await ingestActivityJSONL({
      agent: "custom",
      agentName: "Release Bot",
      dataDirectory: directory,
      input: Readable.from(["9007199254740993\n"]),
    });
    assert.equal(custom.malformed, 1);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("a journal applies a narrowed consent to its very next record", async () => {
  const directory = await mkdtemp(join(tmpdir(), "phigon-bridge-narrowed-"));
  try {
    await consent(directory, "full");
    const journal = new SegmentedJournal(directory, managedCommandJournal);
    const record = (output: string) => JSON.stringify({
      type: "phigon_managed_command",
      session_id: "guardian:codex-worker",
      invocation_id: randomUUID(),
      phase: "running",
      stream: "stdout",
      output,
    });
    await journal.append(record("first output under full consent"));
    // The consent narrows to metadata; the same journal writes on at once.
    await consent(directory, "metadata");
    await journal.append(record("second output after narrowing"));
    const stored = await storedLines(directory, "generic");
    assert.match(stored.text, /first output under full consent/u);
    assert.doesNotMatch(stored.text, /second output after narrowing/u);
    // And widens again only when the consent file says so.
    await consent(directory, "full");
    await journal.append(record("third output after widening"));
    assert.match((await storedLines(directory, "generic")).text, /third output after widening/u);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("Guardian's journals keep no secret, and no content without full consent", async () => {
  const directory = await mkdtemp(join(tmpdir(), "phigon-bridge-journal-"));
  try {
    const decision = {
      type: "phigon_guardian_decision",
      decision_id: randomUUID(),
      phigon_agent_name: "Phigon Guardian",
      session_id: "guardian:codex-worker",
      timestamp: "2026-11-08T10:00:00.000Z",
      action: "command.execute",
      resource: `GITHUB_TOKEN=${githubToken} git push`,
      outcome: "allowed",
      reason: "The payroll owner asked for it.",
      context: { userPrompt: "Deploy the payroll service", recentActivity: "read /home/someone/payroll/.env" },
    };
    const command = {
      type: "phigon_managed_command",
      timestamp: "2026-11-08T10:00:01.000Z",
      session_id: "guardian:codex-worker",
      agent_id: "codex:worker",
      invocation_id: randomUUID(),
      phase: "running",
      executable: "/usr/bin/cat",
      arguments: ["/home/someone/payroll/.env"],
      stream: "stdout",
      output: "API_KEY=plainapivalue1\nDB_PASSWORD=hunter2hunter2",
      exit_code: null,
    };
    await new SegmentedJournal(directory, guardianDecisionJournal).append(JSON.stringify(decision));
    await new SegmentedJournal(directory, managedCommandJournal).append(JSON.stringify(command));
    const stored = await storedLines(directory, "generic");
    for (const leak of leaks) assert.ok(!stored.text.includes(leak), `journal kept ${leak}`);
    const adapter = () => createOpenAICompatibleAdapter("generic", AgentKind.GENERIC, "AI agent");
    assert.deepEqual(
      comparable(parseAll(adapter(), stored.values)),
      comparable(parseAll(adapter(), [decision, command])),
    );
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});
