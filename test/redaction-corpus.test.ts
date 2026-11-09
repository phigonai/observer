import assert from "node:assert/strict";
import test from "node:test";
import { toolDrafts } from "../src/activity/normalize.js";
import { LocalPolicyEngine } from "../src/activity/policy.js";
import { redactSecrets } from "../src/content-redaction.js";
import { loadConfig } from "../src/config.js";
import { AgentKind } from "../src/generated/phigon/v1/common_pb.js";
import { ToolPhase } from "../src/generated/phigon/v1/telemetry_pb.js";
import { loadContentConfig } from "./content-config.js";

// Every credential below is assembled at runtime from parts and repeated
// letters, so secret scanners that read this file find nothing to flag.
const fill = (letter: string, length: number) => letter.repeat(length);
const join = (...parts: string[]) => parts.join("");

// A sample that is a line of its own, such as a YAML field, is only
// recognised at the start of a line.
type Sample = Readonly<{ name: string; text: string; secret: string; line?: boolean }>;

/** A credential in its usual setting, and the part that must never be sent. */
function sample(name: string, text: (secret: string) => string, secret: string, line = false): Sample {
  return { name, text: text(secret), secret, ...(line ? { line } : {}) };
}

const value = join("Qv7", fill("q", 13));
const word = (prefix: string, letter: string, length: number) => join(prefix, fill(letter, length));

const corpus: readonly Sample[] = [
  // Private keys, finished and cut off.
  sample("rsa private key", (s) => join("-----BEGIN RSA ", "PRIVATE KEY-----\n", s, "\n-----END RSA ", "PRIVATE KEY-----"), join("MIIE", fill("k", 40))),
  sample("openssh private key, unterminated", (s) => join("-----BEGIN OPENSSH ", "PRIVATE KEY-----\n", s), join("b3Bl", fill("k", 40))),
  sample("pgp private key", (s) => join("-----BEGIN PGP ", "PRIVATE KEY BLOCK-----\n", s, "\n-----END PGP ", "PRIVATE KEY BLOCK-----"), join("lQOY", fill("k", 40))),
  // Fixed-prefix tokens.
  sample("openai key", (s) => `key ${s} used`, word(join("sk", "-proj-"), "A", 40)),
  sample("stripe secret key", (s) => `stripe ${s}`, word(join("sk", "_live_"), "B", 24)),
  sample("stripe restricted key", (s) => `stripe ${s}`, word(join("rk", "_live_"), "C", 24)),
  sample("phigon machine credential", (s) => `machine ${s}`, word(join("phg", "_m_"), "D", 43)),
  sample("github classic token", (s) => `gh ${s}`, word(join("gh", "p_"), "E", 36)),
  sample("github oauth token", (s) => `gh ${s}`, word(join("gh", "o_"), "F", 36)),
  sample("github server token", (s) => `gh ${s}`, word(join("gh", "s_"), "G", 36)),
  sample("github fine-grained token", (s) => `gh ${s}`, word(join("github", "_pat_"), "H", 60)),
  sample("aws access key id", (s) => `aws ${s}`, word(join("AK", "IA"), "J", 16)),
  sample("aws temporary key id", (s) => `aws ${s}`, word(join("AS", "IA"), "K", 16)),
  sample("slack bot token", (s) => `slack ${s}`, word(join("xo", "xb-"), "1", 30)),
  sample("slack app token", (s) => `slack ${s}`, word(join("xa", "pp-1-"), "L", 30)),
  sample("google api key", (s) => `google ${s}`, word(join("AI", "za"), "M", 35)),
  sample("google oauth client secret", (s) => `google ${s}`, word(join("GOC", "SPX-"), "N", 28)),
  sample("google access token", (s) => `google ${s}`, word(join("ya", "29."), "P", 40)),
  sample("npm token", (s) => `npm ${s}`, word(join("np", "m_"), "R", 36)),
  sample("phigon access key", (s) => `key ${s}`, join("ph", "g_", fill("a", 12), "_", fill("b", 32))),
  sample("phigon license key", (s) => `license ${s}`, join("ph", "l_", fill("c", 24), ".", fill("d", 50))),
  sample("phigon enrollment code", (s) => `code ${s}`, word(join("ph", "e_"), "e", 32)),
  sample("phigon uninstall code", (s) => `remove-machine --uninstall-code ${s}`, word(join("ph", "u_"), "u", 32)),
  sample("webhook signing secret", (s) => `secret ${s}`, word(join("wh", "sec_"), "S", 32)),
  sample("slack webhook", (s) => join("post to https://hooks.", "slack.com/services/", s), join("T0", fill("T", 8), "/B0", fill("B", 8), "/", fill("w", 24))),
  sample("gitlab token", (s) => `gitlab ${s}`, word(join("gl", "pat-"), "U", 24)),
  sample("hugging face token", (s) => `hf ${s}`, word(join("h", "f_"), "V", 34)),
  sample("sendgrid key", (s) => `sendgrid ${s}`, join("S", "G.", fill("W", 22), ".", fill("X", 43))),
  sample("shopify token", (s) => `shopify ${s}`, word(join("shp", "at_"), "a", 32)),
  sample("digitalocean token", (s) => `do ${s}`, word(join("do", "p_v1_"), "f", 64)),
  sample("pypi token", (s) => `pypi ${s}`, word(join("py", "pi-"), "Y", 60)),
  sample("jwt", (s) => `token ${s}`, join("ey", "JhbGciOiJIUzI1NiJ9.", "ey", "JzdWIiOiIxMjM0NTYifQ.", fill("Z", 30))),
  // Credentials in addresses.
  sample("url password", (s) => `postgres://admin:${s}@db.internal:5432/app`, value),
  sample("url password with @ and /", (s) => `postgres://admin:${s}@db.internal/app`, join(value, "@x/", value)),
  sample("url password with / and an @ in the query", (s) => `postgres://admin:${s}@db.internal/app?owner=me@example.com`, join(value, "/", value)),
  sample("url password with / and an @ in the fragment", (s) => `https://admin:${s}@db.internal:8080/#me@example.com`, join(value, "/", value)),
  sample("url password without user", (s) => `redis://:${s}@cache.internal:6379/0`, value),
  sample("azure sas signature", (s) => `https://acct.blob.core.windows.net/c/f?sv=2022&sig=${s}`, join(value, "%2B%3D")),
  sample("s3 signature", (s) => `https://b.s3.amazonaws.com/k?X-Amz-Signature=${s}&X-Amz-Date=1`, value),
  // Authorization headers and cookies.
  sample("basic authorization", (s) => `Authorization: Basic ${s}`, join("dXNl", fill("c", 20))),
  sample("token authorization", (s) => `authorization: Token ${s}`, value),
  sample("bearer token", (s) => `Authorization: Bearer ${s}`, value),
  sample("cookie header, later cookie", (s) => `Cookie: theme=dark; lang=en; session=${s}`, value),
  sample("set-cookie header", (s) => `Set-Cookie: sid=${s}; Path=/; HttpOnly`, value),
  // Named values.
  sample("api_key assignment", (s) => `api_key=${s}`, value),
  sample("token json field", (s) => `{"token": "${s}"}`, value),
  sample("secret yaml field", (s) => `secret: ${s}`, value, true),
  sample("password with spaces in yaml", (s) => `password: correct horse ${s}`, value, true),
  sample("quoted password", (s) => `PASSWORD="${s}"`, value),
  sample("private key name", (s) => `private_key=${s}`, value),
  sample("aws secret access key", (s) => `aws_secret_access_key=${s}`, value),
  sample("credential environment variable", (s) => `OPENAI_KEY=${s}`, value),
  sample("db_pass environment variable", (s) => `export DB_PASS=${s}`, value),
  sample("mysql_pwd environment variable", (s) => `MYSQL_PWD=${s}`, value),
  sample("client secret json", (s) => `{"client_secret": "${s}"}`, value),
  sample("camelCase access token", (s) => `accessToken: ${s}`, value),
  sample("azure storage key", (s) => `DefaultEndpointsProtocol=https;AccountName=demo;AccountKey=${s};EndpointSuffix=core`, value),
  sample("connection string pwd", (s) => `Server=db;User Id=sa;Pwd=${s};Database=app`, value),
  sample("connection string password with spaces", (s) => `Server=db;Password=correct horse ${s};`, value),
  // Command lines.
  sample("mysql attached password", (s) => `mysql -u root -p${s} app`, value),
  sample("sshpass password", (s) => `sshpass -p ${s} ssh deploy@host`, value),
  sample("redis-cli password", (s) => `redis-cli -a ${s} ping`, value),
  sample("password option", (s) => `deploy --password ${s} --verbose`, value),
  sample("password option with =", (s) => `deploy --password=${s}`, value),
  sample("token option", (s) => `gh auth login --token ${s}`, value),
  sample("curl user and password", (s) => `curl -u admin:${s} https://api.example`, value),
];

const fullPolicy = () => new LocalPolicyEngine(loadContentConfig({
  PHIGON_COLLECT_COMMAND_ARGUMENTS: "true",
  PHIGON_COLLECT_TOOL_OUTPUT: "true",
  PHIGON_COLLECT_TERMINAL_OUTPUT: "true",
  PHIGON_COLLECT_VENDOR_PAYLOAD: "true",
}).policy, [], {
  summaryBytes: 64,
  contentBytes: 256,
  toolArgumentsBytes: 128 << 10,
  toolOutputBytes: 128 << 10,
  terminalOutputBytes: 256,
  vendorPayloadBytes: 512 << 10,
});

/** The part of a secret whose presence, even cut short, is a leak. */
const tell = (secret: string) => secret.slice(0, 6);

function assertHidden(output: string | undefined, item: Sample, where: string): void {
  if (output === undefined) return;
  assert.ok(!output.includes(tell(item.secret)), `${item.name} survived ${where}`);
}

test("every known secret format is hidden in plain text, in JSON and wherever a limit cuts it", () => {
  const policy = fullPolicy();
  for (const item of corpus) {
    assert.ok(item.text.includes(item.secret), item.name);
    assertHidden(redactSecrets(item.text), item, "redactSecrets");
    assertHidden(policy.content(item.text, "terminalOutput").value, item, "terminal output");
    // Inside JSON, between newlines, as structured data and as escaped text.
    const document = { result: { stdout: `first line\n${item.text}\nlast line` } };
    assertHidden(policy.json(document, "toolOutput").value, item, "tool output JSON");
    assertHidden(policy.vendorRecord({ type: "tool_result", output: document.result.stdout }).value, item, "vendor record");
    assertHidden(policy.content(document, "toolOutput").value, item, "structured content");
    assertHidden(redactSecrets(JSON.stringify(document)), item, "escaped JSON text");
    // The limit falls at every point of the credential.
    const start = 200;
    for (let offset = 0; offset <= item.text.length; offset++) {
      const padding = fill("w", Math.max(0, start - item.text.length + offset - 1));
      const text = `${padding}${item.line === true ? "\n" : " "}${item.text}\ntrailing words`;
      assertHidden(policy.content(text, "terminalOutput").value, item, `terminal output cut at ${offset}`);
    }
  }
});

// A small deterministic generator: the same cases on every run.
function generator(seed: number): () => number {
  let state = seed >>> 0;
  return () => {
    state = (state + 0x6d2b79f5) >>> 0;
    let next = state;
    next = Math.imul(next ^ (next >>> 15), next | 1);
    next ^= next + Math.imul(next ^ (next >>> 7), next | 61);
    return ((next ^ (next >>> 14)) >>> 0) / 4_294_967_296;
  };
}

test("no known secret survives any collection path in generated text and records", () => {
  const random = generator(0x5eed);
  const pick = <T>(items: readonly T[]): T => items[Math.floor(random() * items.length)] as T;
  const words = ["build", "the", "deploy", "ok", "error:", "path/to/file.ts", "über", "日本", "{", "}", "[", "]", "=", ":", ",", "--flag", "\"quoted\"", "'single'", "x=1", "a;b", "https://example.com/a", "line\n", "\t", "  "];
  const separators = [" ", "\n", "\r\n", "\t", " (", ") ", ", ", "; ", "\"", "'", "`", " <", "> ", "\\n"];
  const keys = ["output", "stdout", "text", "result", "message", "data", "items", "nested", "value", "accessToken", "max_tokens", "env"];
  const policy = fullPolicy();
  const metadata = new LocalPolicyEngine(loadConfig({}).policy);
  for (let index = 0; index < 2_000; index++) {
    const item = pick(corpus);
    const parts: string[] = [];
    for (let count = Math.floor(random() * 6); count > 0; count--) parts.push(pick(words));
    // The secret touches the characters around it, as in real output.
    parts.push(`${item.line === true ? pick(["\n", "\r\n"]) : pick(separators)}${item.text}${pick(separators)}`);
    for (let count = Math.floor(random() * 6); count > 0; count--) parts.push(pick(words));
    const text = parts.join(" ");
    let structured: unknown = text;
    for (let depth = Math.floor(random() * 4); depth > 0; depth--) {
      structured = random() < 0.3 ? [pick(words), structured] : { [pick(keys)]: structured, kind: "sample" };
    }
    const where = `case ${index}`;
    assertHidden(policy.content(text, "terminalOutput").value, item, `${where} terminal output`);
    assertHidden(policy.content(structured, "toolOutput").value, item, `${where} structured content`);
    assertHidden(policy.json(structured, "toolOutput").value, item, `${where} tool output JSON`);
    assertHidden(policy.vendorRecord({ type: "tool_result", output: structured }).value, item, `${where} vendor record`);
    assertHidden(policy.safeName(text, "fallback"), item, `${where} name`);
    if (index % 10 === 0) {
      for (const draft of toolDrafts(AgentKind.GENERIC, {
        sessionId: "session-fuzz",
        observedAt: new Date("2026-11-08T10:00:00.000Z"),
        policy: metadata,
      }, {
        invocationId: `call_${index}`,
        toolName: "shell",
        phase: ToolPhase.REQUESTED,
        arguments: { command: text },
      })) {
        if (draft.payload.case === "terminal") {
          assertHidden(draft.payload.value.executable, item, `${where} executable`);
        }
      }
    }
  }
});
