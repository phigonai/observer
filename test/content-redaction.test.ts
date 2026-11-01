import assert from "node:assert/strict";
import test from "node:test";
import { credentialEnvironmentName, credentialName, redactSecrets } from "../src/content-redaction.js";

test("redaction covers multiline and incomplete private keys and token boundaries", () => {
  for (const source of [
    "before\n-----BEGIN RSA PRIVATE KEY-----\nSECRETKEY\n-----END RSA PRIVATE KEY-----\nafter", // gitleaks:allow -- Deliberately invalid synthetic redaction fixture.
    "-----BEGIN OPENSSH PRIVATE KEY-----\nSECRETKEY",
    'password="short secret"', "Bearer partial", "sk-partial", "github_pat_partial",
  ]) {
    const safe = redactSecrets(source);
    assert.match(safe, /REDACTED/);
    assert.doesNotMatch(safe, /SECRETKEY|short secret|partial/);
  }
  assert.equal(redactSecrets("plain command output"), "plain command output");
});

// Vendor-shaped fixtures are assembled at runtime so secret scanners do not flag them.
test("redaction covers vendor tokens, JWTs, URL credentials and non-bearer auth", () => {
  for (const [source, leaked] of [
    ["phg_m_0123456789012345678901234567890123456789012", "0123456789"],
    [["sk_", "live_4eC39HqLyjWDarjtT1zdp7dc"].join(""), "4eC39Hq"],
    [["xox", "b-123456789012-abcdefABCDEF"].join(""), "123456789012"],
    [["AIza", "SyA1234567890abcdefghijklmnopqrstuv"].join(""), "A1234567890"],
    [["eyJhbGciOiJIUzI1NiJ9", "eyJzdWIiOiIxMjM0NTYifQ", "abcDEF123_-xyz"].join("."), "abcDEF123"],
    [["npm", "_abcdefghijklmnopqrstuvwxyz0123456789"].join(""), "abcdefghij"],
    [["tok", "en=abcd1234efgh5678"].join(""), "abcd1234"],
    [['{"refresh_tok', 'en":"abcd1234efgh"}'].join(""), "abcd1234"],
    ["SECRET=hunter2hunter2", "hunter2"],
    ["aws_secret_access_key=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", "wJalrXUtnFEMI"],
    ["Authorization: Basic dXNlcjpwYXNz", "dXNlcjpwYXNz"],
    ["https://user:pa55word@host.example/x", "pa55word"],
  ] as const) {
    const safe = redactSecrets(source);
    assert.match(safe, /REDACTED/, source);
    assert.ok(!safe.includes(leaked), `${source} -> ${safe}`);
  }
  assert.equal(redactSecrets('{"max_tokens": 100}'), '{"max_tokens": 100}');
  assert.equal(redactSecrets("see https://example.com/a:b"), "see https://example.com/a:b");
});

// Assembled at runtime from repeated letters so secret scanners do not flag them.
const filler = (letter: string, length: number) => letter.repeat(length);

test("redaction covers credential names that command output already hid", () => {
  for (const [source, leaked] of [
    [`OPENAI_KEY=${filler("q", 20)}`, filler("q", 20)],
    [`export STRIPE_SECRET_KEY="${filler("w", 24)}"`, filler("w", 24)],
    [`DB_PASS=${filler("e", 12)}`, filler("e", 12)],
    [`MYSQL_PWD=${filler("r", 12)}`, filler("r", 12)],
    [`SENTRY_DSN=https://${filler("t", 16)}.ingest.example/1`, filler("t", 16)],
    [`DSN: postgres://db.example/${filler("y", 10)}`, filler("y", 10)],
    [`DefaultEndpointsProtocol=https;AccountName=demo;AccountKey=${filler("u", 30)}==;EndpointSuffix=core`, filler("u", 30)],
    [`Endpoint=sb://demo.example/;SharedAccessKeyName=root;SharedAccessKey=${filler("i", 30)}=`, filler("i", 30)],
    [`{"client_secret": "${filler("o", 16)}"}`, filler("o", 16)],
    [`accessToken: ${filler("p", 16)}`, filler("p", 16)],
  ] as const) {
    const safe = redactSecrets(source);
    assert.match(safe, /REDACTED/u, source);
    assert.ok(!safe.includes(leaked), `${source} -> ${safe}`);
  }
});

test("redaction covers token formats that command output already hid", () => {
  for (const token of [
    ["glpat", "-", filler("a", 20)],
    ["hf", "_", filler("b", 34)],
    ["ya29", ".", filler("c", 30)],
    ["SG", ".", filler("d", 22), ".", filler("D", 43)],
    ["rk", "_live_", filler("f", 24)],
    ["shpat", "_", filler("a", 32)],
    ["dop", "_v1_", filler("e", 64)],
    ["pypi", "-", filler("g", 60)],
    ["xapp", "-1-", filler("h", 20)],
  ].map((parts) => parts.join(""))) {
    const safe = redactSecrets(`the token is ${token} today`);
    assert.equal(safe, "the token is [REDACTED_SECRET] today", token.slice(0, 8));
  }
});

test("ordinary text and code keep their values", () => {
  for (const ordinary of [
    "PWD=/home/example\nOLDPWD=/tmp\nkey: display-name\nSSH_AUTH_SOCK=/tmp/agent.sock",
    "primary_key=user_identifier, sort_key=created_at, public_key=ssh-ed25519-file",
    "const cacheKey = computeKey(input); monkey: banana bread; hotkey: control-shift-p",
    '{"input_tokens": 128000, "output_tokens": 4096, "max_tokens": 8192}',
    "tokenizer_name=cl100k_base and secrets: inherit",
    "Use a strong passkey policy; the DSN field is documented below.",
    "short values stay: DB_PASS=none, OPENAI_KEY=unset",
  ]) {
    assert.equal(redactSecrets(ordinary), ordinary);
  }
});

test("redaction stays linear on large single-token and dotted inputs", () => {
  // A quadratic filter needs minutes for these; a linear one needs milliseconds.
  for (const input of ["a".repeat(500_000), "a.".repeat(250_000), "ab_".repeat(200_000), "a://".repeat(100_000), "a-".repeat(250_000), "x_key=".repeat(80_000)]) {
    const started = performance.now();
    redactSecrets(input);
    assert.ok(performance.now() - started < 2_000, `redaction of ${input.length} characters was too slow`);
  }
});

test("a remote command never inherits a variable that may hold a credential", () => {
  // Names the narrower text rule lets through are still kept from commands.
  for (const name of ["STRIPEKEY", "MY_TOKEN_VALUE", "AZURE_CREDENTIAL_FILE", "SESSION_COOKIE_JAR", "OPENAI_API_KEY", "DB_PASS", "SENTRY_DSN"]) {
    assert.equal(credentialEnvironmentName(name), true, name);
  }
  assert.equal(credentialName("STRIPEKEY"), false, "free text keeps names without a separator");
  for (const name of ["PATH", "HOME", "PWD", "OLDPWD", "KEY", "LANG", "NODE_OPTIONS"]) {
    assert.equal(credentialEnvironmentName(name), false, name);
  }
});
