import assert from "node:assert/strict";
import test from "node:test";
import { redactSecrets } from "../src/content-redaction.js";

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
    ["token=abcd1234efgh5678", "abcd1234"],
    ['{"refresh_token":"abcd1234efgh"}', "abcd1234"],
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

test("redaction stays linear on large single-token and dotted inputs", () => {
  // A quadratic filter needs minutes for these; a linear one needs milliseconds.
  for (const input of ["a".repeat(500_000), "a.".repeat(250_000), "ab_".repeat(200_000), "a://".repeat(100_000)]) {
    const started = performance.now();
    redactSecrets(input);
    assert.ok(performance.now() - started < 2_000, `redaction of ${input.length} characters was too slow`);
  }
});
