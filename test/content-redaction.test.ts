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
