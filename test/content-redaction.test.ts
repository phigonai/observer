import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
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

test("redaction covers Phigon keys, temporary cloud keys, signing secrets and webhooks", () => {
  for (const token of [
    // Phigon access key: phg_<12 base32>_<32 base32>.
    ["phg", "_", filler("a", 6), "234567", "_", filler("b", 16), "abcdef7654322345"],
    // Phigon license key: phl_<base64url payload>.<base64url signature>.
    ["phl", "_", "eyJ2IjoxLCJpZCI6Im", filler("Q", 40), ".", filler("s", 40), "-_AbC12345", filler("z", 36)],
    // Phigon enrollment code: phe_<32 base64url characters>.
    ["phe", "_", randomBytes(24).toString("base64url")],
    ["phe", "_", filler("x", 10), "-_", filler("Y", 20)],
    ["AS", "IA", "Q3EGRLMN", "4XKP7TZW"],
    ["GOC", "SPX-", filler("k", 20), "_-Ab12Cd"],
    ["wh", "sec_", filler("m", 24), "+/AbC123=="],
    ["https://hooks.", "slack.com/services/", "T0", filler("A", 8), "/B0", filler("B", 8), "/", filler("c", 24)],
  ].map((parts) => parts.join(""))) {
    const safe = redactSecrets(`the token is ${token} today`);
    assert.equal(safe, "the token is [REDACTED_SECRET] today", token.slice(0, 8));
  }
  const password = filler("v", 14);
  for (const url of [`redis://:${password}@cache.internal:6379/0`, `amqp://:${password}@queue.internal`]) {
    const safe = redactSecrets(url);
    assert.match(safe, /REDACTED/u, url.slice(0, 8));
    assert.ok(!safe.includes(password), safe);
  }
});

test("new key formats leave lookalike words and addresses readable", () => {
  for (const ordinary of [
    "phg_status=ok and phl_note=see-docs",
    "phe_enrollment_codes_table and phe_ alone stay readable",
    "ASIA PACIFIC, ASIAN markets and ASIAPACIFIC_REGION",
    "GOCSPX- is the prefix and whsec_ marks a signing secret",
    "redis://cache.internal:6379/0 and https://example.com:8443/path",
    "https://hooks.slack.com/ is Slack's webhook host",
  ]) {
    assert.equal(redactSecrets(ordinary), ordinary);
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

test("redaction covers connection strings, signed URLs, command-line passwords and every cookie", () => {
  const secret = filler("s", 14);
  for (const source of [
    `Server=db.internal;User Id=sa;Pwd=${secret};Database=app`,
    `Server=db.internal; User Id=sa; Pwd=${secret}`,
    `Pwd=${secret};Server=db.internal`,
    `Data Source=db;Password=correct horse ${secret};`,
    `jdbc:sqlserver://db:1433;user=sa;password=${secret};`,
    `postgres://admin:p@ss/${secret}@db.internal:5432/app`,
    `mongodb+srv://admin:${secret}@cluster0.example.net/app?retryWrites=true`,
    `password: correct horse ${secret}`,
    `  db_password: "correct horse ${secret}"`,
    `- secret: two words ${secret}`,
    `https://acct.blob.core.windows.net/c/f.txt?sv=2022-11-02&se=2026&sig=${secret}%2B%3D`,
    `https://bucket.s3.amazonaws.com/k?X-Amz-Signature=${secret}&X-Amz-Date=1`,
    `mysql -h db -u root -p${secret} app`,
    `mysqldump --single-transaction -p'${secret}' app`,
    `sshpass -p ${secret} ssh deploy@host`,
    `redis-cli -h cache -a ${secret} ping`,
    `deploy --password ${secret} --verbose`,
    `gh auth login --token ${secret}`,
    `curl -u admin:${secret} https://api.example`,
    `curl --user "admin:${secret}" https://api.example`,
    `Cookie: theme=dark; lang=en; session=${secret}`,
    `Set-Cookie: a=b; sessionid=${secret}; Path=/; HttpOnly`,
    `curl -H 'Cookie: a=b; sid=${secret}' https://api.example`,
  ]) {
    const safe = redactSecrets(source);
    assert.match(safe, /REDACTED/u, source);
    assert.ok(!safe.includes(secret), `${source} -> ${safe}`);
  }
  // An "@" in the query or fragment does not decide where the password ends.
  const slashed = `${filler("p", 10)}/${filler("q", 10)}`;
  for (const source of [
    `postgres://admin:${slashed}@db.internal/app?owner=me@example.com`,
    `https://admin:${slashed}@db.internal:8080/#me@example.com`,
  ]) {
    const safe = redactSecrets(source);
    assert.ok(!safe.includes(filler("p", 10)) && !safe.includes(filler("q", 10)), `${source} -> ${safe}`);
    assert.match(safe, /\[REDACTED_SECRET\]@db\.internal/u);
    assert.match(safe, /me@example\.com$/u);
  }
  // Separate pieces of a password that has spaces are hidden too.
  assert.equal(redactSecrets(`password: correct horse battery`), "password: [REDACTED_SECRET]");
  assert.equal(redactSecrets(`Server=db;Pwd=correct horse;Database=app`), "Server=db;Pwd=[REDACTED_SECRET];Database=app");
});

test("escaped JSON text, quoted names and values that are themselves assignments are redacted", () => {
  const secret = filler("s", 14);
  for (const source of [
    // JSON inside JSON, as agents report command output.
    JSON.stringify({ output: `first\nAuthorization: Basic ${secret}\nlast` }),
    JSON.stringify({ output: JSON.stringify({ token: secret }) }),
    JSON.stringify({ output: `ok\nDB_PASS=${secret}\n` }),
    `echo 'OPENAI_KEY=${secret}'`,
    `run <API_TOKEN=${secret}>`,
    `error: OPENAI_KEY=${secret}`,
    `über: \`MYSQL_PWD=${secret}\``,
  ]) {
    const safe = redactSecrets(source);
    assert.match(safe, /REDACTED/u, source);
    assert.ok(!safe.includes(secret), `${source} -> ${safe}`);
  }
  // Escaped text that also holds line separators, or any other character,
  // is redacted the same way, and keeps every character outside a secret.
  const lineSeparator = String.fromCharCode(0x2028);
  const paragraphSeparator = String.fromCharCode(0x2029);
  const privateUse = String.fromCharCode(0xe000);
  for (const [source, expected] of [
    [`x\\nTOKEN=${secret}${lineSeparator}tail`, `x\\nTOKEN=[REDACTED_SECRET]${lineSeparator}tail`],
    [`line\\npassword: correct horse ${secret}${lineSeparator}tail`, `line\\npassword: [REDACTED_SECRET]${lineSeparator}tail`],
    [`a${paragraphSeparator}b\\nDB_PASS=${secret}${lineSeparator}tail`, `a${paragraphSeparator}b\\nDB_PASS=[REDACTED_SECRET]${lineSeparator}tail`],
    [`${lineSeparator}x\\nAuthorization: Basic ${secret}${paragraphSeparator}y`, `${lineSeparator}x\\nAuthorization: [REDACTED_SECRET]${paragraphSeparator}y`],
    // Both separators, with a private key across escaped lines.
    [
      `${lineSeparator}${paragraphSeparator}-----BEGIN RSA ${"PRIVATE KEY"}-----\\n${secret}\\n-----END RSA ${"PRIVATE KEY"}-----\\nDB_PASS=${secret}`,
      `${lineSeparator}${paragraphSeparator}[REDACTED_SECRET]\\nDB_PASS=[REDACTED_SECRET]`,
    ],
    [`x\\nDB_PASS=${secret}${privateUse} tail`, `x\\nDB_PASS=[REDACTED_SECRET] tail`],
  ] as const) {
    assert.equal(redactSecrets(source), expected);
  }
  // A character that is not a boundary belongs to the value it follows, in
  // escaped text as in plain text.
  const glued = `TOKEN=${secret}${privateUse}tail`;
  assert.equal(redactSecrets(`x\\n${glued}`), `x\\n${redactSecrets(glued)}`);
  // Where nothing is redacted every character stays where it was.
  for (const ordinary of [
    `a\\nb${lineSeparator}c${privateUse}d`,
    `${privateUse}\\t${lineSeparator}${paragraphSeparator}${lineSeparator}`,
  ]) {
    assert.equal(redactSecrets(ordinary), ordinary);
  }
  // The line breaks used while redacting escaped text are taken out again.
  const escaped = JSON.stringify({ output: `first\nDB_PASS=${secret}\nlast` });
  assert.deepEqual(JSON.parse(redactSecrets(escaped)), { output: "first\nDB_PASS=[REDACTED_SECRET]\nlast" });
  assert.equal(redactSecrets(JSON.stringify({ a: "line\nnext" })), JSON.stringify({ a: "line\nnext" }));
});

test("password-like options and addresses that hold no credential stay readable", () => {
  for (const ordinary of [
    "PWD=/home/example",
    "docker run -u 1000:1000 image",
    "git push -u origin main",
    "mysql -P 3306 -p app",
    "https://example.com:8080/?email=me@example.com",
    "ssh://git@github.com:22/org/repo.git",
    "https://example.com/a:b/c",
    "see the cookies: three of them",
    "deploy --password-file ./secret.txt",
  ]) {
    assert.equal(redactSecrets(ordinary), ordinary);
  }
});

test("redaction stays linear on large single-token and dotted inputs", () => {
  // Compare n with 4n characters instead of a time budget, which a busy
  // machine can miss: linear work grows about 4 times (up to 7 with garbage
  // collection), quadratic 16 times. The fastest of several interleaved
  // runs after a warm-up ignores pauses from other work.
  const fastest = (small: string, large: string): [number, number] => {
    let smallBest = Infinity;
    let largeBest = Infinity;
    redactSecrets(small);
    for (let run = 0; run < 3; run++) {
      let started = performance.now();
      redactSecrets(small);
      smallBest = Math.min(smallBest, performance.now() - started);
      started = performance.now();
      redactSecrets(large);
      largeBest = Math.min(largeBest, performance.now() - started);
      // A run this slow is far above timer noise; do not repeat it.
      if (largeBest > 1_000) break;
    }
    return [smallBest, largeBest];
  };
  for (const [unit, count] of [
    ["a", 500_000], ["a.", 250_000], ["ab_", 200_000], ["a://", 100_000], ["a-", 250_000], ["x_key=", 80_000], ["a://:", 80_000], ["phe_", 100_000],
    // Connection strings, command-line passwords, cookies, YAML lines and
    // addresses whose password holds "@" or "/".
    ["pwd=", 100_000], [";pwd=", 80_000], ["mysql -p", 60_000], ["-u a:", 80_000], ["cookie:", 60_000],
    ["password: a b\n", 30_000], ["--token ", 60_000], ["&sig=", 80_000], ["x://a/@", 60_000], ["x://a:b@c/", 40_000], ["x://a:b/c@d?e@", 30_000],
    // Escaped line breaks next to line separators, one or both kinds.
    [`k=\\n${String.fromCharCode(0x2028, 0xe000)}`, 60_000],
    [`k=\\n${String.fromCharCode(0x2028, 0x2029)}`, 40_000],
  ] as const) {
    const [small, large] = fastest(unit.repeat(count / 4), unit.repeat(count));
    // Under 50 ms for the large input cannot be quadratic at this size
    // (minutes), and keeps timer noise on tiny durations from deciding.
    assert.ok(
      large < 50 || large < small * 10,
      `redaction of ${JSON.stringify(unit)} grew from ${small.toFixed(1)} ms to ${large.toFixed(1)} ms for 4 times the input`,
    );
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
