/** Pure redaction shared by collection, model egress and command output. Run before truncation. */
export function redactSecrets(value: string, marker = "[REDACTED_SECRET]"): string {
  return value
    .replace(/\x1b\[[0-?]*[ -/]*[@-~]/gu, "")
    // An unterminated block is sensitive through the end, including bounded
    // command captures that stopped halfway through a private key.
    .replace(/-----BEGIN (?:[A-Z0-9 ]*PRIVATE KEY|PGP PRIVATE KEY BLOCK)-----[\s\S]*?(?:-----END (?:[A-Z0-9 ]*PRIVATE KEY|PGP PRIVATE KEY BLOCK)-----|$)/gu, marker)
    .replace(/\b(?:sk-[A-Za-z0-9_-]+|sk_(?:live|test)_[A-Za-z0-9]+|phg_m_[A-Za-z0-9_-]+|gh[pousr]_[A-Za-z0-9]+|github_pat_[A-Za-z0-9_]+|AKIA[0-9A-Z]+|xox[abeoprs]-[A-Za-z0-9-]+|AIza[0-9A-Za-z_-]{35}|npm_[A-Za-z0-9]{20,})\b/gu, marker)
    .replace(tokenFormats, marker)
    .replace(/\beyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*/gu, marker)
    // Bounded scheme length: an open-ended one made long dotted runs quadratic.
    // The user may be empty, as in redis://:password@host.
    .replace(/(\b[a-z][a-z0-9+.-]{0,31}:\/\/)[^\s/:@]*:[^\s/@]+@/giu, `$1${marker}@`)
    // Non-bearer schemes carry the credential after the scheme word.
    .replace(/(\bauthorization["']?\s*[:=]\s*)(?:Basic|Digest|Token)\s+[^\s,}"']+/giu, `$1${marker}`)
    .replace(/\b(Bearer\s+)[A-Za-z0-9._~+/=-]+/giu, `$1${marker}`)
    // No leading "[\w-]*": matching from the keyword itself keeps names such as
    // refresh_token covered without rescanning every word run (quadratic).
    .replace(/(["']?(?:api[_-]?key|token|secret(?:[_-]access[_-]key)?|password|passwd|private[_-]?key|authorization)["']?\s*[:=]\s*)(?:"[^"\n]*(?:"|$)|'[^'\n]*(?:'|$)|[^,\s}]+)/gimu, `$1${marker}`)
    // Any other NAME=value or "name": value whose name is a credential's.
    // Short values such as ids and booleans stay readable.
    .replace(assignment, (match: string, lead: string, quote: string, name: string, separator: string, item: string) =>
      credentialName(name) && item.replace(/^["']|["']$/gu, "").length >= 6 && !item.includes("[REDACTED")
        ? `${lead}${quote}${name}${quote}${separator}${marker}`
        : match);
}

/**
 * Names whose values are credentials, in environment variables and in
 * NAME=value text. A name ending in "key", "pass" or "pwd" counts after a
 * separator or a credential word only, so names such as monkey, cacheKey,
 * PWD and primary_key, and token counts such as max_tokens, stay readable.
 */
export function credentialName(name: string): boolean {
  const lower = name.toLowerCase();
  return credentialNamePattern.test(lower) && !keyNamePattern.test(lower);
}

/**
 * Names whose values may be credentials, judged broadly: which variables a
 * remote command may inherit from the observer's environment, and which
 * environment values are masked in its output. A command that misses a
 * variable costs little; one that receives a secret can print it, so this
 * keeps every name the narrower credentialName lets through, such as
 * STRIPEKEY, MY_TOKEN_VALUE or AZURE_CREDENTIAL_FILE.
 */
export function credentialEnvironmentName(name: string): boolean {
  const lower = name.toLowerCase();
  if (lower === "key" || lower === "pwd" || lower === "oldpwd") return false;
  return credentialName(name) || broadCredentialNamePattern.test(lower);
}

const broadCredentialNamePattern = /token|secret|passw(?:or)?d|api[_-]?key|passphrase|credential|cookie|(?:key|pwd)$|(?:^|[_.-])auth$|dsn$|connection[_-]?string/u;

// Well-known credential formats with a fixed prefix. Phigon access keys are
// phg_<12 base32>_<32 base32>; license keys are phl_<payload>.<signature> in
// base64url; enrollment codes are phe_<32 base64url>; AWS temporary key IDs
// are ASIA and 16 more characters.
const tokenFormats = /\b(?:phg_[a-z2-7]{12}_[a-z2-7]{32}|phl_[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{43,}|phe_[A-Za-z0-9_-]{32,}|ASIA[0-9A-Z]{16}\b|GOCSPX-[A-Za-z0-9_-]{20,}|whsec_[A-Za-z0-9+/]{20,}={0,2}|https?:\/\/hooks\.slack\.com\/services\/[A-Za-z0-9_/-]+|glpat-[A-Za-z0-9_-]{20,}|xapp-[A-Za-z0-9-]{10,}|hf_[A-Za-z0-9]{30,}|ya29\.[A-Za-z0-9_-]{20,}|SG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}|rk_(?:live|test)_[A-Za-z0-9]{10,}|shp(?:at|ca|pa|ss)_[a-fA-F0-9]{32}|dop_v1_[a-f0-9]{64}|pypi-[A-Za-z0-9_-]{50,})/gu;
const credentialNamePattern = /passw(?:or)?d|passphrase|secret(?!s$)|token$|credentials?$|cookie$|api[_-]?key$|(?:access|account|private|signing|encryption|master|license|subscription|client)[_-]?key$|[_.-](?:key|pass|pwd)$|(?:^|[_.-])auth$|dsn$|connection[_-]?string/u;
// Keys that name or index something rather than unlock it.
const keyNamePattern = /(?:primary|foreign|sort|partition|cache|public|idempotency|unique|hash|range|row|object|composite)[_.-]?key$/u;
const assignment = /(^|[\s;,{(&?-])(["']?)([A-Za-z_][A-Za-z0-9_.-]{0,127})\2([ \t]*[:=][ \t]*)("[^"\n]*"|'[^'\n]*'|[^\s,;}&]+)/gmu;
