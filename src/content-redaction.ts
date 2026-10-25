/** Pure redaction shared by collection and model egress. Run before truncation. */
export function redactSecrets(value: string, marker = "[REDACTED_SECRET]"): string {
  return value
    .replace(/\x1b\[[0-?]*[ -/]*[@-~]/gu, "")
    // An unterminated block is sensitive through the end, including bounded
    // command captures that stopped halfway through a private key.
    .replace(/-----BEGIN (?:[A-Z0-9 ]*PRIVATE KEY|PGP PRIVATE KEY BLOCK)-----[\s\S]*?(?:-----END (?:[A-Z0-9 ]*PRIVATE KEY|PGP PRIVATE KEY BLOCK)-----|$)/gu, marker)
    .replace(/\b(?:sk-[A-Za-z0-9_-]+|gh[pousr]_[A-Za-z0-9]+|github_pat_[A-Za-z0-9_]+|AKIA[0-9A-Z]+)\b/gu, marker)
    .replace(/\b(Bearer\s+)[A-Za-z0-9._~+/=-]+/giu, `$1${marker}`)
    .replace(/(["']?(?:api[_-]?key|access[_-]?token|client[_-]?secret|password|passwd|private[_-]?key|authorization)["']?\s*[:=]\s*)(?:"[^"\n]*(?:"|$)|'[^'\n]*(?:'|$)|[^,\s}]+)/gimu, `$1${marker}`);
}
