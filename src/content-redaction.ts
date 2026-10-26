/** Pure redaction shared by collection and model egress. Run before truncation. */
export function redactSecrets(value: string, marker = "[REDACTED_SECRET]"): string {
  return value
    .replace(/\x1b\[[0-?]*[ -/]*[@-~]/gu, "")
    // An unterminated block is sensitive through the end, including bounded
    // command captures that stopped halfway through a private key.
    .replace(/-----BEGIN (?:[A-Z0-9 ]*PRIVATE KEY|PGP PRIVATE KEY BLOCK)-----[\s\S]*?(?:-----END (?:[A-Z0-9 ]*PRIVATE KEY|PGP PRIVATE KEY BLOCK)-----|$)/gu, marker)
    .replace(/\b(?:sk-[A-Za-z0-9_-]+|sk_(?:live|test)_[A-Za-z0-9]+|phg_m_[A-Za-z0-9_-]+|gh[pousr]_[A-Za-z0-9]+|github_pat_[A-Za-z0-9_]+|AKIA[0-9A-Z]+|xox[abeoprs]-[A-Za-z0-9-]+|AIza[0-9A-Za-z_-]{35}|npm_[A-Za-z0-9]{20,})\b/gu, marker)
    .replace(/\beyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*/gu, marker)
    // Bounded scheme length: an open-ended one made long dotted runs quadratic.
    .replace(/(\b[a-z][a-z0-9+.-]{0,31}:\/\/)[^\s/:@]+:[^\s/@]+@/giu, `$1${marker}@`)
    // Non-bearer schemes carry the credential after the scheme word.
    .replace(/(\bauthorization["']?\s*[:=]\s*)(?:Basic|Digest|Token)\s+[^\s,}"']+/giu, `$1${marker}`)
    .replace(/\b(Bearer\s+)[A-Za-z0-9._~+/=-]+/giu, `$1${marker}`)
    // No leading "[\w-]*": matching from the keyword itself keeps names such as
    // refresh_token covered without rescanning every word run (quadratic).
    .replace(/(["']?(?:api[_-]?key|token|secret(?:[_-]access[_-]key)?|password|passwd|private[_-]?key|authorization)["']?\s*[:=]\s*)(?:"[^"\n]*(?:"|$)|'[^'\n]*(?:'|$)|[^,\s}]+)/gimu, `$1${marker}`);
}
