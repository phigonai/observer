/** Pure redaction shared by collection, model egress and command output. Run before truncation. */
export function redactSecrets(value: string, marker = "[REDACTED_SECRET]"): string {
  // JSON and other escaped text writes a line break or tab as a backslash and
  // a letter, which no pattern takes for a boundary: in "line\nPASSWORD=x"
  // the name runs into the n. While the patterns run, a line separator
  // (whitespace and a line end to them) stands on each side of each escape,
  // so a value ends before it and a name starts after it. The separator is
  // one the text does not hold, so taking it out again changes nothing else.
  if (!/\\[nrt]/u.test(value)) return redactText(value, marker);
  const separator = !value.includes("\u2028") ? "\u2028" : !value.includes("\u2029") ? "\u2029" : undefined;
  if (separator === undefined) {
    // Text that holds both line separators: private keys, which span
    // lines, are redacted in the whole text, the rest escaped line by
    // escaped line.
    return redactBlocks(value, marker)
      .split(/(\\[nrt])/u)
      .map((part, index) => index % 2 === 1 ? part : redactLines(part, marker))
      .join("");
  }
  return redactText(value.replace(/\\[nrt]/gu, `${separator}$&${separator}`), marker)
    .replaceAll(separator, "");
}

function redactText(value: string, marker: string): string {
  return redactLines(redactBlocks(value, marker), marker);
}

/** Terminal colour codes, and private keys, which span lines. */
function redactBlocks(value: string, marker: string): string {
  return value
    .replace(/\x1b\[[0-?]*[ -/]*[@-~]/gu, "")
    // An unterminated block is sensitive through the end, including bounded
    // command captures that stopped halfway through a private key.
    .replace(/-----BEGIN (?:[A-Z0-9 ]*PRIVATE KEY|PGP PRIVATE KEY BLOCK)-----[\s\S]*?(?:-----END (?:[A-Z0-9 ]*PRIVATE KEY|PGP PRIVATE KEY BLOCK)-----|$)/gu, marker);
}

/** Every other credential, each within a line. */
function redactLines(value: string, marker: string): string {
  return value
    .replace(/\b(?:sk-[A-Za-z0-9_-]+|sk_(?:live|test)_[A-Za-z0-9]+|phg_m_[A-Za-z0-9_-]+|gh[pousr]_[A-Za-z0-9]+|github_pat_[A-Za-z0-9_]+|AKIA[0-9A-Z]+|xox[abeoprs]-[A-Za-z0-9-]+|AIza[0-9A-Za-z_-]{35}|npm_[A-Za-z0-9]{20,})\b/gu, marker)
    .replace(tokenFormats, marker)
    .replace(/\beyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*/gu, marker)
    // A password may hold "@" or "/" (postgres://u:p@ss/w0rd@host): the
    // credentials run to the last "@" of the address. Each match consumes
    // the whole address, so long runs stay linear.
    .replace(/(\b[a-z][a-z0-9+.-]{0,31}:\/\/)([^\s"'<>`]+)/giu, (match: string, scheme: string, rest: string) =>
      addressWithoutCredentials(match, scheme, rest, marker))
    // Bounded scheme length: an open-ended one made long dotted runs quadratic.
    // The user may be empty, as in redis://:password@host. This also finds
    // an address inside another one's query.
    .replace(/(\b[a-z][a-z0-9+.-]{0,31}:\/\/)[^\s/:@]*:[^\s/@]+@/giu, `$1${marker}@`)
    // Signed URLs: Azure SAS, S3 and Cloud Storage signatures and tokens.
    .replace(/([?&](?:sig|signature|x-amz-signature|x-amz-security-token|x-goog-signature)=)[^&\s"'#<>]+/giu, `$1${marker}`)
    // Non-bearer schemes carry the credential after the scheme word.
    .replace(/(\bauthorization["']?\s*[:=]\s*)(?:Basic|Digest|Token)\s+[^\s,}"']+/giu, `$1${marker}`)
    .replace(/\b(Bearer\s+)[A-Za-z0-9._~+/=-]+/giu, `$1${marker}`)
    // Every cookie of a Cookie or Set-Cookie header, not only the first.
    .replace(/(\b(?:set-)?cookie["']?[ \t]*[:=][ \t]*)("[^"\r\n\u2028\u2029]*"|'[^'\r\n\u2028\u2029]*'|[^\r\n\u2028\u2029"']+)/giu, (match: string, lead: string, value: string) =>
      isMarker(value, marker) ? match : `${lead}${marker}`)
    // Connection strings: Server=…;User Id=…;Pwd=correct horse;. The value
    // runs to the next ";". A ";" before or after keeps PWD=/home/me, the
    // shell's working directory, readable.
    .replace(/(^|[;\s"'])((?:pwd|password|passwd)[ \t]*=[ \t]*)([^;\r\n\u2028\u2029"']*)(;?)/gimu, (match: string, lead: string, name: string, value: string, end: string, offset: number, whole: string) =>
      value.trim() !== "" &&
      !isMarker(value, marker) &&
      (end === ";" || lead === ";" || /;[ \t]*$/u.test(whole.slice(Math.max(0, offset - 16), offset + lead.length)))
        ? `${lead}${name}${marker}${end}`
        : match)
    // Passwords given on a command line: mysql -pSECRET, sshpass -p SECRET,
    // redis-cli -a SECRET. Each match consumes the command it looks in.
    .replace(/\b(mysql|mysqldump|mysqladmin|mysqlimport|mysqlcheck|mysqlshow|mariadb|mariadb-dump|sshpass|redis-cli)\b[^\r\n\u2028\u2029|;&]*/giu, (command: string, tool: string) =>
      command.replace(commandPasswordFlags(tool.toLowerCase()), `$1${marker}`))
    .replace(/((?:^|\s)--(?:password|passwd|pass|token|secret|api-key|apikey|client-secret|access-token|auth-token|private-key|cookie)(?:=|[ \t]+))(?!-)(?:"[^"\r\n\u2028\u2029]*"|'[^'\r\n\u2028\u2029]*'|[^\s"']+)/giu, `$1${marker}`)
    // curl -u user:password; a numeric uid:gid, as in docker -u 1000:1000,
    // stays.
    .replace(/((?:^|\s)(?:-u|--user)(?:=|[ \t]*))(["']?)([^\s:"']*):([^\s"']+)\2/gu, (match: string, flag: string, quote: string, user: string, password: string) =>
      /^\d*$/u.test(user) && /^\d+$/u.test(password)
        ? match
        : `${flag}${quote}${user}:${marker}${quote}`)
    // YAML and similar lines whose credential value has spaces:
    // `password: correct horse battery`. Single words are left to the rules
    // below.
    .replace(/^([ \t]*(?:-[ \t]+)?)(["']?)([A-Za-z_][A-Za-z0-9_.-]{0,127})\2([ \t]*:[ \t]+)([^\r\n\u2028\u2029]+)$/gmu, (match: string, indent: string, quote: string, name: string, separator: string, value: string) => {
      if (!credentialName(name) || isMarker(value, marker)) return match;
      const quoted = /^(["'])(.*)\1(,?)[ \t]*$/u.exec(value);
      if (!/\S\s+\S/u.test(quoted?.[2] ?? value)) return match;
      const replacement = quoted === null
        ? marker
        : `${quoted[1] ?? ""}${marker}${quoted[1] ?? ""}${quoted[3] ?? ""}`;
      return `${indent}${quote}${name}${quote}${separator}${replacement}`;
    })
    // No leading "[\w-]*": matching from the keyword itself keeps names such as
    // refresh_token covered without rescanning every word run (quadratic).
    // A quote may be escaped, as in JSON inside JSON: {\"token\": \"…\"}.
    .replace(/(\\?["']?(?:api[_-]?key|token|secret(?:[_-]access[_-]key)?|password|passwd|private[_-]?key|authorization)\\?["']?\s*[:=]\s*)(?!\[REDACTED)(?:\\?"[^"\n\u2028\u2029]*(?:"|$)|'[^'\n\u2028\u2029]*(?:'|$)|[^,\s}]+)/gimu, `$1${marker}`)
    // Any other NAME=value or "name": value whose name is a credential's.
    // Short values such as ids and booleans stay readable.
    .replace(assignment, (match: string, lead: string, quote: string, name: string, separator: string, item: string) => {
      if (!credentialName(name)) {
        // The value may itself be NAME=value, as in "error: TOKEN=…".
        return `${lead}${quote}${name}${quote}${separator}${nestedAssignment(item, marker)}`;
      }
      return credentialValue(item)
        ? `${lead}${quote}${name}${quote}${separator}${marker}`
        : match;
    });
}

/** Long enough to be a credential, and not redacted already. */
function credentialValue(item: string): boolean {
  return item.replace(/^["']|["']$/gu, "").length >= 6 && !item.includes("[REDACTED");
}

/**
 * A value that holds further NAME=value pairs, with the first credential's
 * value redacted. Only a few levels are read, so each value is scanned a
 * bounded number of times.
 */
function nestedAssignment(item: string, marker: string): string {
  let prefix = "";
  let rest = item;
  for (let depth = 0; depth < 4; depth++) {
    // A quote or bracket may open the inner pair: `TOKEN=…`.
    const inner = /^([^A-Za-z0-9_\s]{0,4})([A-Za-z_][A-Za-z0-9_.-]{0,127})([ \t]*[:=][ \t]*)([\s\S]+)$/u.exec(rest);
    if (inner === null) return item;
    const [, opening = "", name = "", separator = "", value = ""] = inner;
    if (credentialName(name)) {
      return credentialValue(value) ? `${prefix}${opening}${name}${separator}${marker}` : item;
    }
    prefix += `${opening}${name}${separator}`;
    rest = value;
  }
  return item;
}

/**
 * An address (`scheme://` and what follows up to a space or quote) with its
 * user and password replaced. The query and fragment are set aside first,
 * since an "@" there belongs to a value such as an e-mail address. In what
 * is left the credentials end at the last "@" and start with a "user:"
 * before any "/", so a path holding ":" stays.
 */
function addressWithoutCredentials(match: string, scheme: string, rest: string, marker: string): string {
  const query = rest.search(/[?#]/u);
  const at = (query < 0 ? rest : rest.slice(0, query)).lastIndexOf("@");
  if (at <= 0) return match;
  const credentials = rest.slice(0, at);
  const colon = credentials.indexOf(":");
  if (colon < 0 || credentials.slice(0, colon).includes("/")) return match;
  if (isMarker(credentials, marker)) return match;
  return `${scheme}${marker}@${rest.slice(at + 1)}`;
}

/** Whether a value is only the redaction marker, quoted or not. */
function isMarker(value: string, marker: string): boolean {
  return value.trim().replace(/^["']|["']?,?$/gu, "") === marker;
}

/** Each tool's command-line password option, with the option kept in $1. */
function commandPasswordFlags(tool: string): RegExp {
  if (tool === "sshpass") return /(\s-p[ \t]*)(?:"[^"\r\n\u2028\u2029]*"|'[^'\r\n\u2028\u2029]*'|[^\s"']+)/gu;
  if (tool === "redis-cli") return /(\s-a[ \t]+)(?:"[^"\r\n\u2028\u2029]*"|'[^'\r\n\u2028\u2029]*'|[^\s"']+)/gu;
  // mysql's -p takes the password only when joined to it; a separate word
  // is the database name.
  return /(\s-p)(?=[^\s-])(?:"[^"\r\n\u2028\u2029]*"|'[^'\r\n\u2028\u2029]*'|[^\s"']+)/gu;
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

/**
 * Whether a field of structured data (a JSON key, a header name) holds a
 * credential. camelCase and hyphens count as separators, so accessToken,
 * clientSecret, x-api-key and refreshToken are credentials, while counts and
 * indexes such as max_tokens, tokenCount, primaryKey and cacheKey are not.
 */
export function credentialFieldName(name: string): boolean {
  if (name.length > 128) return false;
  const normalized = name
    .replace(/([a-z0-9])([A-Z])/gu, "$1_$2")
    .replace(/([A-Z]+)([A-Z][a-z])/gu, "$1_$2")
    .replace(/[^A-Za-z0-9]+/gu, "_")
    .toLowerCase();
  return credentialName(normalized) || credentialFieldPattern.test(normalized);
}

// Field names credentialName leaves readable in free text but that hold
// credentials in structured data.
const credentialFieldPattern = /(?:^|_)(?:authorization|cookies|secrets|api_?keys|private_?keys|(?:access|refresh|id|session|auth|bearer|csrf|xsrf)_?tokens|pin|pin_?code|passcode|(?:auth|authorization|verification|security|recovery|confirmation|sms|login|one_?time)_?codes?)$|(?:^|_)(?:otp|totp|hotp|mfa|2fa|two_?factor)(?:_|$)/u;

const broadCredentialNamePattern =/token|secret|passw(?:or)?d|api[_-]?key|passphrase|credential|cookie|(?:key|pwd)$|(?:^|[_.-])auth$|dsn$|connection[_-]?string/u;

// Well-known credential formats with a fixed prefix. Phigon access keys are
// phg_<12 base32>_<32 base32>; license keys are phl_<payload>.<signature> in
// base64url; enrollment codes are phe_<32 base64url>; AWS temporary key IDs
// are ASIA and 16 more characters.
const tokenFormats = /\b(?:phg_[a-z2-7]{12}_[a-z2-7]{32}|phl_[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{43,}|phe_[A-Za-z0-9_-]{32,}|phu_[a-z2-7]{32}|ASIA[0-9A-Z]{16}\b|GOCSPX-[A-Za-z0-9_-]{20,}|whsec_[A-Za-z0-9+/]{20,}={0,2}|https?:\/\/hooks\.slack\.com\/services\/[A-Za-z0-9_/-]+|glpat-[A-Za-z0-9_-]{20,}|xapp-[A-Za-z0-9-]{10,}|hf_[A-Za-z0-9]{30,}|ya29\.[A-Za-z0-9_-]{20,}|SG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}|rk_(?:live|test)_[A-Za-z0-9]{10,}|shp(?:at|ca|pa|ss)_[a-fA-F0-9]{32}|dop_v1_[a-f0-9]{64}|pypi-[A-Za-z0-9_-]{50,})/gu;
const credentialNamePattern = /passw(?:or)?d|passphrase|secret(?!s$)|token$|credentials?$|cookie$|api[_-]?key$|(?:access|account|private|signing|encryption|master|license|subscription|client)[_-]?key$|[_.-](?:key|pass|pwd)$|(?:^|[_.-])auth$|dsn$|connection[_-]?string/u;
// Keys that name or index something rather than unlock it.
const keyNamePattern = /(?:primary|foreign|sort|partition|cache|public|idempotency|unique|hash|range|row|object|composite)[_.-]?key$/u;
// The name starts after any character a name cannot hold, so 'TOKEN=…',
// <TOKEN=…> and `TOKEN=…` count as well as a TOKEN=… word.
const assignment = /(^|[^A-Za-z0-9_.])(\\?["']|)([A-Za-z_][A-Za-z0-9_.-]{0,127})\2([ \t]*[:=][ \t]*)("[^"\n\u2028\u2029]*"|'[^'\n\u2028\u2029]*'|[^\s,;}&]+)/gmu;
