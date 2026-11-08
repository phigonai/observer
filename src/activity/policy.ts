import { credentialFieldName, redactSecrets } from "../content-redaction.js";
import { createHash, createHmac } from "node:crypto";
import { CONTENT_COLLECTION_CATEGORIES, type CollectionPolicy } from "../config.js";
import { commandSummary } from "./command-line.js";
import { processIdentifierKey } from "./identifier-key.js";

export type ContentCategory =
  | "promptContent"
  | "responseContent"
  | "reasoningContent"
  | "commandArguments"
  | "terminalOutput"
  | "fileContent"
  | "browserContent"
  | "gitPatchContent"
  | "toolOutput"
  | "vendorPayload";

export type MetadataCategory =
  | "processMetadata"
  | "fileMetadata"
  | "networkMetadata"
  | "browserMetadata";

export type SanitizedContent = Readonly<{
  value?: string;
  redacted: boolean;
  truncated: boolean;
}>;

type StructuredPolicy = Pick<
  CollectionPolicy,
  | "browserContent"
  | "browserUrls"
  | "commandArguments"
  | "environmentValues"
  | "fileContent"
  | "filePaths"
  | "gitPatchContent"
  | "networkEndpoints"
  | "promptContent"
  | "reasoningContent"
  | "responseContent"
  | "terminalOutput"
  | "toolOutput"
>;

export type ContentLimits = Readonly<{
  summaryBytes: number;
  contentBytes: number;
  toolArgumentsBytes: number;
  toolOutputBytes: number;
  terminalOutputBytes: number;
  vendorPayloadBytes: number;
}>;

const defaultLimits: ContentLimits = Object.freeze({
  summaryBytes: 512,
  contentBytes: 64 << 10,
  toolArgumentsBytes: 128 << 10,
  toolOutputBytes: 256 << 10,
  terminalOutputBytes: 64 << 10,
  vendorPayloadBytes: 512 << 10,
});

const maxNameInput = 1_024;
// A path from a root, a drive, a share or the home folder, through at least
// one folder, anywhere in a value: /home/alice/x, session-/home/alice/x,
// C:\tools\x, \\server\share, ~/x. A relative name such as
// github/create_issue or anthropic/claude-3.5, or a /command, is not one.
const embeddedPathPattern =
  /(?:^|[^A-Za-z0-9.])(?:~[\\/]|[A-Za-z]:[\\/]|\\\\|[\\/][^\\/\s]+[\\/])/u;
// An address's scheme, anywhere in a value.
const embeddedSchemePattern = /([A-Za-z][A-Za-z0-9+.-]{0,31}):\/\//gu;
// A host or IP address with a port, anywhere in a value: db.internal:5432.
const embeddedEndpointPattern =
  /(?:^|[^A-Za-z0-9.])(?:\[[0-9A-Fa-f:]+\]|(?:\d{1,3}\.){3}\d{1,3}|[A-Za-z0-9-]{1,63}(?:\.[A-Za-z0-9-]{1,63}){0,7}\.[A-Za-z]{2,24}):\d{1,5}(?!\d)/u;

/**
 * Whether a short value such as an ID or a name holds, anywhere in it, a
 * path, URL or endpoint that `policy` does not collect. Timestamps, model
 * names, relative names and ordinary IDs hold none.
 */
function containsWithheldAddress(policy: CollectionPolicy, value: string): boolean {
  // An address's own path is judged with the address, by its scheme.
  const withoutAddresses = value.replace(/[A-Za-z][A-Za-z0-9+.-]{0,31}:\/\/\S*/gu, " ");
  if (!policy.filePaths && embeddedPathPattern.test(withoutAddresses)) return true;
  if (!policy.networkEndpoints && embeddedEndpointPattern.test(withoutAddresses)) return true;
  for (const match of value.matchAll(embeddedSchemePattern)) {
    const scheme = (match[1] ?? "").toLowerCase();
    const collected = /^(?:https?|wss?)$/u.test(scheme)
      ? policy.browserUrls
      : scheme === "file"
        ? policy.filePaths
        : policy.networkEndpoints;
    if (!collected) return true;
  }
  return false;
}

export class LocalPolicyEngine {
  readonly #collection: CollectionPolicy;
  readonly #pathPatterns: readonly string[];
  readonly #limits: ContentLimits;
  readonly #identifierKey: Uint8Array;

  /**
   * `identifierKey` keys the digests sent in place of paths, addresses and
   * records (see loadIdentifierKey); without one, a key that lasts as long
   * as the process is used, never a plain hash.
   */
  constructor(
    collection: CollectionPolicy,
    pathPatterns: readonly string[] = [],
    limits: ContentLimits = defaultLimits,
    identifierKey: Uint8Array = processIdentifierKey(),
  ) {
    this.#collection = collection;
    this.#pathPatterns = pathPatterns;
    this.#limits = limits;
    this.#identifierKey = identifierKey;
  }

  /**
   * The digest sent in place of a path, address or record: an HMAC-SHA-256
   * with this installation's secret key, so withheld values cannot be found
   * by hashing guesses such as common home folders. The same value gives the
   * same digest on this computer only.
   */
  digestIdentifier(value: string): string {
    return createHmac("sha256", this.#identifierKey).update(value).digest("hex");
  }

  summary(value: string): string {
    return this.#redactAndTruncate(value, this.#limits.summaryBytes).value;
  }

  allowsMetadata(category: MetadataCategory): boolean {
    return this.#collection[category];
  }

  content(
    value: unknown,
    category: ContentCategory,
  ): SanitizedContent {
    if (!this.#collection[category]) {
      return { redacted: true, truncated: false };
    }
    const limit = this.#limitFor(category);
    if (
      value !== null &&
      typeof value === "object" &&
      !Buffer.isBuffer(value)
    ) {
      // Structured content is redacted value by value, as in json().
      const redacted = this.#redactTree(value);
      const truncated = truncateUTF8(serializeTree(redacted.value), limit);
      return {
        value: truncated.value,
        redacted: redacted.changed,
        truncated: redacted.truncated || truncated.truncated,
      };
    }
    const text = stringValue(value);
    if (text === "") {
      return { value: "", redacted: false, truncated: false };
    }
    return this.#redactAndTruncate(text, limit);
  }

  json(
    value: unknown,
    category: "commandArguments" | "toolOutput",
  ): SanitizedContent {
    if (value === undefined) return { redacted: false, truncated: false };
    if (!this.#collection[category]) {
      return { redacted: true, truncated: false };
    }
    const policySanitized = sanitizeStructuredValue(
      value,
      this.#collection,
    );
    // Each string is redacted before serializing: JSON escaping turns a
    // newline into a backslash and n and puts a quote before each value,
    // which hides credentials from the text patterns.
    const redacted = this.#redactTree(policySanitized.value);
    const serialized = serializeTree(redacted.value);
    const limit = this.#limitFor(category);
    if (Buffer.byteLength(serialized, "utf8") <= limit) {
      // A bound that left something out makes the result incomplete even
      // when it fits the limit.
      return {
        value: serialized,
        redacted: policySanitized.changed || redacted.changed,
        truncated: redacted.truncated,
      };
    }
    return {
      value: JSON.stringify({
        _phigon: "truncated",
        sha256: digest(serialized),
      }),
      redacted: true,
      truncated: true,
    };
  }

  vendorRecord(value: unknown): Readonly<{
    digest: string;
    value?: string;
    redacted: boolean;
    truncated: boolean;
    redactedFields: readonly string[];
  }> {
    const original = serializeNormalized(value);
    const recordDigest = this.digestIdentifier(original);
    if (!this.#collection.vendorPayload) {
      return {
        digest: recordDigest,
        redacted: true,
        truncated: false,
        redactedFields: [],
      };
    }
    const redactedFields: string[] = [];
    const policySanitized = sanitizeStructuredValue(
      value,
      this.#collection,
      true,
    );
    const sanitized = sanitizeVendorStructure(
      policySanitized.value,
      "",
      redactedFields,
      (text) => this.#redact(text),
    );
    let serialized = serializeNormalized(sanitized);
    let changed =
      policySanitized.changed ||
      redactedFields.length > 0 ||
      serialized !== original;
    const limit = this.#limits.vendorPayloadBytes;
    if (Buffer.byteLength(serialized, "utf8") > limit) {
      serialized = JSON.stringify({
        _phigon: "truncated",
        sha256: digest(serialized),
      });
      changed = true;
      return {
        digest: recordDigest,
        value: serialized,
        redacted: changed,
        truncated: true,
        redactedFields,
      };
    }
    return {
      digest: recordDigest,
      value: serialized,
      redacted: changed,
      truncated: false,
      redactedFields,
    };
  }

  identifier(
    raw: unknown,
    category: "filePaths" | "browserUrls" | "networkEndpoints",
  ): Readonly<{ digest: string; value?: string; redacted: boolean }> {
    const text = stringValue(raw);
    if (text === "") return { digest: "", redacted: true };
    const result = this.#redactAndTruncate(text, 8 << 10);
    if (!this.#collection[category]) {
      return { digest: this.digestIdentifier(text), redacted: true };
    }
    return {
      digest: this.digestIdentifier(text),
      value: result.value,
      redacted: result.redacted,
    };
  }

  /**
   * A short identifier-like name (tool, program, invocation, record type).
   * Names are sent under every profile, so a value that held a secret or a
   * private path is replaced by the fallback, and an address keeps only its
   * scheme: addresses are collected only where the profile allows them.
   */
  safeName(value: unknown, fallback: string): string {
    const raw = stringValue(value);
    // Longer than any name; it may be pasted content.
    if (raw.length > maxNameInput) return fallback;
    if (this.#redact(raw).changed) return fallback;
    const withoutAddresses = raw.replace(/([A-Za-z][A-Za-z0-9+.-]{0,31}):\/\/\S*/gu, "$1");
    // A name that holds a folder path or an endpoint anywhere is sent only
    // where those are collected.
    if (containsWithheldAddress(this.#collection, withoutAddresses)) return fallback;
    const text = withoutAddresses
      .replace(/[^A-Za-z0-9._:/-]+/gu, "-")
      .replace(/^-+|-+$/gu, "")
      .slice(0, 128);
    return text || fallback;
  }

  #limitFor(category: ContentCategory): number {
    if (category === "commandArguments") {
      return this.#limits.toolArgumentsBytes;
    }
    if (category === "toolOutput") return this.#limits.toolOutputBytes;
    if (category === "terminalOutput") {
      return this.#limits.terminalOutputBytes;
    }
    if (category === "vendorPayload") {
      return this.#limits.vendorPayloadBytes;
    }
    return this.#limits.contentBytes;
  }

  #redactAndTruncate(
    value: string,
    limit: number,
  ): Readonly<{
    value: string;
    redacted: boolean;
    truncated: boolean;
  }> {
    // Redaction sees well past the limit, so a credential the limit cuts
    // through is still recognised whole.
    const bounded = boundForRedaction(value, Math.max(limit * 4, 64 << 10));
    const redacted = this.#redact(bounded.value);
    const truncated = truncateUTF8(redacted.value, limit);
    return {
      value: truncated.value,
      redacted: redacted.changed,
      truncated: bounded.bounded || truncated.truncated,
    };
  }

  #redact(value: string): Readonly<{ value: string; changed: boolean }> {
    let result = value;
    for (const pattern of this.#pathPatterns) {
      if (pattern === "") continue;
      result = result.split(pattern).join("[REDACTED_PATH]");
    }
    result = redactSecrets(result);
    return { value: result, changed: result !== value };
  }

  /**
   * A JSON-ready copy of `value` within the normalized bounds, with every
   * string and key redacted, and every value under a credential-named key
   * (accessToken, password, x-api-key) masked whatever its type. Empty
   * strings, booleans and null carry no secret and stay. `truncated` says
   * that a bound left something out: deep nesting, items past the 256th,
   * keys past the 128th, or the end of a long string or key.
   */
  #redactTree(
    value: unknown,
    depth = 0,
    masked = false,
  ): Readonly<{ value: unknown; changed: boolean; truncated: boolean }> {
    if (depth >= 8) return { value: "[MAX_DEPTH]", changed: false, truncated: true };
    if (value === null || typeof value === "boolean") {
      return { value, changed: false, truncated: false };
    }
    if (typeof value === "number" || typeof value === "bigint") {
      if (masked) return { value: secretMarker, changed: true, truncated: false };
      return { value: typeof value === "bigint" ? value.toString() : value, changed: false, truncated: false };
    }
    if (typeof value === "string") {
      if (value === "") return { value, changed: false, truncated: false };
      if (masked) {
        return { value: secretMarker, changed: value !== secretMarker, truncated: false };
      }
      const bounded = boundForRedaction(value, maxStructuredString * 4);
      const redacted = this.#redact(bounded.value);
      return {
        value: redacted.value.slice(0, maxStructuredString),
        changed: redacted.changed,
        truncated: bounded.bounded || redacted.value.length > maxStructuredString,
      };
    }
    if (Array.isArray(value)) {
      let changed = false;
      let truncated = value.length > maxStructuredItems;
      const result = value.slice(0, maxStructuredItems).map((item) => {
        const child = this.#redactTree(item, depth + 1, masked);
        changed ||= child.changed;
        truncated ||= child.truncated;
        return child.value;
      });
      return { value: result, changed, truncated };
    }
    if (typeof value === "object") {
      let changed = false;
      const keys = Object.keys(value);
      let truncated = keys.length > maxStructuredKeys;
      const result: Record<string, unknown> = Object.create(null);
      for (const key of keys.sort().slice(0, maxStructuredKeys)) {
        const name = this.#redactKey(key, result);
        const child = this.#redactTree(
          (value as Record<string, unknown>)[key],
          depth + 1,
          masked || credentialFieldName(key),
        );
        result[name] = child.value;
        changed ||= child.changed || name !== key.slice(0, 128);
        truncated ||= child.truncated || (name === key.slice(0, 128) && key.length > 128);
      }
      return { value: result, changed, truncated };
    }
    return { value: String(value), changed: false, truncated: false };
  }

  /** A key with its secrets and private paths removed, unique in `taken`. */
  #redactKey(key: string, taken: Readonly<Record<string, unknown>>): string {
    if (!this.#redact(key).changed) return key.slice(0, 128);
    let name = secretMarker;
    for (let index = 2; Object.hasOwn(taken, name); index++) {
      name = `${secretMarker}#${index}`;
    }
    return name;
  }
}

const secretMarker = "[REDACTED_SECRET]";
const maxStructuredString = 64 << 10;
const maxStructuredItems = 256;
const maxStructuredKeys = 128;
const maxVendorString = 256 << 10;

/**
 * At most `maximum` characters of `value` for redaction to read before the
 * result is cut to a smaller limit. A word the bound cuts through is
 * dropped: its first part may be too short for any pattern to recognise.
 */
export function boundForRedaction(
  value: string,
  maximum: number,
): Readonly<{ value: string; bounded: boolean }> {
  if (value.length <= maximum) return { value, bounded: false };
  let end = maximum;
  if (!/\s/u.test(value[end] ?? "")) {
    while (end > 0 && !/\s/u.test(value[end - 1] ?? "")) end--;
  }
  return { value: value.slice(0, end), bounded: true };
}

function serializeTree(value: unknown): string {
  try {
    return JSON.stringify(value);
  } catch {
    return JSON.stringify({ _phigon: "unserializable" });
  }
}

export function sanitizeStructuredValue(
  value: unknown,
  policy: StructuredPolicy,
  failClosedUnclassifiedStrings = false,
): Readonly<{ value: unknown; changed: boolean }> {
  return sanitizeStructuredNode(
    value,
    policy,
    "",
    0,
    undefined,
    failClosedUnclassifiedStrings,
  );
}

export function truncateUTF8(
  value: string,
  maximumBytes: number,
): Readonly<{ value: string; truncated: boolean }> {
  const bytes = Buffer.from(value, "utf8");
  if (bytes.length <= maximumBytes) {
    return { value, truncated: false };
  }
  let end = maximumBytes;
  while (end > 0) {
    try {
      const decoded = new TextDecoder("utf-8", { fatal: true }).decode(
        bytes.subarray(0, end),
      );
      return { value: decoded, truncated: true };
    } catch {
      end--;
    }
  }
  return { value: "", truncated: true };
}

function normalizeStructure(value: unknown, depth: number): unknown {
  if (depth >= 8) return "[MAX_DEPTH]";
  if (
    value === null ||
    typeof value === "boolean" ||
    typeof value === "number"
  ) {
    return value;
  }
  if (typeof value === "string") return value.slice(0, 64 << 10);
  if (typeof value === "bigint") return value.toString();
  if (Array.isArray(value)) {
    return value
      .slice(0, 256)
      .map((item) => normalizeStructure(item, depth + 1));
  }
  if (typeof value === "object") {
    const result: Record<string, unknown> = Object.create(null);
    for (const key of Object.keys(value).sort().slice(0, 128)) {
      result[key.slice(0, 128)] = normalizeStructure(
        (value as Record<string, unknown>)[key],
        depth + 1,
      );
    }
    return result;
  }
  return String(value);
}

const policyRedactedValue = "[REDACTED_POLICY]";

export type StorableRecordOptions = Readonly<{
  /**
   * What may be collected on this computer. A value in a category it leaves
   * off is stored only as the metadata that category's profile reads.
   */
  policy: CollectionPolicy;
  /** The installation's key for digests (loadIdentifierKey). */
  identifierKey: Uint8Array;
  /** PHIGON_REDACT_PATH_PATTERNS: text replaced wherever it appears. */
  pathPatterns?: readonly string[];
}>;

/**
 * A copy of an activity record fit to wait on disk until the collector reads
 * it. Secrets are always redacted and values under credential-named keys
 * masked. Every value in a category the policy leaves off, and every
 * unclassified value when no content is collected at all, is replaced, and
 * what the metadata profile reads stays: types, roles, IDs, names,
 * timestamps, a command's program and Git operation, and keyed digests in
 * place of paths and addresses.
 */
export function storableRecord(
  value: unknown,
  options: StorableRecordOptions,
): unknown {
  return storableNode(value, options, "", undefined, 0, undefined, false);
}

function storableNode(
  value: unknown,
  options: StorableRecordOptions,
  key: string,
  parent: Readonly<Record<string, unknown>> | undefined,
  depth: number,
  inheritedCategory: keyof StructuredPolicy | undefined,
  masked: boolean,
): unknown {
  if (depth >= 64) return "[MAX_DEPTH]";
  if (value === null || typeof value === "boolean") return value;
  const rawNumber = isRawJSONNumber(value);
  const explicitCategory = structuredCategory(key, parent);
  // Inside a category the policy withholds, everything stays withheld,
  // whatever a field's own name says: a prompt inside withheld tool output
  // is still withheld output, and env.PATH is an environment value, not a
  // path. What the metadata profile reads (a path's digest, a command's
  // program) still comes from the field's own name.
  const category =
    inheritedCategory !== undefined && !options.policy[inheritedCategory]
      ? inheritedCategory
      : explicitCategory ?? inheritedCategory;
  if (typeof value === "number" || typeof value === "bigint" || rawNumber) {
    if (masked) return secretMarker;
    // A number in a category the policy leaves off is withheld like text,
    // except a time, ID, count or exit code the collector reads; nothing
    // in the environment is kept.
    if (
      !collected(options.policy, category) &&
      (category === "environmentValues" ||
        !(numericMetadataKeyPattern.test(normalizedKey(key)) || numericIdKeyPattern.test(key)))
    ) {
      return policyRedactedValue;
    }
    // A number from parseLosslessJSON is written back exactly as it was.
    return typeof value === "bigint" ? value.toString() : value;
  }
  if (typeof value === "string") {
    if (value === "") return value;
    if (masked) return secretMarker;
    // JSON text inside a record, as tool arguments often are, is stored
    // value by value under the same rules, whatever its category.
    const json = jsonContainer(value);
    if (json !== undefined) {
      const stored = JSON.stringify(storableNode(json, options, "", undefined, depth + 1, category, false));
      // Nothing changed but layout: the text as it was, byte for byte.
      return stored === compactJSON(value) ? value : stored;
    }
    const redacted = redactSecrets(redactPaths(value, options.pathPatterns));
    if (storedAsIs(options.policy, category, redacted)) {
      // An ID or name keeps no withheld address, even where its content
      // would be collected.
      return identityLike(key, redacted) && containsWithheldAddress(options.policy, redacted)
        ? storedDigest(options, redacted)
        : redacted;
    }
    return storableMetadataString(redacted, options, key, explicitCategory, category);
  }
  if (Array.isArray(value)) {
    const strings = value.every((item) => typeof item === "string");
    if (
      !masked &&
      strings &&
      value.length > 0 &&
      /^(?:command|cmd|argv)$/u.test(normalizedKey(key)) &&
      !storedAsIs(options.policy, category, "")
    ) {
      // An argv array: its program and operation, word by word.
      const summary = commandSummary(redactSecrets(redactPaths(value.join(" "), options.pathPatterns)));
      return summary === "" ? [policyRedactedValue] : summary.split(" ");
    }
    return value.map((item) =>
      storableNode(item, options, "", undefined, depth + 1, category, masked)
    );
  }
  if (typeof value === "object") {
    const result: Record<string, unknown> = Object.create(null);
    for (const [childKey, child] of Object.entries(value)) {
      const name = storableKey(childKey, options, category, result);
      result[name] = storableNode(
        child,
        options,
        childKey,
        value as Record<string, unknown>,
        depth + 1,
        category,
        masked || credentialFieldName(childKey),
      );
    }
    return result;
  }
  return undefined;
}

function storableMetadataString(
  value: string,
  options: StorableRecordOptions,
  key: string,
  explicitCategory: keyof StructuredPolicy | undefined,
  category: keyof StructuredPolicy | undefined,
): string {
  const digestOf = (text: string) => storedDigest(options, text);
  if (category === "environmentValues") return policyRedactedValue;
  // An address the policy withholds is a digest under any key, a name or a
  // model included, so this comes before anything is kept for its key.
  if (
    explicitCategory === "filePaths" ||
    explicitCategory === "browserUrls" ||
    explicitCategory === "networkEndpoints" ||
    withheldAddress(options.policy, value)
  ) {
    return digestOf(value);
  }
  // What the collector reads to attribute, order and name a record, and a
  // record's kind, role or state when it is one word (a sentence under such
  // a key, such as Guardian's reason, is content). One that holds a withheld
  // address anywhere is kept as a digest: records still group by it, but
  // the address cannot be read back.
  if (identityLike(key, value)) {
    return containsWithheldAddress(options.policy, value) ? digestOf(value) : value;
  }
  if (explicitCategory === "commandArguments") return commandSummary(value);
  if (
    category === "filePaths" ||
    category === "browserUrls" ||
    category === "networkEndpoints" ||
    (category === undefined &&
      (looksLikePath(value) || looksLikeURL(value) || looksLikeNetworkEndpoint(value)))
  ) {
    return digestOf(value);
  }
  // Any other string may be content, however short or word-like: a project
  // name is as private as a prompt.
  return policyRedactedValue;
}

/**
 * Whether a string is stored as it is (secrets aside): its category is
 * collected, or, when no field names it, every kind of text it could be is
 * collected and it is not an address the policy withholds. Text no field
 * names may be a prompt, a reply, reasoning, output or a file, so with any
 * of those off it is kept only as metadata.
 */
function storedAsIs(
  policy: CollectionPolicy,
  category: keyof StructuredPolicy | undefined,
  value: string,
): boolean {
  // As in the collector, an address is withheld under any category but its
  // own: a path in a reply is still a path.
  return collected(policy, category) && !withheldAddress(policy, value);
}

/**
 * Whether values in `category` are collected; for a value no field names,
 * whether every kind of text it could be is.
 */
function collected(
  policy: CollectionPolicy,
  category: keyof StructuredPolicy | undefined,
): boolean {
  if (category !== undefined) return policy[category];
  return unclassifiedContentCategories.every((name) => policy[name]);
}

/**
 * Whether a string under `key` identifies or classifies its record: an ID,
 * name, agent, model, source or time, or a one-word kind, role or state.
 */
function identityLike(key: string, value: string): boolean {
  const field = normalizedKey(key);
  return (
    (identityKeyPattern.test(field) &&
      value.length <= 256 &&
      !/[\u0000-\u001f\u007f]/u.test(value)) ||
    (enumKeyPattern.test(field) && /^[A-Za-z0-9][A-Za-z0-9_.:/-]{0,63}$/u.test(value))
  );
}

/** The keyed digest a stored record keeps in place of a value. */
function storedDigest(options: StorableRecordOptions, value: string): string {
  return `${storedDigestPrefix}${createHmac("sha256", options.identifierKey).update(value).digest("hex")}`;
}

/** `value` with every configured private path replaced, as the policy engine does. */
function redactPaths(value: string, patterns: readonly string[] | undefined): string {
  let result = value;
  for (const pattern of patterns ?? []) {
    if (pattern === "") continue;
    result = result.split(pattern).join("[REDACTED_PATH]");
  }
  return result;
}

/** Whether `value` is a URL, path or endpoint the policy does not collect. */
function withheldAddress(policy: CollectionPolicy, value: string): boolean {
  return (
    (!policy.browserUrls && looksLikeURL(value)) ||
    (!policy.filePaths && looksLikePath(value)) ||
    (!policy.networkEndpoints && looksLikeNetworkEndpoint(value))
  );
}

/**
 * A key without secrets, and without a path, URL or endpoint the policy
 * withholds anywhere in it. In an object whose values are withheld
 * (`category`, the object's own), a key that is not a plain field name,
 * such as a sentence used as a map key, is kept only as a digest: it is
 * data, not structure.
 */
function storableKey(
  key: string,
  options: StorableRecordOptions,
  category: keyof StructuredPolicy | undefined,
  taken: Readonly<Record<string, unknown>>,
): string {
  let name = key;
  if (redactSecrets(redactPaths(key, options.pathPatterns)) !== key) {
    name = secretMarker;
  } else if (
    withheldAddress(options.policy, key) ||
    containsWithheldAddress(options.policy, key) ||
    (!collected(options.policy, category) && !fieldNamePattern.test(key))
  ) {
    name = `${storedDigestPrefix}${createHmac("sha256", options.identifierKey).update(key).digest("hex")}`;
  } else {
    return key;
  }
  const base = name;
  for (let index = 2; Object.hasOwn(taken, name); index++) {
    name = `${base}#${index}`;
  }
  return name;
}

// What a value in a record that no field names could be: any content the
// policy switches, including the raw vendor record (vendorPayload), MCP
// arguments and output, and model prompts and replies. Environment values
// are kept apart by their key, and paths, URLs and endpoints by their shape
// (withheldAddress), so those switches withhold only addresses.
const unclassifiedContentCategories = CONTENT_COLLECTION_CATEGORIES.filter(
  (name) => !["environmentValues", "filePaths", "browserUrls", "networkEndpoints"].includes(name),
);

// A key that names a field: a word with digits, underscores, dots, hyphens
// or colons, as JSON records use. A map keyed by sentences, paths or hosts
// does not match.
const fieldNamePattern = /^[A-Za-z_$@][A-Za-z0-9_.$@:-]{0,63}$/u;

// Keys, without separators, whose numbers are kept where other numbers are
// withheld, one by one: times, exit and status codes, process IDs, sequence
// numbers, counts, durations and token usage. A credential name is masked
// before this is asked, so an OTP or PIN is never one of them.
const numericMetadataKeyPattern =
  /^(?:ts|timestamp|time|created|createdat|updated|updatedat|started|startedat|ended|endedat|completed|completedat|start|end|exit|exitcode|statuscode|status|pid|processid|seq|sequence|index|count|version|duration|durationms|latencyms|confidence|tokens|inputtokens|outputtokens|totaltokens|cachedtokens|reasoningtokens)$/u;

// A number under an ID's name (id, session_id, call-id, sessionId, callID)
// identifies the record. Matched on the name as written, so amount_paid is
// not one.
const numericIdKeyPattern = /^(?:[iI][dD]|.*[-_. ][iI][dD]|.*[a-z0-9]I[dD])$/u;

// A digest kept in a stored record in place of a path or address.
const storedDigestPrefix = "phigon-digest:";
// Keys, without separators, whose short values identify rather than say
// something: IDs, names, agents, models, sources and times.
const identityKeyPattern =
  /^(?:model|provider|source|agent|tool|version|timestamp|time|createdat|updatedat|startedat|endedat)$|(?:id|name)$/u;
// Keys whose one-word values say what kind of record it is, or its state.
const enumKeyPattern =
  /^(?:type|kind|role|status|state|phase|stream|event|outcome|action|reason|finishreason|stopreason|decisionsource)$/u;

function normalizedKey(key: string): string {
  return key.toLowerCase().replace(/[^a-z0-9]+/gu, "");
}

function jsonContainer(value: string): unknown {
  const trimmed = value.trimStart();
  if (!trimmed.startsWith("{") && !trimmed.startsWith("[")) return undefined;
  try {
    const parsed = parseLosslessJSON(value);
    return typeof parsed === "object" && parsed !== null && !isRawJSONNumber(parsed) ? parsed : undefined;
  } catch {
    return undefined;
  }
}

// JSON.parse with each value's source text, and raw JSON values, are in
// Node.js 21 and later; TypeScript's library does not describe them yet.
const losslessJSON = JSON as unknown as Readonly<{
  parse(
    text: string,
    reviver: (key: string, value: unknown, context?: Readonly<{ source?: string }>) => unknown,
  ): unknown;
  rawJSON(text: string): unknown;
  isRawJSON(value: unknown): boolean;
}>;

/**
 * JSON text parsed with every number kept as its original text, so that
 * writing it back changes no digit: 9007199254740993 stays exact, and 1.50
 * stays 1.50. JSON.stringify writes such a number as it was.
 */
export function parseLosslessJSON(text: string): unknown {
  return losslessJSON.parse(text, (_key, value, context) =>
    typeof value === "number" && context?.source !== undefined
      ? losslessJSON.rawJSON(context.source)
      : value);
}

/** Whether `value` is a number from parseLosslessJSON. */
export function isRawJSONNumber(value: unknown): boolean {
  return typeof value === "object" && value !== null && losslessJSON.isRawJSON(value);
}

/**
 * JSON text without the spaces and line breaks between its tokens, to tell
 * whether writing a parsed copy back changed anything but layout.
 */
export function compactJSON(text: string): string {
  const parts: string[] = [];
  let start = 0;
  let inString = false;
  for (let index = 0; index < text.length; index++) {
    const character = text[index];
    if (inString) {
      if (character === "\\") index++;
      else if (character === "\"") inString = false;
      continue;
    }
    if (character === "\"") {
      inString = true;
    } else if (character === " " || character === "\t" || character === "\n" || character === "\r") {
      parts.push(text.slice(start, index));
      start = index + 1;
    }
  }
  parts.push(text.slice(start));
  return parts.join("");
}

function sanitizeStructuredNode(
  value: unknown,
  policy: StructuredPolicy,
  key: string,
  depth: number,
  parent?: Readonly<Record<string, unknown>>,
  failClosedUnclassifiedStrings = false,
  inheritedCategory?: keyof StructuredPolicy,
): Readonly<{ value: unknown; changed: boolean }> {
  if (depth >= 16) {
    return { value: "[MAX_DEPTH]", changed: true };
  }
  const explicitCategory = structuredCategory(key, parent);
  const category = explicitCategory ?? inheritedCategory;
  if (category !== undefined && !policy[category]) {
    return { value: policyRedactedValue, changed: true };
  }
  if (typeof value === "string") {
    if (
      failClosedUnclassifiedStrings &&
      category === undefined &&
      !isStructuralMetadataString(key, value, parent)
    ) {
      return { value: policyRedactedValue, changed: true };
    }
    if (
      (!policy.browserUrls && looksLikeURL(value)) ||
      (!policy.filePaths && looksLikePath(value)) ||
      (!policy.networkEndpoints && looksLikeNetworkEndpoint(value))
    ) {
      return { value: policyRedactedValue, changed: true };
    }
    return { value, changed: false };
  }
  if (Array.isArray(value)) {
    let changed = false;
    const result = value.slice(0, 2_048).map((item) => {
      const child = sanitizeStructuredNode(
        item,
        policy,
        "",
        depth + 1,
        undefined,
        failClosedUnclassifiedStrings,
        category,
      );
      changed ||= child.changed;
      return child.value;
    });
    return {
      value: result,
      changed: changed || result.length !== value.length,
    };
  }
  if (value !== null && typeof value === "object") {
    let changed = false;
    const result: Record<string, unknown> = Object.create(null);
    const keys = Object.keys(value).sort().slice(0, 1_024);
    for (const childKey of keys) {
      const child = sanitizeStructuredNode(
        (value as Record<string, unknown>)[childKey],
        policy,
        childKey,
        depth + 1,
        value as Record<string, unknown>,
        failClosedUnclassifiedStrings,
        category,
      );
      result[childKey] = child.value;
      changed ||= child.changed;
    }
    return {
      value: result,
      changed: changed || keys.length !== Object.keys(value).length,
    };
  }
  return { value, changed: false };
}

function structuredCategory(
  rawKey: string,
  parent?: Readonly<Record<string, unknown>>,
): keyof StructuredPolicy | undefined {
  const key = rawKey.toLowerCase().replace(/[^a-z0-9]+/gu, "_");
  const context = [
    typeof parent?.["role"] === "string" ? parent["role"] : "",
    typeof parent?.["type"] === "string" ? parent["type"] : "",
    typeof parent?.["kind"] === "string" ? parent["kind"] : "",
  ].join(" ").toLowerCase();
  if (
    /^(?:env|environment|environment_variables|env_vars|process_env)$/u.test(
      key,
    )
  ) {
    return "environmentValues";
  }
  if (
    /^(?:path|file_path|filepath|filename|directory|dir|cwd|workdir|working_directory|repo|repository)$/u.test(
      key,
    )
  ) {
    return "filePaths";
  }
  if (/^(?:file_content|contents|content_bytes)$/u.test(key)) {
    return "fileContent";
  }
  if (/^(?:patch|diff|git_patch)$/u.test(key)) {
    return "gitPatchContent";
  }
  if (/^(?:url|uri|href|origin)$/u.test(key)) {
    return "browserUrls";
  }
  if (/^(?:html|page_content|browser_content|selector|target)$/u.test(key)) {
    return "browserContent";
  }
  if (
    /^(?:endpoint|network_endpoint|host|hostname|ip|ip_address|port)$/u.test(
      key,
    )
  ) {
    return "networkEndpoints";
  }
  if (/^(?:prompt|user_prompt|input_text)$/u.test(key)) {
    return "promptContent";
  }
  if (/^(?:response|assistant_response|output_text)$/u.test(key)) {
    return "responseContent";
  }
  if (
    /^(?:reasoning|analysis|chain_of_thought|thinking|thought)$/u.test(key)
  ) {
    return "reasoningContent";
  }
  if (
    /^(?:command|cmd|args|arguments|command_line|argv)$/u.test(key)
  ) {
    return "commandArguments";
  }
  if (/^(?:stdout|stderr|terminal_output)$/u.test(key)) {
    return "terminalOutput";
  }
  if (/^(?:tool_output|result)$/u.test(key)) {
    return "toolOutput";
  }
  if (key === "output") {
    return /assistant|response|agent_message/u.test(context)
      ? "responseContent"
      : "toolOutput";
  }
  if (key === "content" || key === "message") {
    if (/user|prompt|input/u.test(context)) return "promptContent";
    if (/reasoning|analysis|thinking|thought/u.test(context)) {
      return "reasoningContent";
    }
    if (/assistant|response|output|agent_message/u.test(context)) {
      return "responseContent";
    }
    return "fileContent";
  }
  if (key === "text") {
    if (/reasoning|analysis|thinking|thought/u.test(context)) {
      return "reasoningContent";
    }
    if (/user|prompt|input/u.test(context)) return "promptContent";
    if (/assistant|response|output|agent_message/u.test(context)) {
      return "responseContent";
    }
  }
  return undefined;
}

function isStructuralMetadataString(
  rawKey: string,
  value: string,
  parent?: Readonly<Record<string, unknown>>,
): boolean {
  const key = rawKey.toLowerCase().replace(/[^a-z0-9]+/gu, "_");
  const parentType = [
    typeof parent?.["type"] === "string" ? parent["type"] : "",
    typeof parent?.["kind"] === "string" ? parent["kind"] : "",
  ].join(" ").toLowerCase();
  const toolName =
    key === "name" &&
    (
      /(?:function|tool)[_-]?(?:call|use|invocation)/u.test(parentType) ||
      Object.hasOwn(parent ?? {}, "arguments")
    );
  if (
    !toolName &&
    !/^(?:id|type|kind|role|status|state|phase|model|provider|version|source|agent|session_id|call_id|tool_name)$/u.test(
      key,
    )
  ) {
    return false;
  }
  return (
    value.length <= 256 &&
    /^[A-Za-z0-9][A-Za-z0-9._:/@+-]*$/u.test(value)
  );
}

function looksLikeURL(value: string): boolean {
  return /^(?:https?|wss?):\/\//iu.test(value.trim());
}

function looksLikePath(value: string): boolean {
  const trimmed = value.trim();
  return /^(?:~[\\/]|\/(?!\/)|[A-Za-z]:[\\/]|\\\\)/u.test(trimmed);
}

function looksLikeNetworkEndpoint(value: string): boolean {
  const trimmed = value.trim();
  return /^(?:\[[0-9A-Fa-f:]+\]|(?:\d{1,3}\.){3}\d{1,3}|[A-Za-z0-9.-]+\.[A-Za-z]{2,}):\d{1,5}$/u.test(
    trimmed,
  );
}

function sanitizeVendorStructure(
  value: unknown,
  path: string,
  redactedFields: string[],
  redact: (value: string) => Readonly<{ value: string; changed: boolean }>,
  depth = 0,
): unknown {
  if (depth >= 16) return "[MAX_DEPTH]";
  if (typeof value === "string") {
    // Redact first: a credential cut at the limit could pass in part.
    const result = redact(boundForRedaction(value, maxVendorString * 4).value);
    if (result.changed && path !== "") redactedFields.push(path);
    return result.value.slice(0, maxVendorString);
  }
  if (
    value === null ||
    typeof value === "boolean" ||
    typeof value === "number"
  ) {
    return value;
  }
  if (typeof value === "bigint") return value.toString();
  if (Array.isArray(value)) {
    return value.slice(0, 2_048).map((item, index) =>
      sanitizeVendorStructure(
        item,
        `${path}[${index}]`,
        redactedFields,
        redact,
        depth + 1,
      )
    );
  }
  if (typeof value === "object") {
    const result: Record<string, unknown> = Object.create(null);
    for (const key of Object.keys(value).sort().slice(0, 1_024)) {
      const childPath = path === "" ? key : `${path}.${key}`;
      if (credentialFieldName(key)) {
        result[key] = "[REDACTED_SECRET]";
        redactedFields.push(childPath);
        continue;
      }
      result[key] = sanitizeVendorStructure(
        (value as Record<string, unknown>)[key],
        childPath,
        redactedFields,
        redact,
        depth + 1,
      );
    }
    return result;
  }
  return String(value);
}

function serializeNormalized(value: unknown): string {
  try {
    return JSON.stringify(normalizeStructure(value, 0));
  } catch {
    return JSON.stringify({ _phigon: "unserializable" });
  }
}

function stringValue(value: unknown): string {
  if (typeof value === "string") return value;
  if (value === undefined || value === null) return "";
  if (Buffer.isBuffer(value)) return value.toString("utf8");
  try {
    return JSON.stringify(normalizeStructure(value, 0));
  } catch {
    return "";
  }
}

function digest(value: string): string {
  return createHash("sha256").update(value).digest("hex");
}
