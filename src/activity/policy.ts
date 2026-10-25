import { redactSecrets } from "../content-redaction.js";
import { createHash } from "node:crypto";
import type { CollectionPolicy } from "../config.js";

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

const sensitiveFieldPattern =
  /(?:^|_)(?:api_?key|auth(?:orization)?|cookie|credential|password|passwd|private_?key|secret|session_?token|token)(?:$|_)/iu;

export class LocalPolicyEngine {
  readonly #collection: CollectionPolicy;
  readonly #pathPatterns: readonly string[];
  readonly #limits: ContentLimits;

  constructor(
    collection: CollectionPolicy,
    pathPatterns: readonly string[] = [],
    limits: ContentLimits = defaultLimits,
  ) {
    this.#collection = collection;
    this.#pathPatterns = pathPatterns;
    this.#limits = limits;
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
    const text = stringValue(value);
    if (text === "") {
      return { value: "", redacted: false, truncated: false };
    }
    const limit = this.#limitFor(category);
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
    const normalized = normalizeStructure(policySanitized.value, 0);
    let serialized: string;
    try {
      serialized = JSON.stringify(normalized);
    } catch {
      serialized = JSON.stringify({ _phigon: "unserializable" });
    }
    const limit = this.#limitFor(category);
    const redacted = this.#redact(serialized);
    if (Buffer.byteLength(redacted.value, "utf8") <= limit) {
      return {
        value: redacted.value,
        redacted: policySanitized.changed || redacted.changed,
        truncated: false,
      };
    }
    return {
      value: JSON.stringify({
        _phigon: "truncated",
        sha256: digest(redacted.value),
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
    const recordDigest = digest(original);
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
      return { digest: digest(text), redacted: true };
    }
    return {
      digest: digest(text),
      value: result.value,
      redacted: result.redacted,
    };
  }

  safeName(value: unknown, fallback: string): string {
    const text = stringValue(value)
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
    const redacted = this.#redact(value);
    const truncated = truncateUTF8(redacted.value, limit);
    return {
      value: truncated.value,
      redacted: redacted.changed,
      truncated: truncated.truncated,
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
    const bounded = value.slice(0, 256 << 10);
    const result = redact(bounded);
    if (result.changed && path !== "") redactedFields.push(path);
    return result.value;
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
      if (sensitiveFieldPattern.test(key)) {
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
