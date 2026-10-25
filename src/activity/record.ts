export function objectValue(value: unknown): Record<string, unknown> | null {
  return typeof value === "object" && value !== null
    ? (value as Record<string, unknown>)
    : null;
}

export function stringField(
  value: unknown,
  field: string,
): string {
  const object = objectValue(value);
  return typeof object?.[field] === "string"
    ? object[field]
    : "";
}

export function nestedField(
  value: unknown,
  ...fields: readonly string[]
): unknown {
  let current: unknown = value;
  for (const field of fields) {
    const object = objectValue(current);
    if (object === null) return undefined;
    current = object[field];
  }
  return current;
}

export function arrayField(
  value: unknown,
  field: string,
): readonly unknown[] {
  const object = objectValue(value);
  return Array.isArray(object?.[field]) ? object[field] : [];
}

export function recordObservedAt(
  record: unknown,
  fallback: Date,
): Date {
  for (const field of ["timestamp", "created_at", "createdAt", "time"]) {
    const candidate = stringField(record, field);
    if (candidate === "") continue;
    const parsed = new Date(candidate);
    if (!Number.isNaN(parsed.getTime())) return parsed;
  }
  return fallback;
}

export function extractText(value: unknown, depth = 0): string {
  if (depth >= 8) return "";
  if (typeof value === "string") return value;
  if (Array.isArray(value)) {
    return value
      .slice(0, 256)
      .map((item) => extractText(item, depth + 1))
      .filter(Boolean)
      .join("\n");
  }
  const object = objectValue(value);
  if (object === null) return "";
  for (const field of ["text", "message", "content", "output", "result"]) {
    if (field in object) {
      const text = extractText(object[field], depth + 1);
      if (text !== "") return text;
    }
  }
  return "";
}
