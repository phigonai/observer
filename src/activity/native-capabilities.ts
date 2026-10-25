export type NativeCapability = Readonly<{
  name: string;
  available: boolean;
  permission: string;
  detail: string;
}>;

export type NativeCapabilityReport = Readonly<{
  nativeLoaded: boolean;
  capabilities: readonly NativeCapability[];
}>;

type NativeModule = Readonly<{
  negotiateCapabilities(
    requested: readonly string[],
  ): readonly NativeCapability[];
}>;

type ModuleImporter = (specifier: string) => Promise<unknown>;

export async function negotiateNativeCapabilities(
  requested: readonly string[],
  importer: ModuleImporter = defaultImporter,
): Promise<NativeCapabilityReport> {
  const bounded = requested
    .slice(0, 64)
    .map((name) => normalizeName(name));
  for (const specifier of [
    "@phigon/native",
    new URL("../../../../native/index.js", import.meta.url).href,
  ]) {
    try {
      const loaded = await importer(specifier);
      const module = nativeModule(loaded);
      if (module === null) continue;
      const capabilities = module
        .negotiateCapabilities(bounded)
        .slice(0, 64)
        .map(validateCapability);
      return { nativeLoaded: true, capabilities };
    } catch {
      // Try the next packaged or repository-local native binding.
    }
  }
  return {
    nativeLoaded: false,
    capabilities: bounded.map((name) => ({
      name,
      available: false,
      permission: "native_unavailable",
      detail: "Optional native capability module is unavailable.",
    })),
  };
}

async function defaultImporter(specifier: string): Promise<unknown> {
  return await import(specifier);
}

function nativeModule(value: unknown): NativeModule | null {
  if (
    typeof value === "object" &&
    value !== null &&
    "default" in value
  ) {
    const nested = nativeModule(value.default);
    if (nested !== null) return nested;
  }
  if (
    typeof value !== "object" ||
    value === null ||
    !("negotiateCapabilities" in value) ||
    typeof value.negotiateCapabilities !== "function"
  ) {
    return null;
  }
  return value as NativeModule;
}

function validateCapability(value: unknown): NativeCapability {
  if (
    typeof value !== "object" ||
    value === null ||
    !("name" in value) ||
    typeof value.name !== "string" ||
    !("available" in value) ||
    typeof value.available !== "boolean" ||
    !("permission" in value) ||
    typeof value.permission !== "string" ||
    !("detail" in value) ||
    typeof value.detail !== "string"
  ) {
    return {
      name: "invalid_native_response",
      available: false,
      permission: "invalid",
      detail: "Native module returned an invalid capability response.",
    };
  }
  return {
    name: normalizeName(value.name),
    available: value.available,
    permission: value.permission.slice(0, 64),
    detail: value.detail.slice(0, 256),
  };
}

function normalizeName(value: string): string {
  return value
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9._-]+/gu, "_")
    .slice(0, 64);
}
