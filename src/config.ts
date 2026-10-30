import { homedir } from "node:os";
import { isAbsolute, join } from "node:path";

export type ObserverLogLevel = "debug" | "info" | "warn" | "error";
export const DEFAULT_CONTROL_PLANE_ORIGIN = "https://api.phigon.online";
export type ObservabilityProfile = "metadata" | "full";
export type InitialReplayMode = "all" | "messages";
export type ActivitySourceDirectories = Readonly<{
  codex: readonly string[];
  claude: readonly string[];
  hermes: readonly string[];
  openclaw: readonly string[];
  copilot: readonly string[];
  opencode: readonly string[];
  gemini: readonly string[];
  cline: readonly string[];
  goose: readonly string[];
  cursor: readonly string[];
  copilotChat: readonly string[];
  kiro: readonly string[];
  zed: readonly string[];
  droid: readonly string[];
  generic: readonly string[];
}>;

export type CollectionPolicy = Readonly<{
  promptContent: boolean;
  responseContent: boolean;
  reasoningContent: boolean;
  commandArguments: boolean;
  terminalOutput: boolean;
  filePaths: boolean;
  fileContent: boolean;
  browserUrls: boolean;
  browserContent: boolean;
  networkEndpoints: boolean;
  gitPatchContent: boolean;
  environmentValues: boolean;
  toolOutput: boolean;
  vendorPayload: boolean;
  processMetadata: boolean;
  processArguments: boolean;
  fileMetadata: boolean;
  fileDiffs: boolean;
  networkMetadata: boolean;
  networkContent: boolean;
  browserMetadata: boolean;
  mcpArguments: boolean;
  mcpOutput: boolean;
  modelPrompts: boolean;
  modelResponses: boolean;
}>;

export type ObserverConfig = Readonly<{
  controlPlaneUrl: URL;
  grpcUrl: URL;
  grpcEndpointConfigured: boolean;
  dataDirectory: string;
  heartbeatIntervalMs: number;
  discoveryIntervalMs: number;
  activityScanIntervalMs: number;
  activityRateLimitPerMinute: number;
  activityQueueCapacity: number;
  activityMaxInFlightEvents: number;
  activityReplayOnFirstStart: boolean;
  activityInitialReplayBytes: number;
  activityInitialReplaySessions: number;
  activityInitialReplayMode: InitialReplayMode;
  redactionPathPatterns: readonly string[];
  activitySourceDirectories: ActivitySourceDirectories;
  logLevel: ObserverLogLevel;
  observabilityProfile: ObservabilityProfile;
  machineTokenConfigured: boolean;
  remoteActionsEnabled: boolean;
  remoteCommandsEnabled: boolean;
  guardianDecisionTimeoutMs: number;
  tlsCaFile: string | undefined;
  tlsClientCertFile: string | undefined;
  tlsClientKeyFile: string | undefined;
  policy: CollectionPolicy;
}>;

const defaultPolicy: CollectionPolicy = Object.freeze({
  promptContent: false,
  responseContent: false,
  reasoningContent: false,
  commandArguments: false,
  terminalOutput: false,
  filePaths: false,
  fileContent: false,
  browserUrls: false,
  browserContent: false,
  networkEndpoints: false,
  gitPatchContent: false,
  environmentValues: false,
  toolOutput: false,
  vendorPayload: false,
  processMetadata: true,
  processArguments: false,
  fileMetadata: true,
  fileDiffs: false,
  networkMetadata: true,
  networkContent: false,
  browserMetadata: true,
  mcpArguments: false,
  mcpOutput: false,
  modelPrompts: false,
  modelResponses: false,
});

const fullPolicy: CollectionPolicy = Object.freeze({
  promptContent: true,
  responseContent: true,
  reasoningContent: true,
  commandArguments: true,
  terminalOutput: true,
  filePaths: true,
  fileContent: true,
  browserUrls: true,
  browserContent: true,
  networkEndpoints: true,
  gitPatchContent: true,
  // Environment values frequently contain credentials. Keep them outside
  // the full profile unless an operator grants this category explicitly.
  environmentValues: false,
  toolOutput: true,
  vendorPayload: true,
  processMetadata: true,
  processArguments: true,
  fileMetadata: true,
  fileDiffs: true,
  networkMetadata: true,
  networkContent: true,
  browserMetadata: true,
  mcpArguments: true,
  mcpOutput: true,
  modelPrompts: true,
  modelResponses: true,
});

export function loadConfig(
  environment: NodeJS.ProcessEnv = process.env,
): ObserverConfig {
  const controlPlaneUrl = parseControlPlaneUrl(
    environment["PHIGON_CONTROL_PLANE_URL"] ?? DEFAULT_CONTROL_PLANE_ORIGIN,
  );
  const grpcUrl = parseEndpointUrl(
    environment["PHIGON_GRPC_URL"] ?? "https://observer.phigon.online",
    "PHIGON_GRPC_URL",
  );

  const heartbeatIntervalMs = parseBoundedPositiveInteger(
    environment["PHIGON_HEARTBEAT_INTERVAL_MS"] ?? "5000",
    "PHIGON_HEARTBEAT_INTERVAL_MS",
    1_000,
    60_000,
  );
  const discoveryIntervalMs = parseInterval(
    environment["PHIGON_DISCOVERY_INTERVAL_MS"] ?? "10000",
    "PHIGON_DISCOVERY_INTERVAL_MS",
  );
  const activityScanIntervalMs = parseInterval(
    environment["PHIGON_ACTIVITY_SCAN_INTERVAL_MS"] ?? "1000",
    "PHIGON_ACTIVITY_SCAN_INTERVAL_MS",
  );
  const activityRateLimitPerMinute = parseBoundedPositiveInteger(
    environment["PHIGON_ACTIVITY_RATE_LIMIT_PER_MINUTE"] ?? "1200",
    "PHIGON_ACTIVITY_RATE_LIMIT_PER_MINUTE",
    1,
    10_000,
  );
  const activityQueueCapacity = parseBoundedPositiveInteger(
    environment["PHIGON_ACTIVITY_QUEUE_CAPACITY"] ?? "8192",
    "PHIGON_ACTIVITY_QUEUE_CAPACITY",
    128,
    65_536,
  );
  if (activityQueueCapacity < activityRateLimitPerMinute) {
    throw new Error(
      "PHIGON_ACTIVITY_QUEUE_CAPACITY must be greater than or equal to " +
        "PHIGON_ACTIVITY_RATE_LIMIT_PER_MINUTE so one collection window " +
        "cannot overflow the in-memory delivery queue.",
    );
  }
  const activityMaxInFlightEvents = parseBoundedPositiveInteger(
    environment["PHIGON_ACTIVITY_MAX_IN_FLIGHT_EVENTS"] ?? "64",
    "PHIGON_ACTIVITY_MAX_IN_FLIGHT_EVENTS",
    1,
    256,
  );
  const observabilityProfile = parseObservabilityProfile(
    environment["PHIGON_OBSERVABILITY_PROFILE"] ?? "metadata",
  );
  const profilePolicy =
    observabilityProfile === "full" ? fullPolicy : defaultPolicy;

  const logLevel = parseLogLevel(
    environment["PHIGON_LOG_LEVEL"] ?? "info",
  );
  const machineTokenConfigured =
    (environment["PHIGON_MACHINE_TOKEN"]?.trim().length ?? 0) > 0;
  const tlsClientCertFile =
    environment["PHIGON_TLS_CLIENT_CERT_FILE"]?.trim() || undefined;
  const tlsClientKeyFile =
    environment["PHIGON_TLS_CLIENT_KEY_FILE"]?.trim() || undefined;
  if ((tlsClientCertFile === undefined) !==
    (tlsClientKeyFile === undefined)) {
    throw new Error(
      "PHIGON_TLS_CLIENT_CERT_FILE and PHIGON_TLS_CLIENT_KEY_FILE must be configured together.",
    );
  }

  return Object.freeze({
    controlPlaneUrl,
    grpcUrl,
    grpcEndpointConfigured: Boolean(environment["PHIGON_GRPC_URL"]?.trim()),
    dataDirectory:
      environment["PHIGON_DATA_DIR"]?.trim() ||
      join(homedir(), ".phigon", "observer"),
    heartbeatIntervalMs,
    discoveryIntervalMs,
    activityScanIntervalMs,
    activityRateLimitPerMinute,
    activityQueueCapacity,
    activityMaxInFlightEvents,
    activityReplayOnFirstStart: parseBoolean(
      environment["PHIGON_ACTIVITY_REPLAY_ON_FIRST_START"] ?? "false",
      "PHIGON_ACTIVITY_REPLAY_ON_FIRST_START",
    ),
    activityInitialReplayBytes: parseBoundedPositiveInteger(
      environment["PHIGON_ACTIVITY_INITIAL_REPLAY_BYTES"] ?? "262144",
      "PHIGON_ACTIVITY_INITIAL_REPLAY_BYTES",
      4_096,
      8 << 20,
    ),
    activityInitialReplaySessions: parseBoundedPositiveInteger(
      environment["PHIGON_ACTIVITY_INITIAL_REPLAY_SESSIONS"] ?? "1",
      "PHIGON_ACTIVITY_INITIAL_REPLAY_SESSIONS",
      1,
      256,
    ),
    activityInitialReplayMode: parseInitialReplayMode(
      environment["PHIGON_ACTIVITY_INITIAL_REPLAY_MODE"] ?? "all",
    ),
    redactionPathPatterns: parseRedactionPathPatterns(
      environment["PHIGON_REDACT_PATH_PATTERNS"] ?? "",
    ),
    activitySourceDirectories: Object.freeze({
      codex: parseDirectoryList(
        environment["PHIGON_CODEX_ACTIVITY_DIRS"],
        [join(homedir(), ".codex", "sessions")],
      ),
      claude: parseDirectoryList(
        environment["PHIGON_CLAUDE_ACTIVITY_DIRS"],
        [
          join(homedir(), ".claude", "projects"),
          join(homedir(), ".claude", "sessions"),
        ],
      ),
      hermes: parseDirectoryList(
        environment["PHIGON_HERMES_ACTIVITY_DIRS"],
        [
          join(homedir(), ".hermes", "sessions"),
          join(homedir(), ".hermes", "logs"),
        ],
      ),
      openclaw: parseDirectoryList(
        environment["PHIGON_OPENCLAW_ACTIVITY_DIRS"],
        [
          join(homedir(), ".openclaw", "sessions"),
          join(homedir(), ".openclaw", "logs"),
        ],
      ),
      copilot: parseDirectoryList(
        environment["PHIGON_COPILOT_ACTIVITY_DIRS"],
        [join(homedir(), ".copilot", "session-state")],
      ),
      opencode: parseDirectoryList(
        environment["PHIGON_OPENCODE_ACTIVITY_DIRS"],
        [join(homedir(), ".local", "share", "opencode")],
      ),
      gemini: parseDirectoryList(
        environment["PHIGON_GEMINI_ACTIVITY_DIRS"],
        [join(homedir(), ".gemini", "tmp")],
      ),
      cline: parseDirectoryList(
        environment["PHIGON_CLINE_ACTIVITY_DIRS"],
        [join(homedir(), ".cline", "data", "sessions")],
      ),
      goose: parseDirectoryList(
        environment["PHIGON_GOOSE_ACTIVITY_DIRS"],
        gooseSessionDirectories(environment),
      ),
      cursor: parseDirectoryList(
        environment["PHIGON_CURSOR_ACTIVITY_DIRS"],
        [join(homedir(), ".cursor", "projects")],
      ),
      copilotChat: parseDirectoryList(
        environment["PHIGON_COPILOT_CHAT_ACTIVITY_DIRS"],
        ["Code", "Code - Insiders"].flatMap((product) => {
          const user = editorUserDirectory(environment, product);
          return [
            join(user, "workspaceStorage"),
            join(user, "globalStorage", "emptyWindowChatSessions"),
          ];
        }),
      ),
      kiro: parseDirectoryList(
        environment["PHIGON_KIRO_ACTIVITY_DIRS"],
        [join(
          editorUserDirectory(environment, "Kiro"),
          "globalStorage",
          "kiro.kiroagent",
          "workspace-sessions",
        )],
      ),
      zed: parseDirectoryList(
        environment["PHIGON_ZED_ACTIVITY_DIRS"],
        zedThreadDirectories(environment),
      ),
      droid: parseDirectoryList(
        environment["PHIGON_DROID_ACTIVITY_DIRS"],
        [join(homedir(), ".factory", "sessions")],
      ),
      generic: parseDirectoryList(
        environment["PHIGON_GENERIC_ACTIVITY_DIRS"],
        [join(homedir(), ".phigon", "agent-events")],
      ),
    }),
    logLevel,
    observabilityProfile,
    machineTokenConfigured,
    remoteActionsEnabled: parseBoolean(
      environment["PHIGON_REMOTE_ACTIONS_ENABLED"] ?? "false",
      "PHIGON_REMOTE_ACTIONS_ENABLED",
    ),
    remoteCommandsEnabled: parseBoolean(environment["PHIGON_REMOTE_COMMANDS_ENABLED"] ?? "false", "PHIGON_REMOTE_COMMANDS_ENABLED"),
    guardianDecisionTimeoutMs: parseBoundedPositiveInteger(
      environment["PHIGON_GUARDIAN_DECISION_TIMEOUT_MS"] ?? "65000",
      "PHIGON_GUARDIAN_DECISION_TIMEOUT_MS",
      250,
      125_000,
    ),
    tlsCaFile: environment["PHIGON_TLS_CA_FILE"]?.trim() || undefined,
    tlsClientCertFile,
    tlsClientKeyFile,
    policy: Object.freeze({
      ...profilePolicy,
      promptContent: policyFlag(
        environment,
        "PROMPT_CONTENT",
        profilePolicy.promptContent,
      ),
      responseContent: policyFlag(
        environment,
        "RESPONSE_CONTENT",
        profilePolicy.responseContent,
      ),
      reasoningContent: policyFlag(
        environment,
        "REASONING_CONTENT",
        profilePolicy.reasoningContent,
      ),
      commandArguments: policyFlag(
        environment,
        "COMMAND_ARGUMENTS",
        profilePolicy.commandArguments,
      ),
      terminalOutput: policyFlag(
        environment,
        "TERMINAL_OUTPUT",
        profilePolicy.terminalOutput,
      ),
      filePaths: policyFlag(
        environment,
        "FILE_PATHS",
        profilePolicy.filePaths,
      ),
      fileContent: policyFlag(
        environment,
        "FILE_CONTENT",
        profilePolicy.fileContent,
      ),
      browserUrls: policyFlag(
        environment,
        "BROWSER_URLS",
        profilePolicy.browserUrls,
      ),
      browserContent: policyFlag(
        environment,
        "BROWSER_CONTENT",
        profilePolicy.browserContent,
      ),
      networkEndpoints: policyFlag(
        environment,
        "NETWORK_ENDPOINTS",
        profilePolicy.networkEndpoints,
      ),
      gitPatchContent: policyFlag(
        environment,
        "GIT_PATCH_CONTENT",
        profilePolicy.gitPatchContent,
      ),
      environmentValues: policyFlag(
        environment,
        "ENVIRONMENT_VALUES",
        profilePolicy.environmentValues,
      ),
      toolOutput: policyFlag(
        environment,
        "TOOL_OUTPUT",
        profilePolicy.toolOutput,
      ),
      vendorPayload: policyFlag(
        environment,
        "VENDOR_PAYLOAD",
        profilePolicy.vendorPayload,
      ),
      processMetadata: policyFlag(
        environment,
        "PROCESS_METADATA",
        profilePolicy.processMetadata,
      ),
      processArguments: policyFlag(
        environment,
        "PROCESS_ARGUMENTS",
        profilePolicy.processArguments,
      ),
      fileMetadata: policyFlag(
        environment,
        "FILE_METADATA",
        profilePolicy.fileMetadata,
      ),
      fileDiffs: policyFlag(
        environment,
        "FILE_DIFFS",
        profilePolicy.fileDiffs,
      ),
      networkMetadata: policyFlag(
        environment,
        "NETWORK_METADATA",
        profilePolicy.networkMetadata,
      ),
      networkContent: policyFlag(
        environment,
        "NETWORK_CONTENT",
        profilePolicy.networkContent,
      ),
      browserMetadata: policyFlag(
        environment,
        "BROWSER_METADATA",
        profilePolicy.browserMetadata,
      ),
      mcpArguments: policyFlag(
        environment,
        "MCP_ARGUMENTS",
        profilePolicy.mcpArguments,
      ),
      mcpOutput: policyFlag(
        environment,
        "MCP_OUTPUT",
        profilePolicy.mcpOutput,
      ),
      modelPrompts: policyFlag(
        environment,
        "MODEL_PROMPTS",
        profilePolicy.modelPrompts,
      ),
      modelResponses: policyFlag(
        environment,
        "MODEL_RESPONSES",
        profilePolicy.modelResponses,
      ),
    }),
  });
}

function parseControlPlaneUrl(value: string): URL {
  return parseEndpointUrl(value, "PHIGON_CONTROL_PLANE_URL");
}

function parseEndpointUrl(value: string, name: string): URL {
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new Error(`${name} must be a valid URL.`);
  }

  const isLoopback =
    url.hostname === "localhost" ||
    url.hostname === "127.0.0.1" ||
    url.hostname === "::1" ||
    url.hostname === "[::1]";
  if (url.protocol !== "https:" && !(isLoopback && url.protocol === "http:")) {
    throw new Error(
      `${name} must use HTTPS unless it targets loopback.`,
    );
  }

  if (url.username || url.password) {
    throw new Error(
      `${name} must not contain embedded credentials.`,
    );
  }

  if (url.pathname !== "/" || url.search || url.hash) {
    throw new Error(`${name} must be an origin without a path, query, or fragment.`);
  }

  return url;
}

function parsePositiveInteger(value: string, name: string): number {
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed <= 0) {
    throw new Error(`${name} must be a positive integer.`);
  }
  return parsed;
}

function parseInterval(value: string, name: string): number {
  const parsed = parsePositiveInteger(value, name);
  if (parsed < 1_000 || parsed > 3_600_000) {
    throw new Error(`${name} must be between 1000 and 3600000 milliseconds.`);
  }
  return parsed;
}

function parseBoundedPositiveInteger(
  value: string,
  name: string,
  minimum: number,
  maximum: number,
): number {
  const parsed = parsePositiveInteger(value, name);
  if (parsed < minimum || parsed > maximum) {
    throw new Error(`${name} must be between ${minimum} and ${maximum}.`);
  }
  return parsed;
}

function policyFlag(
  environment: NodeJS.ProcessEnv,
  suffix: string,
  fallback: boolean,
): boolean {
  return parseBoolean(
    environment[`PHIGON_COLLECT_${suffix}`] ?? String(fallback),
    `PHIGON_COLLECT_${suffix}`,
  );
}

function parseObservabilityProfile(value: string): ObservabilityProfile {
  const normalized = value.trim().toLowerCase();
  if (normalized === "metadata" || normalized === "full") {
    return normalized;
  }
  throw new Error(
    "PHIGON_OBSERVABILITY_PROFILE must be metadata or full.",
  );
}

function parseInitialReplayMode(value: string): InitialReplayMode {
  const normalized = value.trim().toLowerCase();
  if (normalized === "all" || normalized === "messages") {
    return normalized;
  }
  throw new Error(
    "PHIGON_ACTIVITY_INITIAL_REPLAY_MODE must be all or messages.",
  );
}

function parseBoolean(value: string, name: string): boolean {
  const normalized = value.trim().toLowerCase();
  if (normalized === "true" || normalized === "1") return true;
  if (normalized === "false" || normalized === "0") return false;
  throw new Error(`${name} must be true or false.`);
}

function parseRedactionPathPatterns(value: string): readonly string[] {
  const patterns = value
    .split(",")
    .map((pattern) => pattern.trim())
    .filter(Boolean);
  if (patterns.length > 32 || patterns.some((pattern) => pattern.length > 256)) {
    throw new Error(
      "PHIGON_REDACT_PATH_PATTERNS supports at most 32 values of 256 characters.",
    );
  }
  return Object.freeze(patterns);
}

/**
 * Goose keeps sessions.db in <data dir>/sessions. The data directory is
 * $GOOSE_PATH_ROOT/data when that is an absolute path, otherwise the
 * etcetera app strategy for author "Block" and app "goose": XDG on Linux
 * and macOS, %APPDATA%/Block/goose/data on Windows.
 */
function gooseSessionDirectories(
  environment: NodeJS.ProcessEnv,
): readonly string[] {
  const pathRoot = environment["GOOSE_PATH_ROOT"]?.trim();
  if (pathRoot !== undefined && isAbsolute(pathRoot)) {
    return [join(pathRoot, "data", "sessions")];
  }
  if (process.platform === "win32") {
    const appData = environment["APPDATA"]?.trim() ||
      join(homedir(), "AppData", "Roaming");
    return [join(appData, "Block", "goose", "data", "sessions")];
  }
  const dataHome = environment["XDG_DATA_HOME"]?.trim();
  return [join(
    dataHome !== undefined && isAbsolute(dataHome)
      ? dataHome
      : join(homedir(), ".local", "share"),
    "goose",
    "sessions",
  )];
}

/**
 * Zed keeps agent threads in <data dir>/threads/threads.db. The data
 * directory is %LOCALAPPDATA%/Zed on Windows, ~/Library/Application
 * Support/Zed on macOS, and $FLATPAK_XDG_DATA_HOME or $XDG_DATA_HOME (or
 * ~/.local/share) with "zed" elsewhere. The Flatpak build's own data folder
 * is included because Zed outside the sandbox does not see it.
 */
function zedThreadDirectories(
  environment: NodeJS.ProcessEnv,
): readonly string[] {
  if (process.platform === "win32") {
    const localAppData = environment["LOCALAPPDATA"]?.trim() ||
      join(homedir(), "AppData", "Local");
    return [join(localAppData, "Zed", "threads")];
  }
  if (process.platform === "darwin") {
    return [join(homedir(), "Library", "Application Support", "Zed", "threads")];
  }
  const dataHome = [
    environment["FLATPAK_XDG_DATA_HOME"]?.trim(),
    environment["XDG_DATA_HOME"]?.trim(),
  ].find((value) => value !== undefined && isAbsolute(value));
  return [
    join(dataHome ?? join(homedir(), ".local", "share"), "zed", "threads"),
    join(homedir(), ".var", "app", "dev.zed.Zed", "data", "zed", "threads"),
  ];
}

/**
 * The `User` folder of a VS Code-based editor: %APPDATA%/<product>/User on
 * Windows, ~/Library/Application Support/<product>/User on macOS, and
 * $XDG_CONFIG_HOME (or ~/.config)/<product>/User elsewhere.
 */
function editorUserDirectory(
  environment: NodeJS.ProcessEnv,
  product: string,
): string {
  if (process.platform === "win32") {
    const appData = environment["APPDATA"]?.trim() ||
      join(homedir(), "AppData", "Roaming");
    return join(appData, product, "User");
  }
  if (process.platform === "darwin") {
    return join(homedir(), "Library", "Application Support", product, "User");
  }
  const configHome = environment["XDG_CONFIG_HOME"]?.trim();
  return join(
    configHome !== undefined && isAbsolute(configHome)
      ? configHome
      : join(homedir(), ".config"),
    product,
    "User",
  );
}

function parseDirectoryList(
  value: string | undefined,
  fallback: readonly string[],
): readonly string[] {
  if (value === undefined || value.trim() === "") {
    return Object.freeze([...fallback]);
  }
  if (value.trim().toLowerCase() === "none") {
    return Object.freeze([]);
  }
  const directories = value
    .split(",")
    .map((directory) => directory.trim())
    .filter(Boolean);
  if (
    directories.length > 16 ||
    directories.some((directory) => directory.length > 1_024)
  ) {
    throw new Error(
      "Activity source directory lists support at most 16 paths.",
    );
  }
  return Object.freeze(directories);
}

function parseLogLevel(value: string): ObserverLogLevel {
  if (
    value === "debug" ||
    value === "info" ||
    value === "warn" ||
    value === "error"
  ) {
    return value;
  }
  throw new Error("PHIGON_LOG_LEVEL must be debug, info, warn, or error.");
}
