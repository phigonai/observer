import assert from "node:assert/strict";
import { homedir, tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { loadConfig } from "../src/config.js";

test("loadConfig connects zero-configuration installs to Phigon production", () => {
  const config = loadConfig({});

  assert.equal(config.controlPlaneUrl.origin, "https://api.phigon.online");
  assert.equal(config.grpcUrl.origin, "https://observer.phigon.online");
  assert.equal(config.observabilityProfile, "metadata");
});

test("loadConfig uses safe collection defaults", () => {
  const config = loadConfig({
    PHIGON_CONTROL_PLANE_URL: "http://localhost:8080",
    PHIGON_MACHINE_TOKEN: "",
  });

  assert.equal(config.controlPlaneUrl.origin, "http://localhost:8080");
  assert.equal(config.machineTokenConfigured, false);
  assert.equal(config.discoveryIntervalMs, 10_000);
  assert.equal(config.activityRateLimitPerMinute, 1_200);
  assert.equal(config.activityQueueCapacity, 8_192);
  assert.equal(config.activityMaxInFlightEvents, 64);
  assert.equal(config.activityReplayOnFirstStart, false);
  assert.equal(config.activityInitialReplayBytes, 262_144);
  assert.equal(config.activityInitialReplaySessions, 1);
  assert.equal(config.activityInitialReplayMode, "all");
  assert.equal(config.observabilityProfile, "metadata");
  assert.deepEqual(config.policy, {
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
});

test("loadConfig treats an empty data directory as unset", () => {
  const config = loadConfig({
    PHIGON_CONTROL_PLANE_URL: "http://127.0.0.1:8080",
    PHIGON_GRPC_URL: "http://127.0.0.1:9090",
    PHIGON_DATA_DIR: "   ",
  });

  assert.match(config.dataDirectory, /[\\/]\.phigon[\\/]observer$/u);
});

test("loadConfig supports the full observability profile with explicit overrides", () => {
  const config = loadConfig({
    PHIGON_OBSERVABILITY_PROFILE: "full",
    PHIGON_COLLECT_FILE_CONTENT: "false",
  });

  assert.equal(config.observabilityProfile, "full");
  assert.equal(config.policy.promptContent, true);
  assert.equal(config.policy.responseContent, true);
  assert.equal(config.policy.reasoningContent, true);
  assert.equal(config.policy.commandArguments, true);
  assert.equal(config.policy.toolOutput, true);
  assert.equal(config.policy.vendorPayload, true);
  assert.equal(config.policy.fileContent, false);
  assert.equal(config.policy.environmentValues, false);
  assert.equal(config.policy.processMetadata, true);
  assert.equal(config.policy.processArguments, true);
  assert.equal(config.policy.networkContent, true);
});

test("loadConfig validates observability throughput settings", () => {
  assert.throws(
    () => loadConfig({ PHIGON_HEARTBEAT_INTERVAL_MS: "60001" }),
    /between 1000 and 60000/,
  );
  assert.throws(
    () => loadConfig({ PHIGON_ACTIVITY_QUEUE_CAPACITY: "64" }),
    /between 128 and 65536/,
  );
  assert.throws(
    () =>
      loadConfig({
        PHIGON_ACTIVITY_RATE_LIMIT_PER_MINUTE: "1200",
        PHIGON_ACTIVITY_QUEUE_CAPACITY: "1024",
      }),
    /must be greater than or equal to PHIGON_ACTIVITY_RATE_LIMIT_PER_MINUTE/,
  );
  assert.throws(
    () => loadConfig({ PHIGON_ACTIVITY_MAX_IN_FLIGHT_EVENTS: "257" }),
    /between 1 and 256/,
  );
  assert.throws(
    () => loadConfig({ PHIGON_ACTIVITY_INITIAL_REPLAY_BYTES: "4095" }),
    /between 4096 and 8388608/,
  );
  assert.throws(
    () => loadConfig({ PHIGON_ACTIVITY_INITIAL_REPLAY_SESSIONS: "257" }),
    /between 1 and 256/,
  );
  assert.throws(
    () => loadConfig({ PHIGON_ACTIVITY_INITIAL_REPLAY_MODE: "tools" }),
    /must be all or messages/,
  );
  assert.throws(
    () => loadConfig({ PHIGON_OBSERVABILITY_PROFILE: "everything" }),
    /metadata or full/,
  );
});

test("loadConfig enables content only through explicit policy flags", () => {
  const config = loadConfig({
    PHIGON_COLLECT_PROMPT_CONTENT: "true",
    PHIGON_COLLECT_TOOL_OUTPUT: "1",
    PHIGON_COLLECT_VENDOR_PAYLOAD: "true",
    PHIGON_REDACT_PATH_PATTERNS: "/private/project,/secret",
  });

  assert.equal(config.policy.promptContent, true);
  assert.equal(config.policy.toolOutput, true);
  assert.equal(config.policy.vendorPayload, true);
  assert.equal(config.policy.responseContent, false);
  assert.deepEqual(config.redactionPathPatterns, [
    "/private/project",
    "/secret",
  ]);
});

test("loadConfig accepts an explicit generic-agent activity source", () => {
  const config = loadConfig({
    PHIGON_GENERIC_ACTIVITY_DIRS:
      "/var/lib/agent-one,/var/lib/agent-two",
  });
  assert.deepEqual(config.activitySourceDirectories.generic, [
    "/var/lib/agent-one",
    "/var/lib/agent-two",
  ]);
});

test("loadConfig uses Copilot CLI's native session event directory", () => {
  const config = loadConfig({
    PHIGON_COPILOT_ACTIVITY_DIRS: "/var/lib/copilot-sessions",
  });
  assert.deepEqual(config.activitySourceDirectories.copilot, [
    "/var/lib/copilot-sessions",
  ]);
});

test("loadConfig reads Gemini CLI chat recordings from its temp directory", () => {
  assert.deepEqual(loadConfig({}).activitySourceDirectories.gemini, [
    join(homedir(), ".gemini", "tmp"),
  ]);
  assert.deepEqual(
    loadConfig({ PHIGON_GEMINI_ACTIVITY_DIRS: "/var/lib/gemini-home/tmp" })
      .activitySourceDirectories.gemini,
    ["/var/lib/gemini-home/tmp"],
  );
});

test("loadConfig reads Cline CLI sessions from its data directory", () => {
  assert.deepEqual(loadConfig({}).activitySourceDirectories.cline, [
    join(homedir(), ".cline", "data", "sessions"),
  ]);
  assert.deepEqual(
    loadConfig({ PHIGON_CLINE_ACTIVITY_DIRS: "/var/lib/cline/sessions" })
      .activitySourceDirectories.cline,
    ["/var/lib/cline/sessions"],
  );
});

test("loadConfig reads Cursor agent transcripts from its projects directory", () => {
  assert.deepEqual(loadConfig({}).activitySourceDirectories.cursor, [
    join(homedir(), ".cursor", "projects"),
  ]);
  assert.deepEqual(
    loadConfig({ PHIGON_CURSOR_ACTIVITY_DIRS: "none" })
      .activitySourceDirectories.cursor,
    [],
  );
});

test("loadConfig reads VS Code chat sessions from the editor storage folders", () => {
  const directories = loadConfig({ APPDATA: join(tmpdir(), "roaming") })
    .activitySourceDirectories.copilotChat;
  assert.equal(directories.length, 4);
  assert.ok(directories.some((directory) =>
    directory.endsWith(join("Code", "User", "workspaceStorage"))
  ));
  assert.ok(directories.some((directory) =>
    directory.endsWith(join("Code - Insiders", "User", "globalStorage", "emptyWindowChatSessions"))
  ));
  assert.deepEqual(
    loadConfig({ PHIGON_COPILOT_CHAT_ACTIVITY_DIRS: "/srv/vscode/workspaceStorage" })
      .activitySourceDirectories.copilotChat,
    ["/srv/vscode/workspaceStorage"],
  );
});

test("loadConfig reads Kiro chat sessions from the editor storage folder", () => {
  const [directory] = loadConfig({ APPDATA: join(tmpdir(), "roaming") })
    .activitySourceDirectories.kiro;
  assert.ok(directory?.endsWith(
    join("Kiro", "User", "globalStorage", "kiro.kiroagent", "workspace-sessions"),
  ));
  assert.deepEqual(
    loadConfig({ PHIGON_KIRO_ACTIVITY_DIRS: "none" }).activitySourceDirectories.kiro,
    [],
  );
});

test("loadConfig finds Zed's threads database folder", () => {
  const [directory] = loadConfig({ LOCALAPPDATA: join(tmpdir(), "local"), XDG_DATA_HOME: "/srv/data" })
    .activitySourceDirectories.zed;
  assert.equal(
    directory,
    process.platform === "win32"
      ? join(tmpdir(), "local", "Zed", "threads")
      : process.platform === "darwin"
        ? join(homedir(), "Library", "Application Support", "Zed", "threads")
        : join("/srv/data", "zed", "threads"),
  );
  assert.deepEqual(
    loadConfig({ PHIGON_ZED_ACTIVITY_DIRS: "none" }).activitySourceDirectories.zed,
    [],
  );
});

test("loadConfig reads Factory Droid sessions from ~/.factory/sessions", () => {
  assert.deepEqual(
    loadConfig({}).activitySourceDirectories.droid,
    [join(homedir(), ".factory", "sessions")],
  );
  assert.deepEqual(
    loadConfig({ PHIGON_DROID_ACTIVITY_DIRS: "none" }).activitySourceDirectories.droid,
    [],
  );
});

test("loadConfig finds the Goose sessions database directory", () => {
  assert.deepEqual(
    loadConfig({ GOOSE_PATH_ROOT: "/srv/goose" }).activitySourceDirectories.goose,
    [join("/srv/goose", "data", "sessions")],
  );
  const expected = process.platform === "win32"
    ? join("C:/Users/dev/AppData/Roaming", "Block", "goose", "data", "sessions")
    : join("/home/dev/.data", "goose", "sessions");
  assert.deepEqual(
    loadConfig({
      APPDATA: "C:/Users/dev/AppData/Roaming",
      XDG_DATA_HOME: "/home/dev/.data",
    }).activitySourceDirectories.goose,
    [expected],
  );
  assert.deepEqual(
    loadConfig({ PHIGON_GOOSE_ACTIVITY_DIRS: "none" }).activitySourceDirectories.goose,
    [],
  );
});

test("loadConfig accepts OpenCode's consented local database directory", () => {
  const config = loadConfig({
    PHIGON_OPENCODE_ACTIVITY_DIRS: "/var/lib/opencode-data",
  });
  assert.deepEqual(config.activitySourceDirectories.opencode, [
    "/var/lib/opencode-data",
  ]);
});

test("loadConfig bounds the recurring discovery interval", () => {
  assert.throws(
    () =>
      loadConfig({
        PHIGON_DISCOVERY_INTERVAL_MS: "999",
      }),
    /between 1000 and 3600000/,
  );
});

test("loadConfig requires TLS for non-loopback control planes", () => {
  assert.throws(
    () =>
      loadConfig({
        PHIGON_CONTROL_PLANE_URL: "http://control.example.test",
      }),
    /must use HTTPS/,
  );
});

test("loadConfig accepts bracketed IPv6 loopback over HTTP", () => {
  const config = loadConfig({
    PHIGON_CONTROL_PLANE_URL: "http://[::1]:8080",
    PHIGON_GRPC_URL: "http://[::1]:9090",
  });
  assert.equal(config.controlPlaneUrl.hostname, "[::1]");
  assert.equal(config.grpcUrl.hostname, "[::1]");
});

test("loadConfig rejects embedded credentials", () => {
  assert.throws(
    () =>
      loadConfig({
        PHIGON_CONTROL_PLANE_URL:
          "https://machine-token@control.example.test",
      }),
    /must not contain embedded credentials/,
  );
});

test("loadConfig requires paired mutual-TLS client files", () => {
  assert.throws(
    () =>
      loadConfig({
        PHIGON_TLS_CLIENT_CERT_FILE: "/secure/client.crt",
      }),
    /configured together/,
  );
  const config = loadConfig({
    PHIGON_TLS_CA_FILE: "/secure/root-ca.pem",
    PHIGON_TLS_CLIENT_CERT_FILE: "/secure/client.crt",
    PHIGON_TLS_CLIENT_KEY_FILE: "/secure/client.key",
  });
  assert.equal(config.tlsCaFile, "/secure/root-ca.pem");
  assert.equal(config.tlsClientKeyFile, "/secure/client.key");
});

test("loadConfig accepts case-insensitive, padded boolean overrides", () => {
  const config = loadConfig({ PHIGON_COLLECT_PROMPT_CONTENT: " True ", PHIGON_COLLECT_TOOL_OUTPUT: "FALSE" });
  assert.equal(config.policy.promptContent, true);
  assert.equal(config.policy.toolOutput, false);
  assert.throws(() => loadConfig({ PHIGON_COLLECT_PROMPT_CONTENT: "maybe" }), /must be true or false/u);
});
