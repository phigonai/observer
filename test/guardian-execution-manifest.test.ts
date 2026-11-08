import assert from "node:assert/strict";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { createExecutionManifest, executionEnvironment, verifyExecutionManifest } from "../src/guardian-execution-manifest.js";

test("execution review binds file content, arguments, cwd, and environment", async () => {
  const directory = await mkdtemp(join(tmpdir(), "guardian-manifest-"));
  try {
    const script = join(directory, "agent.js"); await writeFile(script, "process.exit(0)");
    const environment = executionEnvironment(process.env);
    const manifest = await createExecutionManifest({ executable: process.execPath, arguments: [script], agentId: "test", environment, cwd: directory });
    await verifyExecutionManifest(manifest, environment);
    await assert.rejects(verifyExecutionManifest(manifest, { ...environment, GUARDIAN_TEST_VALUE: "changed" }), /changed after review/u);
    await writeFile(script, "process.exit(9)");
    await assert.rejects(verifyExecutionManifest(manifest, environment), /changed after review/u);
  } finally { await rm(directory, { recursive: true, force: true }); }
});

test("workload environment strips management secrets and interpreter injection", () => {
  const environment = executionEnvironment({ PHIGON_MACHINE_TOKEN: "secret", phigon_data_dir: "private", NODE_OPTIONS: "--require attacker", LD_PRELOAD: "attacker", PATH: "safe", NORMAL: "kept" });
  assert.deepEqual(environment, { PATH: "safe" });
});

test("workload environment passes only allowlisted and configured variables", () => {
  const injection = {
    LD_AUDIT: "x", LD_LIBRARY_PATH: "x", DYLD_INSERT_LIBRARIES: "x", "BASH_FUNC_git%%": "() { x; }", BASH_ENV: "x", ENV: "x", PS4: "$(x)",
    PROMPT_COMMAND: "x", IFS: "x", JAVA_TOOL_OPTIONS: "x", _JAVA_OPTIONS: "x", JDK_JAVA_OPTIONS: "x", MAVEN_OPTS: "x", NODE_PATH: "x",
    PYTHONSTARTUP: "x", PYTHONPATH: "x", PERL5OPT: "x", RUBYOPT: "x", GIT_SSH_COMMAND: "x", GIT_EXEC_PATH: "x", GIT_CONFIG_COUNT: "1",
    GIT_PAGER: "x", GIT_ASKPASS: "x", SSH_ASKPASS: "x", GCONV_PATH: "x", OPENSSL_CONF: "x", LESSOPEN: "x", ZDOTDIR: "x",
    ELECTRON_RUN_AS_NODE: "1", DOTNET_STARTUP_HOOKS: "x", COR_PROFILER_PATH: "x", CORECLR_PROFILER_PATH: "x",
  };
  const ordinary = { HOME: "/home/agent", LANG: "C.UTF-8", LC_ALL: "C.UTF-8", TERM: "xterm-256color", https_proxy: "http://proxy:3128",
    SSL_CERT_FILE: "/etc/ssl/cert.pem", GIT_AUTHOR_NAME: "Agent", XDG_CONFIG_HOME: "/home/agent/.config" };
  const configured = Object.keys(injection).join(",");
  const environment = executionEnvironment({ ...injection, ...ordinary, GITHUB_TOKEN: "kept-when-configured", EDITOR: "vim",
    UNRELATED: "dropped", PHIGON_GUARDIAN_ENV_ALLOW: `GITHUB_TOKEN, EDITOR ${configured}` });
  assert.deepEqual(environment, { ...ordinary, GITHUB_TOKEN: "kept-when-configured", EDITOR: "vim" });
});
