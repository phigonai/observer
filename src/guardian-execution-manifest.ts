import { createHash } from "node:crypto";
import { constants, createReadStream } from "node:fs";
import { access, realpath, stat } from "node:fs/promises";
import { delimiter, isAbsolute, resolve } from "node:path";

export type ExecutionManifest = Readonly<{
  sandbox: string;
  executable: string;
  executable_digest: string;
  arguments: readonly string[];
  working_directory: string;
  environment_digest: string;
  inputs: readonly Readonly<{ path: string; digest: string }>[];
  agent_id: string;
  model: string;
  cgroup_root: string;
}>;

export function executionEnvironment(source: NodeJS.ProcessEnv): NodeJS.ProcessEnv {
  const result: NodeJS.ProcessEnv = {};
  const seen = new Set<string>();
  for (const key of Object.keys(source).sort()) {
    const value = source[key];
    const normalized = process.platform === "win32" ? key.toUpperCase() : key;
    if (value === undefined || seen.has(normalized)) continue;
    seen.add(normalized);
    // Machine management credentials and runtime injection must never be
    // inherited by the supervised workload.
    if (/^PHIGON_/iu.test(key) || /^(NODE_OPTIONS|NODE_PATH|LD_PRELOAD|LD_LIBRARY_PATH|DYLD_.*|PYTHONPATH|PYTHONHOME|RUBYOPT|PERL5OPT|BASH_ENV|ENV)$/iu.test(key)) continue;
    result[key] = value;
  }
  return result;
}

export async function digestExecutable(path: string): Promise<string> {
  const info = await stat(path);
  if (!info.isFile() || info.size > 1 << 30) throw new Error("Guardian execution input is not a supported regular file.");
  const hash = createHash("sha256");
  for await (const chunk of createReadStream(path)) hash.update(chunk as Buffer);
  return hash.digest("hex");
}

async function resolveExecutable(executable: string, cwd: string, env: NodeJS.ProcessEnv): Promise<string> {
  const explicit = isAbsolute(executable) || /[/\\]/u.test(executable);
  const pathKey = Object.keys(env).find((key) => key.toUpperCase() === "PATH");
  const paths = explicit ? [resolve(cwd, executable)] : (env[pathKey ?? "PATH"] ?? "").split(delimiter)
    .filter((entry) => entry !== "" && isAbsolute(entry)).map((entry) => resolve(entry, executable));
  for (const path of paths) {
    const candidates = process.platform === "win32" && !/\.exe$/iu.test(path) ? [path, `${path}.exe`] : [path];
    for (const candidate of candidates) {
      try {
        const resolved = await realpath(candidate);
        if (process.platform === "win32" && !/\.exe$/iu.test(resolved)) continue;
        if (!(await stat(resolved)).isFile()) continue;
        await access(resolved, process.platform === "win32" ? constants.F_OK : constants.X_OK);
        return resolved;
      } catch { /* Try the next explicit PATH entry. */ }
    }
  }
  throw new Error("Guardian could not resolve a native executable. For scripts, name the interpreter explicitly.");
}

export async function createExecutionManifest(options: Readonly<{
  executable: string; arguments: readonly string[]; agentId: string; model?: string;
  environment: NodeJS.ProcessEnv; cwd?: string;
  cgroupRoot?: string;
  sandbox?: string;
}>): Promise<ExecutionManifest> {
  const cwd = await realpath(options.cwd ?? process.cwd());
  if (options.cgroupRoot && (process.platform !== "linux" || !isAbsolute(options.cgroupRoot))) throw new Error("Guardian cgroup configuration requires an absolute Linux cgroup-v2 root.");
  const executable = await resolveExecutable(options.executable, cwd, options.environment);
  const inputs: { path: string; digest: string }[] = [];
  // Bind existing file arguments, including directly named scripts/configs.
  // Files read indirectly need an OS filesystem policy; they are not guessed.
  for (const arg of options.arguments) {
    if (arg.startsWith("-") || arg.includes("\0") || arg.length > 4096) continue;
    let path: string;
    try { path = await realpath(resolve(cwd, arg)); if (!(await stat(path)).isFile()) continue; }
    catch { continue; }
    if (!inputs.some((input) => input.path === path)) inputs.push({ path, digest: await digestExecutable(path) });
    if (inputs.length > 64) throw new Error("Guardian execution has too many file inputs.");
  }
  const environmentEntries = Object.entries(options.environment).filter((entry) => entry[1] !== undefined).sort(([a], [b]) => a < b ? -1 : a > b ? 1 : 0);
  const manifest = Object.freeze({
    sandbox: options.sandbox ?? "",
    executable, executable_digest: await digestExecutable(executable), arguments: Object.freeze([...options.arguments]),
    working_directory: cwd, environment_digest: createHash("sha256").update(JSON.stringify(environmentEntries)).digest("hex"),
    inputs: Object.freeze(inputs.map((input) => Object.freeze(input))), agent_id: options.agentId, model: options.model ?? "", cgroup_root: options.cgroupRoot ?? "",
  });
  if (Buffer.byteLength(JSON.stringify(manifest)) > 56 << 10) throw new Error("Guardian execution manifest exceeds its bound.");
  return manifest;
}

export async function verifyExecutionManifest(manifest: ExecutionManifest, environment: NodeJS.ProcessEnv): Promise<void> {
  const current = await createExecutionManifest({ executable: manifest.executable, arguments: manifest.arguments,
    agentId: manifest.agent_id, model: manifest.model, cwd: manifest.working_directory, environment, cgroupRoot: manifest.cgroup_root, sandbox: manifest.sandbox });
  if (JSON.stringify(current) !== JSON.stringify(manifest)) throw new Error("Phigon Guardian blocked execution because its executable, inputs, directory, or environment changed after review.");
}
