/**
 * Agents installed with npm (Gemini CLI, GitHub Copilot CLI, Amp, Claude
 * Code) run as their JavaScript runtime, so the process image (`node`) does
 * not say which agent it is. For interpreter processes only, discovery reads
 * the command line on this computer and keeps just the npm package that owns
 * the script being run: the folder after the last `node_modules`.
 *
 * A command line can hold secrets. It is parsed in memory and dropped right
 * away; it is never kept, logged, hashed or sent. The bundled Windows helper
 * (go/cmd/guardian-runner/script_package.go) applies the same rules
 * and reports only the package.
 */

const interpreterNames: ReadonlySet<string> = new Set(["node", "bun", "deno"]);

// Interpreter options that take their value as the next argument.
const separateValueOptions: ReadonlySet<string> = new Set([
  "-r",
  "--require",
  "--import",
  "--loader",
  "--experimental-loader",
  "-C",
  "--conditions",
  "--input-type",
  "--env-file",
  "--title",
  "--inspect-port",
  "--preload",
  "--cwd",
  "--config",
]);

// Options after which the interpreter runs code that is not a script file.
const inlineCodeOptions: ReadonlySet<string> = new Set([
  "-e",
  "--eval",
  "-p",
  "--print",
  "-pe",
]);

const maxPackageNameLength = 214;
const packageSegmentPattern = /^[a-z0-9~-][a-z0-9._~-]*$/u;
// Windows limits a command line to 32,767 UTF-16 characters.
const maxCommandLineLength = 32_767;

/** Whether a normalized executable name (`node`, not `node.exe`) is a script runtime. */
export function isInterpreterName(executableName: string): boolean {
  return interpreterNames.has(executableName);
}

/**
 * Splits a Windows command line as CommandLineToArgvW and the Microsoft C
 * runtime do: the program name ends at the first space outside quotes, and
 * later arguments follow the quote and backslash rules.
 */
export function windowsCommandLineArguments(commandLine: string): string[] {
  const line = commandLine.slice(0, maxCommandLineLength);
  const isBlank = (index: number) => line[index] === " " || line[index] === "\t";
  let index = 0;
  while (index < line.length && isBlank(index)) index++;
  let program = "";
  let quoted = false;
  for (; index < line.length; index++) {
    const character = line[index];
    if (character === '"') {
      quoted = !quoted;
      continue;
    }
    if (!quoted && isBlank(index)) break;
    program += character;
  }
  const values = [program];
  for (;;) {
    while (index < line.length && isBlank(index)) index++;
    if (index >= line.length) return values;
    let value = "";
    quoted = false;
    while (index < line.length && (quoted || !isBlank(index))) {
      const character = line[index];
      if (character === "\\") {
        let backslashes = 0;
        while (line[index] === "\\") {
          backslashes++;
          index++;
        }
        if (line[index] === '"') {
          value += "\\".repeat(Math.floor(backslashes / 2));
          if (backslashes % 2 === 1) {
            value += '"';
            index++;
          }
        } else {
          value += "\\".repeat(backslashes);
        }
        continue;
      }
      if (character === '"') {
        if (quoted && line[index + 1] === '"') {
          value += '"';
          index += 2;
          continue;
        }
        quoted = !quoted;
        index++;
        continue;
      }
      value += character;
      index++;
    }
    values.push(value);
  }
}

/**
 * The script an interpreter runs: the first argument that is not one of its
 * options. Code given inline (`node -e`) or on standard input has no script.
 */
export function scriptArgument(
  interpreter: string,
  values: readonly string[],
): string | undefined {
  let index = 1;
  if ((interpreter === "bun" || interpreter === "deno") && values[index] === "run") {
    index++;
  }
  for (; index < values.length; index++) {
    const value = values[index] ?? "";
    if (value === "--") return values[index + 1];
    if (value === "-") return undefined;
    if (value.startsWith("-")) {
      const separator = value.indexOf("=");
      const name = separator === -1 ? value : value.slice(0, separator);
      if (inlineCodeOptions.has(name)) return undefined;
      if (separator === -1 && separateValueOptions.has(name)) index++;
      continue;
    }
    return value;
  }
  return undefined;
}

/**
 * The npm package that owns a script: the folder after the last
 * `node_modules` (`@scope/name` or `name`), in lower case. Anything that is
 * not a valid package name, such as `.bin`, gives none.
 */
export function packageFromScriptPath(path: string): string | undefined {
  const segments = path.split(/[\\/]/u).filter((segment) => segment.length > 0);
  let last = -1;
  for (let index = segments.length - 1; index >= 0; index--) {
    if (segments[index]?.toLowerCase() === "node_modules") {
      last = index;
      break;
    }
  }
  if (last === -1) return undefined;
  const first = segments[last + 1]?.toLowerCase();
  if (first === undefined) return undefined;
  if (!first.startsWith("@")) return validScriptPackage(first);
  const second = segments[last + 2]?.toLowerCase();
  return second === undefined ? undefined : validScriptPackage(`${first}/${second}`);
}

/** Accepts only a well-formed npm package name. */
export function validScriptPackage(value: unknown): string | undefined {
  if (typeof value !== "string" || value.length === 0 || value.length > maxPackageNameLength) {
    return undefined;
  }
  const parts = value.split("/");
  const valid = parts.length === 1
    ? packageSegmentPattern.test(value)
    : parts.length === 2 &&
      parts[0]!.startsWith("@") &&
      packageSegmentPattern.test(parts[0]!.slice(1)) &&
      packageSegmentPattern.test(parts[1]!);
  return valid ? value : undefined;
}

/** The package an interpreter's Windows command line runs, if any. */
export function scriptPackageFromWindowsCommandLine(
  executableName: string,
  commandLine: string,
): string | undefined {
  if (!isInterpreterName(executableName)) return undefined;
  const script = scriptArgument(executableName, windowsCommandLineArguments(commandLine));
  return script === undefined ? undefined : packageFromScriptPath(script);
}

export type ScriptProcess = Readonly<{
  processId: number;
  parentProcessId?: number | undefined;
  startedAt: Date;
  scriptPackage?: string | undefined;
}>;

/**
 * The package each process runs, by process ID. Some CLIs relaunch
 * themselves (Gemini CLI starts its own child to set memory limits); a
 * process started by a process of the same package belongs to that run, so
 * only the first one is reported. Stopping it stops its descendants.
 */
export function scriptPackagesByProcess(
  processes: readonly ScriptProcess[],
): ReadonlyMap<number, string> {
  const byID = new Map(processes.map((entry) => [entry.processId, entry]));
  const packages = new Map<number, string>();
  for (const entry of processes) {
    if (entry.scriptPackage === undefined) continue;
    const parent = entry.parentProcessId === undefined
      ? undefined
      : byID.get(entry.parentProcessId);
    if (
      parent !== undefined &&
      parent.processId !== entry.processId &&
      parent.scriptPackage === entry.scriptPackage &&
      parent.startedAt.getTime() <= entry.startedAt.getTime()
    ) {
      continue;
    }
    packages.set(entry.processId, entry.scriptPackage);
  }
  return packages;
}
