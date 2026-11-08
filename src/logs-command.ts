import { stat } from "node:fs/promises";
import { UsageError } from "./command-options.js";
import { followLog, logFilePath, logTail } from "./observer-log.js";

export const defaultLogLines = 50;
const maxLogLines = 10_000;

/** How many lines `--tail <lines>` asks for, or the default without it. */
export function tailLines(flags: readonly string[]): number {
  let value: string | undefined;
  for (let index = 0; index < flags.length; index++) {
    const flag = flags[index];
    if (flag === "--tail") value = flags[index + 1];
    else if (flag?.startsWith("--tail=")) value = flag.slice("--tail=".length);
  }
  if (value === undefined) return defaultLogLines;
  const count = Number(value);
  // A wrong count is a wrong command line, which exits with 2 like any other.
  if (!/^\d{1,5}$/u.test(value) || count < 1 || count > maxLogLines) {
    throw new UsageError(`--tail takes a number of lines from 1 to ${maxLogLines}.`);
  }
  return count;
}

/**
 * `logs [--tail <lines>] [--follow]`: the last lines of the observer log in the
 * data directory, which the background service writes, then with --follow
 * every new line until interrupted. Secrets are masked again on the way out.
 */
export async function runLogsCommand(
  flags: readonly string[],
  dataDirectory: string,
  output: Readonly<{ stdout: (value: string) => void }>,
  stopSignal?: AbortSignal,
): Promise<number> {
  const count = tailLines(flags);
  const follow = flags.includes("--follow");
  const path = logFilePath(dataDirectory);
  const exists = await stat(path).then(() => true, () => false);
  if (!exists && !follow) {
    output.stdout(`There is no observer log yet (${path}). The background service writes it once it runs.\n`);
    return 0;
  }
  for (const line of await logTail(dataDirectory, count)) output.stdout(`${line}\n`);
  if (!follow) return 0;
  const controller = new AbortController();
  const stop = () => controller.abort();
  if (stopSignal?.aborted === true) stop();
  stopSignal?.addEventListener("abort", stop, { once: true });
  if (stopSignal === undefined) {
    process.once("SIGINT", stop);
    process.once("SIGTERM", stop);
  }
  try {
    await followLog(dataDirectory, (line) => output.stdout(`${line}\n`), controller.signal);
  } finally {
    stopSignal?.removeEventListener("abort", stop);
    process.removeListener("SIGINT", stop);
    process.removeListener("SIGTERM", stop);
  }
  return 0;
}
