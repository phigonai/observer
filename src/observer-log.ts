import { appendFileSync, existsSync, mkdirSync, statSync } from "node:fs";
import { join } from "node:path";
import { atomicReplaceSync } from "./atomic-replace.js";
import type { ObserverLogLevel } from "./config.js";
import { makeDirectoryPrivateSync } from "./private-directory.js";

/** The log folder in the data directory, and the file the observer writes. */
export const logDirectoryName = "logs";
export const logFileName = "observer.log";
/** About 5 MB per file and three files: the current one and two older ones. */
export const defaultLogFileBytes = 5 * 1024 * 1024;
export const defaultLogFiles = 3;
const maxLineBytes = 4 * 1024;

const severity: Readonly<Record<ObserverLogLevel, number>> = Object.freeze({
  debug: 10,
  info: 20,
  warn: 30,
  error: 40,
});

export function logFilePath(dataDirectory: string): string {
  return join(dataDirectory, logDirectoryName, logFileName);
}

/**
 * `PHIGON_LOG_LEVEL`, read before the rest of the configuration so that a
 * configuration error is logged too. An invalid value logs at info; the
 * configuration check then reports it.
 */
export function logLevelFrom(value: string | undefined): ObserverLogLevel {
  return value === "debug" || value === "warn" || value === "error" ? value : "info";
}

export type RotatingLogFileOptions = Readonly<{
  maxBytes?: number;
  files?: number;
  now?: () => Date;
  /** Told once when the file cannot be written; logging then stops. */
  onFailure?: (message: string) => void;
}>;

/**
 * A log file in the data directory that a background service keeps, since
 * a scheduled task or LaunchAgent throws its output away. It is written
 * synchronously, one short line at a time, and rotated by size, so it never
 * holds anything in memory and never grows past `files` × `maxBytes`. It
 * only ever receives messages that are already safe to print.
 */
export class RotatingLogFile {
  readonly #dataDirectory: string;
  readonly #path: string;
  readonly #maxBytes: number;
  readonly #files: number;
  readonly #now: () => Date;
  readonly #onFailure: ((message: string) => void) | undefined;
  #size: number | undefined;
  #failed = false;

  constructor(dataDirectory: string, options: RotatingLogFileOptions = {}) {
    this.#dataDirectory = dataDirectory;
    this.#path = logFilePath(dataDirectory);
    this.#maxBytes = options.maxBytes ?? defaultLogFileBytes;
    this.#files = Math.max(1, options.files ?? defaultLogFiles);
    this.#now = options.now ?? (() => new Date());
    this.#onFailure = options.onFailure;
  }

  get path(): string {
    return this.#path;
  }

  write(level: ObserverLogLevel, message: string): void {
    if (this.#failed) return;
    const stamp = this.#now().toISOString();
    const label = level.toUpperCase().padEnd(5);
    const text = message
      .split(/\r?\n/u)
      .map(clean)
      .filter((line) => line.length > 0)
      .map((line) => `${stamp} ${label} ${line}\n`)
      .join("");
    if (text.length === 0) return;
    try {
      if (this.#size === undefined) this.#size = this.#open();
      const bytes = Buffer.byteLength(text, "utf8");
      if (this.#size > 0 && this.#size + bytes > this.#maxBytes) {
        this.#rotate();
        this.#size = 0;
      }
      appendFileSync(this.#path, text, { encoding: "utf8", mode: 0o600 });
      this.#size += bytes;
    } catch {
      // The observer keeps running without its log; say so once.
      this.#failed = true;
      this.#onFailure?.(
        `The observer log could not be written to ${this.#path}; messages are no longer logged there.\n`,
      );
    }
  }

  #open(): number {
    const directory = join(this.#dataDirectory, logDirectoryName);
    if (!existsSync(this.#dataDirectory)) {
      mkdirSync(this.#dataDirectory, { recursive: true, mode: 0o700 });
    }
    makeDirectoryPrivateSync(this.#dataDirectory);
    mkdirSync(directory, { recursive: true, mode: 0o700 });
    try {
      return statSync(this.#path).size;
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "ENOENT") return 0;
      throw error;
    }
  }

  #rotate(): void {
    for (let index = this.#files - 1; index >= 1; index--) {
      const from = index === 1 ? this.#path : `${this.#path}.${index - 1}`;
      if (existsSync(from)) atomicReplaceSync(from, `${this.#path}.${index}`);
    }
    // With a single file there is nothing to keep: start it again.
    if (this.#files === 1 && existsSync(this.#path)) {
      appendFileSync(this.#path, "", { flag: "w" });
    }
  }
}

/** Drops control characters, such as terminal colour codes, and caps the length. */
function clean(line: string): string {
  const printable = line.replace(/[\u0000-\u0008\u000b-\u001f\u007f\u009b]/gu, "").trimEnd();
  if (Buffer.byteLength(printable, "utf8") <= maxLineBytes) return printable;
  return `${Buffer.from(printable, "utf8").subarray(0, maxLineBytes).toString("utf8").replace(/�$/u, "")}…`;
}

export type LogOutput = Readonly<{
  stdout: (value: string) => void;
  stderr: (value: string) => void;
}>;

/** `LogOutput` that also takes errors and debug details. */
export type LevelledOutput = LogOutput & Readonly<{
  error: (value: string) => void;
  debug: (value: string) => void;
}>;

/**
 * Applies `PHIGON_LOG_LEVEL` to what a command prints and copies each
 * message it keeps to the log file: status lines are info, problems on
 * stderr are warnings, and the message a command fails with is an error.
 */
export function levelledOutput(
  output: LogOutput,
  level: ObserverLogLevel,
  log?: RotatingLogFile,
): LevelledOutput {
  const emit = (messageLevel: ObserverLogLevel, write: (value: string) => void) =>
    (value: string) => {
      if (severity[messageLevel] < severity[level]) return;
      // The log first: a background service's console may already be gone.
      log?.write(messageLevel, value);
      write(value);
    };
  return Object.freeze({
    stdout: emit("info", output.stdout),
    stderr: emit("warn", output.stderr),
    error: emit("error", output.stderr),
    debug: emit("debug", output.stdout),
  });
}
