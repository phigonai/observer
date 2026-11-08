import { appendFileSync, existsSync, mkdirSync, statSync } from "node:fs";
import { open, stat } from "node:fs/promises";
import { join } from "node:path";
import { abortableDelay } from "./abortable-delay.js";
import { atomicReplaceSync } from "./atomic-replace.js";
import type { ObserverLogLevel } from "./config.js";
import { redactSecrets } from "./content-redaction.js";
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
 * Where launchd puts what a LaunchAgent's process prints itself, such as
 * Node.js failing to start the observer or crashing. The observer's own
 * messages go to observer.log.
 */
export const serviceErrorsFileName = "service-errors.log";

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

  /** Whether writing failed, after which nothing more is logged. */
  get failed(): boolean {
    return this.#failed;
  }

  write(level: ObserverLogLevel, message: string): void {
    if (this.#failed) return;
    const stamp = this.#now().toISOString();
    const label = level.toUpperCase().padEnd(5);
    // Whatever a caller passes, a credential is never stored: the whole
    // message is masked first, so a key spread over lines is caught too.
    const text = redactSecrets(message)
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

// ---------------------------------------------------------------------------
// Reading the log back, for `logs` and `service status`.

/** How much of the end of a log file is read; files are at most about 5 MB. */
const maxTailBytes = 1024 * 1024;

/** The last `maxBytes` of a file, starting at a whole line; empty when it is missing. */
async function readTail(path: string, maxBytes = maxTailBytes): Promise<string> {
  let file;
  try {
    file = await open(path, "r");
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return "";
    throw error;
  }
  try {
    const { size } = await file.stat();
    const length = Math.min(size, maxBytes);
    const buffer = Buffer.alloc(length);
    const { bytesRead } = await file.read(buffer, 0, length, size - length);
    const text = buffer.subarray(0, bytesRead).toString("utf8");
    return length < size ? text.slice(text.indexOf("\n") + 1) : text;
  } finally {
    await file.close();
  }
}

function lines(text: string): string[] {
  return text.split(/\r?\n/u).filter((line) => line.length > 0);
}

/**
 * One log line made safe to show: the log only receives messages that are
 * already safe to print, and secrets are masked again in case one slipped
 * through.
 */
export function shownLogLine(line: string): string {
  return redactSecrets(clean(line));
}

/**
 * The last `count` lines of the observer log, oldest first: from the
 * current file, then the rotated ones before it (observer.log.1, .2) while
 * more are wanted. Each file is read backwards in small chunks, so memory
 * holds the lines asked for, not the files.
 */
export async function logTail(dataDirectory: string, count: number): Promise<string[]> {
  if (count <= 0) return [];
  const path = logFilePath(dataDirectory);
  const files = [path, ...Array.from({ length: defaultLogFiles - 1 }, (_, index) => `${path}.${index + 1}`)];
  const collected: string[] = [];
  for (const file of files) {
    if (collected.length >= count) break;
    collected.unshift(...await lastLines(file, count - collected.length));
  }
  return collected.map(shownLogLine);
}

/** A line longer than this (the writer keeps lines to 4 KB) is cut to its end. */
const maxPartialLineBytes = 64 * 1024;

/** The last `count` non-empty lines of a file, oldest first; none when it is missing. */
export async function lastLines(path: string, count: number, chunkBytes = 64 * 1024): Promise<string[]> {
  let file;
  try {
    file = await open(path, "r");
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return [];
    throw error;
  }
  try {
    let position = (await file.stat()).size;
    // The start of a line whose beginning is in an earlier chunk.
    let partial = Buffer.alloc(0);
    const newestFirst: string[] = [];
    while (position > 0 && newestFirst.length < count) {
      const length = Math.min(chunkBytes, position);
      position -= length;
      const chunk = Buffer.alloc(length);
      const { bytesRead } = await file.read(chunk, 0, length, position);
      const data = Buffer.concat([chunk.subarray(0, bytesRead), partial]);
      let end = data.length;
      for (let index = data.length - 1; index >= 0 && newestFirst.length < count; index--) {
        if (data[index] !== 0x0a) continue;
        const line = data.subarray(index + 1, end).toString("utf8").replace(/\r$/u, "");
        if (line.length > 0) newestFirst.push(line);
        end = index;
      }
      partial = data.subarray(Math.max(0, end - maxPartialLineBytes), end);
    }
    if (position === 0 && newestFirst.length < count) {
      const first = partial.toString("utf8").replace(/\r$/u, "");
      if (first.length > 0) newestFirst.push(first);
    }
    return newestFirst.reverse();
  } finally {
    await file.close();
  }
}

/**
 * Prints lines added to the observer log until `signal` aborts, starting
 * at its current end.
 *
 * The file being followed stays open, so after a rotation renames it the
 * lines written to it just before are still read. A rotation is told by
 * the file at the log's path no longer being the open one (its file ID),
 * not by its size, since the new file can outgrow the old offset before
 * the next look; the new file is then read from its beginning.
 */
export async function followLog(
  dataDirectory: string,
  write: (line: string) => void,
  signal: AbortSignal,
  intervalMs = 500,
): Promise<void> {
  const path = logFilePath(dataDirectory);
  let file = await open(path, "r").catch(() => undefined);
  let identity = file === undefined ? undefined : await file.stat().then((metadata) => metadata.ino, () => undefined);
  let offset = file === undefined ? 0 : await file.stat().then((metadata) => metadata.size, () => 0);
  let partial = "";
  const emit = (text: string, final: boolean) => {
    const all = partial + text;
    const end = final ? all.length : all.lastIndexOf("\n");
    partial = end === -1 ? all : all.slice(end + (final ? 0 : 1));
    for (const line of lines(end === -1 ? "" : all.slice(0, end))) write(shownLogLine(line));
  };
  // Reads what the open file gained since the offset, 1 MB at a time.
  const drain = async () => {
    if (file === undefined) return;
    for (;;) {
      const size = await file.stat().then((metadata) => metadata.size, () => offset);
      // Cut short in place (not rotated): start it again.
      if (size < offset) {
        offset = 0;
        partial = "";
      }
      if (size === offset) return;
      const length = Math.min(size - offset, maxTailBytes);
      const buffer = Buffer.alloc(length);
      const { bytesRead } = await file.read(buffer, 0, length, offset);
      if (bytesRead === 0) return;
      offset += bytesRead;
      emit(buffer.subarray(0, bytesRead).toString("utf8"), false);
    }
  };
  try {
    while (!signal.aborted) {
      await abortableDelay(intervalMs, signal);
      if (signal.aborted) break;
      await drain();
      const current = await stat(path).catch(() => undefined);
      if (current === undefined) continue;
      // Still the open file. A file system without file IDs (0) leaves
      // only the size to tell by.
      const sameFile = file !== undefined &&
        (identity !== 0 ? current.ino === identity : current.ino === 0 && current.size >= offset);
      if (sameFile) continue;
      // Replaced by a rotation, or created: finish the old file's last line
      // and follow the new one from its start.
      if (file !== undefined) {
        emit("", true);
        await file.close().catch(() => undefined);
      }
      file = await open(path, "r").catch(() => undefined);
      identity = file === undefined ? undefined : await file.stat().then((metadata) => metadata.ino, () => undefined);
      offset = 0;
      partial = "";
      await drain();
    }
  } finally {
    await file?.close().catch(() => undefined);
  }
}

/** The most recent error the observer, or Node.js under launchd, recorded. */
export type LoggedError = Readonly<{
  /** When, as an ISO time. */
  at: string;
  message: string;
  /** observer.log, or launchd's service-errors.log. */
  source: "observer-log" | "service-errors";
}>;

const errorLine = /^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z) ERROR (.+)$/u;

/**
 * The latest ERROR line of the observer log (or the rotated file before
 * it), or the last error Node.js printed into service-errors.log, which
 * is dated by when that file last changed.
 */
export async function lastLoggedError(dataDirectory: string): Promise<LoggedError | undefined> {
  const path = logFilePath(dataDirectory);
  let fromLog: LoggedError | undefined;
  for (const candidate of [path, `${path}.1`]) {
    const match = lines(await readTail(candidate).catch(() => "")).reverse()
      .map((line) => errorLine.exec(line)).find((found) => found !== null);
    if (match !== undefined && match !== null) {
      fromLog = { at: match[1] ?? "", message: shownLogLine(match[2] ?? "").slice(0, 500), source: "observer-log" };
      break;
    }
  }
  const errorsPath = join(dataDirectory, logDirectoryName, serviceErrorsFileName);
  let fromService: LoggedError | undefined;
  try {
    const written = (await stat(errorsPath)).mtime;
    const printed = lines(await readTail(errorsPath, 64 * 1024));
    // Node.js ends a crash with its stack and version; the error is the
    // last line that names one, else the last line that is not a frame.
    const message = [...printed].reverse().find((line) => /^[A-Za-z]*Error\b/u.test(line)) ??
      [...printed].reverse().find((line) => !/^\s+at |^Node\.js v\d/u.test(line) && line.trim().length > 1);
    if (message !== undefined) {
      fromService = { at: written.toISOString(), message: shownLogLine(message.trim()).slice(0, 500), source: "service-errors" };
    }
  } catch {
    // No such file: not macOS, or Node.js never printed anything.
  }
  if (fromLog === undefined) return fromService;
  if (fromService === undefined) return fromLog;
  return Date.parse(fromService.at) > Date.parse(fromLog.at) ? fromService : fromLog;
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
 * The console of a background service whose output launchd keeps in
 * service-errors.log, which nothing rotates. While the log file works,
 * messages go only there, so that file keeps only what Node.js itself
 * prints, such as a crash, and stays small.
 */
export function serviceConsole(output: LogOutput, log: RotatingLogFile): LogOutput {
  // Only when the log failed, and masked like it: this console is a file.
  return Object.freeze({
    stdout: (value: string) => {
      if (log.failed) output.stdout(redactSecrets(value));
    },
    stderr: (value: string) => {
      if (log.failed) output.stderr(redactSecrets(value));
    },
  });
}

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
