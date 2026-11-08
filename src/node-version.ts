// Loaded before anything else, so it imports nothing: an older Node.js must
// reach the plain message below instead of failing on a newer API.

/**
 * The oldest Node.js the observer runs on. Trusting a company's own server
 * needs `tls.setDefaultCACertificates`, which Node.js 24.5 added.
 */
export const minimumNodeVersion = "24.5.0";

/**
 * The data directory of a background service's `run --service-settings
 * <file>`, whose settings file sits in it, or undefined for any other
 * command.
 */
export function serviceDataDirectory(argv: readonly string[], dirname: (path: string) => string): string | undefined {
  if (argv[0] !== "run") return undefined;
  for (let index = 1; index < argv.length; index++) {
    const value = argv[index];
    if (value === "--service-settings") {
      const file = argv[index + 1];
      return file === undefined || file.startsWith("--") ? undefined : dirname(file);
    }
    if (value !== undefined && value.startsWith("--service-settings=")) {
      return dirname(value.slice("--service-settings=".length));
    }
  }
  return undefined;
}

/**
 * Writes why a background service's observer could not start to its log,
 * logs/observer.log, where `service status` and `logs` read it: nobody sees
 * what a service prints. Imports what it needs only now, so an older
 * Node.js still gets this far. Never throws.
 */
export async function logServiceStartupFailure(argv: readonly string[], message: string, now: Date = new Date()): Promise<void> {
  try {
    const { dirname, join } = await import("node:path");
    const { appendFile, mkdir } = await import("node:fs/promises");
    const dataDirectory = serviceDataDirectory(argv, dirname);
    if (dataDirectory === undefined) return;
    const logs = join(dataDirectory, "logs");
    await mkdir(logs, { recursive: true, mode: 0o700 });
    // Masked like everything the log keeps. If even that module cannot be
    // loaded, the message (a Node.js version or loading error) is kept as is.
    const redact = await import("./content-redaction.js").then(
      (module) => module.redactSecrets,
      () => (value: string) => value,
    );
    const line = redact(message).replace(/[\u0000-\u001f\u007f]+/gu, " ").trim().slice(0, 2000);
    await appendFile(join(logs, "observer.log"), `${now.toISOString()} ERROR ${line}\n`, { encoding: "utf8", mode: 0o600 });
  } catch {
    // Nothing else to tell; the service manager still records the exit.
  }
}

/**
 * Keeps launchd's service-errors.log small: what Node.js printed in earlier
 * starts is cut to its last part before this start adds to it. launchd
 * opens the file for appending, so the observer's own output still follows.
 */
export async function trimServiceErrors(argv: readonly string[], limitBytes = 256 * 1024, keepBytes = 64 * 1024): Promise<void> {
  try {
    const { dirname, join } = await import("node:path");
    const { open, stat } = await import("node:fs/promises");
    const dataDirectory = serviceDataDirectory(argv, dirname);
    if (dataDirectory === undefined) return;
    const path = join(dataDirectory, "logs", "service-errors.log");
    const size = (await stat(path)).size;
    if (size <= limitBytes) return;
    const file = await open(path, "r+");
    try {
      const kept = Buffer.alloc(keepBytes);
      const { bytesRead } = await file.read(kept, 0, keepBytes, size - keepBytes);
      const text = kept.subarray(0, bytesRead).toString("utf8");
      // Start at a whole line.
      const tail = Buffer.from(text.slice(text.indexOf("\n") + 1), "utf8");
      await file.truncate(0);
      await file.write(tail, 0, tail.length, 0);
    } finally {
      await file.close();
    }
  } catch {
    // Missing (not macOS, or nothing printed yet) or unreadable: leave it.
  }
}

/** Why this Node.js cannot run the observer, or undefined when it can. */
export function nodeVersionProblem(version: string): string | undefined {
  const match = /^v?(\d+)\.(\d+)\.(\d+)/u.exec(version);
  const major = match === null ? 0 : Number(match[1]);
  const minor = match === null ? 0 : Number(match[2]);
  if (major > 24 || (major === 24 && minor >= 5)) return undefined;
  return `Phigon observer needs Node.js 24.5 or newer; this computer has ${version.replace(/^v/u, "")}.`;
}
