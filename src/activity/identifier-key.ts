import { randomBytes } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";

/** The file, in the data directory, holding the key for identifier digests. */
export const identifierKeyFileName = "identifier-key";

// Used without a data directory, or when its key cannot be read or written:
// digests stay keyed, and change only when the process restarts.
const processKey = randomBytes(32);

/** A key that lasts as long as this process. */
export function processIdentifierKey(): Buffer {
  return processKey;
}

/**
 * This installation's secret key for the digests of paths, addresses and
 * records sent in place of the values themselves. A plain SHA-256 of a
 * common path such as a home folder can be found by hashing guesses; a
 * digest keyed with a secret that never leaves the computer cannot. The key
 * is created on first use, readable only by its owner, in the data directory
 * the observer keeps private; the directory itself is never created here.
 */
export function loadIdentifierKey(dataDirectory: string): Buffer {
  const path = join(dataDirectory, identifierKeyFileName);
  // A second pass reads the key another process created first.
  for (let attempt = 0; attempt < 2; attempt++) {
    try {
      const stored = readFileSync(path, "utf8").trim();
      return /^[0-9a-f]{64}$/u.test(stored) ? Buffer.from(stored, "hex") : processKey;
    } catch (error) {
      if (errorCode(error) !== "ENOENT") return processKey;
    }
    const key = randomBytes(32);
    try {
      writeFileSync(path, `${key.toString("hex")}\n`, { flag: "wx", mode: 0o600 });
      return key;
    } catch (error) {
      if (errorCode(error) !== "EEXIST") return processKey;
    }
  }
  return processKey;
}

function errorCode(error: unknown): string | undefined {
  return error instanceof Error && "code" in error ? String(error.code) : undefined;
}
