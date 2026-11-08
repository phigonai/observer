import { makeDirectoryPrivate } from "./private-directory.js";
import { createHash, randomUUID } from "node:crypto";
import { mkdir, readFile, rename, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { atomicReplace } from "./atomic-replace.js";

/** The file holding this installation's ID, in the data directory. */
export const installationFileName = "installation-id";

const uuidPattern =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

export async function loadOrCreateInstallationID(
  dataDirectory: string,
): Promise<string> {
  return await loadOrCreateID(dataDirectory, installationFileName);
}

/**
 * The installation ID for a new machine that is to replace this computer's
 * pairing, kept apart from the current one until that pairing succeeds,
 * with the code it was sent with (`pairingAttempt`, never the code itself).
 * A retry with the same code after a lost response reuses it, so the
 * server, which bound the code to the ID it first saw, answers with the
 * machine it already made. Another code starts another pairing with a new
 * ID: the server may already hold the earlier one for a machine whose
 * answer was lost, and refuses it for a new machine.
 */
export const pendingInstallationFileName = "installation-id.pending";

/** Identifies a pairing or enrollment code without keeping the code. */
export function pairingAttempt(code: string): string {
  return createHash("sha256").update("phigon-observer-pairing-attempt\0", "utf8").update(code, "utf8").digest("hex");
}

export async function loadOrCreatePendingInstallationID(
  dataDirectory: string,
  attempt: string,
): Promise<string> {
  await mkdir(dataDirectory, { recursive: true, mode: 0o700 });
  await makeDirectoryPrivate(dataDirectory);
  const path = join(dataDirectory, pendingInstallationFileName);
  const pending = await readPendingInstallation(dataDirectory);
  if (pending?.attempt === attempt) return pending.installationID;
  const installationID = randomUUID();
  const temporary = `${path}.${process.pid}.${randomUUID()}.tmp`;
  try {
    await writeFile(temporary, `${installationID}\n${attempt}\n`, { encoding: "utf8", flag: "wx", mode: 0o600 });
    await atomicReplace(temporary, path);
  } catch (error) {
    await rm(temporary, { force: true });
    throw error;
  }
  return installationID;
}

/** The pending installation ID and the attempt it belongs to; undefined when there is none, or it is damaged. */
export async function readPendingInstallation(
  dataDirectory: string,
): Promise<Readonly<{ installationID: string; attempt: string | undefined }> | undefined> {
  let text: string;
  try {
    text = await readFile(join(dataDirectory, pendingInstallationFileName), "utf8");
  } catch (error) {
    if (isNodeError(error) && error.code === "ENOENT") return undefined;
    throw error;
  }
  const [installationID = "", attempt] = text.split("\n").map((line) => line.trim());
  if (!uuidPattern.test(installationID)) return undefined;
  return { installationID, attempt: attempt === "" ? undefined : attempt };
}

/**
 * Makes the pending installation ID this installation's ID, once the
 * current one has been set aside with the pairing it belonged to.
 */
export async function promotePendingInstallationID(
  dataDirectory: string,
  replace: typeof rename = rename,
): Promise<void> {
  const pending = await readPendingInstallation(dataDirectory);
  if (pending === undefined) throw new Error("The new installation ID for this pairing is missing. Run the same pair command again.");
  // Only the ID: the code it was sent with stays out of the current file.
  const path = join(dataDirectory, installationFileName);
  const temporary = `${path}.${process.pid}.${randomUUID()}.tmp`;
  try {
    await writeFile(temporary, `${pending.installationID}\n`, { encoding: "utf8", flag: "wx", mode: 0o600 });
    // Windows refuses a rename while a scanner holds the file; wait and retry.
    await atomicReplace(temporary, path, replace);
  } catch (error) {
    await rm(temporary, { force: true });
    throw error;
  }
  await rm(join(dataDirectory, pendingInstallationFileName), { force: true });
}

/**
 * After a replacement pairing set the earlier pairing aside but could not
 * make its new ID current (or save its key), the computer has no ID and no
 * key, and only the pending ID gets the machine back from the server: a
 * retry with the same code makes it current first.
 */
export async function adoptPendingInstallationID(dataDirectory: string, attempt: string): Promise<boolean> {
  const pending = await readPendingInstallation(dataDirectory);
  if (pending?.attempt !== attempt) return false;
  try {
    await readFile(join(dataDirectory, installationFileName));
    return false;
  } catch (error) {
    if (!isNodeError(error) || error.code !== "ENOENT") throw error;
  }
  await promotePendingInstallationID(dataDirectory);
  return true;
}

async function loadOrCreateID(dataDirectory: string, fileName: string): Promise<string> {
  await mkdir(dataDirectory, { recursive: true, mode: 0o700 });
  await makeDirectoryPrivate(dataDirectory);
  const installationPath = join(dataDirectory, fileName);
  try {
    const existing = (await readFile(installationPath, "utf8")).trim();
    if (!uuidPattern.test(existing)) {
      throw new Error("Stored observer installation ID is invalid.");
    }
    return existing;
  } catch (error) {
    if (!isNodeError(error) || error.code !== "ENOENT") {
      throw error;
    }
  }

  const installationID = randomUUID();
  try {
    await writeFile(installationPath, `${installationID}\n`, {
      encoding: "utf8",
      flag: "wx",
      mode: 0o600,
    });
    return installationID;
  } catch (error) {
    if (!isNodeError(error) || error.code !== "EEXIST") {
      throw error;
    }
    const existing = (await readFile(installationPath, "utf8")).trim();
    if (!uuidPattern.test(existing)) {
      throw new Error("Stored observer installation ID is invalid.");
    }
    return existing;
  }
}

function isNodeError(error: unknown): error is NodeJS.ErrnoException {
  return error instanceof Error && "code" in error;
}
