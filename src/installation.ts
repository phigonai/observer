import { randomUUID } from "node:crypto";
import { chmod, mkdir, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";

const uuidPattern =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

export async function loadOrCreateInstallationID(
  dataDirectory: string,
): Promise<string> {
  await mkdir(dataDirectory, { recursive: true, mode: 0o700 });
  await chmod(dataDirectory, 0o700);
  const installationPath = join(dataDirectory, "installation-id");
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
