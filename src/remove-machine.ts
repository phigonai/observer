import type { ObserverConfig } from "./config.js";
import type { StoredMachineCredential } from "./credential-store.js";
import { serverFetch } from "./server-fetch.js";

export type RemoveMachineResult = Readonly<{
  /**
   * `already_removed`: an administrator had already removed this computer
   * or revoked its key, so only the local cleanup was left to do.
   */
  status: "removed" | "already_removed";
  machineId: string;
  controlPlaneOrigin: string;
  credentialRemoved: true;
}>;

export async function removeMachine(options: Readonly<{
  config: ObserverConfig;
  credential: StoredMachineCredential;
  clearCredential: () => Promise<boolean>;
  fetcher?: typeof fetch;
}>): Promise<RemoveMachineResult> {
  const configuredOrigin = options.config.controlPlaneUrl.origin;
  if (options.credential.controlPlaneOrigin !== configuredOrigin) {
    throw new Error(
      `The stored machine belongs to ${options.credential.controlPlaneOrigin}, ` +
        `but the observer is configured for ${configuredOrigin}. Restore the ` +
        "original PHIGON_CONTROL_PLANE_URL before removing this machine.",
    );
  }

  const endpoint = new URL("/v1/machine", options.config.controlPlaneUrl);
  const fetcher = options.fetcher ?? serverFetch;
  let response: Response;
  try {
    response = await fetcher(endpoint, {
      method: "DELETE",
      headers: {
        Authorization: `Bearer ${options.credential.credential}`,
        Accept: "application/json",
      },
      redirect: "error",
      signal: AbortSignal.timeout(10_000),
    });
  } catch (error) {
    if (error instanceof Error && error.name === "TimeoutError") {
      throw new Error(
        `Machine removal timed out while contacting ${endpoint.origin}. ` +
          "The local credential was kept; try again.",
      );
    }
    throw new Error(
      `Could not reach ${endpoint.origin}. The local credential was kept; ` +
        "check your connection and try again.",
    );
  }

  let alreadyRemoved = false;
  if (!response.ok) {
    const failure = await removalFailure(response);
    // The server no longer accepts this key: an administrator already
    // removed the computer or revoked the key. Nothing is left to
    // unregister, and the key is useless, so finish the local cleanup.
    if (response.status !== 401 || failure.code !== "invalid_credential") {
      throw new Error(failure.message);
    }
    alreadyRemoved = true;
  } else if (response.status !== 204) {
    throw new Error(
      `Control plane returned an unexpected machine-removal response ` +
        `(HTTP ${response.status}). The local credential was kept.`,
    );
  }
  try {
    await options.clearCredential();
  } catch {
    throw new Error(
      `Machine ${options.credential.machineId} was removed from ` +
        `${configuredOrigin}, but local credential cleanup failed. Remove ` +
        `machine-credential.json from ${options.config.dataDirectory} before ` +
        "pairing again.",
    );
  }
  return Object.freeze({
    status: alreadyRemoved ? "already_removed" : "removed",
    machineId: options.credential.machineId,
    controlPlaneOrigin: configuredOrigin,
    credentialRemoved: true,
  });
}

async function removalFailure(
  response: Response,
): Promise<Readonly<{ code?: string; message: string }>> {
  const fallback = `Machine removal failed with HTTP ${response.status}. ` +
    "The local credential was kept.";
  try {
    const value: unknown = await response.json();
    if (
      typeof value === "object" &&
      value !== null &&
      "error" in value &&
      typeof value.error === "object" &&
      value.error !== null
    ) {
      const error = value.error;
      const code = "code" in error && typeof error.code === "string"
        ? { code: error.code }
        : {};
      if ("message" in error && typeof error.message === "string") {
        const message = error.message.trim();
        if (
          message.length > 0 &&
          Buffer.byteLength(message, "utf8") <= 512 &&
          !/[\u0000-\u001f\u007f]/u.test(message)
        ) {
          return { ...code, message: `${message} The local credential was kept.` };
        }
      }
      return { ...code, message: fallback };
    }
  } catch {
    // The status code is still useful and does not expose the credential.
  }
  return { message: fallback };
}
