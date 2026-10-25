import type { ObserverConfig } from "./config.js";
import type { StoredMachineCredential } from "./credential-store.js";

export type RemoveMachineResult = Readonly<{
  status: "removed";
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
  const fetcher = options.fetcher ?? fetch;
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

  if (!response.ok) {
    throw new Error(await removalFailureMessage(response));
  }
  if (response.status !== 204) {
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
    status: "removed",
    machineId: options.credential.machineId,
    controlPlaneOrigin: configuredOrigin,
    credentialRemoved: true,
  });
}

async function removalFailureMessage(response: Response): Promise<string> {
  try {
    const value: unknown = await response.json();
    if (
      typeof value === "object" &&
      value !== null &&
      "error" in value &&
      typeof value.error === "object" &&
      value.error !== null &&
      "message" in value.error &&
      typeof value.error.message === "string"
    ) {
      const message = value.error.message.trim();
      if (
        message.length > 0 &&
        Buffer.byteLength(message, "utf8") <= 512 &&
        !/[\u0000-\u001f\u007f]/u.test(message)
      ) {
        return `${message} The local credential was kept.`;
      }
    }
  } catch {
    // The status code is still useful and does not expose the credential.
  }
  return `Machine removal failed with HTTP ${response.status}. ` +
    "The local credential was kept.";
}
