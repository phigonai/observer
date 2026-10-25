import { loadConfig } from "./config.js";
import { FileCredentialStore } from "./credential-store.js";

/** Restore paired endpoints so a new terminal/service cannot switch workspaces. */
export async function connectionEnvironment(
  environment: NodeJS.ProcessEnv,
  flags: readonly string[] = [],
): Promise<NodeJS.ProcessEnv> {
  const result = { ...environment };
  for (const [flag, name] of [["--control-plane-url", "PHIGON_CONTROL_PLANE_URL"], ["--grpc-url", "PHIGON_GRPC_URL"]] as const) {
    const index = flags.indexOf(flag);
    if (index < 0) continue;
    const value = flags[index + 1];
    if (!value || value.startsWith("--")) throw new Error(`${flag} requires an endpoint URL.`);
    result[name] = value;
  }
  const initial = loadConfig(result);
  const credential = await new FileCredentialStore(initial.dataDirectory).load();
  if (!credential) return result;
  result["PHIGON_CONTROL_PLANE_URL"] ||= credential.controlPlaneOrigin;
  if (credential.grpcOrigin) result["PHIGON_GRPC_URL"] ||= credential.grpcOrigin;
  return result;
}
