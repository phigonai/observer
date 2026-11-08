import { loadConfig } from "./config.js";
import { FileCredentialStore } from "./credential-store.js";
import { trustSavedAuthority } from "./server-authority.js";

/** Restore paired endpoints so a new terminal/service cannot switch workspaces. */
export async function connectionEnvironment(
  environment: NodeJS.ProcessEnv,
  flags: readonly string[] = [],
): Promise<NodeJS.ProcessEnv> {
  const result = { ...environment };
  for (const [flag, name] of [["--control-plane-url", "PHIGON_CONTROL_PLANE_URL"], ["--grpc-url", "PHIGON_GRPC_URL"]] as const) {
    // Both "--flag value" and "--flag=value", as every other option.
    const joined = flags.find((item) => item.startsWith(`${flag}=`));
    const index = flags.indexOf(flag);
    if (joined === undefined && index < 0) continue;
    const value = joined === undefined ? flags[index + 1] : joined.slice(flag.length + 1);
    if (!value || value.startsWith("--")) throw new Error(`${flag} requires an endpoint URL.`);
    result[name] = value;
  }
  const initial = loadConfig(result);
  const credential = await new FileCredentialStore(initial.dataDirectory).load();
  // A company's own server: trust the authority pinned when this computer
  // paired, and only it. The stream trusts it too, whatever
  // PHIGON_TLS_CA_FILE says (see streamTrust).
  const authority = trustSavedAuthority(initial.dataDirectory, credential?.serverAuthoritySha256);
  if (authority !== undefined) result["PHIGON_TLS_CA_FILE"] ||= authority;
  if (!credential) return result;
  result["PHIGON_CONTROL_PLANE_URL"] ||= credential.controlPlaneOrigin;
  if (credential.grpcOrigin) result["PHIGON_GRPC_URL"] ||= credential.grpcOrigin;
  return result;
}
