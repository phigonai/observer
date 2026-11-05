import { isIP } from "node:net";
import { networkInterfaces, type NetworkInterfaceInfo } from "node:os";
import type * as tls from "node:tls";
import type { ObserverConfig } from "./config.js";
import { FileCredentialStore } from "./credential-store.js";
import {
  forgetServerAuthority,
  readServerAuthority,
  saveServerAuthority,
  savedAuthorityFingerprint,
  verifyServerAuthority,
} from "./server-authority.js";
import { trustServerAuthority } from "./server-fetch.js";

/**
 * What a pairing needs to know about the server it is about to reach:
 * whether the server this computer is already paired with moved there, and
 * how to keep the authority the pairing command named.
 */
export type PairingAuthority = Readonly<{
  /** The stored machine's server now answers at the new address. */
  serverMoved: boolean;
  /**
   * Saves the authority the command named. Called only once pairing has
   * succeeded, so a refused pairing keeps the authority of the server
   * this computer already uses.
   */
  commit: () => Promise<void>;
}>;

type Connect = (options: tls.ConnectionOptions, listener: () => void) => tls.TLSSocket;

export type PairingAuthorityOptions = Readonly<{
  config: ObserverConfig;
  /** The `--server-ca-sha256` fingerprint, when the command has one. */
  fingerprint?: string | undefined;
  proxy?: URL | undefined;
  connect?: Connect;
  interfaces?: () => NodeJS.Dict<NetworkInterfaceInfo[]>;
}>;

/**
 * Reads the authority a pairing command names, and trusts it alone for the
 * pairing's requests, in this process only. A computer paired with a server at another address may
 * follow it when that server proves it is the same one: it holds a
 * certificate from the authority pinned when the computer paired, which
 * the command names again. A server on this computer may also move between
 * its own addresses, for example when sharing with the network is turned
 * on or off. Anything else is refused by the pairing before the stored key
 * is sent anywhere.
 */
export async function preparePairingAuthority(
  options: PairingAuthorityOptions,
): Promise<PairingAuthority> {
  const { config } = options;
  const target = config.controlPlaneUrl;
  const authorityOptions = { proxy: options.proxy };
  const pem = options.fingerprint === undefined
    ? undefined
    : await readServerAuthority(target, options.fingerprint, options.connect, authorityOptions);
  const previous = await new FileCredentialStore(config.dataDirectory).load();
  // A first pairing without a fingerprint is with a server whose certificate
  // the system's authorities check: an authority left from an earlier
  // pairing does not apply to it, and is forgotten once it succeeds.
  const stale = pem === undefined && previous === null && savedAuthorityFingerprint(config.dataDirectory) !== undefined;
  if (stale) trustServerAuthority(undefined);
  const commit = async () => {
    if (stale) {
      await forgetServerAuthority(config.dataDirectory).catch(() => undefined);
      return;
    }
    if (pem === undefined) return;
    try {
      await saveServerAuthority(config.dataDirectory, pem);
    } catch {
      throw new Error("This computer is paired, but the server's certificate authority could not be saved in the data directory. Run the same pair command again.");
    }
  };
  if (previous === null || previous.controlPlaneOrigin === target.origin) {
    return { serverMoved: false, commit };
  }
  if (pem !== undefined && savedAuthorityFingerprint(config.dataDirectory) === options.fingerprint) {
    // The stored key goes to the new address only after it proves it holds
    // a certificate the pinned authority issued for that address.
    await verifyServerAuthority(target, pem, options.connect, authorityOptions);
    return { serverMoved: true, commit };
  }
  const interfaces = options.interfaces ?? networkInterfaces;
  const local = localAddresses(interfaces());
  return {
    serverMoved: onThisComputer(new URL(previous.controlPlaneOrigin), local) && onThisComputer(target, local),
    commit,
  };
}

/** This computer's own IP addresses, from its network interfaces. */
function localAddresses(interfaces: NodeJS.Dict<NetworkInterfaceInfo[]>): ReadonlySet<string> {
  const addresses = new Set<string>();
  for (const entries of Object.values(interfaces)) {
    for (const entry of entries ?? []) addresses.add(entry.address.toLowerCase());
  }
  return addresses;
}

/** Whether `url` names this computer: a loopback address or one of its own. */
export function onThisComputer(url: URL, localAddresses: ReadonlySet<string>): boolean {
  const host = url.hostname.replace(/^\[|\]$/gu, "").toLowerCase();
  if (host === "localhost" || host === "::1") return true;
  if (isIP(host) === 4 && host.startsWith("127.")) return true;
  return isIP(host) !== 0 && localAddresses.has(host);
}
