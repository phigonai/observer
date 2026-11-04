import { createHash, X509Certificate } from "node:crypto";
import { lookup as lookupName } from "node:dns/promises";
import { readFile } from "node:fs/promises";
import { isIP } from "node:net";
import { setTimeout as delay } from "node:timers/promises";
import type * as tls from "node:tls";
import { FileCredentialStore, type StoredMachineCredential } from "./credential-store.js";
import { serverAuthorityPath, verifyServerAuthority } from "./server-authority.js";
import { moveServiceEndpoints } from "./service.js";

type Connect = (options: tls.ConnectionOptions, listener: () => void) => tls.TLSSocket;
type Lookup = (name: string) => Promise<readonly string[]>;

/** Where the server answers now. */
export type MovedServer = Readonly<{ controlPlaneOrigin: string; grpcOrigin: string }>;

type Reach = Readonly<{
  connect?: Connect;
  /** The proxy for a URL, as the observer's settings choose it. */
  proxyFor?: (url: URL) => URL | undefined;
}>;

// The Phigon app names the authority of the server it runs after the
// computer it runs on.
const authorityPrefix = "Phigon server authority ";

/** Phigon's relay, which reaches a Phigon app's server from any network. */
export const RELAY_DOMAIN = "relay.phigon.online";

/**
 * Where the Phigon app's server whose authority is `pem` answers through
 * Phigon's relay: under the first 80 bits of the authority's SHA-256
 * fingerprint, the one pinned at pairing, in lowercase base32. Only the
 * server holding that authority's key can connect there, and it proves the
 * same certificate pairing checked. Undefined for an unreadable authority.
 */
export function relayServer(pem: string, domain = RELAY_DOMAIN): MovedServer | undefined {
  let raw: Buffer;
  try {
    raw = new X509Certificate(pem).raw;
  } catch {
    return undefined;
  }
  const label = relayLabel(raw);
  return { controlPlaneOrigin: `https://${label}.${domain}`, grpcOrigin: `https://${label}-grpc.${domain}` };
}

/** The relay's name for an authority with the DER bytes `raw` (relay.Label on the server). */
export function relayLabel(raw: Uint8Array): string {
  return base32(createHash("sha256").update(raw).digest().subarray(0, 10));
}

function base32(bytes: Uint8Array): string {
  const alphabet = "abcdefghijklmnopqrstuvwxyz234567";
  let bits = 0;
  let value = 0;
  let output = "";
  for (const byte of bytes) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      output += alphabet[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) output += alphabet[(value << (5 - bits)) & 31];
  return output;
}

/**
 * The name of the computer whose Phigon app issued the authority `pem`;
 * undefined for an authority the Phigon app did not make.
 */
export function authorityComputerName(pem: string): string | undefined {
  let subject: string;
  try {
    subject = new X509Certificate(pem).subject;
  } catch {
    return undefined;
  }
  const common = subject.split("\n").find((line) => line.startsWith("CN="))?.slice(3);
  if (common === undefined || !common.startsWith(authorityPrefix)) return undefined;
  const name = common.slice(authorityPrefix.length).trim().toLowerCase();
  return /^[a-z0-9][a-z0-9.-]{0,252}$/u.test(name) ? name : undefined;
}

/**
 * Whether a computer paired as `credential` can follow its server to a new
 * address: a Phigon app on the company network, reached by its private IP
 * address, which a network may hand out again to another computer. A server
 * reached by a name already moves with its name.
 */
export function canFollow(credential: StoredMachineCredential, authority: string): boolean {
  if (credential.grpcOrigin === undefined || authorityComputerName(authority) === undefined) return false;
  try {
    const http = new URL(credential.controlPlaneOrigin);
    const grpc = new URL(credential.grpcOrigin);
    return http.protocol === "https:" && grpc.protocol === "https:" &&
      http.hostname === grpc.hostname && privateAddress(http.hostname);
  } catch {
    return false;
  }
}

/**
 * Looks for the server this computer is paired with under the name of the
 * computer that runs it, then through Phigon's relay. An address counts
 * only on the company network or at the server's own relay address, and
 * only once it proves it holds a certificate the pinned authority issued
 * for that address, the same proof pairing at a new address asks for, so
 * the stored key is never sent anywhere else.
 */
export async function findMovedServer(options: Reach & Readonly<{
  credential: StoredMachineCredential;
  authority: string;
  lookup?: Lookup;
  /** Phigon's relay; RELAY_DOMAIN unless a test names another. */
  relayDomain?: string;
}>): Promise<MovedServer | undefined> {
  const name = authorityComputerName(options.authority);
  if (name === undefined || options.credential.grpcOrigin === undefined) return undefined;
  const current = new URL(options.credential.controlPlaneOrigin);
  const grpc = new URL(options.credential.grpcOrigin);
  const lookup = options.lookup ?? lookupAddresses;
  const addresses = new Set<string>();
  // On a home or office network without a name server, a computer answers
  // to its name with .local (multicast DNS).
  for (const host of name.endsWith(".local") ? [name] : [name, `${name}.local`]) {
    for (const address of await lookup(host).catch(() => [])) {
      if (privateAddress(address) && address !== current.hostname) addresses.add(address);
    }
  }
  for (const address of addresses) {
    const candidate = withHost(current, address);
    try {
      await verifyServerAuthority(candidate, options.authority, options.connect, { proxy: options.proxyFor?.(candidate) });
    } catch {
      continue;
    }
    return { controlPlaneOrigin: candidate.origin, grpcOrigin: withHost(grpc, address).origin };
  }
  // The Phigon app connects its server to the relay, so it is found there
  // from any network: after the computer that runs it moved to another
  // network, or this one did.
  const relayed = relayServer(options.authority, options.relayDomain);
  if (relayed === undefined || relayed.controlPlaneOrigin === current.origin) return undefined;
  const candidate = new URL(relayed.controlPlaneOrigin);
  try {
    await verifyServerAuthority(candidate, options.authority, options.connect, { proxy: options.proxyFor?.(candidate) });
    await verifyServerAuthority(new URL(relayed.grpcOrigin), options.authority, options.connect, { proxy: options.proxyFor?.(new URL(relayed.grpcOrigin)) });
  } catch {
    return undefined;
  }
  return relayed;
}

/**
 * Saves the server's new address in the pairing and in the background
 * service's settings that named the old one. A running observer sees the
 * pairing change and starts again there. Nothing changes when the pairing
 * is no longer `before`, for example because the computer paired again.
 */
export async function saveMovedServer(
  dataDirectory: string,
  before: StoredMachineCredential,
  moved: MovedServer,
): Promise<boolean> {
  const store = new FileCredentialStore(dataDirectory);
  const stored = await store.load();
  if (stored === null || stored.controlPlaneOrigin !== before.controlPlaneOrigin || stored.grpcOrigin !== before.grpcOrigin) {
    return false;
  }
  const moves = (from: Readonly<{ controlPlaneOrigin: string; grpcOrigin?: string | undefined }>, to: MovedServer) => ({
    PHIGON_CONTROL_PLANE_URL: { from: from.controlPlaneOrigin, to: to.controlPlaneOrigin },
    PHIGON_GRPC_URL: { from: from.grpcOrigin, to: to.grpcOrigin },
  });
  // The settings first: the pairing is what restarts the observer, and the
  // two must agree when it starts again.
  await moveServiceEndpoints(dataDirectory, moves(stored, moved));
  try {
    await store.save({ ...stored, ...moved });
  } catch (error) {
    if (stored.grpcOrigin !== undefined) {
      const back = { controlPlaneOrigin: stored.controlPlaneOrigin, grpcOrigin: stored.grpcOrigin };
      await moveServiceEndpoints(dataDirectory, moves(moved, back)).catch(() => undefined);
    }
    throw error;
  }
  return true;
}

export type ServerFollowOptions = Reach & Readonly<{
  dataDirectory: string;
  credential: StoredMachineCredential;
  signal: AbortSignal;
  /** Saves where the server answers now; false to keep looking. */
  onMoved: (moved: MovedServer) => Promise<boolean>;
  lookup?: Lookup;
  relayDomain?: string;
  /** How often the server is checked. */
  intervalMs?: number;
  /** Failed checks in a row before the server is looked for elsewhere. */
  failuresBeforeSearch?: number;
  /** The wait between two searches while the server cannot be reached. */
  searchEveryMs?: number;
  now?: () => number;
}>;

/**
 * Follows the Phigon app's server when the computer that runs it gets a new
 * address from the network. Once a minute the server is checked where this
 * computer reaches it; after three failures in a row it is looked for under
 * its computer's name, then through Phigon's relay, at most every five
 * minutes while it stays away. A server that is only switched off is found
 * again where it was.
 */
export async function followServer(options: ServerFollowOptions): Promise<void> {
  const authority = await readFile(serverAuthorityPath(options.dataDirectory), "utf8").catch(() => undefined);
  if (authority === undefined || !canFollow(options.credential, authority)) return;
  const current = new URL(options.credential.controlPlaneOrigin);
  const now = options.now ?? Date.now;
  const searchEveryMs = options.searchEveryMs ?? 5 * 60_000;
  let failures = 0;
  let nextSearch = 0;
  while (!options.signal.aborted) {
    try {
      await delay(options.intervalMs ?? 60_000, undefined, { signal: options.signal });
    } catch {
      return;
    }
    try {
      await verifyServerAuthority(current, authority, options.connect, { proxy: options.proxyFor?.(current) });
      failures = 0;
      continue;
    } catch {
      failures++;
    }
    if (failures < (options.failuresBeforeSearch ?? 3) || now() < nextSearch) continue;
    nextSearch = now() + searchEveryMs;
    const moved = await findMovedServer({ ...options, authority }).catch(() => undefined);
    if (moved === undefined || options.signal.aborted) continue;
    if (await options.onMoved(moved)) return;
  }
}

/** The IPv4 addresses for a name, or none within five seconds. */
async function lookupAddresses(name: string): Promise<readonly string[]> {
  const timeout = new AbortController();
  try {
    return await Promise.race([
      lookupName(name, { all: true, family: 4 }).then((entries) => entries.map((entry) => entry.address)),
      delay(5_000, [] as string[], { signal: timeout.signal }),
    ]);
  } finally {
    timeout.abort();
  }
}

/** A private IPv4 address: a company or home network, including CGNAT. */
function privateAddress(host: string): boolean {
  if (isIP(host) !== 4) return false;
  const [a, b] = host.split(".").map(Number) as [number, number];
  return a === 10 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) || (a === 100 && b >= 64 && b <= 127);
}

function withHost(url: URL, host: string): URL {
  const next = new URL(url.origin);
  next.hostname = host;
  return next;
}
