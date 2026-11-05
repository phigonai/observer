import { createHash, X509Certificate } from "node:crypto";
import { lookup as lookupName } from "node:dns/promises";
import { readFile } from "node:fs/promises";
import { setTimeout as delay } from "node:timers/promises";
import type * as tls from "node:tls";
import { FileCredentialStore, type StoredMachineCredential } from "./credential-store.js";
import { authorityFingerprint, RELAY_DOMAIN, serverAuthorityPath, verifyServerAuthority } from "./server-authority.js";
import {
  fetchServerEndpoints,
  loadLearnedEndpoints,
  networkAddress,
  privateAddress,
  sameAddress,
  saveLearnedEndpoints,
  type LearnedEndpoints,
  type ServerAddress,
} from "./server-endpoints.js";
import { pinnedFetch } from "./server-fetch.js";
import { moveServiceEndpoints } from "./service.js";

export { RELAY_DOMAIN } from "./server-authority.js";

type Connect = (options: tls.ConnectionOptions, listener: () => void) => tls.TLSSocket;
type Lookup = (name: string) => Promise<readonly string[]>;

/** Where the server answers now. */
export type MovedServer = ServerAddress;

type Reach = Readonly<{
  connect?: Connect;
  /** The proxy for a URL, as the observer's settings choose it. */
  proxyFor?: (url: URL) => URL | undefined;
}>;

// The Phigon app names the authority of the server it runs after the
// computer it runs on.
const authorityPrefix = "Phigon server authority ";

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
 * undefined for an authority the Phigon app did not make, or a name a
 * network cannot look up (PARTH_PC, or one with accents).
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

type Endpoints = Readonly<{ controlPlaneOrigin: string; grpcOrigin?: string | undefined }>;

/**
 * Which address of the server whose authority is `authority` `server` is:
 * on a company network (its private IP address, which the network may hand
 * to another computer later) or its relay address. Anything else, such as a
 * public name, moves with its name and is not followed.
 */
function addressKind(server: Endpoints, authority: string, relayDomain?: string): "network" | "relay" | undefined {
  if (server.grpcOrigin === undefined) return undefined;
  const network = networkAddress(server.controlPlaneOrigin, server.grpcOrigin);
  if (network !== undefined && sameAddress(network, server)) return "network";
  return sameAddress(relayServer(authority, relayDomain), server) ? "relay" : undefined;
}

/**
 * Whether a computer paired as `credential` can follow its server to
 * another address: it pinned the server's authority, and reaches it at its
 * network address or through Phigon's relay. A server reached by a public
 * name already moves with its name.
 */
export function canFollow(credential: StoredMachineCredential, authority: string, relayDomain?: string): boolean {
  return relayServer(authority, relayDomain) !== undefined && addressKind(credential, authority, relayDomain) !== undefined;
}

/**
 * Proves that `server` holds certificates the pinned authority issued for
 * both its API and its telemetry address, before any key goes there.
 */
async function proveServer(
  server: ServerAddress,
  authority: string,
  options: Reach & Readonly<{ relayDomain?: string | undefined; timeoutMs?: number }>,
): Promise<void> {
  for (const origin of [server.controlPlaneOrigin, server.grpcOrigin]) {
    const url = new URL(origin);
    await verifyServerAuthority(url, authority, options.connect, {
      proxy: options.proxyFor?.(url),
      ...(options.timeoutMs === undefined ? {} : { timeoutMs: options.timeoutMs }),
      ...(options.relayDomain === undefined ? {} : { relayDomain: options.relayDomain }),
    });
  }
}

/**
 * Looks for the server this computer is paired with: at its network address
 * when that is known, under the name of the computer that runs it, then
 * through Phigon's relay. An address counts only on the company network or
 * at the server's own relay address, and only once both its API and its
 * telemetry address prove they hold certificates the pinned authority
 * issued for them, the same proof pairing at a new address asks for, so the
 * stored key is never sent anywhere else.
 */
export async function findMovedServer(options: Reach & Readonly<{
  credential: StoredMachineCredential;
  authority: string;
  /** The server's address on its network, when known. */
  network?: ServerAddress | undefined;
  lookup?: Lookup;
  /** Phigon's relay; RELAY_DOMAIN unless a test names another. */
  relayDomain?: string | undefined;
  /** Told why an address was not taken. */
  onRefused?: (candidate: ServerAddress, error: unknown) => void;
}>): Promise<MovedServer | undefined> {
  if (options.credential.grpcOrigin === undefined) return undefined;
  const current: ServerAddress = { controlPlaneOrigin: options.credential.controlPlaneOrigin, grpcOrigin: options.credential.grpcOrigin };
  const tried: ServerAddress[] = [current];
  const found = async (candidate: ServerAddress): Promise<boolean> => {
    if (tried.some((address) => sameAddress(address, candidate))) return false;
    tried.push(candidate);
    try {
      await proveServer(candidate, options.authority, options);
      return true;
    } catch (error) {
      options.onRefused?.(candidate, error);
      return false;
    }
  };
  if (options.network !== undefined && await found(options.network)) return options.network;
  // Under its computer's name, on the ports it has on the network. A name a
  // network cannot look up skips only this step.
  const name = authorityComputerName(options.authority);
  const ports = options.network ?? networkAddress(current.controlPlaneOrigin, current.grpcOrigin);
  if (name !== undefined && ports !== undefined) {
    const lookup = options.lookup ?? lookupAddresses;
    const addresses = new Set<string>();
    // On a home or office network without a name server, a computer answers
    // to its name with .local (multicast DNS).
    for (const host of name.endsWith(".local") ? [name] : [name, `${name}.local`]) {
      for (const address of await lookup(host).catch(() => [])) {
        if (privateAddress(address)) addresses.add(address);
      }
    }
    for (const address of addresses) {
      const candidate = { controlPlaneOrigin: withHost(ports.controlPlaneOrigin, address), grpcOrigin: withHost(ports.grpcOrigin, address) };
      if (await found(candidate)) return candidate;
    }
  }
  // The Phigon app connects its server to the relay, so it is found there
  // from any network: after the computer that runs it moved to another
  // network, or this one did.
  const relayed = relayServer(options.authority, options.relayDomain);
  if (relayed !== undefined && await found(relayed)) return relayed;
  return undefined;
}

/**
 * Saves the server's new address in the pairing and in the background
 * service's settings that named the old one. A running observer sees the
 * pairing change and starts again there. Nothing changes when the pairing
 * is no longer at `before`'s address, for example because the computer
 * paired again.
 */
export async function saveMovedServer(
  dataDirectory: string,
  before: StoredMachineCredential,
  moved: MovedServer,
): Promise<boolean> {
  const store = new FileCredentialStore(dataDirectory);
  const atBefore = (stored: StoredMachineCredential | null): stored is StoredMachineCredential =>
    stored !== null && stored.controlPlaneOrigin === before.controlPlaneOrigin && stored.grpcOrigin === before.grpcOrigin;
  const stored = await store.load();
  if (!atBefore(stored)) return false;
  const moves = (from: Endpoints, to: Endpoints) => ({
    PHIGON_CONTROL_PLANE_URL: { from: from.controlPlaneOrigin, to: to.controlPlaneOrigin },
    ...(to.grpcOrigin === undefined ? {} : { PHIGON_GRPC_URL: { from: from.grpcOrigin, to: to.grpcOrigin } }),
  });
  // The settings first: the pairing is what restarts the observer, and the
  // two must agree when it starts again. One that starts between the two
  // writes takes the pairing's address (reconcileServiceEndpoints).
  await moveServiceEndpoints(dataDirectory, moves(stored, moved));
  try {
    // Read again just before writing: a pairing made meanwhile wins, and
    // the settings go where it is.
    const latest = await store.load();
    if (!atBefore(latest)) {
      if (latest !== null) await moveServiceEndpoints(dataDirectory, moves(moved, latest)).catch(() => undefined);
      return false;
    }
    await store.save({ ...latest, ...moved });
  } catch (error) {
    await moveServiceEndpoints(dataDirectory, moves(moved, stored)).catch(() => undefined);
    throw error;
  }
  return true;
}

/**
 * A background service whose saved endpoints and pairing name two addresses
 * of the same pinned server, because a move stopped between its two writes:
 * the pairing's address wins, and the settings are written again with it.
 * Without this, every start would refuse to send the key. Returns the
 * settings to run with, unchanged for anything else.
 */
export async function reconcileServiceEndpoints(
  dataDirectory: string,
  settings: Readonly<Record<string, string>>,
  relayDomain?: string,
): Promise<Readonly<{ settings: Readonly<Record<string, string>>; moved?: string }>> {
  const unchanged = { settings };
  const api = origin(settings["PHIGON_CONTROL_PLANE_URL"]);
  const grpcSetting = settings["PHIGON_GRPC_URL"];
  if (api === undefined) return unchanged;
  const credential = await new FileCredentialStore(dataDirectory).load().catch(() => null);
  if (credential === null || credential.grpcOrigin === undefined) return unchanged;
  const configured = { controlPlaneOrigin: api, grpcOrigin: grpcSetting === undefined ? credential.grpcOrigin : origin(grpcSetting) };
  if (configured.grpcOrigin === undefined || sameAddress({ ...configured, grpcOrigin: configured.grpcOrigin }, credential)) return unchanged;
  const authority = await readFile(serverAuthorityPath(dataDirectory), "utf8").catch(() => undefined);
  if (authority === undefined || !canFollow(credential, authority, relayDomain) || addressKind(configured, authority, relayDomain) === undefined) {
    return unchanged;
  }
  // Running with the pairing's address does not depend on saving it.
  await moveServiceEndpoints(dataDirectory, {
    PHIGON_CONTROL_PLANE_URL: { from: undefined, to: credential.controlPlaneOrigin },
    ...(grpcSetting === undefined ? {} : { PHIGON_GRPC_URL: { from: undefined, to: credential.grpcOrigin } }),
  }).catch(() => undefined);
  return {
    settings: {
      ...settings,
      PHIGON_CONTROL_PLANE_URL: credential.controlPlaneOrigin,
      ...(grpcSetting === undefined ? {} : { PHIGON_GRPC_URL: credential.grpcOrigin }),
    },
    moved: credential.controlPlaneOrigin,
  };
}

export type ServerFollowOptions = Reach & Readonly<{
  dataDirectory: string;
  credential: StoredMachineCredential;
  signal: AbortSignal;
  /** Saves where the server answers now; false to keep looking. */
  onMoved: (moved: MovedServer) => Promise<boolean>;
  /** One line for the log, said once for each new reason. */
  onStatus?: (message: string) => void;
  lookup?: Lookup;
  relayDomain?: string;
  /** Asks the server for its addresses; trusts only the pinned authority unless a test names another. */
  fetcher?: typeof fetch;
  /** How often the server is checked. */
  intervalMs?: number;
  /** Failed checks in a row before the server is looked for elsewhere. */
  failuresBeforeSearch?: number;
  /** The wait between two searches while the server cannot be reached. */
  searchEveryMs?: number;
  /** How often the server is asked for its addresses. */
  endpointsEveryMs?: number;
  /** How often, on the relay, the network address is tried. */
  probeEveryMs?: number;
  /** How long a try at the network address may take, for each of its two hosts. */
  probeTimeoutMs?: number;
  /** Successful tries in a row before moving back to the network address. */
  probesBeforeReturn?: number;
  /** How long after leaving the network address it is not tried again. */
  holdAfterLeavingMs?: number;
  now?: () => number;
}>;

/** How the server is followed; see followServer. */
export const followTimings: Readonly<Record<"intervalMs" | "failuresBeforeSearch" | "searchEveryMs" | "endpointsEveryMs" | "probeEveryMs" | "probeTimeoutMs" | "probesBeforeReturn" | "holdAfterLeavingMs", number>> = Object.freeze({
  intervalMs: 60_000,
  failuresBeforeSearch: 3,
  searchEveryMs: 5 * 60_000,
  endpointsEveryMs: 30 * 60_000,
  probeEveryMs: 5 * 60_000,
  probeTimeoutMs: 3_000,
  probesBeforeReturn: 2,
  holdAfterLeavingMs: 15 * 60_000,
});

/**
 * Follows the Phigon app's server between its network address and Phigon's
 * relay, and to a new network address. Once a minute the server is checked
 * where this computer reaches it. Every 30 minutes it is asked where it
 * answers on its network; a computer paired there remembers that address
 * too. On the relay, the network address is tried every 5 minutes with a
 * short timeout, and taken again after two good tries in a row (not within
 * 15 minutes of leaving it), since it is the shorter way. After three failed
 * checks in a row the server is looked for at its network address, under
 * its computer's name, then through the relay, at most every five minutes
 * while it stays away. A server that is only switched off is found again
 * where it was.
 */
export async function followServer(options: ServerFollowOptions): Promise<void> {
  const authority = await readFile(serverAuthorityPath(options.dataDirectory), "utf8").catch(() => undefined);
  if (authority === undefined || !canFollow(options.credential, authority, options.relayDomain)) return;
  const fingerprint = authorityFingerprint(authority);
  const relay = relayServer(authority, options.relayDomain);
  if (fingerprint === undefined || relay === undefined || options.credential.grpcOrigin === undefined) return;
  const current: ServerAddress = { controlPlaneOrigin: options.credential.controlPlaneOrigin, grpcOrigin: options.credential.grpcOrigin };
  const onRelay = sameAddress(relay, current);
  const timing = { ...followTimings, ...definedTimings(options) };
  const now = options.now ?? Date.now;
  const reach = options;

  let learned: LearnedEndpoints = await loadLearnedEndpoints(options.dataDirectory, fingerprint);
  const remember = async (next: LearnedEndpoints) => {
    learned = next;
    // Kept in memory either way; a later change writes it again.
    await saveLearnedEndpoints(options.dataDirectory, fingerprint, next).catch(() => undefined);
  };
  const ownFetch = options.fetcher === undefined ? pinnedFetch(authority, options.proxyFor) : undefined;
  const fetcher = options.fetcher ?? ownFetch as typeof fetch;

  let failures = 0;
  let nextSearch = 0;
  let nextEndpoints = 0;
  let nextProbe = 0;
  let goodProbes = 0;
  // Whether the server itself named its network address in this run.
  let networkFromServer = false;
  let reported: string | undefined;
  try {
    while (!options.signal.aborted) {
      try {
        await delay(timing.intervalMs, undefined, { signal: options.signal });
      } catch {
        return;
      }
      if (now() >= nextEndpoints) {
        nextEndpoints = now() + timing.endpointsEveryMs;
        // An older server does not know the request: nothing changes.
        const said = await fetchServerEndpoints(new URL(current.controlPlaneOrigin), options.credential.credential, fetcher);
        if (said?.network !== undefined) {
          networkFromServer = true;
          if (!sameAddress(said.network, learned.network)) await remember({ ...learned, network: said.network });
        } else if (said !== undefined && onRelay && learned.network !== undefined) {
          // Not shared on its network any more.
          await remember(learned.leftNetworkAt === undefined ? {} : { leftNetworkAt: learned.leftNetworkAt });
        }
      }
      if (options.signal.aborted) return;
      // Both addresses: a network that lets the API through but blocks
      // telemetry leaves nothing to collect for, so it counts as a failure.
      const answered = await proveServer(current, authority, { ...reach, relayDomain: options.relayDomain })
        .then(() => true, () => false);
      if (answered) {
        failures = 0;
        reported = undefined;
        if (!onRelay) {
          // Paired on the network: that is its network address, unless the
          // server says otherwise.
          if (!networkFromServer && !sameAddress(learned.network, current)) await remember({ ...learned, network: current });
          continue;
        }
        const network = learned.network;
        const leftAt = learned.leftNetworkAt === undefined ? Number.NaN : Date.parse(learned.leftNetworkAt);
        const holding = Number.isFinite(leftAt) && now() - leftAt >= 0 && now() - leftAt < timing.holdAfterLeavingMs;
        if (network === undefined || holding || now() < nextProbe) continue;
        nextProbe = now() + timing.probeEveryMs;
        const back = await proveServer(network, authority, { ...reach, timeoutMs: timing.probeTimeoutMs }).then(() => true, () => false);
        goodProbes = back ? goodProbes + 1 : 0;
        if (goodProbes < timing.probesBeforeReturn || options.signal.aborted) continue;
        goodProbes = 0;
        if (await options.onMoved(network)) return;
        continue;
      }
      failures++;
      goodProbes = 0;
      if (failures < timing.failuresBeforeSearch || now() < nextSearch) continue;
      nextSearch = now() + timing.searchEveryMs;
      let reason: string | undefined;
      const moved = await findMovedServer({
        ...reach,
        authority,
        network: learned.network,
        onRefused: (candidate, error) => {
          // The relay's answer says the most to someone away from the office.
          if (reason === undefined || sameAddress(candidate, relay)) reason = error instanceof Error ? error.message : undefined;
        },
      }).catch(() => undefined);
      if (options.signal.aborted) return;
      if (moved === undefined) {
        const message = `Phigon's server stopped answering at ${current.controlPlaneOrigin}, and it was not found at another address.` +
          `${reason === undefined ? "" : ` ${reason}`} The observer keeps looking.`;
        if (message !== reported) options.onStatus?.(message);
        reported = message;
        continue;
      }
      if (!onRelay && sameAddress(moved, relay)) {
        await remember({ network: learned.network ?? current, leftNetworkAt: new Date(now()).toISOString() });
      }
      if (await options.onMoved(moved)) return;
    }
  } finally {
    await ownFetch?.close();
  }
}

function definedTimings(options: ServerFollowOptions): Partial<typeof followTimings> {
  const result: Partial<Record<keyof typeof followTimings, number>> = {};
  for (const name of Object.keys(followTimings) as (keyof typeof followTimings)[]) {
    const value = options[name];
    if (value !== undefined) result[name] = value;
  }
  return result;
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

function origin(value: string | undefined): string | undefined {
  if (value === undefined) return undefined;
  try {
    return new URL(value).origin;
  } catch {
    return undefined;
  }
}

function withHost(address: string, host: string): string {
  const next = new URL(address);
  next.hostname = host;
  return next.origin;
}
