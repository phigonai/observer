import { createHash, X509Certificate } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { rm, writeFile } from "node:fs/promises";
import { isIP, type Socket } from "node:net";
import { join } from "node:path";
import * as tls from "node:tls";
import { connectThroughProxy } from "./proxy.js";
import { pinnedAuthorityMissingMessage, RELAY_DOMAIN, relayHost } from "./relay-host.js";
import { refuseServerRequests, trustServerAuthority } from "./server-fetch.js";

export {
  pinnedAuthorityMissingMessage,
  RELAY_DOMAIN,
  relayHost,
  relayNeedsAuthorityMessage,
} from "./relay-host.js";

/**
 * A company's own Phigon server (run by the Phigon app) signs its HTTPS
 * certificate with an authority of its own. The pairing command carries
 * that authority's SHA-256 fingerprint; pairing pins it here, and every
 * later HTTPS and gRPC connection to that server trusts it and nothing else.
 */
export const SERVER_AUTHORITY_FILE = "server-ca.pem";

/** What the observer learned about where its server answers (server-endpoints.ts). */
export const SERVER_ENDPOINTS_FILE = "server-endpoints.json";

const FINGERPRINT = /^[0-9a-f]{64}$/u;

export function serverAuthorityPath(dataDirectory: string): string {
  return join(dataDirectory, SERVER_AUTHORITY_FILE);
}

/** Reads `--server-ca-sha256`: 64 hex characters, with or without colons. */
export function parseAuthorityFingerprint(value: string): string {
  const normalized = value.trim().toLowerCase().replace(/:/gu, "");
  if (!FINGERPRINT.test(normalized)) {
    throw new Error("--server-ca-sha256 must be the 64-character fingerprint from the Connect machine dialog.");
  }
  return normalized;
}

/**
 * Trusts `pem`, and only it, for this process's requests to the server it
 * is paired with (`serverFetch`). Other hosts keep the system's authorities.
 */
export function trustAuthority(pem: string): void {
  trustServerAuthority(pem);
}

/**
 * Adds an authority to the ones this process trusts for every host it does
 * not pin, as NODE_EXTRA_CA_CERTS does when Node.js starts.
 */
export function addDefaultAuthority(pem: string): void {
  if (typeof tls.setDefaultCACertificates !== "function" || typeof tls.getCACertificates !== "function") {
    throw new Error("Adding certificate authorities needs Node.js 24.5 or newer. Update Node.js and try again.");
  }
  const current = tls.getCACertificates("default");
  if (!current.some((certificate) => sameCertificate(certificate, pem))) {
    tls.setDefaultCACertificates([...current, pem]);
  }
}

/**
 * Trusts the authority saved when this computer paired for requests to its
 * server, and returns its file; without one, requests use the system's
 * authorities, except to an address on Phigon's relay. A machine key
 * issued under a pinned authority (`issuedUnder`) is never sent under any
 * other: when the saved one is missing or changed, requests are refused.
 */
export function trustSavedAuthority(dataDirectory: string, issuedUnder?: string): string | undefined {
  const file = serverAuthorityPath(dataDirectory);
  const pem = existsSync(file) ? readFileSync(file, "utf8") : undefined;
  trustServerAuthority(pem);
  if (issuedUnder !== undefined && (pem === undefined || authorityFingerprint(pem) !== issuedUnder)) {
    refuseServerRequests(pinnedAuthorityMissingMessage);
  }
  return pem === undefined ? undefined : file;
}

/** Forgets the pinned authority and what was learned about its server's addresses. */
export async function forgetServerAuthority(dataDirectory: string): Promise<void> {
  await rm(serverAuthorityPath(dataDirectory), { force: true });
  await rm(join(dataDirectory, SERVER_ENDPOINTS_FILE), { force: true });
  trustServerAuthority(undefined);
}

/** The SHA-256 of the authority saved when this computer paired, if any. */
export function savedAuthorityFingerprint(dataDirectory: string): string | undefined {
  try {
    return authorityFingerprint(readFileSync(serverAuthorityPath(dataDirectory), "utf8"));
  } catch {
    return undefined;
  }
}

/** The SHA-256 of an authority's DER certificate, in hex; undefined when unreadable. */
export function authorityFingerprint(pem: string): string | undefined {
  try {
    return createHash("sha256").update(new X509Certificate(pem).raw).digest("hex");
  } catch {
    return undefined;
  }
}

/** Why a server on the relay cannot be reached: the relay closed the connection. */
export const relayNotConnectedMessage =
  "The Phigon server is not connected to the relay right now (for example, the admin's computer is off).";

/**
 * Why a certificate for `url` that no Phigon authority issued was refused:
 * something on the way re-signs HTTPS. Names what IT can exempt.
 */
export function inspectionMessage(url: URL, relayDomain = RELAY_DOMAIN): string {
  const exempt = relayHost(url.hostname, relayDomain) ? `*.${relayDomain}` : url.hostname.replace(/^\[|\]$/gu, "");
  return `A proxy or security software on this network is inspecting HTTPS to ${url.host}, ` +
    "so this computer cannot check that it is your company's Phigon server. " +
    `Ask your IT team to exempt ${exempt} from HTTPS inspection.`;
}

/** Why a server could not prove the pinned authority. */
export type AuthorityProblem =
  /** A certificate no Phigon authority issued: HTTPS inspection on the way. */
  | "inspected"
  /** A Phigon server, but not one with a certificate the pinned authority issued for that address. */
  | "not_proven"
  /** The relay closed the connection: that server is not connected to it. */
  | "relay_not_connected"
  | "timeout"
  | "unreachable";

export class ServerAuthorityError extends Error {
  readonly problem: AuthorityProblem;

  constructor(message: string, problem: AuthorityProblem) {
    super(message);
    this.problem = problem;
  }
}

type Connect = (options: tls.ConnectionOptions, listener: () => void) => tls.TLSSocket;
type AuthorityOptions = Readonly<{
  proxy?: URL | undefined;
  /** How long the connection may take; 15 seconds unless said otherwise. */
  timeoutMs?: number;
  /** Phigon's relay; RELAY_DOMAIN unless a test names another. */
  relayDomain?: string;
}>;

/**
 * Finds the certificate in the server's chain whose SHA-256 matches the
 * pinned fingerprint, saves it and trusts it. Nothing is sent to the server
 * on this connection; the requests that follow are verified normally,
 * including the server's name, against the pinned authority. Behind a
 * proxy (`options.proxy`), the chain is read through a CONNECT tunnel.
 */
export async function pinServerAuthority(
  url: URL,
  fingerprint: string,
  dataDirectory: string,
  connect: Connect = tls.connect,
  options: AuthorityOptions = {},
): Promise<string> {
  return await saveServerAuthority(dataDirectory, await readServerAuthority(url, fingerprint, connect, options));
}

/**
 * Like `pinServerAuthority`, but only trusts the authority for this
 * process and returns it: pairing saves it with `saveServerAuthority` once
 * it has succeeded, so a refused pairing keeps the authority of the server
 * this computer already uses. The pairing request itself trusts only it.
 */
export async function readServerAuthority(
  url: URL,
  fingerprint: string,
  connect: Connect = tls.connect,
  options: AuthorityOptions = {},
): Promise<string> {
  if (url.protocol !== "https:") {
    throw new Error("--server-ca-sha256 needs an https:// control plane URL.");
  }
  const tunnel = await tunnelFor(url, options);
  const chain = await peerChain(url, connect, tunnel, options);
  const match = chain.find((raw) => createHash("sha256").update(raw).digest("hex") === fingerprint);
  if (match === undefined) {
    if (!issuedByPhigon(chain)) throw new ServerAuthorityError(inspectionMessage(url, options.relayDomain), "inspected");
    throw new Error("The server's certificate does not match the fingerprint in the pairing command. Check that this computer is on the right network and that you copied the whole command.");
  }
  const pem = new X509Certificate(match).toString();
  trustAuthority(pem);
  return pem;
}

/** Saves an authority read by `readServerAuthority`, and returns its file. */
export async function saveServerAuthority(dataDirectory: string, pem: string): Promise<string> {
  const file = serverAuthorityPath(dataDirectory);
  await writeFile(file, pem, { mode: 0o600 });
  return file;
}

/**
 * Checks that the server at `url` holds a certificate the authority `pem`
 * issued for that address, trusting nothing else. A chain only lists its
 * authority, which anyone can copy; this connection proves the server has
 * a certificate that authority signed. Nothing is sent on it. A refusal is
 * a `ServerAuthorityError` that says why in plain words.
 */
export async function verifyServerAuthority(
  url: URL,
  pem: string,
  connect: Connect = tls.connect,
  options: AuthorityOptions = {},
): Promise<void> {
  const host = url.hostname.replace(/^\[|\]$/gu, "");
  const port = Number(url.port || 443);
  const relayed = relayHost(host, options.relayDomain);
  let tunnel: Socket | undefined;
  try {
    tunnel = await tunnelFor(url, options);
  } catch (error) {
    throw new ServerAuthorityError(error instanceof Error ? error.message : `Could not reach ${url.host}.`, "unreachable");
  }
  const notProven = () => new ServerAuthorityError(
    `The server at ${url.host} could not prove it is the Phigon server this computer is connected to. Check the address, and copy the whole command from Connect machine again.`,
    "not_proven",
  );
  await new Promise<void>((resolve, reject) => {
    const socket = connect({
      ...(tunnel === undefined ? { port } : { socket: tunnel }),
      // Also the name the certificate is checked against.
      host,
      ...(isIP(host) ? {} : { servername: host }),
      ca: [pem],
      // Checked below, from `authorized`, which covers the chain to `pem`
      // and the name; a refused chain is looked at to say why.
      rejectUnauthorized: false,
      timeout: options.timeoutMs ?? 15_000,
    }, () => {
      const authorized = socket.authorized;
      const reason = authorized ? undefined : socket.authorizationError;
      const chain = authorized ? [] : chainOf(socket);
      socket.end();
      if (authorized) {
        resolve();
        return;
      }
      const nameRefused = (reason instanceof Error ? (reason as NodeJS.ErrnoException).code : reason) === "ERR_TLS_CERT_ALTNAME_INVALID";
      reject(nameRefused || issuedByPhigon(chain)
        ? notProven()
        : new ServerAuthorityError(inspectionMessage(url, options.relayDomain), "inspected"));
    });
    socket.once("error", (error: NodeJS.ErrnoException) => {
      // The relay closes a connection for a name no server holds right
      // after reading the TLS hello.
      if (relayed && (error.code === "ECONNRESET" || error.code === "EPIPE")) {
        reject(new ServerAuthorityError(relayNotConnectedMessage, "relay_not_connected"));
        return;
      }
      reject(error.code === "ECONNREFUSED" || error.code === "ENOTFOUND" || error.code === "EHOSTUNREACH" ||
          error.code === "ENETUNREACH" || error.code === "EAI_AGAIN"
        ? new ServerAuthorityError(`Could not reach ${url.host} (${error.code}).`, "unreachable")
        : notProven());
    });
    socket.once("timeout", () => {
      socket.destroy();
      reject(new ServerAuthorityError(`Connecting to ${url.host} timed out. Check that this computer can reach it on the network.`, "timeout"));
    });
  });
}

async function tunnelFor(url: URL, options: AuthorityOptions): Promise<Socket | undefined> {
  return options.proxy === undefined
    ? undefined
    : await connectThroughProxy(options.proxy, url.hostname.replace(/^\[|\]$/gu, ""), Number(url.port || 443), options.timeoutMs);
}

function peerChain(url: URL, connect: Connect, tunnel: Socket | undefined, options: AuthorityOptions): Promise<Buffer[]> {
  const host = url.hostname.replace(/^\[|\]$/gu, "");
  const port = Number(url.port || 443);
  return new Promise((resolve, reject) => {
    const socket = connect({
      ...(tunnel === undefined ? { host, port } : { socket: tunnel }),
      ...(isIP(host) ? {} : { servername: host }),
      // Only to read the chain; the fingerprint decides what is trusted.
      rejectUnauthorized: false,
      timeout: 15_000,
    }, () => {
      const chain = chainOf(socket);
      socket.end();
      resolve(chain);
    });
    socket.once("error", (error: NodeJS.ErrnoException) => reject(
      relayHost(host, options.relayDomain) && (error.code === "ECONNRESET" || error.code === "EPIPE")
        ? new ServerAuthorityError(relayNotConnectedMessage, "relay_not_connected")
        : new Error(`Could not reach ${url.host}: ${error.message}`),
    ));
    socket.once("timeout", () => {
      socket.destroy();
      reject(new Error(`Connecting to ${url.host} timed out. Check that this computer can reach it on the network.`));
    });
  });
}

/** The certificates a server presented, its own first. */
function chainOf(socket: tls.TLSSocket): Buffer[] {
  const chain: Buffer[] = [];
  const seen = new Set<string>();
  let certificate: tls.DetailedPeerCertificate | undefined = socket.getPeerCertificate(true);
  while (certificate?.raw && !seen.has(certificate.fingerprint256)) {
    seen.add(certificate.fingerprint256);
    chain.push(certificate.raw);
    certificate = certificate.issuerCertificate;
  }
  return chain;
}

/**
 * Whether a Phigon authority issued any certificate in `chain`. The Phigon
 * app names its authority "Phigon server authority <computer>"; a proxy that
 * inspects HTTPS signs with its own, so a chain without one was re-signed on
 * the way. A server's own name (a leaf's subject) may say Phigon either way.
 */
function issuedByPhigon(chain: readonly Buffer[]): boolean {
  return chain.some((raw) => {
    try {
      const issuer = new X509Certificate(raw).issuer;
      return issuer.split("\n").some((line) => /^CN=Phigon\b/iu.test(line));
    } catch {
      return false;
    }
  });
}

function sameCertificate(a: string, b: string): boolean {
  const strip = (pem: string) => pem.replace(/\s+/gu, "");
  return strip(a) === strip(b);
}
