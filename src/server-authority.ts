import { createHash, X509Certificate } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { rm, writeFile } from "node:fs/promises";
import { isIP, type Socket } from "node:net";
import { join } from "node:path";
import * as tls from "node:tls";
import { connectThroughProxy } from "./proxy.js";

/**
 * A company's own Phigon server (run by the Phigon app) signs its HTTPS
 * certificate with an authority of its own. The pairing command carries
 * that authority's SHA-256 fingerprint; pairing pins it here, and every
 * later HTTPS and gRPC connection trusts it.
 */
export const SERVER_AUTHORITY_FILE = "server-ca.pem";

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

/** Adds an authority to the ones this process trusts for HTTPS and gRPC. */
export function trustAuthority(pem: string): void {
  if (typeof tls.setDefaultCACertificates !== "function" || typeof tls.getCACertificates !== "function") {
    throw new Error("Connecting to a company's own Phigon server needs Node.js 24.5 or newer. Update Node.js and try again.");
  }
  const current = tls.getCACertificates("default");
  if (!current.some((certificate) => sameCertificate(certificate, pem))) {
    tls.setDefaultCACertificates([...current, pem]);
  }
}

/** Trusts the authority saved when this computer paired, and returns its file. */
export function trustSavedAuthority(dataDirectory: string): string | undefined {
  const file = serverAuthorityPath(dataDirectory);
  if (!existsSync(file)) return undefined;
  trustAuthority(readFileSync(file, "utf8"));
  return file;
}

export async function forgetServerAuthority(dataDirectory: string): Promise<void> {
  await rm(serverAuthorityPath(dataDirectory), { force: true });
}

type Connect = (options: tls.ConnectionOptions, listener: () => void) => tls.TLSSocket;

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
  options: Readonly<{ proxy?: URL | undefined }> = {},
): Promise<string> {
  if (url.protocol !== "https:") {
    throw new Error("--server-ca-sha256 needs an https:// control plane URL.");
  }
  const tunnel = options.proxy === undefined
    ? undefined
    : await connectThroughProxy(options.proxy, url.hostname.replace(/^\[|\]$/gu, ""), Number(url.port || 443));
  const chain = await peerChain(url, connect, tunnel);
  const match = chain.find((raw) => createHash("sha256").update(raw).digest("hex") === fingerprint);
  if (match === undefined) {
    throw new Error("The server's certificate does not match the fingerprint in the pairing command. Check that this computer is on the right network and that you copied the whole command.");
  }
  const pem = new X509Certificate(match).toString();
  trustAuthority(pem);
  const file = serverAuthorityPath(dataDirectory);
  await writeFile(file, pem, { mode: 0o600 });
  return file;
}

function peerChain(url: URL, connect: Connect, tunnel: Socket | undefined): Promise<Buffer[]> {
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
      const chain: Buffer[] = [];
      const seen = new Set<string>();
      let certificate: tls.DetailedPeerCertificate | undefined = socket.getPeerCertificate(true);
      while (certificate?.raw && !seen.has(certificate.fingerprint256)) {
        seen.add(certificate.fingerprint256);
        chain.push(certificate.raw);
        certificate = certificate.issuerCertificate;
      }
      socket.end();
      resolve(chain);
    });
    socket.once("error", (error) => reject(new Error(`Could not reach ${url.host}: ${error.message}`)));
    socket.once("timeout", () => {
      socket.destroy();
      reject(new Error(`Connecting to ${url.host} timed out. Check that this computer can reach it on the network.`));
    });
  });
}

function sameCertificate(a: string, b: string): boolean {
  const strip = (pem: string) => pem.replace(/\s+/gu, "");
  return strip(a) === strip(b);
}
