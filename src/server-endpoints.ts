import { randomUUID } from "node:crypto";
import { chmod, readFile, rm, writeFile } from "node:fs/promises";
import { isIP } from "node:net";
import { join } from "node:path";
import { atomicReplace } from "./atomic-replace.js";
import { SERVER_ENDPOINTS_FILE } from "./server-authority.js";
import { serverFetch } from "./server-fetch.js";

/** Where a server answers: its API and its telemetry stream. */
export type ServerAddress = Readonly<{ controlPlaneOrigin: string; grpcOrigin: string }>;

/**
 * What a computer learned about where its server answers, kept in its own
 * file next to the pairing (older observers do not read it), for the
 * authority pinned at pairing only.
 */
export type LearnedEndpoints = Readonly<{
  /** The server's address on its network, when it is shared there. */
  network?: ServerAddress;
  /** When this computer last moved from that address to the relay. */
  leftNetworkAt?: string;
}>;

const version = 1;
const maxResponseBytes = 16 << 10;

/** A private IPv4 address: a company or home network, including CGNAT. */
export function privateAddress(host: string): boolean {
  if (isIP(host) !== 4) return false;
  const [a, b] = host.split(".").map(Number) as [number, number];
  return a === 10 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) || (a === 100 && b >= 64 && b <= 127);
}

/**
 * The address of a server on a company network: HTTPS, with its API and
 * telemetry on one private IP address. Undefined for anything else.
 */
export function networkAddress(controlPlane: unknown, grpc: unknown): ServerAddress | undefined {
  if (typeof controlPlane !== "string" || typeof grpc !== "string") return undefined;
  try {
    const http = new URL(controlPlane);
    const stream = new URL(grpc);
    if (http.protocol !== "https:" || stream.protocol !== "https:" || http.hostname !== stream.hostname || !privateAddress(http.hostname)) {
      return undefined;
    }
    return { controlPlaneOrigin: http.origin, grpcOrigin: stream.origin };
  } catch {
    return undefined;
  }
}

export function sameAddress(a: ServerAddress | undefined, b: Readonly<{ controlPlaneOrigin: string; grpcOrigin?: string | undefined }> | undefined): boolean {
  return a !== undefined && b !== undefined && a.controlPlaneOrigin === b.controlPlaneOrigin && a.grpcOrigin === b.grpcOrigin;
}

function endpointsPath(dataDirectory: string): string {
  return join(dataDirectory, SERVER_ENDPOINTS_FILE);
}

/**
 * What was learned for the authority with SHA-256 `authority`; nothing for
 * another authority, or a missing or unreadable file.
 */
export async function loadLearnedEndpoints(dataDirectory: string, authority: string): Promise<LearnedEndpoints> {
  let value: unknown;
  try {
    value = JSON.parse(await readFile(endpointsPath(dataDirectory), "utf8"));
  } catch {
    return {};
  }
  if (typeof value !== "object" || value === null || !("version" in value) || value.version !== version ||
    !("authority" in value) || value.authority !== authority) {
    return {};
  }
  const network = "network" in value && typeof value.network === "object" && value.network !== null &&
      "controlPlaneOrigin" in value.network && "grpcOrigin" in value.network
    ? networkAddress(value.network.controlPlaneOrigin, value.network.grpcOrigin)
    : undefined;
  const left = "leftNetworkAt" in value && typeof value.leftNetworkAt === "string" && Number.isFinite(Date.parse(value.leftNetworkAt))
    ? value.leftNetworkAt
    : undefined;
  return {
    ...(network === undefined ? {} : { network }),
    ...(left === undefined ? {} : { leftNetworkAt: left }),
  };
}

/** Saves what was learned for the authority with SHA-256 `authority`, atomically. */
export async function saveLearnedEndpoints(dataDirectory: string, authority: string, learned: LearnedEndpoints): Promise<void> {
  const path = endpointsPath(dataDirectory);
  const temporary = `${path}.${process.pid}.${randomUUID()}.tmp`;
  try {
    await writeFile(temporary, `${JSON.stringify({ version, authority, ...learned })}\n`, { encoding: "utf8", flag: "wx", mode: 0o600 });
    await atomicReplace(temporary, path);
    await chmod(path, 0o600);
  } catch (error) {
    await rm(temporary, { force: true });
    throw error;
  }
}

/**
 * What the server says about its addresses (`GET /v1/machine/endpoints`):
 * `network` only while it is shared on its network. Undefined when that is
 * unknown: an older server (404), no answer, or an answer that cannot be
 * read. A network address that is not a private one is left out.
 */
export async function fetchServerEndpoints(
  controlPlane: URL,
  key: string,
  fetcher: typeof fetch = serverFetch,
  timeoutMs = 10_000,
): Promise<Readonly<{ network?: ServerAddress }> | undefined> {
  let response: Response;
  try {
    response = await fetcher(new URL("/v1/machine/endpoints", controlPlane), {
      method: "GET",
      headers: { Authorization: `Bearer ${key}`, Accept: "application/json" },
      redirect: "error",
      signal: AbortSignal.timeout(timeoutMs),
    });
  } catch {
    return undefined;
  }
  let reader: ReadableStreamDefaultReader<Uint8Array> | undefined;
  try {
    if (!response.ok) return undefined;
    reader = response.body?.getReader();
    if (reader === undefined) return undefined;
    const chunks: Uint8Array[] = [];
    let size = 0;
    for (;;) {
      const chunk = await reader.read();
      if (chunk.done) break;
      size += chunk.value.byteLength;
      if (size > maxResponseBytes) return undefined;
      chunks.push(chunk.value);
    }
    const value: unknown = JSON.parse(Buffer.concat(chunks).toString("utf8"));
    if (typeof value !== "object" || value === null || Array.isArray(value)) return undefined;
    const shared = "network" in value && typeof value.network === "object" && value.network !== null
      ? value.network as Record<string, unknown>
      : undefined;
    const network = shared === undefined ? undefined : networkAddress(shared["control_plane_url"], shared["grpc_url"]);
    return network === undefined ? {} : { network };
  } catch {
    return undefined;
  } finally {
    await (reader === undefined ? response.body?.cancel() : reader.cancel())?.catch(() => undefined);
  }
}
