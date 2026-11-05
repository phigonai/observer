import assert from "node:assert/strict";
import { X509Certificate } from "node:crypto";
import { EventEmitter } from "node:events";
import { existsSync } from "node:fs";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { createServer as createHttpsServer, type Server } from "node:https";
import { createServer as createTcpServer, type AddressInfo, type Server as TcpServer, type Socket } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import * as tls from "node:tls";
import { connectionEnvironment } from "../src/connection-config.js";
import {
  forgetServerAuthority,
  parseAuthorityFingerprint,
  pinServerAuthority,
  serverAuthorityPath,
  inspectionMessage,
  readServerAuthority,
  relayNotConnectedMessage,
  ServerAuthorityError,
  trustSavedAuthority,
  verifyServerAuthority,
} from "../src/server-authority.js";
import { trustedServerAuthority } from "../src/server-fetch.js";
import { serverCertificate, testAuthority, type TestCertificate } from "./support/certificates.js";

// A throwaway test authority; only its certificate is kept.
const AUTHORITY = `-----BEGIN CERTIFICATE-----
MIIBlzCCAT2gAwIBAgIULJuOXFgUkkeJIgd/SpI9mzwtk1wwCgYIKoZIzj0EAwIw
IDEeMBwGA1UEAwwVUGhpZ29uIHRlc3QgYXV0aG9yaXR5MCAXDTI2MTEwMTA1MjA1
NloYDzIxMjYxMDA4MDUyMDU2WjAgMR4wHAYDVQQDDBVQaGlnb24gdGVzdCBhdXRo
b3JpdHkwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAASfoVjMspiJGTY6aYChFSs/
98QHhJHl4H76TMh1BJSIRoioi3Hr8zKI0aClSUWgLUUDtAayyYq2X4LAydh/gl+n
o1MwUTAdBgNVHQ4EFgQUUTmv3giUis45PwIfU0MdvjKqp+wwHwYDVR0jBBgwFoAU
UTmv3giUis45PwIfU0MdvjKqp+wwDwYDVR0TAQH/BAUwAwEB/zAKBggqhkjOPQQD
AgNIADBFAiB0SMBOvNGl8BJ8aZOFWGD0/rV8xNvSUwoC5JnOtQZ4nwIhAISVaoWz
MzwLE5B2zbYJ2rqxkFgxlBjHkXz2ZII1W1Hb
-----END CERTIFICATE-----
`;
const FINGERPRINT = "6a099db5ea98af28e0527090b130e4f5f14e0f36adc9bf5e3769b03a397aaa1a";

/** A connection that presents a leaf and then the test authority. */
function presenting(seen: tls.ConnectionOptions[]) {
  return (options: tls.ConnectionOptions, listener: () => void) => {
    seen.push(options);
    const authority = new X509Certificate(AUTHORITY);
    const root = { raw: authority.raw, fingerprint256: authority.fingerprint256 } as tls.DetailedPeerCertificate;
    root.issuerCertificate = root;
    const leaf = { raw: Buffer.from("leaf"), fingerprint256: "LEAF", issuerCertificate: root } as tls.DetailedPeerCertificate;
    const socket = Object.assign(new EventEmitter(), {
      getPeerCertificate: () => leaf,
      end: () => undefined,
      destroy: () => undefined,
    }) as unknown as tls.TLSSocket;
    queueMicrotask(listener);
    return socket;
  };
}

test("fingerprints from the Connect machine dialog are read with or without colons", () => {
  assert.equal(parseAuthorityFingerprint(` ${FINGERPRINT.toUpperCase()} `), FINGERPRINT);
  assert.equal(parseAuthorityFingerprint(FINGERPRINT.match(/../gu)!.join(":")), FINGERPRINT);
  for (const bad of ["", "abc", `${FINGERPRINT}00`, FINGERPRINT.replace("a", "g")]) {
    assert.throws(() => parseAuthorityFingerprint(bad), /64-character fingerprint/u);
  }
});

test("pairing pins the server's authority, and later commands trust it", async () => {
  const directory = await mkdtemp(join(tmpdir(), "phigon-authority-"));
  try {
    const seen: tls.ConnectionOptions[] = [];
    const file = await pinServerAuthority(new URL("https://192.168.1.20:17080"), FINGERPRINT, directory, presenting(seen));
    assert.equal(file, serverAuthorityPath(directory));
    assert.equal(new X509Certificate(await readFile(file, "utf8")).fingerprint256, new X509Certificate(AUTHORITY).fingerprint256);
    assert.equal(seen[0]?.host, "192.168.1.20");
    assert.equal(seen[0]?.port, 17080);
    assert.equal(seen[0]?.servername, undefined);
    // Trusted for requests to that server only, not for every host.
    assert.equal(trustedServerAuthority()?.replace(/\s+/gu, ""), AUTHORITY.replace(/\s+/gu, ""));
    const trusted = tls.getCACertificates("default").map((pem) => pem.replace(/\s+/gu, ""));
    assert.ok(!trusted.includes(AUTHORITY.replace(/\s+/gu, "")), "the pinned authority is not trusted for other hosts");

    // Every later command trusts it, for gRPC too.
    assert.equal(trustSavedAuthority(directory), file);
    const environment = await connectionEnvironment({ PHIGON_DATA_DIR: directory });
    assert.equal(environment["PHIGON_TLS_CA_FILE"], file);

    await writeFile(join(directory, "server-endpoints.json"), "{}");
    await forgetServerAuthority(directory);
    assert.equal(trustedServerAuthority(), undefined);
    assert.ok(!existsSync(join(directory, "server-endpoints.json")), "what was learned about its addresses goes with it");
    assert.equal(trustSavedAuthority(directory), undefined);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("a server whose chain does not match the fingerprint is refused, and nothing is saved", async () => {
  const directory = await mkdtemp(join(tmpdir(), "phigon-authority-"));
  try {
    await assert.rejects(
      pinServerAuthority(new URL("https://phigon.acme.lan:17080"), "0".repeat(64), directory, presenting([])),
      /does not match the fingerprint/u,
    );
    assert.equal(trustSavedAuthority(directory), undefined);
    await assert.rejects(
      pinServerAuthority(new URL("http://phigon.acme.lan:17080"), FINGERPRINT, directory, presenting([])),
      /needs an https/u,
    );
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

/** A TLS server on this computer presenting `leaf`, then `chain`. */
async function startTlsServer(leaf: TestCertificate, chain = ""): Promise<Readonly<{ port: number; server: Server }>> {
  const server = createHttpsServer({ key: leaf.key, cert: `${leaf.certificate}${chain}` }, (_request, response) => response.end());
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  return { port: (server.address() as AddressInfo).port, server };
}

/** Where the relay closes connections: every one is reset right away. */
async function startClosing(): Promise<Readonly<{ port: number; server: TcpServer }>> {
  const server = createTcpServer((socket) => socket.resetAndDestroy());
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  return { port: (server.address() as AddressInfo).port, server };
}

async function stopServer(server: Server | TcpServer): Promise<void> {
  if ("closeAllConnections" in server) server.closeAllConnections();
  await new Promise<void>((resolve) => server.close(() => resolve()));
}

/** A port nothing listens on: one that was just free. */
async function unusedPort(): Promise<number> {
  const probe = createTcpServer();
  await new Promise<void>((resolve) => probe.listen(0, "127.0.0.1", resolve));
  const port = (probe.address() as AddressInfo).port;
  await new Promise<void>((resolve) => probe.close(() => resolve()));
  return port;
}

/** Connects to the local port listed for a host, checking the certificate against that host. */
function to(routes: Readonly<Record<string, number>>) {
  return (options: tls.ConnectionOptions, listener: () => void) => {
    const host = String(options.host);
    return tls.connect({
      ...options,
      host: "127.0.0.1",
      port: routes[host] ?? 9,
      checkServerIdentity: (_name, certificate) => tls.checkServerIdentity(host, certificate),
    }, listener);
  };
}

const relayName = "abcdefghabcdefgh.relay.phigon.online";

test("a certificate re-signed on the way is explained as HTTPS inspection, at pairing and when checking a server", async () => {
  const pinned = testAuthority("Phigon server authority INSPECTED");
  // What a proxy that inspects HTTPS presents: its own authority, the server's name.
  const inspector = testAuthority("Corporate Inspection Root CA");
  const inspected = await startTlsServer(serverCertificate(inspector, [relayName, "192.168.1.30"]), inspector.certificate);
  const other = testAuthority("Phigon server authority OTHER");
  const otherServer = await startTlsServer(serverCertificate(other, [relayName]), other.certificate);
  try {
    const relayUrl = new URL(`https://${relayName}`);
    await assert.rejects(
      readServerAuthority(relayUrl, pinned.fingerprint, to({ [relayName]: inspected.port })),
      (error: Error) => error instanceof ServerAuthorityError && error.problem === "inspected" &&
        error.message === inspectionMessage(relayUrl) && /exempt \*\.relay\.phigon\.online from HTTPS inspection/u.test(error.message),
    );
    await assert.rejects(
      verifyServerAuthority(relayUrl, pinned.certificate, to({ [relayName]: inspected.port })),
      (error: Error) => error instanceof ServerAuthorityError && error.problem === "inspected" && /proxy or security software/u.test(error.message),
    );
    // On the network, IT exempts the server's own address.
    await assert.rejects(
      verifyServerAuthority(new URL("https://192.168.1.30:17080"), pinned.certificate, to({ "192.168.1.30": inspected.port })),
      /Ask your IT team to exempt 192\.168\.1\.30 from HTTPS inspection\./u,
    );
    // Another Phigon server is not inspection: the command or network is wrong.
    await assert.rejects(
      verifyServerAuthority(relayUrl, pinned.certificate, to({ [relayName]: otherServer.port })),
      (error: Error) => error instanceof ServerAuthorityError && error.problem === "not_proven",
    );
    await assert.rejects(
      readServerAuthority(relayUrl, pinned.fingerprint, to({ [relayName]: otherServer.port })),
      /does not match the fingerprint/u,
    );
  } finally {
    await stopServer(inspected.server);
    await stopServer(otherServer.server);
  }
});

test("a relay that closes the connection says the server is not connected to it", async () => {
  const pinned = testAuthority("Phigon server authority CLOSED");
  const closing = await startClosing();
  try {
    await assert.rejects(
      verifyServerAuthority(new URL(`https://${relayName}`), pinned.certificate, to({ [relayName]: closing.port })),
      (error: Error) => error instanceof ServerAuthorityError && error.problem === "relay_not_connected" && error.message === relayNotConnectedMessage,
    );
    await assert.rejects(
      readServerAuthority(new URL(`https://${relayName}`), pinned.fingerprint, to({ [relayName]: closing.port })),
      (error: Error) => error.message === relayNotConnectedMessage,
    );
    // Anywhere else, a closed connection is not about the relay.
    await assert.rejects(
      verifyServerAuthority(new URL("https://192.168.1.31:17080"), pinned.certificate, to({ "192.168.1.31": closing.port })),
      (error: Error) => error instanceof ServerAuthorityError && error.problem === "not_proven",
    );
    await assert.rejects(
      verifyServerAuthority(new URL("https://192.168.1.32:17080"), pinned.certificate, to({ "192.168.1.32": await unusedPort() })),
      (error: Error) => error instanceof ServerAuthorityError && error.problem === "unreachable" && /ECONNREFUSED/u.test(error.message),
    );
  } finally {
    await stopServer(closing.server);
  }
});

test("a server that never answers times out with a plain sentence", async () => {
  const pinned = testAuthority("Phigon server authority SILENT");
  // Accepts the connection and says nothing.
  const held = new Set<Socket>();
  const silent = createTcpServer((socket) => { held.add(socket); });
  await new Promise<void>((resolve) => silent.listen(0, "127.0.0.1", resolve));
  try {
    const port = (silent.address() as AddressInfo).port;
    await assert.rejects(
      verifyServerAuthority(new URL("https://192.168.1.33:17080"), pinned.certificate, to({ "192.168.1.33": port }), { timeoutMs: 100 }),
      (error: Error) => error instanceof ServerAuthorityError && error.problem === "timeout" && /timed out/u.test(error.message),
    );
  } finally {
    for (const socket of held) socket.destroy();
    await stopServer(silent);
  }
});
