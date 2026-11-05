import assert from "node:assert/strict";
import * as http from "node:http";
import { createServer, type Server } from "node:https";
import type { AddressInfo } from "node:net";
import test from "node:test";
import * as tls from "node:tls";
import { proxySettings } from "../src/proxy.js";
import { addDefaultAuthority } from "../src/server-authority.js";
import {
  pinnedFetch,
  serverFetch,
  trustedServerAuthority,
  trustServerAuthority,
  useServerProxy,
} from "../src/server-fetch.js";
import { serverCertificate, testAuthority, type TestCertificate } from "./support/certificates.js";
import { startConnectProxy } from "./support/connect-proxy.js";

async function startHttpsServer(leaf: TestCertificate): Promise<Readonly<{ port: number; server: Server; seen: string[] }>> {
  const seen: string[] = [];
  const server = createServer({ key: leaf.key, cert: leaf.certificate }, (request, response) => {
    seen.push(request.headers.authorization ?? "");
    response.writeHead(200, { "content-type": "application/json" });
    response.end(JSON.stringify({ status: "ok" }));
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  return { port: (server.address() as AddressInfo).port, server, seen };
}

async function stop(server: Server | http.Server): Promise<void> {
  server.closeAllConnections();
  await new Promise<void>((resolve) => server.close(() => resolve()));
}

// Built at run time, so no key-shaped text is stored.
const key = ["phg", "m", "p".repeat(43)].join("_");

test("requests to the paired server trust only its pinned authority, even over one this computer trusts", async () => {
  const pinned = testAuthority("Phigon server authority PINNED");
  // An authority every program on this computer trusts, as a public one is.
  const publicAuthority = testAuthority("Public test authority");
  addDefaultAuthority(publicAuthority.certificate);
  const genuine = await startHttpsServer(serverCertificate(pinned, ["localhost"]));
  // Someone who got a publicly trusted certificate for the server's name.
  const impostor = await startHttpsServer(serverCertificate(publicAuthority, ["localhost"]));
  const fetcher = pinnedFetch(pinned.certificate);
  try {
    // The rest of the process trusts the impostor's certificate.
    assert.equal((await fetch(`https://localhost:${impostor.port}/`)).status, 200);
    assert.ok(!tls.getCACertificates("default").some((pem) => pem.replace(/\s+/gu, "") === pinned.certificate.replace(/\s+/gu, "")),
      "the pinned authority is not added for every host");

    const response = await fetcher(new URL(`https://localhost:${genuine.port}/healthz`), { headers: { Authorization: `Bearer ${key}` } });
    assert.equal(response.status, 200);
    assert.deepEqual(await response.json(), { status: "ok" });

    await assert.rejects(
      fetcher(`https://localhost:${impostor.port}/healthz`, { method: "POST", headers: { Authorization: `Bearer ${key}` }, body: "{}" }),
      (error: Error & { cause?: { code?: string } }) =>
        ["UNABLE_TO_VERIFY_LEAF_SIGNATURE", "SELF_SIGNED_CERT_IN_CHAIN"].includes(error.cause?.code ?? ""),
    );
    assert.deepEqual(impostor.seen, [""], "the key never reached the impostor");
    // A certificate from the pinned authority, but for another name.
    const misnamed = await startHttpsServer(serverCertificate(pinned, ["other.example"]));
    try {
      await assert.rejects(fetcher(`https://localhost:${misnamed.port}/`), (error: Error & { cause?: { code?: string } }) =>
        error.cause?.code === "ERR_TLS_CERT_ALTNAME_INVALID");
    } finally {
      await stop(misnamed.server);
    }
  } finally {
    await fetcher.close();
    await stop(genuine.server);
    await stop(impostor.server);
  }
});

test("through a CONNECT proxy, requests to the paired server still trust only its pinned authority", async () => {
  const pinned = testAuthority("Phigon server authority PROXIED");
  const publicAuthority = testAuthority("Public proxied authority");
  addDefaultAuthority(publicAuthority.certificate);
  const genuine = await startHttpsServer(serverCertificate(pinned, ["phigon.relay.test"]));
  const impostor = await startHttpsServer(serverCertificate(publicAuthority, ["impostor.relay.test"]));
  const proxy = await startConnectProxy({ "phigon.relay.test:443": genuine.port, "impostor.relay.test:443": impostor.port });
  const secret = ["s3", "cret"].join("");
  const proxyUrl = new URL(proxy.url);
  proxyUrl.username = "user";
  proxyUrl.password = secret;
  const fetcher = pinnedFetch(pinned.certificate, () => proxyUrl);
  try {
    const response = await fetcher("https://phigon.relay.test/healthz", { signal: AbortSignal.timeout(10_000) });
    assert.equal(response.status, 200);
    await response.body?.cancel();
    await assert.rejects(fetcher("https://impostor.relay.test/healthz", { signal: AbortSignal.timeout(10_000) }));
    assert.deepEqual(proxy.tunnels, ["phigon.relay.test:443", "impostor.relay.test:443"]);
    assert.equal(proxy.authorizations[0], `Basic ${Buffer.from(`user:${secret}`).toString("base64")}`);
    assert.deepEqual(impostor.seen, []);
  } finally {
    await fetcher.close();
    await proxy.close();
    await stop(genuine.server);
    await stop(impostor.server);
  }
});

test("serverFetch pins the saved authority, follows the proxy settings, and leaves other requests alone", async () => {
  const pinned = testAuthority("Phigon server authority SERVERFETCH");
  const genuine = await startHttpsServer(serverCertificate(pinned, ["localhost", "phigon.serverfetch.test"]));
  const plain = http.createServer((_request, response) => response.end("plain"));
  await new Promise<void>((resolve) => plain.listen(0, "127.0.0.1", resolve));
  const proxy = await startConnectProxy({ "phigon.serverfetch.test:443": genuine.port });
  try {
    trustServerAuthority(undefined);
    assert.equal(trustedServerAuthority(), undefined);
    // Without a pinned authority, the system's authorities decide.
    await assert.rejects(serverFetch(`https://localhost:${genuine.port}/`));

    trustServerAuthority(pinned.certificate);
    trustServerAuthority(pinned.certificate);
    assert.equal(trustedServerAuthority(), pinned.certificate);
    assert.equal((await serverFetch(`https://localhost:${genuine.port}/`)).status, 200);
    // Plain HTTP has nothing to pin.
    assert.equal(await (await serverFetch(`http://127.0.0.1:${(plain.address() as AddressInfo).port}/`)).text(), "plain");
    await assert.rejects(serverFetch(new Request(`https://localhost:${genuine.port}/`)), /take a URL/u);

    useServerProxy(proxySettings({ HTTPS_PROXY: proxy.url, NO_PROXY: "localhost" }));
    assert.equal((await serverFetch("https://phigon.serverfetch.test/")).status, 200);
    assert.equal((await serverFetch(`https://localhost:${genuine.port}/`)).status, 200);
    assert.deepEqual(proxy.tunnels, ["phigon.serverfetch.test:443"], "NO_PROXY goes directly");
  } finally {
    useServerProxy(undefined);
    trustServerAuthority(undefined);
    await proxy.close();
    await stop(genuine.server);
    await stop(plain);
  }
});
