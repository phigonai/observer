import assert from "node:assert/strict";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import * as http from "node:http";
import { createServer, type Server } from "node:https";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { Client, Server as GrpcServer, ServerCredentials, credentials } from "@grpc/grpc-js";
import {
  connectThroughProxy,
  grpcNoProxy,
  noProxyForAll,
  proxyForUrl,
  proxySettings,
  useProxyFromEnvironment,
} from "../src/proxy.js";
import { addDefaultAuthority, pinServerAuthority } from "../src/server-authority.js";
import { serverCertificate, testAuthority, type TestCertificate } from "./support/certificates.js";
import { startConnectProxy } from "./support/connect-proxy.js";

const nativeProxySupport = typeof (http as unknown as { setGlobalProxyFromEnv?: unknown }).setGlobalProxyFromEnv === "function";

async function startHttpsServer(certificate: TestCertificate, chain = ""): Promise<Readonly<{ port: number; server: Server }>> {
  const server = createServer({ key: certificate.key, cert: `${certificate.certificate}${chain}` }, (request, response) => {
    response.writeHead(request.url === "/healthz" ? 200 : 404, { "content-type": "application/json" });
    response.end(JSON.stringify({ status: "ok" }));
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  return { port: (server.address() as AddressInfo).port, server };
}

async function stop(server: Server): Promise<void> {
  server.closeAllConnections();
  await new Promise<void>((resolve) => server.close(() => resolve()));
}

/** Runs `body` with the proxy variables of this process cleared. */
async function withoutProxyVariables(body: () => Promise<void>): Promise<void> {
  const names = ["https_proxy", "HTTPS_PROXY", "http_proxy", "HTTP_PROXY", "no_proxy", "NO_PROXY", "grpc_proxy", "no_grpc_proxy"];
  const saved = new Map(names.map((name) => [name, process.env[name]]));
  for (const name of names) delete process.env[name];
  try {
    await body();
  } finally {
    for (const [name, value] of saved) {
      if (value === undefined) delete process.env[name];
      else process.env[name] = value;
    }
  }
}

test("proxy settings read either case, with lowercase first, and never echo a bad value", () => {
  const settings = proxySettings({
    HTTPS_PROXY: "http://upper.example:3128",
    https_proxy: "http://lower.example:3128",
    HTTP_PROXY: "proxy.example:8080",
    NO_PROXY: "internal.example",
  });
  assert.equal(settings.https?.host, "lower.example:3128");
  assert.equal(settings.http?.href, "http://proxy.example:8080/");
  assert.equal(settings.noProxy, "internal.example");
  assert.deepEqual(proxySettings({}), { noProxy: "" });

  const secret = ["pass", "word"].join("");
  assert.throws(
    () => proxySettings({ HTTPS_PROXY: `http://user:${secret}@[bad` }),
    (error: unknown) => error instanceof Error &&
      /HTTPS_PROXY is not a valid proxy address/u.test(error.message) && !error.message.includes(secret),
  );
  assert.throws(() => proxySettings({ HTTP_PROXY: "socks5://proxy.example:1080" }), /must be an http:\/\/ or https:\/\//u);
});

test("NO_PROXY matches hosts the way Node.js does", () => {
  const settings = (noProxy: string) => proxySettings({ HTTPS_PROXY: "http://proxy.example:3128", HTTP_PROXY: "http://plain.example:3128", NO_PROXY: noProxy });
  const via = (target: string, noProxy: string) => proxyForUrl(new URL(target), settings(noProxy))?.host;
  assert.equal(via("https://api.phigon.online", ""), "proxy.example:3128");
  assert.equal(via("http://api.phigon.online", ""), "plain.example:3128");
  assert.equal(via("https://phigon.internal", "phigon.internal"), undefined);
  assert.equal(via("https://a.phigon.internal", "phigon.internal"), undefined);
  assert.equal(via("https://a.phigon.internal", ".phigon.internal"), undefined);
  assert.equal(via("https://phigon.internal", ".phigon.internal"), undefined);
  assert.equal(via("https://a.phigon.internal", "*.phigon.internal"), undefined);
  assert.equal(via("https://notphigon.internal", "phigon.internal"), "proxy.example:3128");
  assert.equal(via("https://anything.example", "*"), undefined);
  assert.equal(via("https://server.lan:17080", "server.lan:17080"), undefined);
  assert.equal(via("https://server.lan:17080", "server.lan:443"), "proxy.example:3128");
  assert.equal(via("https://server.lan", " other.lan , server.lan "), undefined);
  assert.equal(via("https://[::1]:8443", "::1"), undefined);
  // Only an HTTPS proxy for HTTPS; HTTP_PROXY is the fallback.
  assert.equal(proxyForUrl(new URL("https://a.example"), proxySettings({ HTTP_PROXY: "http://plain.example:1" }))?.host, "plain.example:1");
  assert.equal(proxyForUrl(new URL("http://a.example"), proxySettings({ HTTPS_PROXY: "http://secure.example:1" })), undefined);
});

test("the telemetry stream gets the same NO_PROXY in the form grpc-js reads", () => {
  assert.equal(grpcNoProxy("*.corp.example, .lan,server.lan:9090,other.lan:443,*", 9090), "corp.example,lan,server.lan");
  assert.equal(noProxyForAll({ NO_PROXY: "a.example, *" }), true);
  assert.equal(noProxyForAll({ no_grpc_proxy: "a.example", NO_PROXY: "*" }), false);
  assert.equal(noProxyForAll({}), false);
});

test("without a proxy nothing changes", () => {
  let calls = 0;
  const target: NodeJS.ProcessEnv = {};
  const setup = useProxyFromEnvironment({ NO_PROXY: "a.example" }, {
    setGlobalProxyFromEnv: () => { calls++; return () => undefined; },
    processEnvironment: target,
  });
  setup.restore();
  assert.equal(calls, 0);
  assert.deepEqual(target, {});
  assert.equal(setup.notice, undefined);
});

test("a proxy is applied to fetch and handed to the stream, and put back afterwards", () => {
  const applied: NodeJS.ProcessEnv[] = [];
  let restored = 0;
  const target: NodeJS.ProcessEnv = { no_grpc_proxy: "kept.example" };
  const setup = useProxyFromEnvironment(
    { HTTPS_PROXY: "http://proxy.example:3128", NO_PROXY: "*.corp.example" },
    {
      setGlobalProxyFromEnv: (environment) => { applied.push(environment); return () => { restored++; }; },
      processEnvironment: target,
      streamUrl: new URL("https://observer.corp.example"),
    },
  );
  assert.equal(setup.notice, undefined);
  assert.deepEqual(applied, [{ HTTPS_PROXY: "http://proxy.example:3128/", NO_PROXY: "*.corp.example" }]);
  assert.equal(target["grpc_proxy"], "http://proxy.example:3128/");
  // The person's own grpc-js settings win.
  assert.equal(target["no_grpc_proxy"], "kept.example");
  setup.restore();
  assert.equal(restored, 1);
  assert.deepEqual(target, { no_grpc_proxy: "kept.example" });

  const fresh: NodeJS.ProcessEnv = {};
  useProxyFromEnvironment({ https_proxy: "http://proxy.example:3128", no_proxy: "*.corp.example" }, {
    setGlobalProxyFromEnv: () => () => undefined,
    processEnvironment: fresh,
  });
  assert.equal(fresh["no_grpc_proxy"], "corp.example");
});

test("an older Node.js or an https:// proxy is explained instead of ignored", () => {
  const target: NodeJS.ProcessEnv = {};
  const old = useProxyFromEnvironment({ HTTPS_PROXY: "http://proxy.example:3128" }, {
    setGlobalProxyFromEnv: undefined,
    startedWithEnvProxy: false,
    nodeVersion: "24.6.0",
    processEnvironment: target,
  });
  assert.match(old.notice ?? "", /Node\.js 24\.6\.0 uses it only when NODE_USE_ENV_PROXY=1 is set/u);
  assert.equal(target["grpc_proxy"], "http://proxy.example:3128/");
  old.restore();
  assert.equal(
    useProxyFromEnvironment({ HTTPS_PROXY: "http://proxy.example:3128" }, {
      setGlobalProxyFromEnv: undefined,
      startedWithEnvProxy: true,
      processEnvironment: {},
    }).notice,
    undefined,
  );

  const secure = useProxyFromEnvironment({ HTTPS_PROXY: "https://proxy.example:3129" }, {
    setGlobalProxyFromEnv: () => () => undefined,
    processEnvironment: {},
  });
  assert.match(secure.notice ?? "", /telemetry stream can use only an http:\/\/ proxy/u);
});

test("HTTPS goes through a CONNECT proxy and still checks the authorities it trusts", { skip: !nativeProxySupport && "needs Node.js 24.14" }, async () => {
  const authority = testAuthority();
  const stranger = testAuthority("Unrelated authority");
  addDefaultAuthority(authority.certificate);
  const trusted = await startHttpsServer(serverCertificate(authority));
  const untrusted = await startHttpsServer(serverCertificate(stranger));
  const proxy = await startConnectProxy();
  try {
    await withoutProxyVariables(async () => {
      const setup = useProxyFromEnvironment({ HTTPS_PROXY: proxy.url }, { processEnvironment: {} });
      try {
        const response = await fetch(`https://localhost:${trusted.port}/healthz`, { signal: AbortSignal.timeout(10_000) });
        assert.equal(response.status, 200);
        assert.deepEqual(proxy.tunnels, [`localhost:${trusted.port}`]);

        // The tunnel opens, but TLS inside it still refuses an unknown authority.
        await assert.rejects(fetch(`https://localhost:${untrusted.port}/healthz`, { signal: AbortSignal.timeout(10_000) }));
        assert.equal(proxy.tunnels.at(-1), `localhost:${untrusted.port}`);
      } finally {
        setup.restore();
      }

      // NO_PROXY sends the request directly.
      const before = proxy.tunnels.length;
      const direct = useProxyFromEnvironment({ HTTPS_PROXY: proxy.url, NO_PROXY: "localhost" }, { processEnvironment: {} });
      try {
        const response = await fetch(`https://localhost:${trusted.port}/healthz`, { signal: AbortSignal.timeout(10_000) });
        assert.equal(response.status, 200);
        assert.equal(proxy.tunnels.length, before);
      } finally {
        direct.restore();
      }
    });
  } finally {
    await proxy.close();
    await stop(trusted.server);
    await stop(untrusted.server);
  }
});

test("pairing reads a company server's authority through the proxy", async () => {
  const authority = testAuthority();
  // A company server presents its authority after its own certificate.
  const server = await startHttpsServer(serverCertificate(authority), authority.certificate);
  const proxy = await startConnectProxy();
  const directory = await mkdtemp(join(tmpdir(), "phigon-proxy-pin-"));
  try {
    const file = await pinServerAuthority(
      new URL(`https://localhost:${server.port}`),
      authority.fingerprint,
      directory,
      undefined,
      { proxy: new URL(proxy.url) },
    );
    assert.deepEqual(proxy.tunnels, [`localhost:${server.port}`]);
    assert.equal((await readFile(file, "utf8")).replace(/\s+/gu, ""), authority.certificate.replace(/\s+/gu, ""));

    await assert.rejects(
      pinServerAuthority(new URL(`https://localhost:${server.port}`), "0".repeat(64), directory, undefined, { proxy: new URL(proxy.url) }),
      /does not match the fingerprint/u,
    );
  } finally {
    await proxy.close();
    await stop(server.server);
    await rm(directory, { recursive: true, force: true });
  }
});

test("a proxy that refuses or is down is reported without its credentials", async () => {
  const refusing = http.createServer();
  refusing.on("connect", (_request, socket) => socket.end("HTTP/1.1 403 Forbidden\r\n\r\n"));
  await new Promise<void>((resolve) => refusing.listen(0, "127.0.0.1", resolve));
  const port = (refusing.address() as AddressInfo).port;
  const secret = ["s3", "cret"].join("");
  try {
    await assert.rejects(
      connectThroughProxy(new URL(`http://user:${secret}@127.0.0.1:${port}`), "server.lan", 443),
      (error: unknown) => error instanceof Error && /refused to connect to server\.lan:443 \(HTTP 403\)/u.test(error.message) &&
        !error.message.includes(secret),
    );
  } finally {
    refusing.closeAllConnections();
    await new Promise<void>((resolve) => refusing.close(() => resolve()));
  }
  await assert.rejects(
    connectThroughProxy(new URL(`http://user:${secret}@127.0.0.1:${port}`), "server.lan", 443),
    (error: unknown) => error instanceof Error && /Could not reach the proxy 127\.0\.0\.1:/u.test(error.message) &&
      !error.message.includes(secret),
  );

  const recorder = await startConnectProxy();
  try {
    const socket = await connectThroughProxy(new URL(`http://user:${secret}@${new URL(recorder.url).host}`), "127.0.0.1", 9);
    socket.destroy();
  } catch {
    // Nothing listens on port 9; only the request to the proxy matters.
  } finally {
    await recorder.close();
  }
  assert.equal(recorder.authorizations[0], `Basic ${Buffer.from(`user:${secret}`).toString("base64")}`);
});

test("the telemetry stream goes through the proxy and checks the pinned authority inside it", async () => {
  const authority = testAuthority();
  const leaf = serverCertificate(authority);
  const server = new GrpcServer();
  const port = await new Promise<number>((resolve, reject) => {
    server.bindAsync(
      "127.0.0.1:0",
      ServerCredentials.createSsl(null, [{ private_key: Buffer.from(leaf.key), cert_chain: Buffer.from(leaf.certificate) }], false),
      (error, bound) => error ? reject(error) : resolve(bound),
    );
  });
  const proxy = await startConnectProxy();
  const ready = (rootCertificate: string, waitMs: number) => new Promise<void>((resolve, reject) => {
    const client = new Client(`localhost:${port}`, credentials.createSsl(Buffer.from(rootCertificate)));
    client.waitForReady(Date.now() + waitMs, (error) => {
      client.close();
      if (error) reject(error);
      else resolve();
    });
  });
  try {
    await withoutProxyVariables(async () => {
      const setup = useProxyFromEnvironment({ HTTPS_PROXY: proxy.url }, { setGlobalProxyFromEnv: () => () => undefined });
      try {
        await ready(authority.certificate, 10_000);
        assert.ok(proxy.tunnels.includes(`localhost:${port}`), "the stream connected through the proxy");
        await assert.rejects(ready(testAuthority("Unrelated authority").certificate, 2_000));
      } finally {
        setup.restore();
      }
      assert.equal(process.env["grpc_proxy"], undefined);
    });
  } finally {
    await proxy.close();
    server.forceShutdown();
  }
});

test("commands refuse a malformed proxy address with a plain sentence", async () => {
  const { run } = await import("../src/cli.js");
  let stderr = "";
  const secret = ["hun", "ter2"].join("");
  const code = await run(["doctor"], { HTTPS_PROXY: `http://admin:${secret}@[broken`, PHIGON_DATA_DIR: join(tmpdir(), "phigon-proxy-unused") }, {
    stdout: () => undefined,
    stderr: (value) => { stderr += value; },
  });
  assert.equal(code, 1);
  assert.match(stderr, /HTTPS_PROXY is not a valid proxy address/u);
  assert.doesNotMatch(stderr, new RegExp(secret, "u"));
});
