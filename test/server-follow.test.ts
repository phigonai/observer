import assert from "node:assert/strict";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { createServer as createHttpsServer, type Server } from "node:https";
import { createServer as createTcpServer, type AddressInfo, type Server as TcpServer } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import * as tls from "node:tls";
import { FileCredentialStore, type StoredMachineCredential } from "../src/credential-store.js";
import { watchPairing } from "../src/pairing-watch.js";
import { authorityFingerprint, relayNotConnectedMessage, serverAuthorityPath } from "../src/server-authority.js";
import { loadLearnedEndpoints, saveLearnedEndpoints } from "../src/server-endpoints.js";
import {
  authorityComputerName,
  canFollow,
  findMovedServer,
  followServer,
  followTimings,
  reconcileServiceEndpoints,
  relayLabel,
  relayServer,
  saveMovedServer,
  type MovedServer,
} from "../src/server-follow.js";
import { readServiceSettings, serviceSettingsPath, writeServiceSettings } from "../src/service.js";
import { serverCertificate, testAuthority, type TestCertificate } from "./support/certificates.js";
import { startConnectProxy } from "./support/connect-proxy.js";

// Machine keys are built at run time, so no key-shaped text is stored.
const key = ["phg", "m", "f".repeat(43)].join("_");
const oldAddress = "192.168.50.3";
const newAddress = "192.168.50.7";
const pinned = testAuthority("Phigon server authority DESKTOP-Follow");
const fingerprint = authorityFingerprint(pinned.certificate)!;

const paired: StoredMachineCredential = {
  machineId: "5f1b4cb4-a77d-4f53-af66-197e184683f4",
  tenantId: "7d1b4cb4-a77d-4f53-af66-197e184683f4",
  credential: key,
  controlPlaneOrigin: `https://${oldAddress}:17080`,
  grpcOrigin: `https://${oldAddress}:17081`,
  createdAt: "2026-11-01T00:00:00.000Z",
  consentProfile: "metadata",
  consentPolicyVersion: "observer-policy-v1",
  consentedAt: "2026-11-01T00:00:00.000Z",
};

const moved: MovedServer = {
  controlPlaneOrigin: `https://${newAddress}:17080`,
  grpcOrigin: `https://${newAddress}:17081`,
};

const relayed = relayServer(pinned.certificate, "relay.test") as MovedServer;
const relayHosts = [new URL(relayed.controlPlaneOrigin).hostname, new URL(relayed.grpcOrigin).hostname] as const;
const onRelay: StoredMachineCredential = { ...paired, ...relayed };

/** A server on this computer presenting `leaf`; tests pretend it is elsewhere. */
async function startServer(leaf: TestCertificate): Promise<Readonly<{ port: number; server: Server }>> {
  const server = createHttpsServer({ key: leaf.key, cert: leaf.certificate }, (_request, response) => response.end());
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  return { port: (server.address() as AddressInfo).port, server };
}

/** Where an address that no longer answers goes: every connection is closed. */
async function startGone(): Promise<Readonly<{ port: number; server: TcpServer }>> {
  const server = createTcpServer((socket) => socket.destroy());
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  return { port: (server.address() as AddressInfo).port, server };
}

async function stop(server: Server | TcpServer): Promise<void> {
  if ("closeAllConnections" in server) server.closeAllConnections();
  await new Promise<void>((resolve) => server.close(() => resolve()));
}

/**
 * Connects to the test server listed for an address (or `address:port`),
 * checking its certificate against that address as a real connection
 * there would.
 */
function routed(routes: Readonly<Record<string, number | (() => number)>>) {
  const reached: string[] = [];
  const connect = (options: tls.ConnectionOptions, listener: () => void) => {
    const host = String(options.host);
    reached.push(host);
    const route = routes[`${host}:${options.port}`] ?? routes[host];
    assert.ok(route !== undefined, `nothing listens for ${host}`);
    return tls.connect({
      ...options,
      host: "127.0.0.1",
      port: typeof route === "function" ? route() : route,
      checkServerIdentity: (_name, certificate) => tls.checkServerIdentity(host, certificate),
    }, listener);
  };
  return { connect, reached };
}

/** An older server, which does not know where it answers. */
const olderServer: typeof fetch = async () => new Response(JSON.stringify({ error: { code: "not_found" } }), { status: 404 });

/** A server that says where it answers on its network. */
function serverSaying(body: unknown, seen: string[] = []): typeof fetch {
  return async (input, init) => {
    seen.push(`${String(input)} ${new Headers(init?.headers).get("authorization") === `Bearer ${key}` ? "with key" : "without key"}`);
    return new Response(JSON.stringify(body), { status: 200, headers: { "content-type": "application/json" } });
  };
}

async function pairedDirectory(credential: StoredMachineCredential = paired): Promise<string> {
  const directory = await mkdtemp(join(tmpdir(), "phigon-server-follow-"));
  await new FileCredentialStore(directory).save(credential);
  await writeFile(serverAuthorityPath(directory), pinned.certificate);
  return directory;
}

const tick = () => new Promise((resolve) => setTimeout(resolve, 5));

test("the Phigon app's authority names the computer that runs it", () => {
  assert.equal(authorityComputerName(pinned.certificate), "desktop-follow");
  assert.equal(authorityComputerName(testAuthority("Phigon server authority Parths-Mac.local").certificate), "parths-mac.local");
  assert.equal(authorityComputerName(testAuthority("Phigon test authority").certificate), undefined);
  assert.equal(authorityComputerName(testAuthority("Phigon server authority bad name!").certificate), undefined);
  assert.equal(authorityComputerName(testAuthority("Phigon server authority PARTH_PC").certificate), undefined);
  assert.equal(authorityComputerName("not a certificate"), undefined);
});

test("a computer that pinned its server's authority follows it from the network address or the relay", () => {
  assert.equal(canFollow(paired, pinned.certificate), true);
  // Paired with the relay addresses, as Connect machine gives while the relay is up.
  assert.equal(canFollow({ ...paired, ...relayServer(pinned.certificate)! }, pinned.certificate), true);
  assert.equal(canFollow(onRelay, pinned.certificate, "relay.test"), true);
  // Another server's relay address is not this one's.
  assert.equal(canFollow({ ...paired, ...relayServer(testAuthority("Phigon server authority OTHER").certificate)! }, pinned.certificate), false);
  const at = (http: string, grpc?: string): StoredMachineCredential => {
    const credential: { -readonly [K in keyof StoredMachineCredential]: StoredMachineCredential[K] } = { ...paired, controlPlaneOrigin: http };
    if (grpc === undefined) delete credential.grpcOrigin;
    else credential.grpcOrigin = grpc;
    return credential;
  };
  // On this computer, on the internet, by name, without HTTPS, or gRPC elsewhere.
  assert.equal(canFollow(at("https://127.0.0.1:17080", "https://127.0.0.1:17081"), pinned.certificate), false);
  assert.equal(canFollow(at("https://203.0.113.5:17080", "https://203.0.113.5:17081"), pinned.certificate), false);
  assert.equal(canFollow(at("https://phigon.example.com", "https://phigon.example.com:4317"), pinned.certificate), false);
  assert.equal(canFollow(at("http://192.168.50.3:17080", "http://192.168.50.3:17081"), pinned.certificate), false);
  assert.equal(canFollow(at("https://192.168.50.3:17080", "https://192.168.50.4:17081"), pinned.certificate), false);
  assert.equal(canFollow(at("https://192.168.50.3:17080"), pinned.certificate), false);
  // The relay needs only the authority, whatever its computer is called.
  assert.equal(canFollow(paired, testAuthority("Phigon test authority").certificate), true);
  assert.equal(canFollow(paired, "not a certificate"), false);
  for (const address of ["10.1.2.3", "172.20.0.4", "100.80.1.2"]) {
    assert.equal(canFollow(at(`https://${address}:17080`, `https://${address}:17081`), pinned.certificate), true, address);
  }
});

test("the server is found at its computer's new address once both its addresses prove the pinned authority", async () => {
  const genuine = await startServer(serverCertificate(pinned, [newAddress, "desktop-follow", "localhost"]));
  try {
    const names: string[] = [];
    const { connect, reached } = routed({ [newAddress]: genuine.port });
    const found = await findMovedServer({
      credential: paired,
      authority: pinned.certificate,
      connect,
      // Public, loopback and the old address are never tried.
      lookup: async (name) => {
        names.push(name);
        return name === "desktop-follow.local" ? ["8.8.8.8", "127.0.0.1", oldAddress, newAddress] : [];
      },
    });
    assert.deepEqual(found, moved);
    assert.deepEqual(names, ["desktop-follow", "desktop-follow.local"]);
    // Its API, then its telemetry.
    assert.deepEqual(reached, [newAddress, newAddress]);
  } finally {
    await stop(genuine.server);
  }
});

test("a server that cannot prove the pinned authority is not followed", async () => {
  // Another Phigon app on a computer with the same name.
  const other = testAuthority("Phigon server authority DESKTOP-Follow");
  const impostor = await startServer(serverCertificate(other, [newAddress]));
  // The genuine authority's certificate, but not for that address.
  const misnamed = await startServer(serverCertificate(pinned, ["192.168.50.9"]));
  try {
    const { connect, reached } = routed({ [newAddress]: impostor.port, "192.168.50.8": misnamed.port });
    const refused: string[] = [];
    const found = await findMovedServer({
      credential: paired,
      authority: pinned.certificate,
      connect,
      relayDomain: "relay.test",
      lookup: async () => [newAddress, "192.168.50.8"],
      onRefused: (candidate) => refused.push(candidate.controlPlaneOrigin),
    });
    assert.equal(found, undefined);
    // The relay is asked last; nothing answers there either.
    assert.deepEqual(reached, [newAddress, "192.168.50.8", relayHosts[0]]);
    assert.deepEqual(refused, [moved.controlPlaneOrigin, "https://192.168.50.8:17080", relayed.controlPlaneOrigin]);
  } finally {
    await stop(impostor.server);
    await stop(misnamed.server);
  }
});

test("the relay names a server after the first 80 bits of its pinned authority's fingerprint", () => {
  // The same values as relay.Label in the control plane.
  assert.equal(relayLabel(Buffer.from("authority")), "r53p2ua3w2hpoh2o");
  assert.equal(relayLabel(new Uint8Array()), "4oymiquy7qobjgx3");
  assert.match(relayed.controlPlaneOrigin, /^https:\/\/[a-z2-7]{16}\.relay\.test$/u);
  assert.equal(relayed.grpcOrigin, relayed.controlPlaneOrigin.replace(".relay.test", "-grpc.relay.test"));
  assert.match(relayServer(pinned.certificate)?.controlPlaneOrigin ?? "", /\.relay\.phigon\.online$/u);
  assert.equal(relayServer("not a certificate"), undefined);
});

test("a server not found on the network is found through the relay once it proves the pinned authority", async () => {
  const genuine = await startServer(serverCertificate(pinned, [...relayHosts]));
  try {
    const { connect, reached } = routed({ [relayHosts[0]]: genuine.port, [relayHosts[1]]: genuine.port });
    const found = await findMovedServer({
      credential: paired,
      authority: pinned.certificate,
      connect,
      relayDomain: "relay.test",
      lookup: async () => [],
    });
    assert.deepEqual(found, relayed);
    assert.deepEqual(reached, relayHosts);
  } finally {
    await stop(genuine.server);
  }
});

test("the relay is found through a CONNECT proxy, which sees only the relay names", async () => {
  const genuine = await startServer(serverCertificate(pinned, [...relayHosts]));
  const proxy = await startConnectProxy({ [`${relayHosts[0]}:443`]: genuine.port, [`${relayHosts[1]}:443`]: genuine.port });
  try {
    const found = await findMovedServer({
      credential: paired,
      authority: pinned.certificate,
      proxyFor: () => new URL(proxy.url),
      relayDomain: "relay.test",
      lookup: async () => [],
    });
    assert.deepEqual(found, relayed);
    assert.deepEqual(proxy.tunnels, [`${relayHosts[0]}:443`, `${relayHosts[1]}:443`]);
  } finally {
    await proxy.close();
    await stop(genuine.server);
  }
});

test("a relay whose telemetry address cannot prove the pinned authority is not followed", async () => {
  const genuine = await startServer(serverCertificate(pinned, [...relayHosts]));
  const impostor = await startServer(serverCertificate(testAuthority("Phigon server authority DESKTOP-Follow"), [...relayHosts]));
  try {
    const { connect, reached } = routed({ [relayHosts[0]]: genuine.port, [relayHosts[1]]: impostor.port });
    const found = await findMovedServer({
      credential: paired, authority: pinned.certificate, connect, relayDomain: "relay.test", lookup: async () => [],
    });
    assert.equal(found, undefined);
    assert.deepEqual(reached, relayHosts);
  } finally {
    await stop(genuine.server);
    await stop(impostor.server);
  }
});

test("a computer name a network cannot look up skips only the name lookup", async () => {
  for (const authority of [testAuthority("Phigon server authority PARTH_PC"), testAuthority("Phigon test authority")]) {
    const relay = relayServer(authority.certificate, "relay.test")!;
    const hosts = [new URL(relay.controlPlaneOrigin).hostname, new URL(relay.grpcOrigin).hostname];
    const genuine = await startServer(serverCertificate(authority, hosts));
    try {
      const { connect, reached } = routed({ [hosts[0]!]: genuine.port, [hosts[1]!]: genuine.port });
      const found = await findMovedServer({
        credential: paired,
        authority: authority.certificate,
        connect,
        relayDomain: "relay.test",
        lookup: async () => assert.fail("no name to look up"),
      });
      assert.deepEqual(found, relay);
      assert.deepEqual(reached, hosts);
    } finally {
      await stop(genuine.server);
    }
  }
});

test("a server already reached through the relay is not looked for there again", async () => {
  const { connect, reached } = routed({});
  const found = await findMovedServer({
    credential: onRelay, authority: pinned.certificate, connect, relayDomain: "relay.test",
    lookup: async () => assert.fail("no network ports are known"),
  });
  assert.equal(found, undefined);
  assert.deepEqual(reached, []);
});

test("its network address is tried first, and names are looked up on its ports", async () => {
  const genuine = await startServer(serverCertificate(pinned, [newAddress]));
  const gone = await startGone();
  try {
    let lookups = 0;
    const first = routed({ [newAddress]: genuine.port });
    assert.deepEqual(await findMovedServer({
      credential: onRelay, authority: pinned.certificate, connect: first.connect, relayDomain: "relay.test", network: moved,
      lookup: async () => { lookups++; return []; },
    }), moved);
    assert.deepEqual(first.reached, [newAddress, newAddress]);
    assert.equal(lookups, 0);

    // Its old network address is gone; its name now leads to the new one.
    const second = routed({ [oldAddress]: gone.port, [newAddress]: genuine.port });
    assert.deepEqual(await findMovedServer({
      credential: onRelay, authority: pinned.certificate, connect: second.connect, relayDomain: "relay.test",
      network: { controlPlaneOrigin: paired.controlPlaneOrigin, grpcOrigin: paired.grpcOrigin! },
      lookup: async (name) => name === "desktop-follow" ? [newAddress] : [],
    }), moved);
    assert.deepEqual(second.reached, [oldAddress, newAddress, newAddress]);
  } finally {
    await stop(genuine.server);
    await stop(gone.server);
  }
});

test("a server that answers where it was is not looked for elsewhere, and its network address is remembered", async () => {
  const directory = await pairedDirectory();
  const genuine = await startServer(serverCertificate(pinned, [oldAddress]));
  const controller = new AbortController();
  try {
    const { connect, reached } = routed({ [oldAddress]: genuine.port });
    let lookups = 0;
    const asked: string[] = [];
    const following = followServer({
      dataDirectory: directory,
      credential: paired,
      signal: controller.signal,
      connect,
      fetcher: async (input, init) => { asked.push(String(input)); return await olderServer(input, init); },
      lookup: async () => { lookups++; return []; },
      onMoved: async () => assert.fail("the server did not move"),
      intervalMs: 5,
      failuresBeforeSearch: 1,
    });
    while (reached.length < 4) await tick();
    controller.abort();
    await following;
    assert.equal(lookups, 0);
    // Asked once where it answers; an older server does not know.
    assert.deepEqual(asked, [`${paired.controlPlaneOrigin}/v1/machine/endpoints`]);
    assert.deepEqual(await loadLearnedEndpoints(directory, fingerprint), {
      network: { controlPlaneOrigin: paired.controlPlaneOrigin, grpcOrigin: paired.grpcOrigin },
    });
  } finally {
    controller.abort();
    await stop(genuine.server);
    await rm(directory, { recursive: true, force: true });
  }
});

test("a server that stopped answering is followed to its new address", async () => {
  const directory = await pairedDirectory();
  const gone = await startGone();
  const genuine = await startServer(serverCertificate(pinned, [newAddress]));
  try {
    const { connect: reach, reached } = routed({ [oldAddress]: gone.port, [newAddress]: genuine.port });
    // Each check of the old address takes a tenth of a second.
    let clock = 0;
    const connect: typeof reach = (options, listener) => {
      if (options.host === oldAddress) clock += 100;
      return reach(options, listener);
    };
    const saved: MovedServer[] = [];
    await followServer({
      dataDirectory: directory,
      credential: paired,
      signal: new AbortController().signal,
      connect,
      fetcher: olderServer,
      lookup: async (name) => name === "desktop-follow" ? [newAddress] : [],
      // The first time it cannot be saved, so it is looked for again later.
      onMoved: async (server) => {
        saved.push(server);
        return saved.length > 1;
      },
      intervalMs: 1,
      failuresBeforeSearch: 2,
      searchEveryMs: 1_000,
      now: () => clock,
    });
    assert.deepEqual(saved, [moved, moved]);
    // Two failures before the first search, then ten checks a second apart.
    const checks = reached.filter((host) => host === oldAddress).length;
    assert.ok(checks >= 11 && checks <= 13, `checked the old address ${checks} times`);
  } finally {
    await stop(gone.server);
    await stop(genuine.server);
    await rm(directory, { recursive: true, force: true });
  }
});

test("a network that lets the API through but blocks telemetry moves the computer to the relay", async () => {
  const directory = await pairedDirectory();
  const network = await startServer(serverCertificate(pinned, [oldAddress]));
  const blocked = await startGone();
  const relay = await startServer(serverCertificate(pinned, [...relayHosts]));
  try {
    const { connect } = routed({
      [`${oldAddress}:17080`]: network.port,
      [`${oldAddress}:17081`]: blocked.port,
      [relayHosts[0]]: relay.port,
      [relayHosts[1]]: relay.port,
    });
    const saved: MovedServer[] = [];
    await followServer({
      dataDirectory: directory,
      credential: paired,
      signal: new AbortController().signal,
      connect,
      fetcher: olderServer,
      lookup: async () => [],
      relayDomain: "relay.test",
      onMoved: async (server) => {
        saved.push(server);
        return true;
      },
      intervalMs: 1,
      failuresBeforeSearch: 2,
    });
    assert.deepEqual(saved, [relayed]);
  } finally {
    await stop(network.server);
    await stop(blocked.server);
    await stop(relay.server);
    await rm(directory, { recursive: true, force: true });
  }
});

test("a computer paired without a pinned authority does not look for its server", async () => {
  const directory = await pairedDirectory();
  await rm(serverAuthorityPath(directory));
  try {
    await followServer({
      dataDirectory: directory,
      credential: paired,
      signal: new AbortController().signal,
      connect: () => assert.fail("nothing is checked"),
      onMoved: async () => assert.fail("nothing moves"),
      intervalMs: 1,
    });
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("a computer paired through the relay moves to the network address its server named when the relay stops answering", async () => {
  const directory = await pairedDirectory(onRelay);
  const gone = await startGone();
  const genuine = await startServer(serverCertificate(pinned, [newAddress]));
  try {
    const { connect, reached } = routed({ [relayHosts[0]]: gone.port, [relayHosts[1]]: gone.port, [newAddress]: genuine.port });
    const asked: string[] = [];
    const saved: MovedServer[] = [];
    const statuses: string[] = [];
    await followServer({
      dataDirectory: directory,
      credential: onRelay,
      signal: new AbortController().signal,
      connect,
      relayDomain: "relay.test",
      fetcher: serverSaying({
        network: { control_plane_url: `${moved.controlPlaneOrigin}/`, grpc_url: moved.grpcOrigin },
        relay: { control_plane_url: relayed.controlPlaneOrigin, grpc_url: relayed.grpcOrigin },
      }, asked),
      lookup: async () => [],
      onMoved: async (server) => { saved.push(server); return true; },
      onStatus: (message) => statuses.push(message),
      intervalMs: 1,
      failuresBeforeSearch: 2,
    });
    assert.deepEqual(saved, [moved]);
    // The key goes only to where the computer is paired, the relay.
    assert.deepEqual(asked, [`${relayed.controlPlaneOrigin}/v1/machine/endpoints with key`]);
    assert.deepEqual(reached.filter((host) => host === newAddress), [newAddress, newAddress]);
    assert.deepEqual((await loadLearnedEndpoints(directory, fingerprint)).network, moved);
    assert.deepEqual(statuses, []);
  } finally {
    await stop(gone.server);
    await stop(genuine.server);
    await rm(directory, { recursive: true, force: true });
  }
});

test("on the relay, a computer moves back to the network address after two good tries in a row", async () => {
  const directory = await pairedDirectory(onRelay);
  const relay = await startServer(serverCertificate(pinned, [...relayHosts]));
  const network = await startServer(serverCertificate(pinned, [newAddress]));
  const gone = await startGone();
  try {
    // Saved by an earlier run, long ago; an older server adds nothing.
    await saveLearnedEndpoints(directory, fingerprint, { network: moved, leftNetworkAt: "2026-01-01T00:00:00.000Z" });
    // The network address answers, then not, then twice in a row.
    const answers = [network.port, gone.port, network.port, network.port];
    let apiTries = 0;
    const { connect } = routed({
      [relayHosts[0]]: relay.port,
      [relayHosts[1]]: relay.port,
      [`${newAddress}:17080`]: () => answers[apiTries++] ?? network.port,
      [`${newAddress}:17081`]: network.port,
    });
    const saved: MovedServer[] = [];
    await followServer({
      dataDirectory: directory,
      credential: onRelay,
      signal: new AbortController().signal,
      connect,
      relayDomain: "relay.test",
      fetcher: olderServer,
      onMoved: async (server) => { saved.push(server); return true; },
      intervalMs: 1,
      probeEveryMs: 0,
    });
    assert.deepEqual(saved, [moved]);
    assert.equal(apiTries, 4, "a failed try starts the count again");
  } finally {
    await stop(relay.server);
    await stop(network.server);
    await stop(gone.server);
    await rm(directory, { recursive: true, force: true });
  }
});

test("a computer that just left the network address does not go back to it at once", async () => {
  const directory = await pairedDirectory(onRelay);
  const relay = await startServer(serverCertificate(pinned, [...relayHosts]));
  const controller = new AbortController();
  try {
    await saveLearnedEndpoints(directory, fingerprint, { network: moved, leftNetworkAt: new Date().toISOString() });
    const { connect, reached } = routed({ [relayHosts[0]]: relay.port, [relayHosts[1]]: relay.port });
    const following = followServer({
      dataDirectory: directory,
      credential: onRelay,
      signal: controller.signal,
      connect,
      relayDomain: "relay.test",
      fetcher: olderServer,
      onMoved: async () => assert.fail("it stays on the relay"),
      intervalMs: 1,
      probeEveryMs: 0,
    });
    while (reached.length < 5) await tick();
    controller.abort();
    await following;
    assert.ok(!reached.includes(newAddress), "the network address is not tried while it settles");
    assert.equal(followTimings.holdAfterLeavingMs, 15 * 60_000);
  } finally {
    controller.abort();
    await stop(relay.server);
    await rm(directory, { recursive: true, force: true });
  }
});

test("a server that is no longer shared on its network is not looked for there", async () => {
  const directory = await pairedDirectory(onRelay);
  const relay = await startServer(serverCertificate(pinned, [...relayHosts]));
  const controller = new AbortController();
  try {
    await saveLearnedEndpoints(directory, fingerprint, { network: moved, leftNetworkAt: "2026-01-01T00:00:00.000Z" });
    const { connect, reached } = routed({ [relayHosts[0]]: relay.port, [relayHosts[1]]: relay.port });
    const following = followServer({
      dataDirectory: directory,
      credential: onRelay,
      signal: controller.signal,
      connect,
      relayDomain: "relay.test",
      fetcher: serverSaying({ relay: { control_plane_url: relayed.controlPlaneOrigin, grpc_url: relayed.grpcOrigin } }),
      onMoved: async () => assert.fail("it stays on the relay"),
      intervalMs: 1,
      probeEveryMs: 0,
    });
    while (reached.length < 3) await tick();
    controller.abort();
    await following;
    assert.ok(!reached.includes(newAddress));
    assert.deepEqual(await loadLearnedEndpoints(directory, fingerprint), { leftNetworkAt: "2026-01-01T00:00:00.000Z" });
  } finally {
    controller.abort();
    await stop(relay.server);
    await rm(directory, { recursive: true, force: true });
  }
});

test("leaving the network for the relay is remembered, and a search that finds nothing is said once", async () => {
  const gone = await startGone();
  const genuine = await startServer(serverCertificate(pinned, [...relayHosts]));
  const directory = await pairedDirectory();
  const second = await pairedDirectory();
  try {
    const left = routed({ [oldAddress]: gone.port, [relayHosts[0]]: genuine.port, [relayHosts[1]]: genuine.port });
    const saved: MovedServer[] = [];
    await followServer({
      dataDirectory: directory, credential: paired, signal: new AbortController().signal, connect: left.connect,
      relayDomain: "relay.test", fetcher: olderServer, lookup: async () => [],
      onMoved: async (server) => { saved.push(server); return true; },
      intervalMs: 1, failuresBeforeSearch: 1,
    });
    assert.deepEqual(saved, [relayed]);
    const learned = await loadLearnedEndpoints(directory, fingerprint);
    assert.deepEqual(learned.network, { controlPlaneOrigin: paired.controlPlaneOrigin, grpcOrigin: paired.grpcOrigin });
    assert.ok(learned.leftNetworkAt !== undefined);

    // The relay closes the connection: the server is not connected to it.
    const controller = new AbortController();
    const statuses: string[] = [];
    let searches = 0;
    const away = routed({ [oldAddress]: gone.port, [relayHosts[0]]: gone.port });
    await followServer({
      dataDirectory: second, credential: paired, signal: controller.signal, connect: away.connect,
      relayDomain: "relay.test", fetcher: olderServer,
      lookup: async (name) => { if (name === "desktop-follow" && ++searches === 4) controller.abort(); return []; },
      onMoved: async () => assert.fail("nothing answers"),
      onStatus: (message) => statuses.push(message),
      intervalMs: 1, failuresBeforeSearch: 1, searchEveryMs: 0,
    });
    assert.equal(statuses.length, 1, statuses.join("\n"));
    assert.equal(
      statuses[0],
      `Phigon's server stopped answering at ${paired.controlPlaneOrigin}, and it was not found at another address. ${relayNotConnectedMessage} The observer keeps looking.`,
    );
  } finally {
    await stop(gone.server);
    await stop(genuine.server);
    await rm(directory, { recursive: true, force: true });
    await rm(second, { recursive: true, force: true });
  }
});

test("following saves the new address in the pairing and the service settings, and restarts the observer", async () => {
  const directory = await pairedDirectory();
  try {
    await writeServiceSettings(directory, {
      PATH: "/usr/bin",
      PHIGON_CONTROL_PLANE_URL: paired.controlPlaneOrigin,
      PHIGON_GRPC_URL: paired.grpcOrigin!,
    });
    const watch = watchPairing({ dataDirectory: directory, current: paired, onChange: () => undefined, intervalMs: 60_000 });
    try {
      assert.equal(await saveMovedServer(directory, paired, moved), true);
      assert.deepEqual(await new FileCredentialStore(directory).load(), { ...paired, ...moved });
      assert.deepEqual(await readServiceSettings(serviceSettingsPath(directory)), {
        PATH: "/usr/bin",
        PHIGON_CONTROL_PLANE_URL: moved.controlPlaneOrigin,
        PHIGON_GRPC_URL: moved.grpcOrigin,
      });
      const change = await watch.check();
      assert.equal(change?.narrowedConsent, false);
      assert.match(change?.message ?? "", /^Phigon's server is now at https:\/\/192\.168\.50\.7:17080, so the observer stops and starts again there\./u);
    } finally {
      watch.stop();
    }
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("a computer paired again meanwhile keeps its new pairing", async () => {
  const directory = await pairedDirectory();
  try {
    const repaired = { ...paired, controlPlaneOrigin: "https://192.168.50.20:17080", grpcOrigin: "https://192.168.50.20:17081" };
    await new FileCredentialStore(directory).save(repaired);
    assert.equal(await saveMovedServer(directory, paired, moved), false);
    assert.deepEqual(await new FileCredentialStore(directory).load(), repaired);
    await assert.rejects(readFile(serviceSettingsPath(directory)), { code: "ENOENT" });
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("a service whose settings and pairing name two addresses of its server starts at the pairing's", async () => {
  const directory = await pairedDirectory();
  try {
    // A move wrote the settings, then stopped before the pairing.
    const settings = { PATH: "/usr/bin", PHIGON_CONTROL_PLANE_URL: relayed.controlPlaneOrigin, PHIGON_GRPC_URL: relayed.grpcOrigin };
    await writeServiceSettings(directory, settings);
    const reconciled = await reconcileServiceEndpoints(directory, settings, "relay.test");
    assert.equal(reconciled.moved, paired.controlPlaneOrigin);
    const expected = { PATH: "/usr/bin", PHIGON_CONTROL_PLANE_URL: paired.controlPlaneOrigin, PHIGON_GRPC_URL: paired.grpcOrigin! };
    assert.deepEqual(reconciled.settings, expected);
    assert.deepEqual(await readServiceSettings(serviceSettingsPath(directory)), expected);

    // The other way round: the pairing moved to the relay, the settings did not.
    await new FileCredentialStore(directory).save(onRelay);
    const back = await reconcileServiceEndpoints(directory, expected, "relay.test");
    assert.equal(back.settings["PHIGON_CONTROL_PLANE_URL"], relayed.controlPlaneOrigin);
    assert.equal(back.settings["PHIGON_GRPC_URL"], relayed.grpcOrigin);

    // Nothing to do when they agree, or for an address that is not this server's.
    assert.equal((await reconcileServiceEndpoints(directory, back.settings, "relay.test")).moved, undefined);
    const elsewhere = { PHIGON_CONTROL_PLANE_URL: "https://phigon.example.com", PHIGON_GRPC_URL: "https://phigon.example.com:4317" };
    assert.deepEqual(await reconcileServiceEndpoints(directory, elsewhere, "relay.test"), { settings: elsewhere });
    assert.deepEqual(await reconcileServiceEndpoints(directory, { PATH: "/usr/bin" }, "relay.test"), { settings: { PATH: "/usr/bin" } });
    await rm(serverAuthorityPath(directory));
    assert.equal((await reconcileServiceEndpoints(directory, expected, "relay.test")).moved, undefined);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});
