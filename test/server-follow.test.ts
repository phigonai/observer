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
import { serverAuthorityPath } from "../src/server-authority.js";
import {
  authorityComputerName,
  canFollow,
  findMovedServer,
  followServer,
  relayLabel,
  relayServer,
  saveMovedServer,
  type MovedServer,
} from "../src/server-follow.js";
import { readServiceSettings, serviceSettingsPath, writeServiceSettings } from "../src/service.js";
import { serverCertificate, testAuthority, type TestCertificate } from "./support/certificates.js";

// Machine keys are built at run time, so no key-shaped text is stored.
const key = ["phg", "m", "f".repeat(43)].join("_");
const oldAddress = "192.168.50.3";
const newAddress = "192.168.50.7";
const pinned = testAuthority("Phigon server authority DESKTOP-Follow");

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

/** A server on this computer presenting `leaf`; tests pretend it is elsewhere. */
async function startServer(leaf: TestCertificate): Promise<Readonly<{ port: number; server: Server }>> {
  const server = createHttpsServer({ key: leaf.key, cert: leaf.certificate }, (_request, response) => response.end());
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  return { port: (server.address() as AddressInfo).port, server };
}

/** Where an address that no longer answers goes: every connection is reset. */
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
 * Connects to the test server listed for an address, checking its
 * certificate against that address as a real connection there would.
 */
function routed(routes: Readonly<Record<string, number>>) {
  const reached: string[] = [];
  const connect = (options: tls.ConnectionOptions, listener: () => void) => {
    const host = String(options.host);
    reached.push(host);
    const port = routes[host];
    assert.ok(port !== undefined, `nothing listens for ${host}`);
    return tls.connect({
      ...options,
      host: "127.0.0.1",
      port,
      checkServerIdentity: (_name, certificate) => tls.checkServerIdentity(host, certificate),
    }, listener);
  };
  return { connect, reached };
}

async function pairedDirectory(): Promise<string> {
  const directory = await mkdtemp(join(tmpdir(), "phigon-server-follow-"));
  await new FileCredentialStore(directory).save(paired);
  await writeFile(serverAuthorityPath(directory), pinned.certificate);
  return directory;
}

test("the Phigon app's authority names the computer that runs it", () => {
  assert.equal(authorityComputerName(pinned.certificate), "desktop-follow");
  assert.equal(authorityComputerName(testAuthority("Phigon server authority Parths-Mac.local").certificate), "parths-mac.local");
  assert.equal(authorityComputerName(testAuthority("Phigon test authority").certificate), undefined);
  assert.equal(authorityComputerName(testAuthority("Phigon server authority bad name!").certificate), undefined);
  assert.equal(authorityComputerName("not a certificate"), undefined);
});

test("only a Phigon app reached by its address on the company network is followed", () => {
  assert.equal(canFollow(paired, pinned.certificate), true);
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
  // An authority the Phigon app did not make names no computer to look for.
  assert.equal(canFollow(paired, testAuthority("Phigon test authority").certificate), false);
  for (const address of ["10.1.2.3", "172.20.0.4", "100.80.1.2"]) {
    assert.equal(canFollow(at(`https://${address}:17080`, `https://${address}:17081`), pinned.certificate), true, address);
  }
});

test("the server is found at its computer's new address once it proves the pinned authority", async () => {
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
    assert.deepEqual(reached, [newAddress]);
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
    const found = await findMovedServer({
      credential: paired,
      authority: pinned.certificate,
      connect,
      relayDomain: "relay.test",
      lookup: async () => [newAddress, "192.168.50.8"],
    });
    assert.equal(found, undefined);
    // The relay is asked last; nothing answers there either.
    assert.deepEqual(reached, [newAddress, "192.168.50.8", new URL(relayed.controlPlaneOrigin).hostname]);
  } finally {
    await stop(impostor.server);
    await stop(misnamed.server);
  }
});

const relayed = relayServer(pinned.certificate, "relay.test") as MovedServer;
const relayHosts = [new URL(relayed.controlPlaneOrigin).hostname, new URL(relayed.grpcOrigin).hostname];

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
  const genuine = await startServer(serverCertificate(pinned, relayHosts));
  try {
    const { connect, reached } = routed({ [relayHosts[0]!]: genuine.port, [relayHosts[1]!]: genuine.port });
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

test("the relay is not followed when what answers there cannot prove the pinned authority", async () => {
  const other = testAuthority("Phigon server authority DESKTOP-Follow");
  const impostor = await startServer(serverCertificate(other, relayHosts));
  try {
    const { connect } = routed({ [relayHosts[0]!]: impostor.port, [relayHosts[1]!]: impostor.port });
    const found = await findMovedServer({
      credential: paired, authority: pinned.certificate, connect, relayDomain: "relay.test", lookup: async () => [],
    });
    assert.equal(found, undefined);
  } finally {
    await stop(impostor.server);
  }
});

test("a server already reached through the relay is not looked for there again", async () => {
  const { connect, reached } = routed({});
  const found = await findMovedServer({
    credential: { ...paired, ...relayed }, authority: pinned.certificate, connect, relayDomain: "relay.test", lookup: async () => [],
  });
  assert.equal(found, undefined);
  assert.deepEqual(reached, []);
});

test("a server that answers where it was is not looked for elsewhere", async () => {
  const directory = await pairedDirectory();
  const genuine = await startServer(serverCertificate(pinned, [oldAddress]));
  const controller = new AbortController();
  try {
    const { connect, reached } = routed({ [oldAddress]: genuine.port });
    let lookups = 0;
    const following = followServer({
      dataDirectory: directory,
      credential: paired,
      signal: controller.signal,
      connect,
      lookup: async () => { lookups++; return []; },
      onMoved: async () => assert.fail("the server did not move"),
      intervalMs: 5,
      failuresBeforeSearch: 1,
    });
    while (reached.length < 4) await new Promise((resolve) => setTimeout(resolve, 5));
    controller.abort();
    await following;
    assert.equal(lookups, 0);
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
    const { connect, reached } = routed({ [oldAddress]: gone.port, [newAddress]: genuine.port });
    let clock = 0;
    const saved: MovedServer[] = [];
    await followServer({
      dataDirectory: directory,
      credential: paired,
      signal: new AbortController().signal,
      connect,
      lookup: async (name) => name === "desktop-follow" ? [newAddress] : [],
      // The first time it cannot be saved, so it is looked for again later.
      onMoved: async (server) => {
        saved.push(server);
        return saved.length > 1;
      },
      intervalMs: 1,
      failuresBeforeSearch: 2,
      searchEveryMs: 1_000,
      now: () => (clock += 100),
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
