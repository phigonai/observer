import assert from "node:assert/strict";
import { existsSync } from "node:fs";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { createServer, type Server } from "node:https";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { run } from "../src/cli.js";
import { loadConfig } from "../src/config.js";
import { FileCredentialStore, type StoredMachineCredential } from "../src/credential-store.js";
import { InstanceLock } from "../src/instance-lock.js";
import { serverAuthorityPath, verifyServerAuthority } from "../src/server-authority.js";
import { onThisComputer, preparePairingAuthority } from "../src/server-move.js";
import { moveServiceEndpoints, readServiceSettings, serviceSettingsPath, writeServiceSettings } from "../src/service.js";
import { serverCertificate, testAuthority, type TestCertificate } from "./support/certificates.js";

// Machine keys are built at run time, so no key-shaped text is stored.
const key = (fill: string) => ["phg", "m", fill.repeat(43)].join("_");
const machineID = "5f1b4cb4-a77d-4f53-af66-197e184683f4";
const tenantID = "7d1b4cb4-a77d-4f53-af66-197e184683f4";
// An address no test computer has: where the server was before it moved.
const oldOrigin = "https://192.0.2.10:17080";
// The trust store finds an issuer by its name, so each test authority has its own.
let authorities = 0;
const authority = (label: string) => testAuthority(`Phigon ${label} authority ${++authorities}`);

type Exchange = Readonly<{ existing_credential?: string }>;

/** A company server on this computer, presenting `leaf` and then `chain`. */
async function startServer(
  leaf: TestCertificate,
  chain: string,
  answer: (body: Exchange) => Readonly<{ status: number; body: unknown }>,
): Promise<Readonly<{ origin: string; server: Server; requests: Exchange[] }>> {
  const requests: Exchange[] = [];
  const server = createServer({ key: leaf.key, cert: `${leaf.certificate}${chain}` }, (request, response) => {
    let text = "";
    request.setEncoding("utf8");
    request.on("data", (chunk: string) => { text += chunk; });
    request.on("end", () => {
      const body = JSON.parse(text || "{}") as Exchange;
      requests.push(body);
      const reply = answer(body);
      response.writeHead(reply.status, { "content-type": "application/json" });
      response.end(JSON.stringify(reply.body));
    });
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  return { origin: `https://127.0.0.1:${(server.address() as AddressInfo).port}`, server, requests };
}

async function stop(server: Server): Promise<void> {
  server.closeAllConnections();
  await new Promise<void>((resolve) => server.close(() => resolve()));
}

/** A computer paired with the server at `oldOrigin`, whose authority it pinned. */
async function pairedComputer(pinned: TestCertificate): Promise<string> {
  const directory = await mkdtemp(join(tmpdir(), "phigon-server-move-"));
  await new FileCredentialStore(directory).save({
    machineId: machineID,
    tenantId: tenantID,
    credential: key("k"),
    controlPlaneOrigin: oldOrigin,
    grpcOrigin: "https://192.0.2.10:17081",
    createdAt: "2026-11-01T00:00:00.000Z",
    consentProfile: "metadata",
    consentPolicyVersion: "observer-policy-v1",
    consentedAt: "2026-11-01T00:00:00.000Z",
  });
  await writeFile(serverAuthorityPath(directory), pinned.certificate);
  // Activity the computer has not delivered yet.
  await writeFile(join(directory, "telemetry-spool.jsonl"), "");
  return directory;
}

async function pair(directory: string, origin: string, fingerprint: string) {
  let stdout = "";
  let stderr = "";
  const exitCode = await run([
    "pair",
    "--code", "ABCDE-FGHIJ",
    "--consent-profile", "metadata",
    "--control-plane-url", origin,
    "--grpc-url", origin,
    "--server-ca-sha256", fingerprint,
    "--accept-consent",
    // These tests are about the address; no service is installed on the test computer.
    "--no-service",
    "--json",
  ], { PHIGON_DATA_DIR: directory, PHIGON_UPDATE_CHECK: "false" }, {
    stdout: (value) => { stdout += value; },
    stderr: (value) => { stderr += value; },
  });
  return { exitCode, stdout, stderr };
}

const sameMachine = (body: Exchange) => ({
  status: 200,
  body: {
    machine: { id: machineID, tenant_id: tenantID, display_name: "Laptop", state: "online" },
    credential: body.existing_credential ?? key("n"),
  },
});

test("a computer follows its server to a new address when the server holds the pinned authority", async () => {
  const pinned = authority("pinned");
  const directory = await pairedComputer(pinned);
  const company = await startServer(serverCertificate(pinned, ["127.0.0.1"]), pinned.certificate, sameMachine);
  try {
    const result = await pair(directory, company.origin, pinned.fingerprint);
    assert.equal(result.exitCode, 0, result.stderr);
    assert.equal(company.requests.length, 1);
    assert.equal(company.requests[0]?.existing_credential, key("k"));

    const stored = await new FileCredentialStore(directory).load();
    assert.equal(stored?.machineId, machineID);
    assert.equal(stored?.credential, key("k"));
    assert.equal(stored?.controlPlaneOrigin, company.origin);
    assert.equal(stored?.grpcOrigin, company.origin);
    // The same machine: its undelivered activity stays where it was.
    assert.ok(existsSync(join(directory, "telemetry-spool.jsonl")));
    assert.ok(!existsSync(join(directory, "retired-pairings")));
    const output = JSON.parse(result.stdout) as Record<string, unknown>;
    assert.equal(output["previousControlPlaneOrigin"], oldOrigin);
    assert.equal(output["replacedMachineId"], undefined);
    assert.ok(!result.stdout.includes(key("k")));
  } finally {
    await stop(company.server);
    await rm(directory, { recursive: true, force: true });
  }
});

test("a background service's saved endpoints follow the server to its new address", async () => {
  const pinned = authority("pinned");
  const directory = await pairedComputer(pinned);
  const company = await startServer(serverCertificate(pinned, ["127.0.0.1"]), pinned.certificate, sameMachine);
  try {
    // Installed while the endpoints were set in the environment.
    await writeServiceSettings(directory, {
      PHIGON_CONTROL_PLANE_URL: `${oldOrigin}/`,
      PHIGON_GRPC_URL: "https://192.0.2.10:17081",
      PHIGON_OBSERVABILITY_PROFILE: "metadata",
    });
    const result = await pair(directory, company.origin, pinned.fingerprint);
    assert.equal(result.exitCode, 0, result.stderr);
    assert.deepEqual(await readServiceSettings(serviceSettingsPath(directory)), {
      PHIGON_CONTROL_PLANE_URL: company.origin,
      PHIGON_GRPC_URL: company.origin,
      PHIGON_OBSERVABILITY_PROFILE: "metadata",
    });
  } finally {
    await stop(company.server);
    await rm(directory, { recursive: true, force: true });
  }
});

test("only saved endpoints that named the earlier address move", async () => {
  const directory = await mkdtemp(join(tmpdir(), "phigon-server-move-"));
  try {
    const moves = {
      PHIGON_CONTROL_PLANE_URL: { from: oldOrigin, to: "https://192.168.1.11:26962" },
      PHIGON_GRPC_URL: { from: "https://192.0.2.10:17081", to: "https://192.168.1.11:26963" },
    };
    assert.equal(await moveServiceEndpoints(directory, moves), false, "no service");
    const settings = { PHIGON_CONTROL_PLANE_URL: "https://198.51.100.7:17080", PHIGON_GRPC_URL: "https://198.51.100.7:17081" };
    await writeServiceSettings(directory, settings);
    assert.equal(await moveServiceEndpoints(directory, moves), false);
    assert.deepEqual(await readServiceSettings(serviceSettingsPath(directory)), settings);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("a pairing that never stored its gRPC address moves the saved one", async () => {
  const pinned = authority("pinned");
  const directory = await pairedComputer(pinned);
  const company = await startServer(serverCertificate(pinned, ["127.0.0.1"]), pinned.certificate, sameMachine);
  try {
    // Paired before the observer stored the gRPC address: the service's
    // setting was where its stream went.
    const store = new FileCredentialStore(directory);
    const stored = Object.entries((await store.load())!).filter(([name]) => name !== "grpcOrigin");
    await store.save(Object.fromEntries(stored) as unknown as StoredMachineCredential);
    await writeServiceSettings(directory, { PHIGON_GRPC_URL: "https://192.0.2.10:17081" });
    const result = await pair(directory, company.origin, pinned.fingerprint);
    assert.equal(result.exitCode, 0, result.stderr);
    assert.equal((await store.load())?.grpcOrigin, company.origin);
    assert.deepEqual(await readServiceSettings(serviceSettingsPath(directory)), { PHIGON_GRPC_URL: company.origin });
  } finally {
    await stop(company.server);
    await rm(directory, { recursive: true, force: true });
  }
});

test("pairing says a running observer restarts only when the pairing changed", async () => {
  const pinned = authority("pinned");
  const directory = await pairedComputer(pinned);
  const company = await startServer(serverCertificate(pinned, ["127.0.0.1"]), pinned.certificate, sameMachine);
  const lock = await InstanceLock.acquire(directory);
  try {
    const moved = await pair(directory, company.origin, pinned.fingerprint);
    assert.equal(moved.exitCode, 0, moved.stderr);
    assert.equal((JSON.parse(moved.stdout) as Record<string, unknown>)["runningObserverRestarts"], true);

    // The same server, address and consent again: only dates change.
    const again = await pair(directory, company.origin, pinned.fingerprint);
    assert.equal(again.exitCode, 0, again.stderr);
    assert.equal((JSON.parse(again.stdout) as Record<string, unknown>)["runningObserverRestarts"], undefined);
  } finally {
    await lock.release();
    await stop(company.server);
    await rm(directory, { recursive: true, force: true });
  }
});

test("a server with another authority gets nothing, and the pinned authority stays", async () => {
  const pinned = authority("pinned");
  const other = authority("other");
  const directory = await pairedComputer(pinned);
  const company = await startServer(serverCertificate(other, ["127.0.0.1"]), other.certificate, sameMachine);
  try {
    const result = await pair(directory, company.origin, other.fingerprint);
    assert.equal(result.exitCode, 1);
    assert.match(result.stderr, /connected to the Phigon server at https:\/\/192\.0\.2\.10:17080.*--server-ca-sha256.*remove-machine/u);
    assert.equal(company.requests.length, 0, "the stored key is never sent");
    assert.equal(await readFile(serverAuthorityPath(directory), "utf8"), pinned.certificate);
    assert.equal((await new FileCredentialStore(directory).load())?.controlPlaneOrigin, oldOrigin);
  } finally {
    await stop(company.server);
    await rm(directory, { recursive: true, force: true });
  }
});

test("only a server holding a certificate from the pinned authority is trusted with the key", async () => {
  const pinned = authority("pinned");
  const impostor = authority("impostor");
  const directory = await pairedComputer(pinned);
  const genuine = await startServer(serverCertificate(pinned, ["127.0.0.1"]), "", sameMachine);
  // Anyone can copy an authority's certificate; only its owner can sign with it.
  const company = await startServer(serverCertificate(impostor, ["127.0.0.1"]), pinned.certificate, sameMachine);
  try {
    await verifyServerAuthority(new URL(genuine.origin), pinned.certificate);
    await assert.rejects(
      verifyServerAuthority(new URL(company.origin), pinned.certificate),
      /could not prove it is the Phigon server this computer is connected to/u,
    );
    await assert.rejects(
      verifyServerAuthority(new URL(genuine.origin.replace("127.0.0.1", "localhost")), pinned.certificate),
      /could not prove/u,
      "a certificate for another name",
    );

    const result = await pair(directory, company.origin, pinned.fingerprint);
    assert.equal(result.exitCode, 1);
    assert.equal(company.requests.length, 0, "the stored key is never sent");
    assert.equal(await readFile(serverAuthorityPath(directory), "utf8"), pinned.certificate);
  } finally {
    await stop(genuine.server);
    await stop(company.server);
    await rm(directory, { recursive: true, force: true });
  }
});

test("a failed first pairing keeps no authority", async () => {
  const first = authority("first");
  const directory = await mkdtemp(join(tmpdir(), "phigon-server-move-"));
  const company = await startServer(serverCertificate(first, ["127.0.0.1"]), first.certificate, () => ({
    status: 400,
    body: { error: { code: "invalid_code", message: "This code expired. Get a new one from Connect machine." } },
  }));
  try {
    const result = await pair(directory, company.origin, first.fingerprint);
    assert.equal(result.exitCode, 1);
    assert.match(result.stderr, /This code expired/u);
    assert.ok(!existsSync(serverAuthorityPath(directory)));
  } finally {
    await stop(company.server);
    await rm(directory, { recursive: true, force: true });
  }
});

test("a first pairing saves the authority the command named", async () => {
  const first = authority("first");
  const directory = await mkdtemp(join(tmpdir(), "phigon-server-move-"));
  const company = await startServer(serverCertificate(first, ["127.0.0.1"]), first.certificate, sameMachine);
  try {
    const result = await pair(directory, company.origin, first.fingerprint);
    assert.equal(result.exitCode, 0, result.stderr);
    const saved = await readFile(serverAuthorityPath(directory), "utf8");
    assert.equal(saved.replace(/\s+/gu, ""), first.certificate.replace(/\s+/gu, ""));
  } finally {
    await stop(company.server);
    await rm(directory, { recursive: true, force: true });
  }
});

test("a server on this computer may move between this computer's own addresses", async () => {
  const directory = await mkdtemp(join(tmpdir(), "phigon-server-move-"));
  try {
    await new FileCredentialStore(directory).save({
      machineId: machineID,
      tenantId: tenantID,
      credential: key("l"),
      controlPlaneOrigin: "http://127.0.0.1:26962",
      createdAt: "2026-11-01T00:00:00.000Z",
    });
    const interfaces = () => ({
      lo: [{ address: "127.0.0.1", family: "IPv4", internal: true } as never],
      wifi: [{ address: "192.168.1.11", family: "IPv4", internal: false } as never],
    });
    const prepared = (url: string) => preparePairingAuthority({
      config: loadConfig({ PHIGON_DATA_DIR: directory, PHIGON_CONTROL_PLANE_URL: url, PHIGON_GRPC_URL: url }),
      interfaces,
    });
    assert.equal((await prepared("https://192.168.1.11:26962")).serverMoved, true);
    assert.equal((await prepared("http://127.0.0.1:26962")).serverMoved, false, "not moved at all");
    assert.equal((await prepared("https://192.168.1.12:26962")).serverMoved, false, "another computer");
    assert.equal((await prepared("https://phigon.example.test")).serverMoved, false);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("only loopback and this computer's own addresses are on this computer", () => {
  const local = new Set(["192.168.1.11", "fe80::1"]);
  for (const url of ["http://127.0.0.1:1", "http://127.8.0.1:1", "http://localhost:1", "http://[::1]:1", "https://192.168.1.11:1", "https://[fe80::1]:1"]) {
    assert.equal(onThisComputer(new URL(url), local), true, url);
  }
  for (const url of ["https://192.168.1.12:1", "https://nikku:1", "https://phigon.example.test", "https://[fe80::2]:1"]) {
    assert.equal(onThisComputer(new URL(url), local), false, url);
  }
});
