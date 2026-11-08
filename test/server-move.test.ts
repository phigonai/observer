import assert from "node:assert/strict";
import { existsSync } from "node:fs";
import { mkdtemp, readFile, rename, rm, writeFile } from "node:fs/promises";
import { createServer, type Server } from "node:https";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { run } from "../src/cli.js";
import { loadConfig } from "../src/config.js";
import { FileCredentialStore, type StoredMachineCredential } from "../src/credential-store.js";
import { loadOrCreatePendingInstallationID, pairingAttempt, promotePendingInstallationID } from "../src/installation.js";
import { InstanceLock } from "../src/instance-lock.js";
import { connectionEnvironment } from "../src/connection-config.js";
import { pairMachine, serverPairingCode } from "../src/pair.js";
import { pinnedAuthorityMissingMessage, serverAuthorityPath, verifyServerAuthority } from "../src/server-authority.js";
import { serverFetch, trustServerAuthority } from "../src/server-fetch.js";
import { streamTrust } from "../src/stream-client.js";
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

type Exchange = Readonly<{ existing_credential?: string; installation_id?: string }>;

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

async function pair(directory: string, origin: string, fingerprint: string, code = "ABCDE-FGHIJ") {
  let stdout = "";
  let stderr = "";
  const exitCode = await run([
    "pair",
    "--code", code,
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

test("a server at the same address with another authority never gets the stored key; the computer pairs as a new machine", async () => {
  const pinned = authority("pinned");
  const other = authority("replacement");
  const directory = await pairedComputer(pinned);
  const newMachine = "6a2c5db5-b88e-4e64-b077-208f295794a5";
  // A new server answers a computer that brings no key with a machine of its own.
  const company = await startServer(serverCertificate(other, ["127.0.0.1"]), other.certificate, (body) => body.existing_credential === undefined
    ? { status: 200, body: { machine: { id: newMachine, tenant_id: tenantID, display_name: "Laptop", state: "online" }, credential: key("n") } }
    : sameMachine(body));
  try {
    // Paired with the server at this very address, under the pinned authority.
    const store = new FileCredentialStore(directory);
    const before = await store.load();
    assert.ok(before);
    await store.save({ ...before, controlPlaneOrigin: company.origin, grpcOrigin: company.origin });

    const result = await pair(directory, company.origin, other.fingerprint);
    assert.equal(result.exitCode, 0, result.stderr);
    assert.equal(company.requests.length, 1);
    assert.equal(company.requests[0]?.existing_credential, undefined, "the stored key is never sent");
    const paired = JSON.parse(result.stdout) as { machineId: string; replacedMachineId?: string; newServerAuthority?: boolean };
    assert.equal(paired.machineId, newMachine);
    assert.equal(paired.replacedMachineId, machineID);
    assert.equal(paired.newServerAuthority, true);
    const stored = await store.load();
    assert.equal(stored?.credential, key("n"));
    assert.equal((await readFile(serverAuthorityPath(directory), "utf8")).replace(/\s+/gu, ""), other.certificate.replace(/\s+/gu, ""));
    // The earlier key and its queue were set aside, not sent.
    assert.ok(existsSync(join(directory, "retired-pairings")));
  } finally {
    await stop(company.server);
    await rm(directory, { recursive: true, force: true });
  }
});

test("a wrong code at a server with another authority leaves the earlier pairing as it was", async () => {
  const pinned = authority("pinned");
  const other = authority("replacement");
  const directory = await pairedComputer(pinned);
  const company = await startServer(serverCertificate(other, ["127.0.0.1"]), other.certificate, () => ({
    status: 400,
    body: { error: { code: "invalid_pairing_code", message: "The pairing code is invalid or has expired." } },
  }));
  try {
    const store = new FileCredentialStore(directory);
    const before = await store.load();
    assert.ok(before);
    await store.save({ ...before, controlPlaneOrigin: company.origin, grpcOrigin: company.origin });
    const installationBefore = "0b7d5f0e-3c1a-4e7b-9a52-6f1d2c3b4a59\n";
    await writeFile(join(directory, "installation-id"), installationBefore);

    const result = await pair(directory, company.origin, other.fingerprint);
    assert.notEqual(result.exitCode, 0);
    assert.equal(company.requests.length, 1);
    assert.equal(company.requests[0]?.existing_credential, undefined, "the stored key is never sent");
    // Nothing moved: the key, its machine, its installation ID and its pin
    // still work with the server they belong to.
    const after = await store.load();
    assert.equal(after?.credential, before.credential);
    assert.equal(after?.machineId, machineID);
    assert.equal(await readFile(join(directory, "installation-id"), "utf8"), installationBefore);
    assert.equal(existsSync(join(directory, "retired-pairings")), false);
    assert.equal(await readFile(serverAuthorityPath(directory), "utf8"), pinned.certificate);
  } finally {
    await stop(company.server);
    await rm(directory, { recursive: true, force: true });
  }
});

test("a retry after a lost answer from a server with another authority uses the same new installation ID", async () => {
  const pinned = authority("pinned");
  const other = authority("replacement");
  const directory = await pairedComputer(pinned);
  const newMachine = "0f3c2b1a-9d8e-4f7a-8b6c-5d4e3f2a1b0c";
  let answered = 0;
  // The first answer is lost on the way back; the server made the machine.
  const company = await startServer(serverCertificate(other, ["127.0.0.1"]), other.certificate, () => ++answered === 1
    ? { status: 503, body: { error: { code: "unavailable", message: "Try again." } } }
    : { status: 200, body: { machine: { id: newMachine, tenant_id: tenantID, display_name: "Laptop", state: "online" }, credential: key("r") } });
  try {
    const store = new FileCredentialStore(directory);
    const before = await store.load();
    assert.ok(before);
    await store.save({ ...before, controlPlaneOrigin: company.origin, grpcOrigin: company.origin });
    await writeFile(join(directory, "installation-id"), "0b7d5f0e-3c1a-4e7b-9a52-6f1d2c3b4a59\n");

    assert.notEqual((await pair(directory, company.origin, other.fingerprint)).exitCode, 0);
    assert.equal((await store.load())?.machineId, machineID, "the earlier pairing stays until one succeeds");
    // Typed differently, the server still reads the same code.
    const retried = await pair(directory, company.origin, other.fingerprint, "abcdefghij");
    assert.equal(retried.exitCode, 0, retried.stderr);

    const sent = company.requests.map((request) => request.installation_id);
    assert.equal(sent.length, 2);
    assert.equal(sent[0], sent[1], "the retry presents the installation ID the code was bound to");
    assert.notEqual(sent[0], "0b7d5f0e-3c1a-4e7b-9a52-6f1d2c3b4a59");
    assert.equal((await readFile(join(directory, "installation-id"), "utf8")).trim(), sent[0]);
    assert.equal(existsSync(join(directory, "installation-id.pending")), false);
    assert.equal((await store.load())?.machineId, newMachine);
  } finally {
    await stop(company.server);
    await rm(directory, { recursive: true, force: true });
  }
});

test("a new code after a lost answer from a server with another authority pairs with a new installation ID", async () => {
  const pinned = authority("pinned");
  const other = authority("replacement");
  const directory = await pairedComputer(pinned);
  const newMachine = "1a2b3c4d-5e6f-4a7b-8c9d-0e1f2a3b4c5d";
  const seen = new Set<string>();
  let answered = 0;
  // The first code made a machine under the ID it was sent with, but its
  // answer was lost; that ID now belongs to that machine.
  const company = await startServer(serverCertificate(other, ["127.0.0.1"]), other.certificate, (body) => {
    answered++;
    const id = body.installation_id ?? "";
    if (answered === 1) {
      seen.add(id);
      return { status: 503, body: { error: { code: "unavailable", message: "Try again." } } };
    }
    return seen.has(id)
      ? { status: 409, body: { error: { code: "installation_exists", message: "This computer is already paired." } } }
      : { status: 200, body: { machine: { id: newMachine, tenant_id: tenantID, display_name: "Laptop", state: "online" }, credential: key("s") } };
  });
  try {
    const store = new FileCredentialStore(directory);
    const before = await store.load();
    assert.ok(before);
    await store.save({ ...before, controlPlaneOrigin: company.origin, grpcOrigin: company.origin });

    assert.notEqual((await pair(directory, company.origin, other.fingerprint, "ABCDE-FGHIJ")).exitCode, 0);
    // The first code expired; the administrator made another.
    const second = await pair(directory, company.origin, other.fingerprint, "KLMNO-PQRST");
    assert.equal(second.exitCode, 0, second.stderr);
    const sent = company.requests.map((request) => request.installation_id);
    assert.equal(sent.length, 2);
    assert.notEqual(sent[0], sent[1], "another code pairs with another installation ID");
    assert.equal((await store.load())?.machineId, newMachine);
    assert.equal((await readFile(join(directory, "installation-id"), "utf8")).trim(), sent[1]);
    // The pending file never holds the code itself.
    assert.equal(existsSync(join(directory, "installation-id.pending")), false);
  } finally {
    await stop(company.server);
    await rm(directory, { recursive: true, force: true });
  }
});

test("a retry after the new installation ID could not be made current gets the machine back", async () => {
  const other = authority("replacement");
  // The earlier pairing was set aside and the server paired the new ID,
  // but making it current failed: no key, no current ID, only the pending one.
  const directory = await mkdtemp(join(tmpdir(), "phigon-server-move-"));
  const pendingID = await loadOrCreatePendingInstallationID(directory, pairingAttempt(serverPairingCode("ABCDE-FGHIJ")));
  const company = await startServer(serverCertificate(other, ["127.0.0.1"]), other.certificate, (body) => body.installation_id === pendingID
    ? { status: 200, body: { machine: { id: machineID, tenant_id: tenantID, display_name: "Laptop", state: "online" }, credential: key("p") } }
    : { status: 409, body: { error: { code: "pairing_used", message: "This pairing code was already used." } } });
  try {
    const result = await pair(directory, company.origin, other.fingerprint, "ABCDE-FGHIJ");
    assert.equal(result.exitCode, 0, result.stderr);
    assert.deepEqual(company.requests.map((request) => request.installation_id), [pendingID]);
    assert.equal((await readFile(join(directory, "installation-id"), "utf8")).trim(), pendingID);
    assert.equal(existsSync(join(directory, "installation-id.pending")), false);
  } finally {
    await stop(company.server);
    await rm(directory, { recursive: true, force: true });
  }
});

test("making the new installation ID current waits out a file Windows briefly holds", { skip: process.platform !== "win32" }, async () => {
  const directory = await mkdtemp(join(tmpdir(), "phigon-pending-promote-"));
  try {
    const pendingID = await loadOrCreatePendingInstallationID(directory, pairingAttempt(serverPairingCode("ABCDE-FGHIJ")));
    let refusals = 2;
    await promotePendingInstallationID(directory, async (from, to) => {
      if (refusals-- > 0) throw Object.assign(new Error("operation not permitted"), { code: "EPERM" });
      await rename(from, to);
    });
    assert.equal((await readFile(join(directory, "installation-id"), "utf8")).trim(), pendingID);
    assert.equal(existsSync(join(directory, "installation-id.pending")), false);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("a pairing with another authority interrupted before the authority is saved refuses to connect", async () => {
  const pinned = authority("pinned");
  const other = authority("replacement");
  const directory = await pairedComputer(pinned);
  const newMachine = "2b3c4d5e-6f7a-4b8c-9d0e-1f2a3b4c5d6e";
  const company = await startServer(serverCertificate(other, ["127.0.0.1"]), other.certificate, () => ({
    status: 200,
    body: { machine: { id: newMachine, tenant_id: tenantID, display_name: "Laptop", state: "online" }, credential: key("i") },
  }));
  try {
    const store = new FileCredentialStore(directory);
    const before = await store.load();
    assert.ok(before);
    await store.save({ ...before, controlPlaneOrigin: company.origin, grpcOrigin: company.origin });
    const config = loadConfig({ PHIGON_DATA_DIR: directory, PHIGON_CONTROL_PLANE_URL: company.origin, PHIGON_GRPC_URL: company.origin });
    const authorityForPairing = await preparePairingAuthority({ config, fingerprint: other.fingerprint });
    assert.equal(authorityForPairing.keyAuthority, other.fingerprint);
    await pairMachine({
      config,
      code: "ABCDE-FGHIJ",
      consentProfile: "metadata",
      storedKeyAllowed: authorityForPairing.storedKeyAllowed,
      serverAuthoritySha256: authorityForPairing.keyAuthority,
    });
    // The process stops here, before commit saves the new authority: the
    // new key is stored with it, and the earlier authority is still saved.
    const stored = await store.load();
    assert.equal(stored?.machineId, newMachine);
    assert.equal(stored?.serverAuthoritySha256, other.fingerprint);
    assert.equal(await readFile(serverAuthorityPath(directory), "utf8"), pinned.certificate);
    await connectionEnvironment({ PHIGON_DATA_DIR: directory });
    await assert.rejects(serverFetch(`${company.origin}/healthz`), (error: Error) => error.message === pinnedAuthorityMissingMessage);
    assert.throws(() => streamTrust(config, stored ?? {}), (error: Error) => error.message === pinnedAuthorityMissingMessage);
    // Finishing the pairing brings everything in line.
    await authorityForPairing.commit();
    await connectionEnvironment({ PHIGON_DATA_DIR: directory });
    assert.equal(streamTrust(config, stored ?? {}).roots?.toString("utf8").replace(/\s+/gu, ""), other.certificate.replace(/\s+/gu, ""));
  } finally {
    trustServerAuthority(undefined);
    await stop(company.server);
    await rm(directory, { recursive: true, force: true });
  }
});

test("the pending installation ID keeps a digest of its code, never the code", async () => {
  const directory = await mkdtemp(join(tmpdir(), "phigon-pending-id-"));
  try {
    const first = await loadOrCreatePendingInstallationID(directory, pairingAttempt(serverPairingCode("ABCDE-FGHIJ")));
    assert.equal(await loadOrCreatePendingInstallationID(directory, pairingAttempt(serverPairingCode("ABCDE-FGHIJ"))), first);
    const text = await readFile(join(directory, "installation-id.pending"), "utf8");
    assert.doesNotMatch(text, /ABCDE|FGHIJ/u);
    assert.notEqual(await loadOrCreatePendingInstallationID(directory, pairingAttempt("KLMNO-PQRST")), first);
    // A damaged file is replaced rather than trusted.
    await writeFile(join(directory, "installation-id.pending"), "not an id\n");
    assert.match(await loadOrCreatePendingInstallationID(directory, pairingAttempt("KLMNO-PQRST")), /^[0-9a-f-]{36}$/u);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("pairing again at the same address with the same authority keeps the machine and its key", async () => {
  const pinned = authority("pinned");
  const directory = await pairedComputer(pinned);
  const company = await startServer(serverCertificate(pinned, ["127.0.0.1"]), pinned.certificate, sameMachine);
  try {
    const store = new FileCredentialStore(directory);
    const before = await store.load();
    assert.ok(before);
    await store.save({ ...before, controlPlaneOrigin: company.origin, grpcOrigin: company.origin });
    const result = await pair(directory, company.origin, pinned.fingerprint);
    assert.equal(result.exitCode, 0, result.stderr);
    assert.equal(company.requests[0]?.existing_credential, key("k"));
    assert.equal((await store.load())?.machineId, machineID);
    assert.equal((await store.load())?.serverAuthoritySha256, pinned.fingerprint);
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
    // The key is stored with the authority it was issued under, so it is
    // never sent under the system's authorities if server-ca.pem goes.
    assert.equal((await new FileCredentialStore(directory).load())?.serverAuthoritySha256, first.fingerprint);
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
