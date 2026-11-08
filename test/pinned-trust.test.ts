import assert from "node:assert/strict";
import {
  Server,
  ServerCredentials,
  type ServerDuplexStream,
  type ServiceDefinition,
} from "@grpc/grpc-js";
import { create, fromBinary, toBinary } from "@bufbuild/protobuf";
import { timestampFromDate } from "@bufbuild/protobuf/wkt";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { loadConfig } from "../src/config.js";
import { connectionEnvironment } from "../src/connection-config.js";
import { FileCredentialStore, type StoredMachineCredential } from "../src/credential-store.js";
import {
  AcknowledgementSchema,
  StreamTelemetryRequestSchema,
  StreamTelemetryResponseSchema,
  type StreamTelemetryRequest,
  type StreamTelemetryResponse,
} from "../src/generated/phigon/v1/observer_service_pb.js";
import { CollectionPolicySchema, PolicySnapshotSchema } from "../src/generated/phigon/v1/policy_pb.js";
import {
  pinnedAuthorityMissingMessage,
  relayNeedsAuthorityMessage,
  serverAuthorityPath,
} from "../src/server-authority.js";
import { refuseServerRequests, serverFetch, trustServerAuthority } from "../src/server-fetch.js";
import { preparePairingAuthority } from "../src/server-move.js";
import { ObserverStreamClient, streamTrust } from "../src/stream-client.js";
import { serverCertificate, testAuthority } from "./support/certificates.js";

// Built at run time, so no key-shaped text is stored.
const key = (fill: string) => ["phg", "m", fill.repeat(43)].join("_");
const machineId = "5f1b4cb4-a77d-4f53-af66-197e184683f4";
const tenantId = "7d1b4cb4-a77d-4f53-af66-197e184683f4";
const relayApi = "https://abcdefghabcdefgh.relay.phigon.online";
const relayGrpc = "https://abcdefghabcdefgh-grpc.relay.phigon.online";

function credential(origin: string, grpcOrigin: string, extra: Partial<StoredMachineCredential> = {}): StoredMachineCredential {
  return {
    machineId,
    tenantId,
    credential: key("t"),
    controlPlaneOrigin: origin,
    grpcOrigin,
    createdAt: "2026-11-01T00:00:00.000Z",
    consentProfile: "metadata",
    consentPolicyVersion: "observer-policy-v1",
    consentedAt: "2026-11-01T00:00:00.000Z",
    ...extra,
  };
}

test("an address on Phigon's relay is never trusted under the system's authorities", async () => {
  trustServerAuthority(undefined);
  // Refused before any connection is made: no name lookup, nothing sent.
  await assert.rejects(serverFetch(`${relayApi}/v1/machine/endpoints`), (error: Error) => error.message === relayNeedsAuthorityMessage);
  await assert.rejects(serverFetch(new URL(`${relayApi}./healthz`)), (error: Error) => error.message === relayNeedsAuthorityMessage);

  const directory = await mkdtemp(join(tmpdir(), "phigon-relay-trust-"));
  try {
    const config = loadConfig({ PHIGON_DATA_DIR: directory, PHIGON_CONTROL_PLANE_URL: relayApi, PHIGON_GRPC_URL: relayGrpc });
    // The stream refuses too.
    assert.throws(() => streamTrust(config, {}), (error: Error) => error.message === relayNeedsAuthorityMessage);
    // And pairing there needs the fingerprint, before anything is sent.
    await assert.rejects(preparePairingAuthority({ config }), (error: Error) => error.message === relayNeedsAuthorityMessage);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("a computer whose pinned authority went missing refuses to connect instead of trusting the system", async () => {
  const pinned = testAuthority("Phigon server authority MISSING");
  const directory = await mkdtemp(join(tmpdir(), "phigon-missing-pin-"));
  try {
    const origin = "https://phigon.acme.example:17080";
    await new FileCredentialStore(directory).save(credential(origin, "https://phigon.acme.example:17081", {
      serverAuthoritySha256: pinned.fingerprint,
    }));
    // server-ca.pem is gone, for example after restoring part of a backup.
    await connectionEnvironment({ PHIGON_DATA_DIR: directory });
    await assert.rejects(serverFetch(`${origin}/healthz`), (error: Error) => error.message === pinnedAuthorityMissingMessage);
    const config = loadConfig({ PHIGON_DATA_DIR: directory, PHIGON_CONTROL_PLANE_URL: origin, PHIGON_GRPC_URL: "https://phigon.acme.example:17081" });
    assert.throws(() => streamTrust(config, { serverAuthoritySha256: pinned.fingerprint }), (error: Error) => error.message === pinnedAuthorityMissingMessage);
    // Pairing again without the fingerprint cannot bring it back either.
    await assert.rejects(preparePairingAuthority({ config }), (error: Error) => error.message === pinnedAuthorityMissingMessage);

    // Another authority in its place is refused the same way.
    await writeFile(serverAuthorityPath(directory), testAuthority("Phigon server authority OTHER").certificate);
    await connectionEnvironment({ PHIGON_DATA_DIR: directory });
    await assert.rejects(serverFetch(`${origin}/healthz`), (error: Error) => error.message === pinnedAuthorityMissingMessage);
    assert.throws(() => streamTrust(config, { serverAuthoritySha256: pinned.fingerprint }), (error: Error) => error.message === pinnedAuthorityMissingMessage);

    // With it back, it alone is trusted again.
    await writeFile(serverAuthorityPath(directory), pinned.certificate);
    await connectionEnvironment({ PHIGON_DATA_DIR: directory });
    assert.equal(streamTrust(config, { serverAuthoritySha256: pinned.fingerprint }).roots?.toString("utf8"), pinned.certificate);
  } finally {
    trustServerAuthority(undefined);
    await rm(directory, { recursive: true, force: true });
  }
});

test("a refusal ends when an authority is trusted again", async () => {
  refuseServerRequests("refused for this test");
  await assert.rejects(serverFetch("https://192.0.2.1/healthz"), /refused for this test/u);
  trustServerAuthority(undefined);
  // Plain http:// requests (a server on this computer) never carried a pin.
  refuseServerRequests("refused for this test");
  await assert.rejects(serverFetch("http://127.0.0.1:1/healthz"), (error: Error) => !/refused for this test/u.test(error.message));
  trustServerAuthority(undefined);
});

const observerServiceDefinition: ServiceDefinition = {
  streamTelemetry: {
    path: "/phigon.v1.ObserverService/StreamTelemetry",
    requestStream: true,
    responseStream: true,
    requestSerialize: (value: StreamTelemetryRequest) => Buffer.from(toBinary(StreamTelemetryRequestSchema, value)),
    requestDeserialize: (value: Buffer) => fromBinary(StreamTelemetryRequestSchema, value),
    responseSerialize: (value: StreamTelemetryResponse) => Buffer.from(toBinary(StreamTelemetryResponseSchema, value)),
    responseDeserialize: (value: Buffer) => fromBinary(StreamTelemetryResponseSchema, value),
  },
};

test("PHIGON_TLS_CA_FILE cannot replace the pinned authority for the stream", async () => {
  const directory = await mkdtemp(join(tmpdir(), "phigon-stream-pin-"));
  const pinned = testAuthority("Phigon server authority STREAM");
  // What a proxy that inspects HTTPS re-signs the server's certificate with.
  const inspector = testAuthority("Inspection test authority");
  const server = new Server();
  let streams = 0;
  server.addService(observerServiceDefinition, {
    streamTelemetry(call: ServerDuplexStream<StreamTelemetryRequest, StreamTelemetryResponse>) {
      streams++;
      call.on("data", (request: StreamTelemetryRequest) => {
        if (request.payload.case !== "resume") return;
        call.write(create(StreamTelemetryResponseSchema, { payload: { case: "policy", value: create(PolicySnapshotSchema, {
          tenantId, machineId, revision: 1n, effectiveAt: timestampFromDate(new Date()), collection: create(CollectionPolicySchema, {}),
        }) } }));
        call.write(create(StreamTelemetryResponseSchema, { payload: { case: "acknowledgement", value: create(AcknowledgementSchema, {
          machineId, throughSequence: 0n, receivedAt: timestampFromDate(new Date()),
        }) } }));
      });
      call.on("end", () => call.end());
    },
  });
  const leaf = serverCertificate(inspector, ["127.0.0.1"]);
  const port = await new Promise<number>((resolve, reject) => {
    server.bindAsync(
      "127.0.0.1:0",
      ServerCredentials.createSsl(null, [{ private_key: Buffer.from(leaf.key), cert_chain: Buffer.from(leaf.certificate) }], false),
      (error, bound) => error ? reject(error) : resolve(bound),
    );
  });
  const controller = new AbortController();
  const deadline = setTimeout(() => controller.abort(), 4_000);
  try {
    const origin = `https://127.0.0.1:${port}`;
    await new FileCredentialStore(directory).save(credential(origin, origin, { serverAuthoritySha256: pinned.fingerprint }));
    await writeFile(serverAuthorityPath(directory), pinned.certificate);
    const inspectorFile = join(directory, "inspector.pem");
    await writeFile(inspectorFile, inspector.certificate);
    const environment = await connectionEnvironment({
      PHIGON_DATA_DIR: directory,
      PHIGON_TLS_CA_FILE: inspectorFile,
    });
    const config = loadConfig(environment);
    const trust = streamTrust(config, { serverAuthoritySha256: pinned.fingerprint });
    assert.equal(trust.ignoredCaFile, true);
    assert.equal(trust.roots?.toString("utf8"), await readFile(serverAuthorityPath(directory), "utf8"));

    const messages: string[] = [];
    const client = new ObserverStreamClient({
      config,
      credentialStore: new FileCredentialStore(directory),
      onStatus: (message) => {
        messages.push(message);
        if (message.startsWith("Telemetry disconnected")) controller.abort();
      },
    });
    await client.run(controller.signal);
    assert.equal(streams, 0, "the inspected connection never reached the stream");
    assert.ok(messages.some((message) => message.startsWith("PHIGON_TLS_CA_FILE is not used for this Phigon server")), messages.join("\n"));
    assert.ok(!messages.some((message) => message.startsWith("Telemetry stream connected")), messages.join("\n"));
  } finally {
    clearTimeout(deadline);
    controller.abort();
    trustServerAuthority(undefined);
    server.forceShutdown();
    await rm(directory, { recursive: true, force: true });
  }
});
