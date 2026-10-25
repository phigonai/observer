import assert from "node:assert/strict";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { connectionEnvironment } from "../src/connection-config.js";
import { FileCredentialStore } from "../src/credential-store.js";
import { loadConfig } from "../src/config.js";

test("a new terminal restores the paired customer's API and telemetry endpoints", async () => {
 const directory = await mkdtemp(join(tmpdir(), "phigon-endpoints-"));
 try {
  await new FileCredentialStore(directory).save({ machineId:"machine", tenantId:"tenant", credential:`phg_m_${"x".repeat(43)}`, controlPlaneOrigin:"https://api.customer.test", grpcOrigin:"https://observer.customer.test", createdAt:new Date().toISOString() });
  const resolved = await connectionEnvironment({ PHIGON_DATA_DIR:directory });
  assert.equal(loadConfig(resolved).grpcUrl.origin, "https://observer.customer.test");
  assert.equal(loadConfig(resolved).controlPlaneUrl.origin, "https://api.customer.test");
  const explicit = await connectionEnvironment({ PHIGON_DATA_DIR:directory }, ["--grpc-url", "https://changed.customer.test"]);
  assert.equal(explicit["PHIGON_GRPC_URL"], "https://changed.customer.test");
  await assert.rejects(connectionEnvironment({ PHIGON_DATA_DIR:directory }, ["--grpc-url"]), /requires/u);
 } finally { await rm(directory, { recursive:true, force:true }); }
});

test("endpoint paths, queries and credentials cannot be silently discarded", () => {
 for (const endpoint of ["https://api.test/path", "https://api.test?token=secret", "https://api.test#fragment", "https://user:secret@api.test"]) {
  assert.throws(() => loadConfig({ PHIGON_CONTROL_PLANE_URL:endpoint }));
 }
});
