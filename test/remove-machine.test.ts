import assert from "node:assert/strict";
import test from "node:test";
import { loadConfig } from "../src/config.js";
import type { StoredMachineCredential } from "../src/credential-store.js";
import { removeMachine } from "../src/remove-machine.js";

const origin = "https://control.example.test";

function fixture() {
  const config = loadConfig({
    PHIGON_CONTROL_PLANE_URL: origin,
    PHIGON_DATA_DIR: "/tmp/phigon-remove-machine-test",
  });
  const credential: StoredMachineCredential = {
    machineId: "machine-remove-test",
    tenantId: "tenant-remove-test",
    credential: `phg_m_${"r".repeat(43)}`,
    controlPlaneOrigin: origin,
    createdAt: "2026-08-09T00:00:00.000Z",
  };
  return { config, credential };
}

test("machine removal reports completed server removal when local cleanup fails", async () => {
  const { config, credential } = fixture();
  await assert.rejects(
    removeMachine({
      config,
      credential,
      fetcher: async () => new Response(null, { status: 204 }),
      clearCredential: async () => {
        throw new Error("permission denied");
      },
    }),
    /was removed.*local credential cleanup failed.*machine-credential\.json/su,
  );
});

test("machine removal does not print unsafe control-plane error text", async () => {
  const { config, credential } = fixture();
  let cleared = false;
  const operation = removeMachine({
    config,
    credential,
    fetcher: async () => new Response(JSON.stringify({
      error: { message: "\u001b[31mforged terminal message" },
    }), {
      status: 400,
      headers: { "Content-Type": "application/json" },
    }),
    clearCredential: async () => {
      cleared = true;
      return true;
    },
  });
  await assert.rejects(operation, /failed with HTTP 400/u);
  await assert.rejects(operation, (error: unknown) =>
    error instanceof Error && !error.message.includes("\u001b"));
  assert.equal(cleared, false);
});

test("machine removal never sends a credential to a different origin", async () => {
  const { config, credential } = fixture();
  let requested = false;
  await assert.rejects(
    removeMachine({
      config,
      credential: {
        ...credential,
        controlPlaneOrigin: "https://other.example.test",
      },
      fetcher: async () => {
        requested = true;
        return new Response(null, { status: 204 });
      },
      clearCredential: async () => true,
    }),
    /Restore the original PHIGON_CONTROL_PLANE_URL/u,
  );
  assert.equal(requested, false);
});
