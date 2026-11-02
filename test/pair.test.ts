import assert from "node:assert/strict";
import { createServer } from "node:http";
import {
  mkdtemp,
  readFile,
  readdir,
  rm,
  stat,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { loadConfig } from "../src/config.js";
import { FileCredentialStore } from "../src/credential-store.js";
import { InstanceLock } from "../src/instance-lock.js";
import { pairMachine } from "../src/pair.js";

test("pairMachine exchanges a code and persists only the machine credential", async () => {
  const dataDirectory = await mkdtemp(join(tmpdir(), "phigon-pair-"));
  const expectedCredential =
    "phg_m_0123456789012345678901234567890123456789012";
  const server = createServer((request, response) => {
    let body = "";
    request.setEncoding("utf8");
    request.on("data", (chunk) => {
      body += chunk;
    });
    request.on("end", () => {
      const value: unknown = JSON.parse(body);
      assert.equal(request.method, "POST");
      assert.equal(request.url, "/v1/pairing/exchange");
      assert.ok(typeof value === "object" && value !== null);
      assert.equal(
        "code" in value ? value.code : undefined,
        "ABCDE-FGHIJ",
      );
      assert.deepEqual("consent" in value ? value.consent : undefined, {
        granted: true,
        profile: "metadata",
        policy_version: "observer-policy-v1",
      });
      response.writeHead(201, { "Content-Type": "application/json" });
      response.end(
        JSON.stringify({
          machine: {
            id: "5f1b4cb4-a77d-4f53-af66-197e184683f4",
            tenant_id: "7d1b4cb4-a77d-4f53-af66-197e184683f4",
            display_name: "Test machine",
            state: "online",
          },
          credential: expectedCredential,
        }),
      );
    });
  });
  await new Promise<void>((resolve) => {
    server.listen(0, "127.0.0.1", resolve);
  });

  try {
    const address = server.address();
    assert.ok(address !== null && typeof address === "object");
    const config = loadConfig({
      PHIGON_CONTROL_PLANE_URL: `http://127.0.0.1:${address.port}`,
      PHIGON_DATA_DIR: dataDirectory,
    });
    const result = await pairMachine({
      config,
      code: "ABCDE-FGHIJ",
      displayName: "Test machine",
      consentProfile: "metadata",
    });

    assert.equal(result.machineId, "5f1b4cb4-a77d-4f53-af66-197e184683f4");
    assert.equal("credential" in result, false);
    const stored = await new FileCredentialStore(dataDirectory).load();
    assert.equal(stored?.credential, expectedCredential);
    assert.equal(stored?.machineId, result.machineId);
    assert.equal(stored?.consentProfile, "metadata");
    assert.equal(stored?.consentPolicyVersion, "observer-policy-v1");
    assert.equal(stored?.consentSource, "owner");
    assert.equal(
      stored?.tenantId,
      "7d1b4cb4-a77d-4f53-af66-197e184683f4",
    );

    if (process.platform !== "win32") {
      const file = await stat(
        join(dataDirectory, "machine-credential.json"),
      );
      assert.equal(file.mode & 0o777, 0o600);
      const directory = await stat(dataDirectory);
      assert.equal(directory.mode & 0o777, 0o700);
    }
  } finally {
    await new Promise<void>((resolve, reject) => {
      server.close((error) => {
        if (error) reject(error);
        else resolve();
      });
    });
    await rm(dataDirectory, { recursive: true, force: true });
  }
});

test("pairMachine does not persist rejected pairing attempts", async () => {
  const dataDirectory = await mkdtemp(join(tmpdir(), "phigon-pair-"));
  const server = createServer((_request, response) => {
    response.writeHead(400, { "Content-Type": "application/json" });
    response.end(
      JSON.stringify({
        error: {
          code: "invalid_pairing_code",
          message: "The pairing code is invalid or expired.",
        },
      }),
    );
  });
  await new Promise<void>((resolve) => {
    server.listen(0, "127.0.0.1", resolve);
  });

  try {
    const address = server.address();
    assert.ok(address !== null && typeof address === "object");
    const config = loadConfig({
      PHIGON_CONTROL_PLANE_URL: `http://127.0.0.1:${address.port}`,
      PHIGON_DATA_DIR: dataDirectory,
    });
    await assert.rejects(
      pairMachine({ config, code: "WRONG-CODE0", consentProfile: "metadata" }),
      /invalid or expired/i,
    );
    assert.equal(
      await new FileCredentialStore(dataDirectory).load(),
      null,
    );
  } finally {
    await new Promise<void>((resolve, reject) => {
      server.close((error) => {
        if (error) reject(error);
        else resolve();
      });
    });
    await rm(dataDirectory, { recursive: true, force: true });
  }
});

test("pairMachine reports an actionable control-plane connection failure", async () => {
  const dataDirectory = await mkdtemp(join(tmpdir(), "phigon-pair-"));
  try {
    const config = loadConfig({
      PHIGON_CONTROL_PLANE_URL: "https://api.phigon.online",
      PHIGON_DATA_DIR: dataDirectory,
    });
    await assert.rejects(
      pairMachine({
        config,
        code: "ABCDE-FGHIJ",
        consentProfile: "metadata",
        fetcher: async () => {
          throw new TypeError("fetch failed");
        },
      }),
      /Could not reach https:\/\/api\.phigon\.online\. Check your internet connection and try again\./u,
    );
    assert.equal(
      await new FileCredentialStore(dataDirectory).load(),
      null,
    );
  } finally {
    await rm(dataDirectory, { recursive: true, force: true });
  }
});

test("malformed pairing responses preserve local recovery data and never echo response fragments", async () => {
  const dataDirectory = await mkdtemp(join(tmpdir(), "phigon-pair-malformed-"));
  try {
    const config = loadConfig({ PHIGON_DATA_DIR: dataDirectory });
    await assert.rejects(pairMachine({
      config, code: "ABCDE-FGHIJ", consentProfile: "metadata",
      fetcher: async () => new Response('private-fixture-credential{"broken":'),
    }), (error: unknown) => {
      assert.ok(error instanceof Error);
      assert.doesNotMatch(error.message, /private-fi/);
      assert.match(error.message, /same code.*expires/i);
      return true;
    });
    assert.equal(await new FileCredentialStore(dataDirectory).load(), null);
  } finally {
    await rm(dataDirectory, { recursive: true, force: true });
  }
});

const oldMachine = {
  machineId: "11111111-1111-4111-8111-111111111111",
  tenantId: "7d1b4cb4-a77d-4f53-af66-197e184683f4",
  credential: `phg_m_${"o".repeat(43)}`,
};
const newMachine = {
  id: "22222222-2222-4222-8222-222222222222",
  tenant_id: oldMachine.tenantId,
  display_name: "Re-paired machine",
  state: "online",
};
const newCredential = `phg_m_${"n".repeat(43)}`;

type RecordedRequest = Readonly<{
  path: string;
  body: Record<string, unknown>;
  authorization?: string;
}>;

/** Answers the pairing exchange and the key check like the control plane. */
function fakeControlPlane(options: Readonly<{
  storedKeyAccepted: boolean;
  requests: RecordedRequest[];
}>): typeof fetch {
  return async (input, init) => {
    const url = new URL(input instanceof Request ? input.url : input.toString());
    const body: Record<string, unknown> = typeof init?.body === "string"
      ? JSON.parse(init.body) as Record<string, unknown>
      : {};
    const authorization = new Headers(init?.headers).get("authorization");
    options.requests.push({
      path: url.pathname,
      body,
      ...(authorization === null ? {} : { authorization }),
    });
    const json = (status: number, value: unknown) =>
      new Response(JSON.stringify(value), {
        status,
        headers: { "Content-Type": "application/json" },
      });
    if (url.pathname === "/v1/machine/heartbeat") {
      return options.storedKeyAccepted
        ? json(200, { id: oldMachine.machineId })
        : json(401, {
          error: { code: "invalid_credential", message: "Machine credential is invalid." },
        });
    }
    if ("existing_credential" in body) {
      return json(400, {
        error: { code: "invalid_request", message: "machine credential is invalid" },
      });
    }
    return json(201, { machine: newMachine, credential: newCredential });
  };
}

async function seedEarlierPairing(
  dataDirectory: string,
  origin: string,
): Promise<void> {
  await new FileCredentialStore(dataDirectory).save({
    ...oldMachine,
    controlPlaneOrigin: origin,
    createdAt: "2026-08-09T00:00:00.000Z",
  });
  await writeFile(join(dataDirectory, "telemetry-spool.jsonl"), "{\"old\":true}\n", "utf8");
  await writeFile(join(dataDirectory, "stream-state.json"), "{\"old\":true}\n", "utf8");
}

function repairConfig(dataDirectory: string) {
  return loadConfig({
    PHIGON_CONTROL_PLANE_URL: "https://control.example.test",
    PHIGON_DATA_DIR: dataDirectory,
  });
}

test("pairing again after an administrator removed the machine pairs it as a new machine", async () => {
  const dataDirectory = await mkdtemp(join(tmpdir(), "phigon-pair-removed-"));
  try {
    const config = repairConfig(dataDirectory);
    await seedEarlierPairing(dataDirectory, config.controlPlaneUrl.origin);
    const requests: RecordedRequest[] = [];
    const result = await pairMachine({
      config,
      code: "ABCDE-FGHIJ",
      consentProfile: "metadata",
      fetcher: fakeControlPlane({ storedKeyAccepted: false, requests }),
    });

    assert.deepEqual(requests.map((request) => request.path), [
      "/v1/pairing/exchange",
      "/v1/machine/heartbeat",
      "/v1/pairing/exchange",
    ]);
    assert.equal(requests[0]?.body["existing_credential"], oldMachine.credential);
    assert.equal(requests[1]?.authorization, `Bearer ${oldMachine.credential}`);
    assert.equal("existing_credential" in (requests[2]?.body ?? {}), false);
    // A new installation ID: a server can still hold the old one for the
    // deleted machine.
    assert.notEqual(requests[2]?.body["installation_id"], requests[0]?.body["installation_id"]);
    assert.equal(
      (await readFile(join(dataDirectory, "installation-id"), "utf8")).trim(),
      requests[2]?.body["installation_id"],
    );
    assert.equal(result.machineId, newMachine.id);
    assert.equal(result.replacedMachineId, oldMachine.machineId);

    const stored = await new FileCredentialStore(dataDirectory).load();
    assert.equal(stored?.machineId, newMachine.id);
    assert.equal(stored?.credential, newCredential);
    // The old queue and cursor moved aside with the key that decrypts the queue.
    await assert.rejects(stat(join(dataDirectory, "telemetry-spool.jsonl")), { code: "ENOENT" });
    await assert.rejects(stat(join(dataDirectory, "stream-state.json")), { code: "ENOENT" });
    const retired = await readdir(join(dataDirectory, "retired-pairings"));
    assert.equal(retired.length, 1);
    assert.match(retired[0] ?? "", new RegExp(`-${oldMachine.machineId}-`, "u"));
    const retiredDirectory = join(dataDirectory, "retired-pairings", retired[0] ?? "");
    assert.deepEqual((await readdir(retiredDirectory)).sort(), [
      "installation-id",
      "machine-credential.json",
      "stream-state.json",
      "telemetry-spool.jsonl",
    ]);
    assert.match(
      await readFile(join(retiredDirectory, "machine-credential.json"), "utf8"),
      new RegExp(oldMachine.machineId, "u"),
    );
  } finally {
    await rm(dataDirectory, { recursive: true, force: true });
  }
});

test("a stored key that is still valid elsewhere is never set aside", async () => {
  const dataDirectory = await mkdtemp(join(tmpdir(), "phigon-pair-other-workspace-"));
  try {
    const config = repairConfig(dataDirectory);
    await seedEarlierPairing(dataDirectory, config.controlPlaneUrl.origin);
    const requests: RecordedRequest[] = [];
    await assert.rejects(
      pairMachine({
        config,
        code: "ABCDE-FGHIJ",
        consentProfile: "metadata",
        fetcher: fakeControlPlane({ storedKeyAccepted: true, requests }),
      }),
      /paired with another workspace.*separate data directory/u,
    );
    assert.deepEqual(requests.map((request) => request.path), [
      "/v1/pairing/exchange",
      "/v1/machine/heartbeat",
    ]);
    assert.equal(
      (await new FileCredentialStore(dataDirectory).load())?.machineId,
      oldMachine.machineId,
    );
    assert.equal(
      await readFile(join(dataDirectory, "telemetry-spool.jsonl"), "utf8"),
      "{\"old\":true}\n",
    );
  } finally {
    await rm(dataDirectory, { recursive: true, force: true });
  }
});

test("pairing as a new machine refuses while an observer is running", async () => {
  const dataDirectory = await mkdtemp(join(tmpdir(), "phigon-pair-running-"));
  const lock = await InstanceLock.acquire(dataDirectory);
  try {
    const config = repairConfig(dataDirectory);
    await seedEarlierPairing(dataDirectory, config.controlPlaneUrl.origin);
    const requests: RecordedRequest[] = [];
    await assert.rejects(
      pairMachine({
        config,
        code: "ABCDE-FGHIJ",
        consentProfile: "metadata",
        fetcher: fakeControlPlane({ storedKeyAccepted: false, requests }),
      }),
      /already running/u,
    );
    // Nothing moved, and no new machine was requested.
    assert.equal(
      requests.filter((request) => request.path === "/v1/pairing/exchange").length,
      1,
    );
    assert.equal(
      (await new FileCredentialStore(dataDirectory).load())?.machineId,
      oldMachine.machineId,
    );
    assert.equal(
      await readFile(join(dataDirectory, "telemetry-spool.jsonl"), "utf8"),
      "{\"old\":true}\n",
    );
  } finally {
    await lock.release();
    await rm(dataDirectory, { recursive: true, force: true });
  }
});

test("a retry after a lost response pairs without the key that was set aside", async () => {
  const dataDirectory = await mkdtemp(join(tmpdir(), "phigon-pair-retry-"));
  try {
    const config = repairConfig(dataDirectory);
    await seedEarlierPairing(dataDirectory, config.controlPlaneUrl.origin);
    const requests: RecordedRequest[] = [];
    const controlPlane = fakeControlPlane({ storedKeyAccepted: false, requests });
    await assert.rejects(
      pairMachine({
        config,
        code: "ABCDE-FGHIJ",
        consentProfile: "metadata",
        fetcher: async (input, init) => {
          const response = await controlPlane(input, init);
          return response.status === 201
            ? new Response("{\"machine\":")
            : response;
        },
      }),
      /incomplete or invalid/u,
    );
    assert.equal(await new FileCredentialStore(dataDirectory).load(), null);

    requests.length = 0;
    const result = await pairMachine({
      config,
      code: "ABCDE-FGHIJ",
      consentProfile: "metadata",
      fetcher: controlPlane,
    });
    assert.deepEqual(requests.map((request) => request.path), ["/v1/pairing/exchange"]);
    assert.equal("existing_credential" in (requests[0]?.body ?? {}), false);
    assert.equal(result.machineId, newMachine.id);
  } finally {
    await rm(dataDirectory, { recursive: true, force: true });
  }
});
