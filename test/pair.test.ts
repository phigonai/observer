import assert from "node:assert/strict";
import { createServer } from "node:http";
import { mkdtemp, rm, stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { loadConfig } from "../src/config.js";
import { FileCredentialStore } from "../src/credential-store.js";
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
