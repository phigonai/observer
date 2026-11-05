import assert from "node:assert/strict";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { SERVER_ENDPOINTS_FILE } from "../src/server-authority.js";
import {
  fetchServerEndpoints,
  loadLearnedEndpoints,
  networkAddress,
  privateAddress,
  saveLearnedEndpoints,
} from "../src/server-endpoints.js";

// Built at run time, so no key-shaped text is stored.
const key = ["phg", "m", "e".repeat(43)].join("_");
const authority = "a".repeat(64);
const network = { controlPlaneOrigin: "https://192.168.1.20:17080", grpcOrigin: "https://192.168.1.20:17090" };

const answering = (status: number, body: string): typeof fetch => async () => new Response(body, { status });

test("only a private address with its API and telemetry on one host is a network address", () => {
  assert.deepEqual(networkAddress("https://192.168.1.20:17080/", "https://192.168.1.20:17090"), network);
  for (const address of ["10.0.0.1", "172.16.0.1", "172.31.255.1", "192.168.0.1", "100.64.0.1", "100.127.0.1"]) {
    assert.equal(privateAddress(address), true, address);
  }
  for (const address of ["8.8.8.8", "172.32.0.1", "100.128.0.1", "127.0.0.1", "phigon.lan", "::1"]) {
    assert.equal(privateAddress(address), false, address);
  }
  assert.equal(networkAddress("http://192.168.1.20:17080", "http://192.168.1.20:17090"), undefined);
  assert.equal(networkAddress("https://192.168.1.20:17080", "https://192.168.1.21:17090"), undefined);
  assert.equal(networkAddress("https://203.0.113.5:17080", "https://203.0.113.5:17090"), undefined);
  assert.equal(networkAddress("not a url", "https://192.168.1.20:17090"), undefined);
  assert.equal(networkAddress(undefined, 3), undefined);
});

test("where the server says it answers is read, and anything unknown is no answer", async () => {
  const url = new URL("https://abcdefghabcdefgh.relay.phigon.online");
  const said = JSON.stringify({
    network: { control_plane_url: network.controlPlaneOrigin, grpc_url: network.grpcOrigin },
    relay: { control_plane_url: url.origin, grpc_url: "https://abcdefghabcdefgh-grpc.relay.phigon.online" },
  });
  const requests: RequestInit[] = [];
  assert.deepEqual(await fetchServerEndpoints(url, key, async (input, init) => {
    assert.equal(String(input), `${url.origin}/v1/machine/endpoints`);
    requests.push(init ?? {});
    return new Response(said, { status: 200 });
  }), { network });
  assert.equal(new Headers(requests[0]?.headers).get("authorization"), `Bearer ${key}`);
  assert.equal(requests[0]?.redirect, "error");

  // Not shared on its network: only the relay.
  assert.deepEqual(await fetchServerEndpoints(url, key, answering(200, JSON.stringify({ relay: {} }))), {});
  // A network address it cannot use is left out.
  assert.deepEqual(await fetchServerEndpoints(url, key, answering(200, JSON.stringify({
    network: { control_plane_url: "https://203.0.113.5:17080", grpc_url: "https://203.0.113.5:17090" },
  }))), {});
  // An older server, a failure, or an answer that cannot be read: unknown.
  assert.equal(await fetchServerEndpoints(url, key, answering(404, "{\"error\":{\"code\":\"not_found\"}}")), undefined);
  assert.equal(await fetchServerEndpoints(url, key, answering(500, "")), undefined);
  assert.equal(await fetchServerEndpoints(url, key, answering(200, "not json")), undefined);
  assert.equal(await fetchServerEndpoints(url, key, answering(200, "[]")), undefined);
  assert.equal(await fetchServerEndpoints(url, key, answering(200, JSON.stringify({ padding: "x".repeat(20_000) }))), undefined);
  assert.equal(await fetchServerEndpoints(url, key, async () => { throw new TypeError("fetch failed"); }), undefined);
  assert.equal(await fetchServerEndpoints(url, key, async () => new Response(null, { status: 200 })), undefined);
});

test("what was learned is kept for the pinned authority only, in a file older observers ignore", async () => {
  const directory = await mkdtemp(join(tmpdir(), "phigon-endpoints-"));
  try {
    assert.deepEqual(await loadLearnedEndpoints(directory, authority), {});
    await saveLearnedEndpoints(directory, authority, { network, leftNetworkAt: "2026-11-05T10:00:00.000Z" });
    assert.deepEqual(await loadLearnedEndpoints(directory, authority), { network, leftNetworkAt: "2026-11-05T10:00:00.000Z" });
    const saved = JSON.parse(await readFile(join(directory, SERVER_ENDPOINTS_FILE), "utf8")) as Record<string, unknown>;
    assert.equal(saved["version"], 1);
    assert.equal(saved["authority"], authority);
    // Another server's authority learns nothing from it.
    assert.deepEqual(await loadLearnedEndpoints(directory, "b".repeat(64)), {});

    await writeFile(join(directory, SERVER_ENDPOINTS_FILE), JSON.stringify({
      version: 1, authority, network: { controlPlaneOrigin: "https://8.8.8.8", grpcOrigin: "https://8.8.8.8" }, leftNetworkAt: "never",
    }));
    assert.deepEqual(await loadLearnedEndpoints(directory, authority), {});
    await writeFile(join(directory, SERVER_ENDPOINTS_FILE), "{");
    assert.deepEqual(await loadLearnedEndpoints(directory, authority), {});
    await writeFile(join(directory, SERVER_ENDPOINTS_FILE), JSON.stringify({ version: 2, authority }));
    assert.deepEqual(await loadLearnedEndpoints(directory, authority), {});
    await assert.rejects(saveLearnedEndpoints(join(directory, "missing", "folder"), authority, {}));
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});
