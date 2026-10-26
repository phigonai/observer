import assert from "node:assert/strict";
import test from "node:test";
import { request } from "node:http";
import { startGuardianModelBridge } from "../src/guardian-model-bridge.js";

test("local model bridge authenticates each request and hides the machine credential", async () => {
  let calls = 0;
  const bridge = await startGuardianModelBridge({ controlPlaneURL: new URL("https://guardian.example"), credential: "machine-secret", agentId: "agent:test", provider: "example",
    fetcher: (async (url, init) => {
      calls++; assert.equal(String(url), "https://guardian.example/v1/machine/guardian/models/example/v1/responses");
      assert.equal(new Headers(init?.headers).get("Authorization"), "Bearer machine-secret");
      assert.equal(init?.redirect, "error");
      return new Response('data: {"ok":true}\n\n', { headers: { "Content-Type": "text/event-stream" } });
    }) as typeof fetch });
  try {
    const denied = await fetch(`${bridge.baseURL}/responses`, { method: "POST", body: '{}' });
    assert.equal(denied.status, 403); assert.equal(calls, 0);
    const allowed = await fetch(`${bridge.baseURL}/responses`, { method: "POST", headers: { Authorization: `Bearer ${bridge.token}` }, body: '{"model":"basic"}' });
    assert.equal(allowed.status, 200); assert.match(await allowed.text(), /ok/u); assert.equal(calls, 1);
    const browser = await fetch(`${bridge.baseURL}/responses`, { method: "POST", headers: { Authorization: `Bearer ${bridge.token}`, Origin: "https://attacker.example" }, body: '{}' });
    assert.equal(browser.status, 403); assert.equal(calls, 1);
  } finally { await bridge.close(); }
});

test("bridge admission covers incomplete uploads and releases capacity after completion", async () => {
  let calls = 0;
  const bridge = await startGuardianModelBridge({ controlPlaneURL: new URL("https://guardian.example"), credential: "secret", agentId: "test", provider: "example", maxConcurrentRequests: 1,
    fetcher: (async () => { calls++; return new Response("{}"); }) as typeof fetch });
  const upload = request(`${bridge.baseURL}/responses`, { method: "POST", headers: { Authorization: `Bearer ${bridge.token}`, Expect: "100-continue", "Transfer-Encoding": "chunked" } });
  upload.on("error", () => { /* a failed assertion may close this test upload */ });
  try {
    const ready = new Promise<void>((resolve, reject) => { upload.once("continue", resolve); upload.once("error", reject); });
    const completed = new Promise<number | undefined>((resolve, reject) => { upload.once("response", (response) => { response.resume(); response.once("end", () => resolve(response.statusCode)); }); upload.once("error", reject); });
    upload.flushHeaders(); await ready; upload.write("{");
    const blocked = await fetch(`${bridge.baseURL}/responses`, { method: "POST", headers: { Authorization: `Bearer ${bridge.token}` }, body: "{}" });
    assert.equal(blocked.status, 429);
    assert.equal(blocked.headers.get("retry-after"), "1");
    await blocked.text(); assert.equal(calls, 0, "incomplete requests must reserve capacity before contacting the server");
    upload.end("}"); assert.equal(await completed, 200);
    const recovered = await fetch(`${bridge.baseURL}/responses`, { method: "POST", headers: { Authorization: `Bearer ${bridge.token}` }, body: "{}" });
    assert.equal(recovered.status, 200); await recovered.text(); assert.equal(calls, 2);
  } finally { upload.destroy(); await bridge.close(); await bridge.close(); }
});

test("bridge recovers capacity after upstream failure and aborts broken response streams", async () => {
  let calls = 0;
  const bridge = await startGuardianModelBridge({ controlPlaneURL: new URL("https://guardian.example"), credential: "secret", agentId: "test", provider: "example", maxConcurrentRequests: 1,
    fetcher: (async () => {
      if (++calls === 1) throw new Error("test upstream failure");
      if (calls === 2) return new Response(new ReadableStream<Uint8Array>({ start(controller) {
        controller.enqueue(new TextEncoder().encode("partial response"));
        setTimeout(() => controller.error(new Error("test truncated stream")), 50);
      } }));
      return new Response("recovered");
    }) as typeof fetch });
  const options = { method: "POST", headers: { Authorization: `Bearer ${bridge.token}` }, body: "{}" };
  try {
    const failed = await fetch(`${bridge.baseURL}/responses`, options); assert.equal(failed.status, 503); await failed.text();
    await assert.rejects(async () => { const broken = await fetch(`${bridge.baseURL}/responses`, options); await broken.text(); });
    const recovered = await fetch(`${bridge.baseURL}/responses`, options); assert.equal(recovered.status, 200); assert.equal(await recovered.text(), "recovered");
  } finally { await bridge.close(); }
});

test("bridge accepts allowed endpoints with a query string and forwards it", async () => {
  let forwarded = "";
  const bridge = await startGuardianModelBridge({ controlPlaneURL: new URL("https://guardian.example"), credential: "secret", agentId: "test", provider: "example",
    fetcher: (async (url) => { forwarded = String(url); return new Response("{}"); }) as typeof fetch });
  try {
    const messages = bridge.baseURL.replace(/\/v1$/u, "");
    const allowed = await fetch(`${messages}/v1/messages?beta=true`, { method: "POST", headers: { "x-api-key": bridge.token }, body: "{}" });
    assert.equal(allowed.status, 200); await allowed.text();
    assert.equal(forwarded, "https://guardian.example/v1/machine/guardian/models/example/v1/messages?beta=true");
    const other = await fetch(`${messages}/v1/models?x=1`, { method: "POST", headers: { "x-api-key": bridge.token }, body: "{}" });
    assert.equal(other.status, 403); await other.text();
  } finally { await bridge.close(); }
});
