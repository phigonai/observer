import { randomBytes, timingSafeEqual } from "node:crypto";
import { createServer } from "node:http";
import { once } from "node:events";

export async function startGuardianModelBridge(options: Readonly<{
  controlPlaneURL: URL; credential: string; agentId: string; provider: string;
  fetcher?: typeof fetch;
  maxConcurrentRequests?: number;
}>): Promise<Readonly<{ baseURL: string; token: string; close: () => Promise<void> }>> {
  const token = randomBytes(32).toString("hex");
  const maximum = options.maxConcurrentRequests ?? 8;
  if (!Number.isInteger(maximum) || maximum < 1 || maximum > 64) throw new Error("Invalid model bridge concurrency limit.");
  const requests = new Set<AbortController>();
  const server = createServer({ connectionsCheckingInterval: 1_000 }, (request, response) => {
    void (async () => {
      const presented = request.headers.authorization?.replace(/^Bearer /u, "") ?? request.headers["x-api-key"];
      const supplied = typeof presented === "string" ? Buffer.from(presented) : Buffer.alloc(0);
      if (request.method !== "POST" || request.headers.origin !== undefined || supplied.length !== token.length || !timingSafeEqual(supplied, Buffer.from(token)) ||
          // Clients such as Anthropic's send query strings (/v1/messages?beta=true).
          !["/v1/chat/completions", "/v1/responses", "/v1/embeddings", "/v1/messages"].includes((request.url ?? "").split("?")[0]!)) {
        response.writeHead(403, { Connection: "close" }); response.end("Phigon Guardian: model gateway access denied."); return;
      }
      // Admission starts before body buffering. Slow uploads consume a slot too.
      if (requests.size >= maximum) {
        response.writeHead(429, { "Content-Type": "application/json", "Retry-After": "1", Connection: "close" });
        response.end(JSON.stringify({ error: { code: "phigon_guardian_capacity", message: "Phigon Guardian model bridge is busy. Try again shortly." } }));
        return;
      }
      const controller = new AbortController(); requests.add(controller);
      response.once("close", () => controller.abort());
      try {
        const chunks: Buffer[] = []; let size = 0;
        for await (const chunk of request) {
          const data = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk as string);
          size += data.length;
          if (size > 1 << 20) { response.writeHead(413, { Connection: "close" }); response.end(); return; }
          chunks.push(data);
        }
        if (controller.signal.aborted) return;
        const upstream = await (options.fetcher ?? fetch)(new URL(`/v1/machine/guardian/models/${options.provider}${request.url}`, options.controlPlaneURL), {
          method: "POST", redirect: "error", headers: { Authorization: `Bearer ${options.credential}`, "Content-Type": "application/json", "X-Phigon-Agent-ID": options.agentId },
          body: Buffer.concat(chunks), signal: AbortSignal.any([controller.signal, AbortSignal.timeout(370_000)]),
        });
        response.writeHead(upstream.status, { "Content-Type": upstream.headers.get("content-type") ?? "application/json", "Cache-Control": "no-store" });
        if (upstream.body) for await (const chunk of upstream.body) {
          if (!response.write(chunk)) await once(response, "drain", { signal: controller.signal });
        }
        response.end();
      } finally { requests.delete(controller); controller.abort(); }
    })().catch(() => {
      if (response.headersSent) { response.destroy(); return; }
      response.writeHead(503, { "Content-Type": "application/json", Connection: "close" });
      response.end(JSON.stringify({ error: { code: "phigon_guardian_unavailable", message: "Phigon Guardian blocked the model request because enforcement is unavailable." } }));
    });
  });
  server.requestTimeout = 15_000; server.headersTimeout = 10_000;
  server.maxConnections = maximum * 4;
  let closing: Promise<void> | undefined;
  await new Promise<void>((resolve, reject) => { server.once("error", reject); server.listen(0, "127.0.0.1", resolve); });
  const address = server.address(); if (address === null || typeof address === "string") throw new Error("Guardian model bridge did not bind.");
  return { baseURL: `http://127.0.0.1:${address.port}/v1`, token, close: () => {
    if (closing) return closing;
    for (const controller of requests) controller.abort();
    server.closeAllConnections(); closing = new Promise<void>((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
    return closing;
  } };
}
