import { GuardianDecisionUnavailableError } from "./agentic-guardian.js";

export class GuardianHostedClient {
  constructor(private readonly options: Readonly<{ controlPlaneURL: URL; credential: string; fetcher?: typeof fetch }>) {}

  async post(path: string, body: unknown, signal?: AbortSignal, timeoutMs = 370_000): Promise<Record<string, unknown>> {
    try {
      const timeout = AbortSignal.timeout(timeoutMs);
      const response = await (this.options.fetcher ?? fetch)(new URL(path, this.options.controlPlaneURL), {
        method: "POST", redirect: "error", headers: { Authorization: `Bearer ${this.options.credential}`, "Content-Type": "application/json" },
        body: JSON.stringify(body), signal: signal === undefined ? timeout : AbortSignal.any([timeout, signal]),
      });
      const reader = response.body?.getReader();
      if (!reader) throw new Error("Missing response.");
      const chunks: Uint8Array[] = []; let size = 0;
      try { while (true) { const chunk = await reader.read(); if (chunk.done) break; size += chunk.value.byteLength;
        if (size > 64 << 10) throw new Error("Oversized response."); chunks.push(chunk.value);
      } } finally { await reader.cancel(); }
      if (!response.ok) throw new Error(`Service returned ${response.status}.`);
      const value: unknown = JSON.parse(Buffer.concat(chunks).toString("utf8"));
      if (value === null || typeof value !== "object" || Array.isArray(value)) throw new Error("Invalid response.");
      return value as Record<string, unknown>;
    } catch {
      throw new GuardianDecisionUnavailableError("Phigon Guardian could not verify hosted enforcement; the action remains blocked.");
    }
  }
}
