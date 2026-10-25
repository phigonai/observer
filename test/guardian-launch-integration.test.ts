import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { createServer } from "node:http";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { create } from "@bufbuild/protobuf";
import test from "node:test";
import { run } from "../src/cli.js";
import { FileCredentialStore } from "../src/credential-store.js";
import { FileActionPolicyStore } from "../src/action-policy.js";
import { ActionGuardrailPolicySchema } from "../src/generated/phigon/v1/policy_pb.js";

for (const scenario of [
  { name: "acknowledged completion", failures: 0, exit: 0 },
  { name: "transient completion outage", failures: 2, exit: 0 },
  { name: "unacknowledged successful execution", failures: 3, exit: 0 },
  { name: "unacknowledged failed execution", failures: 3, exit: 23 },
]) {
test(`CLI preserves the actual execution result: ${scenario.name}`, { timeout: 30_000 }, async () => {
  const directory = await mkdtemp(join(tmpdir(), "guardian-launch-flow-"));
  const marker = join(directory, "started.txt"); const calls: string[] = [];
  let finishAttempts = 0;
  const policyDigest = "a".repeat(64); const token = "b".repeat(64);
  const server = createServer((request, response) => {
    void (async () => {
      calls.push(request.url ?? ""); const chunks: Buffer[] = [];
      for await (const chunk of request) chunks.push(Buffer.from(chunk as Buffer));
      if (request.url?.endsWith("/execution-profile")) {
        response.setHeader("Content-Type", "application/json");
        response.end(JSON.stringify({ sandbox: "", policy_digest: policyDigest })); return;
      }
      const body = JSON.parse(Buffer.concat(chunks).toString("utf8")) as { manifest: string; token?: string };
      const digest = createHash("sha256").update(body.manifest).digest("hex");
      const manifest = JSON.parse(body.manifest) as { executable_digest: string; arguments: string[] };
      assert.equal(manifest.executable_digest.length, 64); assert.ok(manifest.arguments.includes("-e"));
      response.setHeader("Content-Type", "application/json");
      if (request.url?.endsWith("/executions")) {
        response.end(JSON.stringify({ token, manifest_digest: digest, policy_digest: policyDigest, expires_at: new Date(Date.now()+15_000).toISOString() }));
      } else if (request.url?.endsWith("/consume") || request.url?.endsWith("/renew")) {
        assert.equal(body.token, token); await assert.rejects(readFile(marker), { code: "ENOENT" });
        response.end(JSON.stringify({ authorized: true, manifest_digest: digest, policy_digest: policyDigest, lease_seconds: 30 }));
      } else {
        assert.equal(await readFile(marker, "utf8"), "executed");
        finishAttempts++;
        if (finishAttempts <= scenario.failures) { response.statusCode = 503; response.end(JSON.stringify({ error: { message: "Receipt storage unavailable" } })); return; }
        response.end(JSON.stringify({ finished: true }));
      }
    })().catch((error: unknown) => { response.statusCode = 500; response.end(String(error)); });
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  try {
    const address = server.address(); assert.ok(address && typeof address === "object");
    const origin = `http://127.0.0.1:${address.port}`; const machineId = "5f1b4cb4-a77d-4f53-af66-197e184683f4";
    await new FileCredentialStore(directory).save({ machineId, tenantId: "7d1b4cb4-a77d-4f53-af66-197e184683f4", credential: `phg_m_${"m".repeat(43)}`, controlPlaneOrigin: origin, createdAt: new Date().toISOString() });
    await new FileActionPolicyStore(directory).save(machineId, create(ActionGuardrailPolicySchema, { policyDigest, defaultEffect: "allow", rules: [] }));
    let output = "";
    const exit = await run(["guardian", "exec", "--", process.execPath, "-e", `require('node:fs').appendFileSync(${JSON.stringify(marker)},'executed');process.exit(${scenario.exit})`],
      { PHIGON_CONTROL_PLANE_URL: origin, PHIGON_DATA_DIR: directory }, { stdout: (value) => { output+=value; }, stderr: (value) => { output+=value; } });
    assert.equal(exit, scenario.exit, output);
    assert.equal(await readFile(marker, "utf8"), "executed", "completion retries must never execute the workload twice");
    assert.equal(finishAttempts, Math.min(scenario.failures + 1, 3));
    assert.doesNotMatch(output, /action remains blocked/iu);
    if (scenario.failures >= 3) assert.match(output, /command executed.*completion report could not be acknowledged/iu);
    else assert.doesNotMatch(output, /completion report could not be acknowledged/iu);
    assert.deepEqual(calls.filter((url, index) => !url.endsWith("/finish") || index === calls.indexOf(url)), ["/v1/machine/guardian/execution-profile", "/v1/machine/guardian/executions", "/v1/machine/guardian/executions/consume", "/v1/machine/guardian/executions/renew", "/v1/machine/guardian/executions/finish"]);
  } finally { server.closeAllConnections(); await new Promise<void>((resolve) => server.close(() => resolve())); await rm(directory, { recursive: true, force: true }); }
});

}
