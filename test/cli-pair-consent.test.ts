import assert from "node:assert/strict";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { createServer } from "node:http";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Readable } from "node:stream";
import test from "node:test";
import { run } from "../src/cli.js";

// Built at run time, so no key-shaped text is stored.
const key = ["phg", "m", "p".repeat(43)].join("_");

/** A control plane that pairs every code and counts the requests it gets. */
async function setUp() {
  let requests = 0;
  const server = createServer((request, response) => {
    requests++;
    request.resume();
    request.on("end", () => {
      response.writeHead(200, { "Content-Type": "application/json" });
      response.end(JSON.stringify({
        machine: { id: "5f1b4cb4-a77d-4f53-af66-197e184683f4", tenant_id: "7d1b4cb4-a77d-4f53-af66-197e184683f4", display_name: "Laptop", state: "online" },
        credential: key,
      }));
    });
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const origin = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  const root = await mkdtemp(join(tmpdir(), "phigon-pair-consent-"));
  const pair = async (extra: readonly string[], input: readonly string[] = []) => {
    let stdout = "";
    let stderr = "";
    const code = await run(
      ["pair", "--code", "ABCDE-FGHIJ", "--control-plane-url", origin, "--grpc-url", origin, "--consent-profile", "metadata", "--no-service", ...extra],
      { PHIGON_DATA_DIR: root, PHIGON_UPDATE_CHECK: "false" },
      { stdout: (value) => { stdout += value; }, stderr: (value) => { stderr += value; } },
      Readable.from(input),
    );
    return { code, stdout, stderr };
  };
  const stored = async () =>
    (JSON.parse(await readFile(join(root, "machine-credential.json"), "utf8")) as Record<string, unknown>)["remoteActions"];
  const close = async () => {
    await new Promise<void>((resolve) => server.close(() => resolve()));
    await rm(root, { recursive: true, force: true });
  };
  return { pair, stored, close, requests: () => requests };
}

test("an owner who accepts without the prompt lets administrators do nothing unless the owner says so", async () => {
  const setup = await setUp();
  try {
    const scripted = await setup.pair(["--accept-consent"]);
    assert.equal(scripted.code, 0, scripted.stderr);
    assert.match(scripted.stdout, /Your company's Phigon administrators cannot stop agents or run commands on this computer\./u);
    assert.match(scripted.stdout, /To let them stop agents, or also run the commands they approve, pair again with --remote-actions stop-agents or --remote-actions all\./u);
    assert.equal(await setup.stored(), "none");

    // JSON pairing needs --accept-consent, so it too allows nothing by default.
    const json = await setup.pair(["--accept-consent", "--json"]);
    assert.equal(json.code, 0, json.stderr);
    assert.equal((JSON.parse(json.stdout) as Record<string, unknown>)["remoteActions"], "none");

    for (const [choice, consent] of [["all", "all"], ["stop-agents", "stop_agents"], ["none", "none"]] as const) {
      const chosen = await setup.pair(["--accept-consent", "--remote-actions", choice, "--json"]);
      assert.equal(chosen.code, 0, chosen.stderr);
      assert.equal((JSON.parse(chosen.stdout) as Record<string, unknown>)["remoteActions"], consent);
      assert.equal(await setup.stored(), consent);
    }
    const said = await setup.pair(["--accept-consent", "--remote-actions=none"]);
    assert.doesNotMatch(said.stdout, /pair again with --remote-actions/u);
  } finally {
    await setup.close();
  }
});

test("the consent prompt still allows both by default, says so, and says how to allow less", async () => {
  const setup = await setUp();
  try {
    const prompted = await setup.pair([], ["yes\n"]);
    assert.equal(prompted.code, 0, prompted.stderr);
    assert.match(prompted.stdout, /can stop AI agents on this computer and run the commands they approve\./u);
    assert.match(prompted.stdout, /To allow only stopping agents, run pair again with --remote-actions stop-agents; to allow neither, use --remote-actions none\./u);
    assert.equal(await setup.stored(), "all");

    const narrowed = await setup.pair(["--remote-actions", "stop-agents"], ["yes\n"]);
    assert.equal(narrowed.code, 0, narrowed.stderr);
    assert.match(narrowed.stdout, /administrators can stop AI agents on this computer\. You see/u);
    assert.doesNotMatch(narrowed.stdout, /To allow only stopping agents/u);
    assert.equal(await setup.stored(), "stop_agents");
  } finally {
    await setup.close();
  }
});

test("contradictory remote action options stop pairing before anything is sent", async () => {
  const setup = await setUp();
  try {
    for (const extra of [
      ["--remote-actions", "all", "--no-remote-commands", "--accept-consent"],
      ["--remote-actions", "stop-agents", "--no-remote-actions"],
      ["--remote-actions", "some", "--accept-consent"],
    ]) {
      const result = await setup.pair(extra, ["yes\n"]);
      assert.equal(result.code, 2, extra.join(" "));
      assert.match(result.stderr, /^Observer command failed: --remote-actions /u);
      // Refused before the prompt.
      assert.doesNotMatch(result.stdout, /Type "yes"/u);
    }
    assert.equal(setup.requests(), 0);
  } finally {
    await setup.close();
  }
});
