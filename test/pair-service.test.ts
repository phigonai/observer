import assert from "node:assert/strict";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Readable } from "node:stream";
import test from "node:test";
import { run } from "../src/cli.js";
import type { CommandResult } from "../src/service.js";

// Built at runtime so secret scanners never see a key-shaped string.
const key = ["phg", "m", "k".repeat(43)].join("_");

type Call = Readonly<{ command: string; args: readonly string[] }>;

/** A control plane that pairs every code, and a fake service manager. */
async function setUp(answer: (call: Call) => Partial<CommandResult> = () => ({})) {
  const server = createServer((request: IncomingMessage, response: ServerResponse) => {
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
  const root = await mkdtemp(join(tmpdir(), "phigon-pair-service-"));
  const calls: Call[] = [];
  const runner = async (command: string, args: readonly string[]): Promise<CommandResult> => {
    const call = { command, args: [...args] };
    calls.push(call);
    return { code: 0, stdout: "", stderr: "", ...answer(call) };
  };
  const pair = async (extra: readonly string[], input: readonly string[] = []) => {
    let stdout = "";
    let stderr = "";
    const code = await run(
      ["pair", "--code", "ABCDE-FGHIJ", "--control-plane-url", origin, "--grpc-url", origin, ...extra],
      { PHIGON_DATA_DIR: join(root, "data"), PHIGON_UPDATE_CHECK: "false", PHIGON_LOG_LEVEL: "warn", PATH: "/usr/bin" },
      { stdout: (value) => { stdout += value; }, stderr: (value) => { stderr += value; } },
      Readable.from(input),
      { serviceRunner: runner, platform: "linux", homeDirectory: root, stopTimeoutMs: 50 },
    );
    return { code, stdout, stderr };
  };
  const close = async () => {
    await new Promise<void>((resolve) => server.close(() => resolve()));
    await rm(root, { recursive: true, force: true });
  };
  return { root, calls, pair, close };
}

test("pairing keeps the observer running in the background, for the profile the owner agreed to", async () => {
  const setup = await setUp();
  try {
    const result = await setup.pair(["--consent-profile", "full"], ["yes\n"]);
    assert.equal(result.code, 0, result.stderr);
    // The owner is told before agreeing.
    assert.match(result.stdout, /keeps running in the background on this computer and starts when you sign in/u);
    // A data directory other than the default one gets its own service name.
    assert.match(result.stdout, /Phigon now runs in the background on this computer \(phigon-observer-[0-9a-f]{8}\)\. You can close this window\./u);
    assert.match(result.stdout, /phigon-observer service uninstall/u);
    assert.ok(setup.calls.some((call) => call.command === "systemctl" && call.args.includes("enable")), JSON.stringify(setup.calls));
    // The service collects what the owner consented to, not the default metadata profile.
    const settings = JSON.parse(await readFile(join(setup.root, "data", "service-settings.json"), "utf8")) as { environment: Record<string, string> };
    assert.equal(settings.environment["PHIGON_OBSERVABILITY_PROFILE"], "full");
    assert.equal(result.stdout.includes(key), false);
  } finally {
    await setup.close();
  }
});

test("a computer that cannot have a background service is still paired and told how to run the observer", async () => {
  const setup = await setUp((call) => call.args.includes("enable") ? { code: 1, stderr: "Failed to connect to bus: No medium found" } : {});
  try {
    const result = await setup.pair(["--consent-profile", "metadata", "--accept-consent"]);
    assert.equal(result.code, 0, result.stderr);
    assert.match(result.stdout, /Machine paired successfully\./u);
    assert.match(result.stdout, /Phigon could not keep running in the background: /u);
    assert.match(result.stdout, /Start collecting with: phigon-observer run --profile metadata, and keep that window open\./u);
  } finally {
    await setup.close();
  }
});

test("--no-service pairs without installing anything, and JSON says what pairing did about the service", async () => {
  const setup = await setUp();
  try {
    const manual = await setup.pair(["--consent-profile", "metadata", "--accept-consent", "--no-service"]);
    assert.equal(manual.code, 0, manual.stderr);
    assert.equal(setup.calls.length, 0);
    assert.doesNotMatch(manual.stdout, /background/u);
    assert.match(manual.stdout, /Start collecting with: phigon-observer run --profile metadata/u);

    const scripted = await setup.pair(["--consent-profile", "metadata", "--accept-consent", "--json"]);
    assert.equal(scripted.code, 0, scripted.stderr);
    const body = JSON.parse(scripted.stdout) as { backgroundService?: { status: string; name?: string } };
    assert.equal(body.backgroundService?.status, "installed");
    assert.match(body.backgroundService?.name ?? "", /^phigon-observer-[0-9a-f]{8}$/u);
  } finally {
    await setup.close();
  }
});

test("pairing again keeps the settings the service was installed with, and changes only the profile", async () => {
  const setup = await setUp();
  try {
    const first = await setup.pair(["--consent-profile", "full", "--accept-consent"]);
    assert.equal(first.code, 0, first.stderr);
    const file = join(setup.root, "data", "service-settings.json");
    const saved = JSON.parse(await readFile(file, "utf8")) as { version: number; environment: Record<string, string> };
    // A setting chosen when the service was installed, which this terminal does not have.
    saved.environment["PHIGON_REMOTE_ACTIONS_ENABLED"] = "true";
    await writeFile(file, JSON.stringify(saved));

    const again = await setup.pair(["--consent-profile", "metadata", "--accept-consent"]);
    assert.equal(again.code, 0, again.stderr);
    assert.doesNotMatch(again.stdout, /An observer you started is still running/u);
    const kept = JSON.parse(await readFile(file, "utf8")) as { environment: Record<string, string> };
    assert.equal(kept.environment["PHIGON_REMOTE_ACTIONS_ENABLED"], "true");
    assert.equal(kept.environment["PHIGON_OBSERVABILITY_PROFILE"], "metadata");
  } finally {
    await setup.close();
  }
});
