import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { mkdtemp, readdir, readFile, rm } from "node:fs/promises";
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Readable } from "node:stream";
import test from "node:test";
import { run } from "../src/cli.js";
import { FileCredentialStore } from "../src/credential-store.js";
import { enrollmentExitCodes } from "../src/enroll.js";

// Enrollment codes are assembled at runtime so secret scanners never see one.
const newCode = () => ["phe", "_", randomBytes(24).toString("base64url")].join("");

type Answer = (body: Record<string, unknown>, response: ServerResponse) => void;

/** A local control plane; returns its URL, the bodies it received and a close. */
async function controlPlane(answer: Answer): Promise<{ url: string; bodies: Array<Record<string, unknown>>; close: () => Promise<void> }> {
  const bodies: Array<Record<string, unknown>> = [];
  const server = createServer((request: IncomingMessage, response: ServerResponse) => {
    let raw = "";
    request.setEncoding("utf8");
    request.on("data", (chunk: string) => { raw += chunk; });
    request.on("end", () => {
      const body = raw === "" ? {} : JSON.parse(raw) as Record<string, unknown>;
      bodies.push({ path: request.url, ...body });
      answer(body, response);
    });
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const { port } = server.address() as AddressInfo;
  return {
    url: `http://127.0.0.1:${port}`,
    bodies,
    close: () => new Promise<void>((resolve, reject) => server.close((error) => error ? reject(error) : resolve())),
  };
}

function reply(response: ServerResponse, status: number, value: unknown): void {
  response.writeHead(status, { "Content-Type": "application/json" });
  response.end(JSON.stringify(value));
}

const enrolledBody = {
  machine: { id: "33333333-3333-4333-8333-333333333333", tenant_id: "7d1b4cb4-a77d-4f53-af66-197e184683f4", display_name: "LAPTOP-042", state: "online" },
  credential: `phg_m_${"q".repeat(43)}`,
  consent: {
    source: "company", profile: "metadata", policy_version: "observer-policy-v1",
    granted_at: "2026-11-02T10:05:00Z", enrollment_code_id: "5f0c8a2e-3b1d-4c55-9a51-0d0e8f6c2b7a",
    enrollment_code_label: "Engineering laptops",
  },
};

async function pair(
  args: readonly string[],
  environment: NodeJS.ProcessEnv,
): Promise<{ exitCode: number; stdout: string; stderr: string }> {
  let stdout = "";
  let stderr = "";
  const exitCode = await run(["pair", ...args], { PHIGON_UPDATE_CHECK: "false", ...environment }, {
    stdout: (value) => { stdout += value; },
    stderr: (value) => { stderr += value; },
  }, Readable.from([]));
  return { exitCode, stdout, stderr };
}

test("pair enrolls with PHIGON_ENROLLMENT_CODE without a prompt and never shows the code", async () => {
  const directory = await mkdtemp(join(tmpdir(), "phigon-cli-enroll-"));
  const server = await controlPlane((_body, response) => reply(response, 201, enrolledBody));
  const code = newCode();
  try {
    const result = await pair(
      ["--control-plane-url", server.url, "--grpc-url", "http://127.0.0.1:9", "--name", "LAPTOP-042", "--json"],
      { PHIGON_DATA_DIR: directory, PHIGON_ENROLLMENT_CODE: `${code}\n` },
    );
    assert.equal(result.exitCode, 0, result.stderr);
    assert.equal(server.bodies.length, 1);
    assert.equal(server.bodies[0]?.["path"], "/v1/machines/enroll");
    assert.equal(server.bodies[0]?.["enrollment_code"], code);
    assert.match(String(server.bodies[0]?.["observer_version"]), /^\d+\.\d+\.\d+/u);
    const output = JSON.parse(result.stdout) as { enrolled: boolean; consent: { source: string; profile: string; enrollmentCodeLabel: string } };
    assert.equal(output.enrolled, true);
    assert.deepEqual(
      [output.consent.source, output.consent.profile, output.consent.enrollmentCodeLabel],
      ["company", "metadata", "Engineering laptops"],
    );
    assert.doesNotMatch(result.stdout, /yes/u);
    for (const text of [result.stdout, result.stderr]) {
      assert.equal(text.includes(code.slice(4)), false);
      assert.equal(text.includes("phg_m_"), false);
    }
    const stored = await new FileCredentialStore(directory).load();
    assert.equal(stored?.consentSource, "company");
    for (const name of await readdir(directory)) {
      assert.equal((await readFile(join(directory, name), "utf8")).includes(code.slice(4)), false, name);
    }
  } finally {
    await server.close();
    await rm(directory, { recursive: true, force: true });
  }
});

test("an enrollment code lets administrators stop agents and run commands, unless the script says less", async () => {
  const directory = await mkdtemp(join(tmpdir(), "phigon-cli-enroll-actions-"));
  const server = await controlPlane((_body, response) => reply(response, 201, enrolledBody));
  const endpoints = ["--control-plane-url", server.url, "--grpc-url", "http://127.0.0.1:9"];
  try {
    // The company's policy is the consent: the default stays all, and the result says so.
    const company = await pair(endpoints, { PHIGON_DATA_DIR: directory, PHIGON_ENROLLMENT_CODE: newCode() });
    assert.equal(company.exitCode, 0, company.stderr);
    assert.match(company.stdout, /Your company's Phigon administrators can stop AI agents on this computer and run the commands they approve\. You see a notification each time\./u);
    assert.equal((await new FileCredentialStore(directory).load())?.remoteActions, "all");

    for (const [flags, consent] of [
      [["--remote-actions", "stop-agents"], "stop_agents"],
      [["--remote-actions=none"], "none"],
      [["--no-remote-commands"], "stop_agents"],
    ] as const) {
      const narrowed = await pair([...endpoints, ...flags, "--json"], { PHIGON_DATA_DIR: directory, PHIGON_ENROLLMENT_CODE: newCode() });
      assert.equal(narrowed.exitCode, 0, narrowed.stderr);
      assert.equal((JSON.parse(narrowed.stdout) as { remoteActions: string }).remoteActions, consent);
      assert.equal((await new FileCredentialStore(directory).load())?.remoteActions, consent);
    }

    const sent = server.bodies.length;
    const contradiction = await pair([...endpoints, "--remote-actions", "all", "--no-remote-actions"], { PHIGON_DATA_DIR: directory, PHIGON_ENROLLMENT_CODE: newCode() });
    assert.equal(contradiction.exitCode, 2);
    assert.match(contradiction.stderr, /--remote-actions all contradicts --no-remote-actions\./u);
    assert.equal(server.bodies.length, sent);
  } finally {
    await server.close();
    await rm(directory, { recursive: true, force: true });
  }
});

test("pair --enrollment-code prints what the company consented to, in plain words", async () => {
  const directory = await mkdtemp(join(tmpdir(), "phigon-cli-enroll-text-"));
  const server = await controlPlane((_body, response) => reply(response, 201, enrolledBody));
  try {
    const result = await pair(
      ["--enrollment-code", newCode(), "--control-plane-url", server.url, "--grpc-url", "http://127.0.0.1:9"],
      { PHIGON_DATA_DIR: directory, PHIGON_OBSERVABILITY_PROFILE: "full" },
    );
    assert.equal(result.exitCode, 0, result.stderr);
    assert.match(result.stdout, /^Computer enrolled\./u);
    assert.match(result.stdout, /Consent: given by your company with the enrollment code "Engineering laptops", metadata profile/u);
    assert.match(result.stdout, /Next step: phigon-observer service install/u);
    // The company chose metadata, so a full local profile would not start.
    assert.match(result.stderr, /covers the metadata profile only.*PHIGON_OBSERVABILITY_PROFILE=full/u);
  } finally {
    await server.close();
    await rm(directory, { recursive: true, force: true });
  }
});

test("a refused enrollment exits with its own code and a JSON error, never the code", async () => {
  const directory = await mkdtemp(join(tmpdir(), "phigon-cli-enroll-refused-"));
  const server = await controlPlane((_body, response) => reply(response, 410, {
    error: { code: "enrollment_code_expired", message: "This enrollment code has expired. Ask your administrator for a new one." },
  }));
  const code = newCode();
  try {
    const result = await pair(
      ["--control-plane-url", server.url, "--grpc-url", "http://127.0.0.1:9", "--json"],
      { PHIGON_DATA_DIR: directory, PHIGON_ENROLLMENT_CODE: code },
    );
    assert.equal(result.exitCode, enrollmentExitCodes.newCodeNeeded);
    assert.match(result.stderr, /Observer command failed: This enrollment code has expired\. Ask your administrator for a new one\./u);
    assert.deepEqual(JSON.parse(result.stdout), {
      enrolled: false,
      error: { code: "enrollment_code_expired", message: "This enrollment code has expired. Ask your administrator for a new one." },
      exitCode: enrollmentExitCodes.newCodeNeeded,
    });
    assert.equal(`${result.stdout}${result.stderr}`.includes(code.slice(4)), false);
    assert.equal(await new FileCredentialStore(directory).load(), null);
  } finally {
    await server.close();
    await rm(directory, { recursive: true, force: true });
  }
});

test("an enrollment code cannot be mixed with an owner's pairing options, and a bad one sends nothing", async () => {
  const directory = await mkdtemp(join(tmpdir(), "phigon-cli-enroll-usage-"));
  const server = await controlPlane((_body, response) => reply(response, 500, {}));
  const code = newCode();
  const endpoints = ["--control-plane-url", server.url, "--grpc-url", "http://127.0.0.1:9"];
  try {
    for (const [args, environment, exitCode, pattern] of [
      [["--consent-profile", "full", "--accept-consent"], { PHIGON_ENROLLMENT_CODE: code }, 1, /Remove --consent-profile and --accept-consent/u],
      [["--code", "ABCDE-FGHIJ"], { PHIGON_ENROLLMENT_CODE: code }, 1, /either --code .* not both/u],
      [["--enrollment-code", "--json"], {}, 2, /--enrollment-code needs the code.*PHIGON_ENROLLMENT_CODE/u],
      [["--enrollment-code="], {}, 2, /--enrollment-code needs the code/u],
      [["--enrollment-code", "ABCDE-FGHIJ"], {}, enrollmentExitCodes.invalidCode, /start with phe_/u],
      [[], { PHIGON_ENROLLMENT_CODE: code.slice(0, 12) }, enrollmentExitCodes.invalidCode, /copied in full/u],
    ] as const) {
      const result = await pair([...endpoints, ...args], { PHIGON_DATA_DIR: directory, ...environment });
      assert.equal(result.exitCode, exitCode, result.stderr);
      assert.match(result.stderr, pattern);
      assert.equal(result.stderr.includes(code.slice(4, 16)), false);
    }
    // A blank variable is no code: pair asks for a pairing code as before.
    const blank = await pair(endpoints, { PHIGON_DATA_DIR: directory, PHIGON_ENROLLMENT_CODE: "  " });
    assert.equal(blank.exitCode, 1);
    assert.match(blank.stderr, /pair requires --code/u);
    assert.equal(server.bodies.length, 0);
  } finally {
    await server.close();
    await rm(directory, { recursive: true, force: true });
  }
});
