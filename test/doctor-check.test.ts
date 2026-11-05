import assert from "node:assert/strict";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { createServer as createHttpServer } from "node:http";
import { createServer as createHttpsServer } from "node:https";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { run } from "../src/cli.js";
import { loadConfig } from "../src/config.js";
import { FileCredentialStore, type StoredMachineCredential } from "../src/credential-store.js";
import {
  doctorCheckExitCodes,
  formatDoctorCheck,
  runDoctorCheck,
  type DoctorCheckReport,
} from "../src/doctor-check.js";
import { InstanceLock } from "../src/instance-lock.js";
import { serverAuthorityPath } from "../src/server-authority.js";
import { trustServerAuthority } from "../src/server-fetch.js";
import { StreamStateStore } from "../src/stream-state.js";
import { serverCertificate, testAuthority } from "./support/certificates.js";

const origin = "https://control.example.test";
const credential = `phg_m_${"d".repeat(43)}`;

function paired(overrides: Partial<StoredMachineCredential> = {}): StoredMachineCredential {
  return {
    machineId: "machine-doctor",
    tenantId: "tenant-doctor",
    credential,
    controlPlaneOrigin: origin,
    createdAt: "2026-11-01T00:00:00.000Z",
    consentProfile: "metadata",
    consentPolicyVersion: "observer-policy-v1",
    consentedAt: "2026-11-01T00:00:00.000Z",
    ...overrides,
  };
}

const healthy: typeof fetch = async () => new Response("{\"status\":\"ok\"}", { status: 200 });

async function check(
  directory: string,
  options: Readonly<{ running?: boolean; fetcher?: typeof fetch; now?: Date; maxAge?: number }> = {},
): Promise<DoctorCheckReport> {
  return await runDoctorCheck({
    config: loadConfig({ PHIGON_CONTROL_PLANE_URL: origin, PHIGON_DATA_DIR: directory }),
    observerVersion: "9.9.9",
    fetcher: options.fetcher ?? healthy,
    inspectLock: async () => options.running === false ? { running: false } : { running: true, pid: 4242 },
    ...(options.now === undefined ? {} : { now: () => options.now! }),
    ...(options.maxAge === undefined ? {} : { maxDeliveryAgeMinutes: options.maxAge }),
  });
}

function statuses(report: DoctorCheckReport): string {
  return report.checks.map((item) => `${item.name}:${item.status}`).join(" ");
}

test("each problem has its own exit code, and the first one decides", async () => {
  const directory = await mkdtemp(join(tmpdir(), "phigon-doctor-check-"));
  try {
    const unpaired = await check(directory, { running: false });
    assert.equal(unpaired.exitCode, doctorCheckExitCodes.notPaired);
    assert.equal(unpaired.ok, false);
    assert.equal(statuses(unpaired), "paired:fail consent:skip running:fail delivery:skip control_plane:pass");

    const store = new FileCredentialStore(directory);
    await store.save({
      machineId: "machine-doctor",
      tenantId: "tenant-doctor",
      credential,
      controlPlaneOrigin: origin,
      createdAt: "2026-11-01T00:00:00.000Z",
    });
    const noConsent = await check(directory);
    assert.equal(noConsent.exitCode, doctorCheckExitCodes.consentMissing);
    assert.match(noConsent.checks[1]?.detail ?? "", /consent is missing or out of date/u);

    await store.save(paired());
    const stopped = await check(directory, { running: false });
    assert.equal(stopped.exitCode, doctorCheckExitCodes.notRunning);
    assert.match(stopped.checks[2]?.detail ?? "", /service install/u);

    const neverDelivered = await check(directory);
    assert.equal(neverDelivered.exitCode, doctorCheckExitCodes.deliveryStale);
    assert.match(neverDelivered.checks[3]?.detail ?? "", /not confirmed any delivery/u);

    await new StreamStateStore(directory).save("machine-doctor", 12n);
    const later = new Date(Date.now() + 40 * 60_000);
    const stale = await check(directory, { now: later });
    assert.equal(stale.exitCode, doctorCheckExitCodes.deliveryStale);
    assert.match(stale.checks[3]?.detail ?? "", /for 4\d minutes/u);
    assert.equal((await check(directory, { now: later, maxAge: 60 })).exitCode, doctorCheckExitCodes.ok);

    const down = await check(directory, { fetcher: async () => { throw Object.assign(new TypeError("fetch failed"), { cause: Object.assign(new Error("x"), { code: "ECONNREFUSED" }) }); } });
    assert.equal(down.exitCode, doctorCheckExitCodes.controlPlaneUnreachable);
    assert.match(down.checks[4]?.detail ?? "", /\(ECONNREFUSED\)/u);
    const failing = await check(directory, { fetcher: async () => new Response("", { status: 503 }) });
    assert.match(failing.checks[4]?.detail ?? "", /answered HTTP 503/u);
    const slow = await runDoctorCheck({
      config: loadConfig({ PHIGON_CONTROL_PLANE_URL: origin, PHIGON_DATA_DIR: directory }),
      observerVersion: "9.9.9",
      inspectLock: async () => ({ running: true }),
      probeTimeoutMs: 50,
      fetcher: async (_url, init) => await new Promise<Response>((_resolve, reject) => {
        init?.signal?.addEventListener("abort", () => reject(init.signal?.reason), { once: true });
      }),
    });
    assert.match(slow.checks[4]?.detail ?? "", /no answer within 0 seconds/u);

    const good = await check(directory);
    assert.equal(good.exitCode, 0);
    assert.equal(good.ok, true);
    assert.equal(statuses(good), "paired:pass consent:pass running:pass delivery:pass control_plane:pass");
    assert.match(formatDoctorCheck(good), /^Phigon observer check passed\.\nok +Pairing/u);
    assert.match(formatDoctorCheck(stopped), /found a problem \(exit code 5\)[\s\S]*FAIL {2}Observer/u);
    // Nothing secret is reported.
    for (const report of [unpaired, noConsent, stopped, stale, down, good]) {
      assert.doesNotMatch(JSON.stringify(report), new RegExp(credential, "u"));
    }

    await store.save(paired({ controlPlaneOrigin: "https://other.example.test" }));
    const elsewhere = await check(directory);
    assert.equal(elsewhere.exitCode, doctorCheckExitCodes.notPaired);
    assert.match(elsewhere.checks[0]?.detail ?? "", /paired with https:\/\/other\.example\.test/u);

    await writeFile(join(directory, "machine-credential.json"), "{not json");
    const unreadable = await check(directory);
    assert.equal(unreadable.exitCode, doctorCheckExitCodes.notPaired);
    assert.match(unreadable.checks[0]?.detail ?? "", /unreadable/u);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("doctor --check probes /healthz and reads the real instance lock", async () => {
  const directory = await mkdtemp(join(tmpdir(), "phigon-doctor-cli-"));
  const requests: string[] = [];
  const server = createHttpServer((request, response) => {
    requests.push(`${request.method} ${request.url}`);
    response.writeHead(200, { "content-type": "application/json" });
    response.end("{\"status\":\"ok\"}");
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const local = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  const environment = { PHIGON_DATA_DIR: directory, PHIGON_CONTROL_PLANE_URL: local, PHIGON_GRPC_URL: local };
  try {
    await new FileCredentialStore(directory).save(paired({ controlPlaneOrigin: local }));
    await new StreamStateStore(directory).save("machine-doctor", 3n);
    let stdout = "";
    const stopped = await run(["doctor", "--check", "--json"], environment, {
      stdout: (value) => { stdout += value; },
      stderr: () => undefined,
    });
    assert.equal(stopped, doctorCheckExitCodes.notRunning);
    const report = JSON.parse(stdout) as DoctorCheckReport;
    assert.equal(report.exitCode, stopped);
    assert.equal(report.checks.find((item) => item.name === "running")?.status, "fail");
    assert.deepEqual(requests, ["GET /healthz"]);

    const lock = await InstanceLock.acquire(directory);
    try {
      let text = "";
      const passing = await run(["doctor", "--check"], environment, {
        stdout: (value) => { text += value; },
        stderr: () => undefined,
      });
      assert.equal(passing, 0);
      assert.match(text, /^Phigon observer check passed\./u);
      assert.doesNotMatch(text, new RegExp(credential, "u"));
    } finally {
      await lock.release();
    }

    // Plain doctor keeps succeeding, even when collection is stopped.
    assert.equal(await run(["doctor"], environment, { stdout: () => undefined, stderr: () => undefined }), 0);

    let stderr = "";
    const invalid = await run(["doctor", "--check", "--max-delivery-age", "0"], environment, {
      stdout: () => undefined,
      stderr: (value) => { stderr += value; },
    });
    assert.equal(invalid, 1);
    assert.match(stderr, /--max-delivery-age must be a number of minutes/u);
  } finally {
    server.closeAllConnections();
    await new Promise<void>((resolve) => server.close(() => resolve()));
    await rm(directory, { recursive: true, force: true });
  }
});

test("doctor --check reaches a company server through its pinned authority", async () => {
  const directory = await mkdtemp(join(tmpdir(), "phigon-doctor-pinned-"));
  const authority = testAuthority();
  const leaf = serverCertificate(authority);
  const server = createHttpsServer({ key: leaf.key, cert: leaf.certificate }, (_request, response) => {
    response.writeHead(200);
    response.end("{}");
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const company = `https://localhost:${(server.address() as AddressInfo).port}`;
  try {
    await new FileCredentialStore(directory).save(paired({ controlPlaneOrigin: company, grpcOrigin: company }));
    const environment = { PHIGON_DATA_DIR: directory };
    const probe = async () => {
      let stdout = "";
      await run(["doctor", "--check", "--json"], environment, {
        stdout: (value) => { stdout += value; },
        stderr: () => undefined,
      });
      return (JSON.parse(stdout) as DoctorCheckReport).checks.find((item) => item.name === "control_plane");
    };
    // Without the pinned authority, the server's certificate is refused.
    assert.equal((await probe())?.status, "fail");
    await writeFile(serverAuthorityPath(directory), authority.certificate, { mode: 0o600 });
    assert.equal((await probe())?.status, "pass");
  } finally {
    server.closeAllConnections();
    await new Promise<void>((resolve) => server.close(() => resolve()));
    await rm(directory, { recursive: true, force: true });
  }
});

test("doctor says whether the owner or the company consented, with the code's label", async () => {
  const directory = await mkdtemp(join(tmpdir(), "phigon-doctor-consent-"));
  const environment = { PHIGON_DATA_DIR: directory, PHIGON_CONTROL_PLANE_URL: origin };
  const doctor = async (args: readonly string[]): Promise<string> => {
    let stdout = "";
    await run(["doctor", ...args], environment, { stdout: (value) => { stdout += value; }, stderr: () => undefined });
    return stdout;
  };
  try {
    const store = new FileCredentialStore(directory);
    await store.save(paired());
    const owner = await check(directory);
    assert.equal(owner.checks[1]?.detail, "The owner consented to the metadata profile on 2026-11-01T00:00:00.000Z.");
    assert.deepEqual(owner.consent, {
      source: "owner", profile: "metadata", policyVersion: "observer-policy-v1", consentedAt: "2026-11-01T00:00:00.000Z",
    });
    assert.match(await doctor([]), /^Consent: given by the computer's owner, at pairing, for the metadata profile$/mu);
    assert.equal((JSON.parse(await doctor(["--json"])) as { consent?: { source: string } }).consent?.source, "owner");

    await store.save(paired({ consentSource: "company", enrollmentCodeLabel: "Engineering laptops", consentProfile: "full" }));
    const company = await check(directory);
    assert.equal(
      company.checks[1]?.detail,
      'Your company consented for this computer to the full profile with the enrollment code "Engineering laptops" on 2026-11-01T00:00:00.000Z.',
    );
    assert.equal(company.consent?.source, "company");
    assert.equal(company.consent?.enrollmentCodeLabel, "Engineering laptops");
    assert.match(await doctor([]), /^Consent: given by your company, with the enrollment code "Engineering laptops", for the full profile$/mu);
    const health = JSON.parse(await doctor(["--json"])) as { consent?: Record<string, string> };
    assert.deepEqual(health.consent, {
      source: "company", profile: "full", policyVersion: "observer-policy-v1",
      consentedAt: "2026-11-01T00:00:00.000Z", enrollmentCodeLabel: "Engineering laptops",
    });

    await store.save(paired({ consentSource: "company", consentPolicyVersion: "observer-policy-v1" }));
    assert.match((await check(directory)).checks[1]?.detail ?? "", /^Your company consented .* with an enrollment code on /u);

    await store.save({
      machineId: "machine-doctor", tenantId: "tenant-doctor", credential,
      controlPlaneOrigin: origin, createdAt: "2026-11-01T00:00:00.000Z",
    });
    assert.match(await doctor([]), /^Consent: none current \(last given by the computer's owner, at pairing\)$/mu);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("doctor says plainly when the relay has no server or HTTPS is inspected on the way", async () => {
  const directory = await mkdtemp(join(tmpdir(), "phigon-doctor-relay-"));
  const relayOrigin = "https://abcdefghabcdefgh.relay.phigon.online";
  const failing = (code: string): typeof fetch => async () => {
    throw Object.assign(new TypeError("fetch failed"), { cause: Object.assign(new Error("socket hang up"), { code }) });
  };
  const probe = async (fetcher: typeof fetch, controlPlane = relayOrigin) => (await runDoctorCheck({
    config: loadConfig({ PHIGON_CONTROL_PLANE_URL: controlPlane, PHIGON_DATA_DIR: directory }),
    observerVersion: "9.9.9",
    inspectLock: async () => ({ running: true }),
    fetcher,
  })).checks.find((item) => item.name === "control_plane")?.detail;
  const notConnected = "The Phigon server is not connected to the relay right now (for example, the admin's computer is off).";
  try {
    assert.equal(await probe(failing("ECONNRESET")), notConnected);
    assert.equal(await probe(failing("UND_ERR_SOCKET")), notConnected);
    // Elsewhere a reset is just a reset.
    assert.match(await probe(failing("ECONNRESET"), origin) ?? "", /\(ECONNRESET\)/u);
    // Without a pinned authority, an unknown certificate is reported as it is.
    trustServerAuthority(undefined);
    assert.match(await probe(failing("UNABLE_TO_GET_ISSUER_CERT_LOCALLY")) ?? "", /\(UNABLE_TO_GET_ISSUER_CERT_LOCALLY\)/u);
    trustServerAuthority(testAuthority("Phigon server authority DOCTOR").certificate);
    try {
      assert.equal(
        await probe(failing("UNABLE_TO_GET_ISSUER_CERT_LOCALLY")),
        "A proxy or security software on this network is inspecting HTTPS to abcdefghabcdefgh.relay.phigon.online, " +
          "so this computer cannot check that it is your company's Phigon server. " +
          "Ask your IT team to exempt *.relay.phigon.online from HTTPS inspection.",
      );
    } finally {
      trustServerAuthority(undefined);
    }
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});
