import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { mkdtemp, readdir, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { loadConfig } from "../src/config.js";
import { FileCredentialStore, consentSourceOf } from "../src/credential-store.js";
import {
  EnrollmentError,
  checkedEnrollmentCode,
  enrollMachine,
  enrollmentExitCodes,
  enrollmentRetry,
  retryAfterMs,
} from "../src/enroll.js";

// Enrollment codes are assembled at runtime so secret scanners never see one.
const newCode = () => ["phe", "_", randomBytes(24).toString("base64url")].join("");
const credential = (letter: string) => `phg_m_${letter.repeat(43)}`;
const origin = "https://control.example.test";
const tenantId = "7d1b4cb4-a77d-4f53-af66-197e184683f4";
const codeId = "5f0c8a2e-3b1d-4c55-9a51-0d0e8f6c2b7a";

type Recorded = Readonly<{ path: string; body: Record<string, unknown>; authorization?: string }>;

function json(status: number, value: unknown, headers: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(value), {
    status,
    headers: { "Content-Type": "application/json", ...headers },
  });
}

function enrolled(machineId: string, key: string, consent: Record<string, unknown> = {}): Response {
  return json(201, {
    machine: { id: machineId, tenant_id: tenantId, display_name: "LAPTOP-042", state: "online", consent: { source: "company" } },
    credential: key,
    consent: {
      source: "company",
      profile: "metadata",
      policy_version: "observer-policy-v1",
      granted_at: "2026-11-02T10:05:00Z",
      granted_by: "1b4cb4a7-7d4f-4f53-af66-197e184683f4",
      enrollment_code_id: codeId,
      enrollment_code_label: "Engineering laptops",
      ...consent,
    },
  });
}

/** A control plane that answers with `answer` and records every request. */
function controlPlane(
  requests: Recorded[],
  answer: (request: Recorded, attempt: number) => Response,
): typeof fetch {
  return async (input, init) => {
    const url = new URL(input instanceof Request ? input.url : input.toString());
    const body = typeof init?.body === "string" ? JSON.parse(init.body) as Record<string, unknown> : {};
    const authorization = new Headers(init?.headers).get("authorization");
    const request = { path: url.pathname, body, ...(authorization === null ? {} : { authorization }) };
    requests.push(request);
    return answer(request, requests.length);
  };
}

async function withDirectory(run: (directory: string) => Promise<void>): Promise<void> {
  const directory = await mkdtemp(join(tmpdir(), "phigon-enroll-"));
  try {
    await run(directory);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
}

/** Every file the observer wrote, to check that the code is in none. */
async function everything(directory: string): Promise<string> {
  let text = "";
  for (const entry of await readdir(directory, { recursive: true, withFileTypes: true })) {
    if (entry.isFile()) text += await readFile(join(entry.parentPath, entry.name), "utf8");
  }
  return text;
}

const config = (directory: string) => loadConfig({ PHIGON_CONTROL_PLANE_URL: origin, PHIGON_DATA_DIR: directory });
const noWait = async () => undefined;

test("an enrollment code connects the computer with the company's consent, asks nothing and keeps no code", async () => {
  await withDirectory(async (directory) => {
    const code = newCode();
    const requests: Recorded[] = [];
    const result = await enrollMachine({
      config: config(directory),
      code: ` ${code}\n`,
      displayName: "LAPTOP-042",
      observerVersion: "8.4.0",
      fetcher: controlPlane(requests, () => enrolled("22222222-2222-4222-8222-222222222222", credential("n"))),
    });

    assert.equal(requests.length, 1);
    assert.equal(requests[0]?.path, "/v1/machines/enroll");
    const body = requests[0]?.body ?? {};
    assert.equal(body["enrollment_code"], code);
    assert.equal(body["display_name"], "LAPTOP-042");
    assert.equal(body["observer_version"], "8.4.0");
    assert.match(String(body["installation_id"]), /^[0-9a-f-]{36}$/u);
    assert.ok(["windows", "macos", "linux"].includes(String(body["operating_system"])));
    assert.equal("consent" in body, false, "the server refuses a consent field");
    assert.equal("existing_credential" in body, false);
    assert.equal(requests[0]?.authorization, undefined);

    assert.deepEqual(result.consent, {
      source: "company",
      profile: "metadata",
      policyVersion: "observer-policy-v1",
      grantedAt: "2026-11-02T10:05:00.000Z",
      enrollmentCodeId: codeId,
      enrollmentCodeLabel: "Engineering laptops",
    });
    assert.equal(result.machineId, "22222222-2222-4222-8222-222222222222");
    assert.equal(JSON.stringify(result).includes(code), false);

    const stored = await new FileCredentialStore(directory).load();
    assert.ok(stored !== null);
    assert.equal(stored.credential, credential("n"));
    assert.equal(stored.consentProfile, "metadata");
    assert.equal(stored.consentPolicyVersion, "observer-policy-v1");
    assert.equal(stored.consentedAt, "2026-11-02T10:05:00.000Z");
    assert.equal(consentSourceOf(stored), "company");
    assert.equal(stored.enrollmentCodeId, codeId);
    assert.equal(stored.enrollmentCodeLabel, "Engineering laptops");
    assert.equal((await everything(directory)).includes(code.slice(4)), false, "the code was written to disk");
  });
});

test("a computer already paired with the server keeps its machine and key, and its consent becomes the company's", async () => {
  await withDirectory(async (directory) => {
    const machineId = "11111111-1111-4111-8111-111111111111";
    const store = new FileCredentialStore(directory);
    await store.save({
      machineId, tenantId, credential: credential("o"), controlPlaneOrigin: origin,
      createdAt: "2026-10-01T00:00:00.000Z", consentProfile: "full",
      consentPolicyVersion: "observer-policy-v1", consentedAt: "2026-10-01T00:00:00.000Z",
    });
    await writeFile(join(directory, "telemetry-spool.jsonl"), "{\"kept\":true}\n", "utf8");
    const requests: Recorded[] = [];
    const result = await enrollMachine({
      config: config(directory),
      code: newCode(),
      fetcher: controlPlane(requests, () => enrolled(machineId, credential("o"))),
    });
    assert.equal(requests.length, 1);
    assert.equal(requests[0]?.body["existing_credential"], credential("o"));
    assert.equal(result.machineId, machineId);
    assert.equal(result.replacedMachineId, undefined);
    const stored = await store.load();
    assert.equal(stored?.consentSource, "company");
    assert.equal(stored?.consentProfile, "metadata");
    assert.equal(await readFile(join(directory, "telemetry-spool.jsonl"), "utf8"), "{\"kept\":true}\n");
  });
});

test("a key the server no longer accepts is set aside and the computer enrolls as a new machine", async () => {
  await withDirectory(async (directory) => {
    const store = new FileCredentialStore(directory);
    await store.save({
      machineId: "11111111-1111-4111-8111-111111111111", tenantId, credential: credential("o"),
      controlPlaneOrigin: origin, createdAt: "2026-10-01T00:00:00.000Z",
    });
    const requests: Recorded[] = [];
    const result = await enrollMachine({
      config: config(directory),
      code: newCode(),
      fetcher: controlPlane(requests, (request) => {
        if (request.path === "/v1/machine/heartbeat") {
          return json(401, { error: { code: "invalid_credential", message: "Machine credential is invalid." } });
        }
        return "existing_credential" in request.body
          ? json(400, { error: { code: "invalid_credential", message: "Machine credential is invalid. Enroll this computer again without its old key." } })
          : enrolled("22222222-2222-4222-8222-222222222222", credential("n"));
      }),
    });
    assert.deepEqual(requests.map((request) => request.path), ["/v1/machines/enroll", "/v1/machine/heartbeat", "/v1/machines/enroll"]);
    assert.notEqual(requests[2]?.body["installation_id"], requests[0]?.body["installation_id"]);
    assert.equal(result.replacedMachineId, "11111111-1111-4111-8111-111111111111");
    assert.equal((await store.load())?.credential, credential("n"));
  });
});

test("a computer paired with another server is not enrolled from the same data directory", async () => {
  await withDirectory(async (directory) => {
    await new FileCredentialStore(directory).save({
      machineId: "11111111-1111-4111-8111-111111111111", tenantId, credential: credential("o"),
      controlPlaneOrigin: "https://other.example.test", createdAt: "2026-10-01T00:00:00.000Z",
    });
    const requests: Recorded[] = [];
    await assert.rejects(
      enrollMachine({ config: config(directory), code: newCode(), fetcher: controlPlane(requests, () => json(500, {})) }),
      /different control plane.*separate data directory/u,
    );
    assert.equal(requests.length, 0);
  });
});

test("a busy server is asked again with the same installation after its Retry-After", async () => {
  await withDirectory(async (directory) => {
    const requests: Recorded[] = [];
    const waits: number[] = [];
    const retries: number[] = [];
    const result = await enrollMachine({
      config: config(directory),
      code: newCode(),
      sleep: async (ms) => { waits.push(ms); },
      random: () => 0.5,
      onRetry: (ms) => retries.push(ms),
      fetcher: controlPlane(requests, (_request, attempt) => attempt === 1
        ? json(429, { error: { code: "rate_limited", message: "Too many enrollment attempts from this network. Try again in a minute." } }, { "Retry-After": "60" })
        : attempt === 2
          ? json(503, { error: { code: "enrollment_unavailable", message: "Enrollment is temporarily unavailable. Try again in a minute." } }, { "Retry-After": "2" })
          : enrolled("22222222-2222-4222-8222-222222222222", credential("n"))),
    });
    assert.equal(result.machineId, "22222222-2222-4222-8222-222222222222");
    assert.equal(requests.length, 3);
    assert.equal(new Set(requests.map((request) => request.body["installation_id"])).size, 1);
    const jitter = enrollmentRetry.jitterMs / 2;
    assert.deepEqual(waits, [60_000 + jitter, 2_000 + jitter]);
    assert.deepEqual(retries, waits);
  });
});

test("retries stop after a few attempts and within a bounded total", async () => {
  await withDirectory(async (directory) => {
    const requests: Recorded[] = [];
    const waits: number[] = [];
    const busy = () => json(503, { error: { code: "rate_limit_unavailable", message: "Enrollment protection is temporarily unavailable. Try again in a minute." } }, { "Retry-After": "1" });
    await assert.rejects(
      enrollMachine({
        config: config(directory), code: newCode(), random: () => 0,
        sleep: async (ms) => { waits.push(ms); }, fetcher: controlPlane(requests, busy),
      }),
      (error: unknown) => {
        assert.ok(error instanceof EnrollmentError);
        assert.equal(error.exitCode, enrollmentExitCodes.retryLater);
        assert.equal(error.code, "rate_limit_unavailable");
        assert.equal(error.message, "Enrollment protection is temporarily unavailable. Try again in a minute.");
        return true;
      },
    );
    assert.equal(requests.length, enrollmentRetry.attempts);
    assert.equal(waits.length, enrollmentRetry.attempts - 1);

    // A long Retry-After uses up the total before the attempts run out.
    requests.length = 0;
    waits.length = 0;
    await assert.rejects(enrollMachine({
      config: config(directory), code: newCode(), random: () => 0, sleep: async (ms) => { waits.push(ms); },
      fetcher: controlPlane(requests, () => json(429, { error: { code: "rate_limited", message: "Too many enrollment attempts from this network. Try again in a minute." } }, { "Retry-After": "600" })),
    }), EnrollmentError);
    assert.deepEqual(waits, [enrollmentRetry.maxWaitMs, enrollmentRetry.maxWaitMs]);
    assert.ok(waits.reduce((sum, wait) => sum + wait, 0) <= enrollmentRetry.totalWaitMs);
    assert.equal(requests.length, 3);
    assert.equal(await new FileCredentialStore(directory).load(), null);
  });
});

test("each refusal keeps the server's sentence and has its own exit code", async () => {
  const cases: ReadonlyArray<readonly [number, string, number]> = [
    [410, "enrollment_code_expired", enrollmentExitCodes.newCodeNeeded],
    [410, "enrollment_code_revoked", enrollmentExitCodes.newCodeNeeded],
    [409, "enrollment_code_used_up", enrollmentExitCodes.newCodeNeeded],
    [409, "enrollment_code_outdated", enrollmentExitCodes.newCodeNeeded],
    [400, "invalid_enrollment_code", enrollmentExitCodes.invalidCode],
    [409, "enrollment_code_already_used", enrollmentExitCodes.alreadyUsed],
    [409, "installation_already_paired", enrollmentExitCodes.alreadyConnected],
    [400, "invalid_request", 1],
    [500, "internal_error", enrollmentExitCodes.retryLater],
  ];
  for (const [status, serverCode, exitCode] of cases) {
    await withDirectory(async (directory) => {
      const message = `Plain sentence for ${serverCode}.`;
      await assert.rejects(
        enrollMachine({
          config: config(directory), code: newCode(), sleep: noWait,
          fetcher: controlPlane([], () => json(status, { error: { code: serverCode, message } })),
        }),
        (error: unknown) => {
          assert.ok(error instanceof EnrollmentError, serverCode);
          assert.equal(error.code, serverCode);
          assert.equal(error.exitCode, exitCode, serverCode);
          assert.equal(error.message, message);
          return true;
        },
      );
      assert.equal(await new FileCredentialStore(directory).load(), null);
    });
  }
});

test("a server message never carries a code or control characters to the screen", async () => {
  await withDirectory(async (directory) => {
    const code = newCode();
    await assert.rejects(
      enrollMachine({
        config: config(directory), code,
        fetcher: controlPlane([], () => json(400, { error: { code: "invalid_enrollment_code", message: `Code ${code}\nis wrong.\u0007` } })),
      }),
      (error: unknown) => {
        assert.ok(error instanceof Error);
        assert.equal(error.message.includes(code.slice(4)), false);
        assert.match(error.message, /^Code \[REDACTED_SECRET\] is wrong\.$/u);
        return true;
      },
    );
    await assert.rejects(
      enrollMachine({ config: config(directory), code, fetcher: controlPlane([], () => new Response("", { status: 502 })) }),
      /Enrollment failed with HTTP 502\. Try again later\./u,
    );
  });
});

test("a value that is not an enrollment code is refused before anything is sent", async () => {
  await withDirectory(async (directory) => {
    const requests: Recorded[] = [];
    for (const [value, pattern] of [
      ["ABCDE-FGHIJ", /start with phe_.*--code/u],
      [newCode().slice(0, 20), /copied in full/u],
      [`${newCode()}x`, /copied in full/u],
      [["phe", "_", "!".repeat(32)].join(""), /copied in full/u],
    ] as const) {
      await assert.rejects(
        enrollMachine({ config: config(directory), code: value, fetcher: controlPlane(requests, () => json(500, {})) }),
        (error: unknown) => {
          assert.ok(error instanceof EnrollmentError);
          assert.equal(error.exitCode, enrollmentExitCodes.invalidCode);
          assert.match(error.message, pattern);
          assert.equal(error.message.includes(value), false);
          return true;
        },
      );
    }
    assert.equal(requests.length, 0);
    assert.equal(checkedEnrollmentCode("  phe_" + "A".repeat(32) + " "), "phe_" + "A".repeat(32));
  });
});

test("an enrollment the observer cannot honour exactly is not stored", async () => {
  await withDirectory(async (directory) => {
    for (const consent of [
      { policy_version: "observer-policy-v2" },
      { source: "owner" },
      { profile: "everything" },
    ]) {
      await assert.rejects(
        enrollMachine({
          config: config(directory), code: newCode(),
          fetcher: controlPlane([], () => enrolled("22222222-2222-4222-8222-222222222222", credential("n"), consent)),
        }),
        /cannot use\. Update the observer/u,
      );
    }
    await assert.rejects(
      enrollMachine({
        config: config(directory), code: newCode(),
        fetcher: controlPlane([], () => new Response(`{"credential":"${credential("n")}"`, { status: 201 })),
      }),
      (error: unknown) => {
        assert.ok(error instanceof EnrollmentError);
        assert.equal(error.exitCode, enrollmentExitCodes.retryLater);
        assert.equal(error.message.includes("phg_m_"), false);
        return true;
      },
    );
    assert.equal(await new FileCredentialStore(directory).load(), null);
  });
});

test("an unreachable server is worth trying again later", async () => {
  await withDirectory(async (directory) => {
    await assert.rejects(
      enrollMachine({ config: config(directory), code: newCode(), fetcher: async () => { throw new TypeError("fetch failed"); } }),
      (error: unknown) => {
        assert.ok(error instanceof EnrollmentError);
        assert.equal(error.exitCode, enrollmentExitCodes.retryLater);
        assert.match(error.message, /Could not reach https:\/\/control\.example\.test/u);
        return true;
      },
    );
  });
});

test("a label is kept as one bounded line, and a missing one is left out", async () => {
  await withDirectory(async (directory) => {
    const result = await enrollMachine({
      config: config(directory), code: newCode(),
      fetcher: controlPlane([], () => enrolled("22222222-2222-4222-8222-222222222222", credential("n"), {
        enrollment_code_label: `Line\none ${"x".repeat(200)}`, granted_at: "not a time", enrollment_code_id: "../../x",
      })),
    });
    assert.equal(result.consent.enrollmentCodeLabel?.startsWith("Line one x"), true);
    assert.equal(result.consent.enrollmentCodeLabel?.length, 100);
    assert.equal(result.consent.enrollmentCodeId, undefined);
    assert.equal(result.consent.grantedAt, undefined);
    const stored = await new FileCredentialStore(directory).load();
    assert.equal(stored?.enrollmentCodeLabel, result.consent.enrollmentCodeLabel);
    assert.ok(Number.isFinite(Date.parse(stored?.consentedAt ?? "")));
  });
  await withDirectory(async (directory) => {
    const result = await enrollMachine({
      config: config(directory), code: newCode(),
      fetcher: controlPlane([], () => enrolled("22222222-2222-4222-8222-222222222222", credential("n"), { enrollment_code_label: " " })),
    });
    assert.equal(result.consent.enrollmentCodeLabel, undefined);
    assert.equal("enrollmentCodeLabel" in (await new FileCredentialStore(directory).load() ?? {}), false);
  });
});

test("Retry-After is read as seconds or a date, within bounds", () => {
  const now = Date.parse("2026-11-02T10:00:00Z");
  assert.equal(retryAfterMs("60", now), 60_000);
  assert.equal(retryAfterMs(null, now), enrollmentRetry.defaultWaitMs);
  assert.equal(retryAfterMs("soon", now), enrollmentRetry.defaultWaitMs);
  assert.equal(retryAfterMs("0", now), 1_000);
  assert.equal(retryAfterMs("100000", now), enrollmentRetry.maxWaitMs);
  assert.equal(retryAfterMs("Mon, 02 Nov 2026 10:00:45 GMT", now), 45_000);
  assert.equal(retryAfterMs("Mon, 02 Nov 2026 09:00:00 GMT", now), 1_000);
});
