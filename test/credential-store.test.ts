import assert from "node:assert/strict";
import { mkdtemp, readdir, readFile, rename, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { FileCredentialStore, consentSourceOf } from "../src/credential-store.js";

test("corrupt pairing data reports recovery instructions without echoing file contents", async () => {
  const directory = await mkdtemp(join(tmpdir(), "phigon-corrupt-credential-"));
  const path = join(directory, "machine-credential.json");
  const damaged = 'private-fixture-credential{"incomplete":';
  try {
    await writeFile(path, damaged);
    await assert.rejects(new FileCredentialStore(directory).load(), (error: unknown) => {
      assert.ok(error instanceof Error);
      assert.doesNotMatch(error.message, /private-fi/);
      assert.match(error.message, /restore.*backup/i);
      assert.match(error.message, /keep.*data directory/i);
      return true;
    });
    assert.equal(await readFile(path, "utf8"), damaged);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("saving retries a rename Windows briefly refuses, and leaves no temporary file", async () => {
  const directory = await mkdtemp(join(tmpdir(), "phigon-credential-rename-"));
  const calls: string[] = [];
  // Only Windows retries; elsewhere the same rename simply succeeds.
  let refusals = process.platform === "win32" ? 2 : 0;
  const store = new FileCredentialStore(directory, {
    rename: async (from, to) => {
      calls.push(String(to));
      if (refusals > 0) {
        refusals--;
        throw Object.assign(new Error("operation not permitted"), { code: "EPERM" });
      }
      await rename(from, to);
    },
  });
  try {
    await store.save({
      machineId: "machine-rename",
      tenantId: "tenant-rename",
      credential: `phg_m_${"s".repeat(43)}`,
      controlPlaneOrigin: "https://phigon.example",
      createdAt: "2026-11-02T00:00:00.000Z",
    });
    assert.equal(calls.length, process.platform === "win32" ? 3 : 1);
    assert.ok(calls.every((to) => to === join(directory, "machine-credential.json")));
    assert.equal((await store.load())?.machineId, "machine-rename");
    assert.deepEqual(await readdir(directory), ["machine-credential.json"]);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("a credential saved before enrollment codes loads as the owner's, and a company's keeps its code label", async () => {
  const directory = await mkdtemp(join(tmpdir(), "phigon-credential-consent-"));
  const path = join(directory, "machine-credential.json");
  const base = {
    machineId: "machine-consent",
    tenantId: "tenant-consent",
    credential: `phg_m_${"c".repeat(43)}`,
    controlPlaneOrigin: "https://phigon.example",
    createdAt: "2026-11-02T00:00:00.000Z",
    consentProfile: "metadata",
    consentPolicyVersion: "observer-policy-v1",
    consentedAt: "2026-11-02T00:00:00.000Z",
  };
  try {
    const store = new FileCredentialStore(directory);
    await writeFile(path, `${JSON.stringify(base)}\n`);
    const old = await store.load();
    assert.ok(old !== null);
    assert.equal(old.consentSource, undefined);
    assert.equal(consentSourceOf(old), "owner");

    await store.save({ ...old, consentSource: "company", enrollmentCodeId: "code-1", enrollmentCodeLabel: "Engineering laptops" });
    const company = await store.load();
    assert.ok(company !== null);
    assert.equal(consentSourceOf(company), "company");
    assert.equal(company.enrollmentCodeLabel, "Engineering laptops");

    for (const invalid of [
      { ...base, consentSource: "employee" },
      {
        machineId: base.machineId, tenantId: base.tenantId, credential: base.credential,
        controlPlaneOrigin: base.controlPlaneOrigin, createdAt: base.createdAt, consentSource: "company",
      },
      { ...base, consentSource: "company", enrollmentCodeLabel: "x".repeat(101) },
      { ...base, consentSource: "company", enrollmentCodeId: 7 },
    ]) {
      await writeFile(path, `${JSON.stringify(invalid)}\n`);
      await assert.rejects(store.load(), /consent evidence is invalid/u);
    }
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});
