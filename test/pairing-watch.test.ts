import assert from "node:assert/strict";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { setTimeout as delay } from "node:timers/promises";
import test from "node:test";
import { run } from "../src/cli.js";
import { FileCredentialStore, type StoredMachineCredential } from "../src/credential-store.js";
import { pairingChangedExitCode, watchPairing, type PairingChange } from "../src/pairing-watch.js";

// Machine keys are built at run time, so no key-shaped text is stored.
const key = (fill: string) => ["phg", "m", fill.repeat(43)].join("_");

const paired: StoredMachineCredential = {
  machineId: "machine-watch",
  tenantId: "tenant-watch",
  credential: key("w"),
  controlPlaneOrigin: "http://127.0.0.1:9",
  grpcOrigin: "http://127.0.0.1:9",
  createdAt: "2026-11-01T00:00:00.000Z",
  consentProfile: "full",
  consentPolicyVersion: "observer-policy-v1",
  consentedAt: "2026-11-01T00:00:00.000Z",
};

async function withPairing(body: (directory: string, store: FileCredentialStore) => Promise<void>) {
  const directory = await mkdtemp(join(tmpdir(), "phigon-pairing-watch-"));
  const store = new FileCredentialStore(directory);
  await store.save(paired);
  try {
    await body(directory, store);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
}

function watch(directory: string) {
  let resolveChange: (change: PairingChange) => void = () => undefined;
  const changed = new Promise<PairingChange>((resolve) => { resolveChange = resolve; });
  const changes: PairingChange[] = [];
  const watcher = watchPairing({
    dataDirectory: directory,
    current: paired,
    intervalMs: 10,
    onChange: (change) => {
      changes.push(change);
      resolveChange(change);
    },
  });
  return { watcher, changed, changes };
}

test("narrower consent from pairing again is noticed at once", async () => {
  await withPairing(async (directory, store) => {
    const { watcher, changed } = watch(directory);
    try {
      await store.save({ ...paired, consentProfile: "metadata", consentedAt: "2026-11-03T00:00:00.000Z" });
      const change = await changed;
      assert.equal(change.narrowedConsent, true);
      assert.match(change.message, /consent changed to agent metadata only, so the observer stops collecting now/u);
      assert.ok(!change.message.includes(key("w")));
    } finally {
      watcher.stop();
    }
  });
});

test("a renewed pairing that changes only its dates is not a change", async () => {
  await withPairing(async (directory, store) => {
    const { watcher, changes } = watch(directory);
    try {
      await store.save({ ...paired, createdAt: "2026-11-03T00:00:00.000Z", consentedAt: "2026-11-03T00:00:00.000Z" });
      await delay(200);
      assert.deepEqual(changes, []);
      assert.equal(await watcher.check(), undefined);
    } finally {
      watcher.stop();
    }
  });
});

test("a new address, a new key or a removed pairing is a change", async () => {
  for (const next of [
    { ...paired, controlPlaneOrigin: "https://192.168.1.11:26962" },
    { ...paired, credential: key("x") },
    { ...paired, consentSource: "company" as const },
  ]) {
    await withPairing(async (directory, store) => {
      const { watcher, changed } = watch(directory);
      try {
        await store.save(next);
        const change = await changed;
        assert.equal(change.narrowedConsent, false);
        assert.match(change.message, /pairing changed, so the observer stops/u);
      } finally {
        watcher.stop();
      }
    });
  }
  await withPairing(async (directory, store) => {
    const { watcher, changed } = watch(directory);
    try {
      await store.clear();
      assert.equal((await changed).narrowedConsent, true);
    } finally {
      watcher.stop();
    }
  });
});

test("a stopped watch reports nothing", async () => {
  await withPairing(async (directory, store) => {
    const { watcher, changes } = watch(directory);
    watcher.stop();
    await store.save({ ...paired, consentProfile: "metadata" });
    await delay(100);
    assert.deepEqual(changes, []);
  });
});

test("run stops collecting and exits for its service to restart it when consent narrows", { timeout: 60_000 }, async () => {
  await withPairing(async (directory, store) => {
    let stdout = "";
    let stderr = "";
    let narrowed = false;
    const exitCode = await run(["run", "--profile", "full"], {
      PHIGON_DATA_DIR: directory,
      PHIGON_UPDATE_CHECK: "false",
      PHIGON_DISCOVERY_INTERVAL_MS: "60000",
    }, {
      stdout: (value) => {
        stdout += value;
        // The owner pairs again with metadata consent while it runs.
        if (!narrowed && value.includes("Connecting telemetry")) {
          narrowed = true;
          void store.save({ ...paired, consentProfile: "metadata", consentedAt: "2026-11-03T00:00:00.000Z" });
        }
      },
      stderr: (value) => { stderr += value; },
    });
    assert.equal(exitCode, pairingChangedExitCode, stderr);
    assert.match(stdout, /consent changed to agent metadata only/u);
    assert.doesNotMatch(stdout, /Observer stopped\./u);
    assert.doesNotMatch(stderr, /Observer command failed/u);
    assert.equal(process.listenerCount("SIGTERM"), 0);
  });
});
