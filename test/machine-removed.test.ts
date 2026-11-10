import assert from "node:assert/strict";
import { existsSync } from "node:fs";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import {
  machineRemovedFileName,
  rememberMachineRemoved,
  removalConfirmed,
  removedAtStart,
  removedRecheckIn,
} from "../src/machine-removed.js";

const machine = {
  machineId: "machine-removed-1",
  credential: "machine-key-one",
  createdAt: "2026-11-01T09:00:00.000Z",
  controlPlaneOrigin: "https://control.example.test",
  grpcOrigin: "https://control.example.test:8443",
};
const controlPlaneUrl = new URL("https://control.example.test");
const hour = 60 * 60_000;

function answering(...responses: (() => Response)[]) {
  const requests: Request[] = [];
  const fetcher = (async (input: URL, init?: RequestInit) => {
    requests.push(new Request(input, init));
    const next = responses.shift();
    if (next === undefined) throw new Error("No more answers in this test.");
    return next();
  }) as typeof fetch;
  return { fetcher, requests };
}

const refused = () => new Response(JSON.stringify({ error: { code: "invalid_credential", message: "machine credential is revoked" } }), { status: 401 });

test("a removal is confirmed by the server before a service stops quietly, then asked again hourly", async () => {
  const directory = await mkdtemp(join(tmpdir(), "phigon-removed-"));
  try {
    const removedAt = new Date("2026-11-03T10:00:00.000Z");
    await rememberMachineRemoved(directory, machine, removedAt);
    const server = answering(refused, refused);
    const check = (at: Date) => removedAtStart({
      dataDirectory: directory, machine, controlPlaneUrl, recheckAfterMs: hour, now: () => at, fetcher: server.fetcher,
    });
    // The stream's refusal alone is not enough: the first start asks.
    assert.equal(await removalConfirmed(directory, machine), false);
    const confirmed = new Date(removedAt.getTime() + 60_000);
    assert.equal(await check(confirmed), "removed");
    // doctor --check now says the computer was removed, instead of "start it".
    assert.equal(await removalConfirmed(directory, machine), true);
    assert.equal(await removalConfirmed(directory, { ...machine, createdAt: "2026-11-04T00:00:00.000Z" }), false);
    assert.equal(server.requests.length, 1);
    assert.equal(server.requests[0]?.method, "POST");
    assert.equal(new URL(server.requests[0]!.url).pathname, "/v1/machine/heartbeat");
    assert.equal(server.requests[0]?.headers.get("authorization"), `Bearer ${machine.credential}`);

    // Confirmed, so later starts stop without asking, for an hour.
    assert.equal(await check(new Date(confirmed.getTime() + 59 * 60_000)), "still_removed");
    assert.equal(server.requests.length, 1);
    const later = new Date(confirmed.getTime() + hour);
    assert.equal(await check(later), "removed");
    assert.equal(server.requests.length, 2);
    assert.equal(await check(new Date(later.getTime() + 30 * 60_000)), "still_removed");
    assert.equal(server.requests.length, 2);
    const saved = await readFile(join(directory, machineRemovedFileName), "utf8");
    assert.doesNotMatch(saved, /machine-key-one/u, "the key itself is never written");
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("a removed computer starts again when the server takes its key, cannot be asked, or it is paired again", async () => {
  const directory = await mkdtemp(join(tmpdir(), "phigon-removed-"));
  const file = join(directory, machineRemovedFileName);
  try {
    const cases: [string, () => Response | never][] = [
      ["accepted", () => new Response(null, { status: 204 })],
      ["unreachable", () => { throw new TypeError("fetch failed"); }],
      ["server error", () => new Response("busy", { status: 503 })],
      ["other refusal", () => new Response(JSON.stringify({ error: { code: "tenant_suspended" } }), { status: 401 })],
      ["unreadable refusal", () => new Response("not json", { status: 401 })],
    ];
    for (const [name, answer] of cases) {
      await rememberMachineRemoved(directory, machine);
      const server = answering(answer);
      // A person running the observer in a terminal: always asked.
      const outcome = await removedAtStart({ dataDirectory: directory, machine, controlPlaneUrl, recheckAfterMs: 0, fetcher: server.fetcher });
      assert.equal(outcome, "start", name);
      assert.equal(server.requests.length, 1, name);
      assert.equal(existsSync(file), false, name);
    }

    // Any pairing since forgets the removal without asking: a new key, the
    // same key renewed, or the same key at a server's new address.
    const repaired = answering();
    for (const pairedAgain of [
      { ...machine, credential: "machine-key-two" },
      { ...machine, createdAt: "2026-11-03T12:00:00.000Z" },
      { ...machine, controlPlaneOrigin: "https://192.0.2.7:26962", grpcOrigin: "https://192.0.2.7:26963" },
    ]) {
      await rememberMachineRemoved(directory, machine);
      assert.equal(await removedAtStart({
        dataDirectory: directory, machine: pairedAgain, controlPlaneUrl, recheckAfterMs: hour, fetcher: repaired.fetcher,
      }), "start");
      assert.equal(existsSync(file), false);
    }
    assert.equal(repaired.requests.length, 0);

    await writeFile(file, "{not json", "utf8");
    assert.equal(await removedAtStart({ dataDirectory: directory, machine, controlPlaneUrl, recheckAfterMs: hour, fetcher: repaired.fetcher }), "start");
    assert.equal(await removedAtStart({ dataDirectory: join(directory, "missing"), machine, controlPlaneUrl, recheckAfterMs: hour, fetcher: repaired.fetcher }), "start");
    assert.equal(repaired.requests.length, 0);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("the next question to the server is counted from the confirmation, so a restart does not put it off", async () => {
  const directory = await mkdtemp(join(tmpdir(), "phigon-removed-recheck-"));
  try {
    // Nothing confirmed yet: ask now.
    assert.equal(await removedRecheckIn(directory, hour), 0);
    const confirmed = new Date("2026-11-03T09:00:00.000Z");
    await rememberMachineRemoved(directory, machine, confirmed);
    assert.equal(await removedRecheckIn(directory, hour, confirmed), 0);
    assert.equal(await removedAtStart({
      dataDirectory: directory, machine, controlPlaneUrl, recheckAfterMs: hour, now: () => confirmed, fetcher: answering(refused).fetcher,
    }), "removed");
    // Restarted at 09:50: the next question is at 10:00, not 10:50.
    assert.equal(await removedRecheckIn(directory, hour, new Date("2026-11-03T09:50:00.000Z")), 10 * 60_000);
    assert.equal(await removedRecheckIn(directory, hour, new Date("2026-11-03T10:30:00.000Z")), 0);
    // A clock set back never makes it wait longer than the interval.
    assert.equal(await removedRecheckIn(directory, hour, new Date("2026-11-03T07:00:00.000Z")), hour);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});
