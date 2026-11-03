import assert from "node:assert/strict";
import { mkdir, mkdtemp, readdir, readFile, rm, stat, writeFile } from "node:fs/promises";
import { createServer } from "node:http";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Readable } from "node:stream";
import test from "node:test";
import { run } from "../src/cli.js";
import { FileCredentialStore } from "../src/credential-store.js";
import { purgeDataDirectory, removeEmptyDataDirectory } from "../src/purge.js";
import type { CommandResult } from "../src/service.js";

const machineKey = ["phg", "_m_", "p".repeat(43)].join("");

/** Files a long-running observer leaves in its data directory. */
async function fillDataDirectory(directory: string): Promise<void> {
  await mkdir(join(directory, "logs"), { recursive: true });
  await mkdir(join(directory, "bridges", "generic"), { recursive: true });
  await mkdir(join(directory, "retired-pairings", "2026-old"), { recursive: true });
  await mkdir(join(directory, "history-sync"), { recursive: true });
  for (const [name, content] of [
    ["activity-cursors.json", "{}"],
    ["stream-state.json", "{}"],
    ["stream-state.json.7f6b3c2a-1111-4222-8333-944445555666.corrupt", "x"],
    ["historical-agent-identities.json", "{}"],
    ["installation-id", "id"],
    ["telemetry-spool.jsonl", "encrypted"],
    ["update-check.json", "{}"],
    ["custom-agents.json", "{}"],
    ["action-policy.json.123.7f6b3c2a-1111-4222-8333-944445555666.tmp", "x"],
    ["service-settings.json", "{}"],
    // Left by a computer the workspace removed.
    ["machine-removed.json", "{}"],
    [join("logs", "observer.log"), "line\n"],
    [join("bridges", "generic", "segment.jsonl"), "{}\n"],
  ] as const) {
    await writeFile(join(directory, name), content);
  }
}

test("a purge removes only what the observer created", async () => {
  const directory = await mkdtemp(join(tmpdir(), "phigon-purge-"));
  try {
    await fillDataDirectory(directory);
    await writeFile(join(directory, "notes.txt"), "someone else's file");
    await writeFile(join(directory, "observer.lock"), "{}");
    const result = await purgeDataDirectory(directory, ["observer.lock"]);
    assert.deepEqual(result.leftBehind, ["notes.txt"]);
    assert.equal(result.removed, 15);
    assert.deepEqual((await readdir(directory)).sort(), ["notes.txt", "observer.lock"]);
    assert.equal(await removeEmptyDataDirectory(directory), false);

    await rm(join(directory, "notes.txt"));
    await rm(join(directory, "observer.lock"));
    assert.equal(await removeEmptyDataDirectory(directory), true);
    assert.equal(await removeEmptyDataDirectory(directory), true);
    assert.deepEqual(await purgeDataDirectory(directory), { removed: 0, leftBehind: [], directoryRemoved: true });
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

type Call = Readonly<{ command: string; args: readonly string[] }>;

async function withControlPlane(
  status: number,
  body: (origin: string, requests: string[]) => Promise<void>,
): Promise<void> {
  const requests: string[] = [];
  const server = createServer((request, response) => {
    requests.push(`${request.method} ${request.url}`);
    if (status === 204) {
      response.writeHead(204);
      response.end();
      return;
    }
    response.writeHead(status, { "content-type": "application/json" });
    response.end(JSON.stringify({ error: { code: "unavailable", message: "Try again later." } }));
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  try {
    await body(`http://127.0.0.1:${(server.address() as AddressInfo).port}`, requests);
  } finally {
    server.closeAllConnections();
    await new Promise<void>((resolve) => server.close(() => resolve()));
  }
}

async function setUp(origin: string) {
  const root = await mkdtemp(join(tmpdir(), "phigon-purge-cli-"));
  const data = join(root, "data");
  await new FileCredentialStore(data).save({
    machineId: "machine-purge",
    tenantId: "tenant-purge",
    credential: machineKey,
    controlPlaneOrigin: origin,
    grpcOrigin: origin,
    createdAt: "2026-11-02T00:00:00.000Z",
    consentProfile: "metadata",
    consentPolicyVersion: "observer-policy-v1",
    consentedAt: "2026-11-02T00:00:00.000Z",
  });
  await fillDataDirectory(data);
  // An installed background service for this data directory.
  const calls: Call[] = [];
  const runner = async (command: string, args: readonly string[]): Promise<CommandResult> => {
    calls.push({ command, args: [...args] });
    return { code: 0, stdout: "", stderr: "" };
  };
  const dependencies = { serviceRunner: runner, platform: "linux" as const, homeDirectory: root, stopTimeoutMs: 50 };
  const environment = { PHIGON_DATA_DIR: data, PHIGON_CONTROL_PLANE_URL: origin };
  let output = "";
  const installed = await run(["service", "install"], environment, {
    stdout: (value) => { output += value; },
    stderr: (value) => { output += value; },
  }, undefined, dependencies);
  assert.equal(installed, 0, output);
  calls.length = 0;
  const unitDirectory = join(root, ".config", "systemd", "user");
  return { root, data, calls, dependencies, environment, unitDirectory };
}

test("remove-machine --purge removes the computer, its service and its local files", async () => {
  await withControlPlane(204, async (origin, requests) => {
    const { root, data, calls, dependencies, environment, unitDirectory } = await setUp(origin);
    try {
      let stdout = "";
      let stderr = "";
      const code = await run(["remove-machine", "--purge", "--yes", "--json"], environment, {
        stdout: (value) => { stdout += value; },
        stderr: (value) => { stderr += value; },
      }, undefined, dependencies);
      assert.equal(code, 0, stderr);
      assert.deepEqual(requests, ["DELETE /v1/machine"]);
      const report = JSON.parse(stdout) as Record<string, unknown>;
      assert.equal(report["status"], "removed");
      assert.deepEqual(report["purged"], {
        serviceRemoved: true,
        filesRemoved: (report["purged"] as { filesRemoved: number }).filesRemoved,
        dataDirectory: data,
        dataDirectoryRemoved: true,
        leftBehind: [],
      });
      assert.deepEqual(calls.map((call) => call.args.slice(1).join(" ")), [
        "stop " + calls[0]!.args[2],
        "disable --now " + calls[0]!.args[2],
        "daemon-reload",
      ]);
      await assert.rejects(stat(data), { code: "ENOENT" });
      assert.deepEqual(await readdir(unitDirectory), []);
      assert.doesNotMatch(stdout + stderr, /phg_m_/u);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });
});

test("a purge that the control plane refuses changes nothing and restarts the service", async () => {
  await withControlPlane(503, async (origin, requests) => {
    const { root, data, calls, dependencies, environment } = await setUp(origin);
    try {
      let stderr = "";
      const code = await run(["remove-machine", "--purge", "--yes"], environment, {
        stdout: () => undefined,
        stderr: (value) => { stderr += value; },
      }, undefined, dependencies);
      assert.equal(code, 1);
      assert.match(stderr, /Try again later\. The local credential was kept\./u);
      assert.equal(requests.length, 1);
      assert.deepEqual(calls.map((call) => call.args[1]), ["stop", "start"]);
      assert.equal((await new FileCredentialStore(data).load())?.machineId, "machine-purge");
      assert.equal(await readFile(join(data, "activity-cursors.json"), "utf8"), "{}");
      assert.equal(await readFile(join(data, "service-settings.json"), "utf8") !== "", true);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });
});

test("a purge asks first, and works on a computer that is no longer paired", async () => {
  const root = await mkdtemp(join(tmpdir(), "phigon-purge-unpaired-"));
  const data = join(root, "data");
  try {
    await fillDataDirectory(data);
    await writeFile(join(data, "keep-me.txt"), "not the observer's");
    const dependencies = {
      serviceRunner: async (): Promise<CommandResult> => ({ code: 0, stdout: "", stderr: "" }),
      platform: "linux" as const,
      homeDirectory: root,
      stopTimeoutMs: 50,
    };
    let stdout = "";
    let stderr = "";
    const declined = await run(["remove-machine", "--purge"], { PHIGON_DATA_DIR: data }, {
      stdout: (value) => { stdout += value; },
      stderr: (value) => { stderr += value; },
    }, Readable.from(["no\n"]), dependencies);
    assert.equal(declined, 1);
    assert.match(stdout, /This computer is not paired\.[\s\S]*every file the observer keeps in/u);
    assert.match(stderr, /not confirmed\. Nothing was changed\./u);
    assert.equal(await readFile(join(data, "stream-state.json"), "utf8"), "{}");

    stdout = "";
    const confirmed = await run(["remove-machine", "--purge"], { PHIGON_DATA_DIR: data }, {
      stdout: (value) => { stdout += value; },
      stderr: () => undefined,
    }, Readable.from(["remove\n"]), dependencies);
    assert.equal(confirmed, 0);
    assert.match(stdout, /not paired, so nothing was sent/u);
    assert.match(stdout, /1 file\(s\) the observer did not create were left there/u);
    assert.match(stdout, /npm uninstall --global @phigon\/observer/u);
    assert.deepEqual(await readdir(data), ["keep-me.txt"]);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("remove-machine without --purge still keeps local progress files", async () => {
  await withControlPlane(204, async (origin) => {
    const root = await mkdtemp(join(tmpdir(), "phigon-remove-keep-"));
    const data = join(root, "data");
    try {
      await new FileCredentialStore(data).save({
        machineId: "machine-keep",
        tenantId: "tenant-keep",
        credential: machineKey,
        controlPlaneOrigin: origin,
        createdAt: "2026-11-02T00:00:00.000Z",
      });
      await fillDataDirectory(data);
      const code = await run(["remove-machine", "--yes"], { PHIGON_DATA_DIR: data, PHIGON_CONTROL_PLANE_URL: origin }, {
        stdout: () => undefined,
        stderr: () => undefined,
      });
      assert.equal(code, 0);
      assert.equal(await new FileCredentialStore(data).load(), null);
      for (const name of ["activity-cursors.json", "historical-agent-identities.json", "logs"]) {
        await stat(join(data, name));
      }
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });
});
