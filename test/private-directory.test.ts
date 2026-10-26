import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { FileCredentialStore } from "../src/credential-store.js";
import { makeDirectoryPrivate } from "../src/private-directory.js";

function aclFor(path: string): string {
  return execFileSync("icacls", [path], { encoding: "utf8", windowsHide: true });
}

test("on Windows the data directory is restricted to its owner and SYSTEM, and new files inherit it", { skip: process.platform !== "win32" }, async () => {
  const directory = await mkdtemp(join(tmpdir(), "phigon-private-"));
  try {
    await makeDirectoryPrivate(directory);
    const file = join(directory, "machine-credential.json");
    await writeFile(file, "{}");
    for (const acl of [aclFor(directory), aclFor(file)]) {
      assert.match(acl, new RegExp(`${process.env["USERNAME"]}`, "iu"));
      assert.doesNotMatch(acl, /Everyone|Authenticated Users|BUILTIN\\Users/u);
    }
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("storing a credential leaves it in a private directory", { skip: process.platform !== "win32" }, async () => {
  const directory = await mkdtemp(join(tmpdir(), "phigon-private-credential-"));
  try {
    await new FileCredentialStore(directory).save({
      machineId: "machine-private-1",
      tenantId: "tenant-private-1",
      credential: `phg_m_${"c".repeat(43)}`,
      controlPlaneOrigin: "https://api.phigon.online",
      createdAt: "2026-10-26T00:00:00.000Z",
    });
    const acl = aclFor(join(directory, "machine-credential.json"));
    assert.doesNotMatch(acl, /Everyone|Authenticated Users|BUILTIN\\Users/u);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});
