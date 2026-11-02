import assert from "node:assert/strict";
import { mkdtemp, readFile, readdir, rm, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { announceCompanyCollection, collectionNoticeFileName } from "../src/collection-notice.js";
import type { StoredMachineCredential } from "../src/credential-store.js";
import { UserNotices, type UserNotice } from "../src/user-notices.js";

const owner: StoredMachineCredential = {
  machineId: "machine-notice",
  tenantId: "tenant-notice",
  credential: `phg_m_${"t".repeat(43)}`,
  controlPlaneOrigin: "https://control.example.test",
  createdAt: "2026-11-02T00:00:00.000Z",
  consentProfile: "metadata",
  consentPolicyVersion: "observer-policy-v1",
  consentedAt: "2026-11-02T00:00:00.000Z",
};
const company: StoredMachineCredential = {
  ...owner,
  consentSource: "company",
  enrollmentCodeId: "5f0c8a2e-3b1d-4c55-9a51-0d0e8f6c2b7a",
  enrollmentCodeLabel: "Engineering laptops",
};

async function withDirectory(run: (directory: string) => Promise<void>): Promise<void> {
  const directory = await mkdtemp(join(tmpdir(), "phigon-collection-notice-"));
  try {
    await run(directory);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
}

function recording(sent: UserNotice[], enabled = true): UserNotices {
  return new UserNotices({ enabled, send: async (notice) => { sent.push(notice); } });
}

test("a company-enrolled computer is told once when collection starts, and again when the profile changes", async () => {
  await withDirectory(async (dataDirectory) => {
    const sent: UserNotice[] = [];
    const notices = recording(sent);
    const announce = (credential: StoredMachineCredential, profile: "metadata" | "full") =>
      announceCompanyCollection({ dataDirectory, credential, profile, notices, now: () => new Date("2026-11-02T10:00:00Z") });

    assert.equal(await announce(company, "metadata"), "shown");
    assert.equal(await announce(company, "metadata"), "already_shown");
    assert.equal(await announce(company, "full"), "shown");
    assert.equal(await announce(company, "full"), "already_shown");
    // Enrolled again as a new machine: a first notice, not a change.
    assert.equal(await announce({ ...company, machineId: "machine-new" }, "full"), "shown");

    assert.deepEqual(sent, [
      {
        title: "Phigon is recording AI agent activity",
        body: "Your company turned on Phigon on this computer (Engineering laptops). It records which AI agents run and what kinds of actions they take, not what they say. Ask your IT team for details.",
      },
      {
        title: "Phigon changed what it records on this computer",
        body: "Your company turned on Phigon on this computer (Engineering laptops). It records what AI agents do here, including prompts, replies and commands. Ask your IT team for details.",
      },
      {
        title: "Phigon is recording AI agent activity",
        body: "Your company turned on Phigon on this computer (Engineering laptops). It records what AI agents do here, including prompts, replies and commands. Ask your IT team for details.",
      },
    ]);
    const remembered = JSON.parse(await readFile(join(dataDirectory, collectionNoticeFileName), "utf8")) as unknown;
    assert.deepEqual(remembered, { machineId: "machine-new", profile: "full", shownAt: "2026-11-02T10:00:00.000Z" });
    if (process.platform !== "win32") {
      assert.equal((await stat(join(dataDirectory, collectionNoticeFileName))).mode & 0o777, 0o600);
    }
    assert.deepEqual(await readdir(dataDirectory), [collectionNoticeFileName]);
  });
});

test("a computer whose owner consented at pairing gets no notice", async () => {
  await withDirectory(async (dataDirectory) => {
    const sent: UserNotice[] = [];
    for (const credential of [owner, { ...owner, consentSource: "owner" as const }]) {
      assert.equal(
        await announceCompanyCollection({ dataDirectory, credential, profile: "metadata", notices: recording(sent) }),
        "owner_consented",
      );
    }
    assert.deepEqual(sent, []);
    assert.deepEqual(await readdir(dataDirectory), []);
  });
});

test("with notices off, or when the system cannot show one, nothing is remembered and it is tried again", async () => {
  await withDirectory(async (dataDirectory) => {
    const sent: UserNotice[] = [];
    assert.equal(
      await announceCompanyCollection({ dataDirectory, credential: company, profile: "metadata", notices: recording(sent, false) }),
      "not_shown",
    );
    const failing = new UserNotices({ enabled: true, send: async () => { throw new Error("no desktop session"); } });
    assert.equal(
      await announceCompanyCollection({ dataDirectory, credential: company, profile: "metadata", notices: failing }),
      "not_shown",
    );
    assert.deepEqual(await readdir(dataDirectory), []);
    assert.equal(
      await announceCompanyCollection({ dataDirectory, credential: company, profile: "metadata", notices: recording(sent) }),
      "shown",
    );
    assert.equal(sent.length, 1);
  });
});

test("a damaged record shows the notice again, and a label is kept short or left out", async () => {
  await withDirectory(async (dataDirectory) => {
    await writeFile(join(dataDirectory, collectionNoticeFileName), "{\"machineId\":", "utf8");
    const sent: UserNotice[] = [];
    const label = `${"Very long label ".repeat(10)}end`;
    assert.equal(
      await announceCompanyCollection({
        dataDirectory, credential: { ...company, enrollmentCodeLabel: label }, profile: "metadata", notices: recording(sent),
      }),
      "shown",
    );
    const { enrollmentCodeLabel: _label, ...unlabelled } = company;
    assert.equal(_label, "Engineering laptops");
    assert.equal(
      await announceCompanyCollection({
        dataDirectory, credential: { ...unlabelled, machineId: "machine-unlabelled" }, profile: "metadata", notices: recording(sent),
      }),
      "shown",
    );
    assert.match(sent[0]?.body ?? "", /^Your company turned on Phigon on this computer \(Very long label [^)]{30,}…\)\. It records/u);
    assert.ok((sent[0]?.body.length ?? 0) <= 240);
    assert.match(sent[0]?.body ?? "", /Ask your IT team for details\.$/u);
    assert.equal(
      sent[1]?.body,
      "Your company turned on Phigon on this computer. It records which AI agents run and what kinds of actions they take, not what they say. Ask your IT team for details.",
    );
  });
});
