import { randomUUID } from "node:crypto";
import { chmod, readFile, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { atomicReplace } from "./atomic-replace.js";
import { consentSourceOf, type StoredMachineCredential } from "./credential-store.js";
import type { UserNotices } from "./user-notices.js";

/**
 * Remembers which collection the person at this computer was told about,
 * so the start-of-collection notice shows once, and again only when what
 * is collected changes.
 */
export const collectionNoticeFileName = "collection-notice.json";

type AnnouncedCollection = Readonly<{
  machineId: string;
  profile: "metadata" | "full";
  shownAt: string;
}>;

export type CollectionNoticeOutcome =
  /** The owner consented at the keyboard; there is nothing to announce. */
  | "owner_consented"
  /** This collection was announced before. */
  | "already_shown"
  /** Handed to the system; it is not shown again. */
  | "shown"
  /** Notices are off, or the system could not show one: tried again next start. */
  | "not_shown";

/**
 * Tells the person at a computer whose company consented for it, with a
 * system notification, that Phigon records AI agent activity here: once
 * when collection starts, and again when the profile changes. A computer
 * whose owner consented at pairing was already told by the pairing prompt,
 * so it gets no notice. With PHIGON_USER_NOTICES=false nothing is shown
 * and nothing is remembered, so turning notices on later shows it then.
 */
export async function announceCompanyCollection(options: Readonly<{
  dataDirectory: string;
  credential: StoredMachineCredential;
  /** What this run collects: the local profile, within the consent. */
  profile: "metadata" | "full";
  notices: UserNotices;
  now?: () => Date;
}>): Promise<CollectionNoticeOutcome> {
  if (consentSourceOf(options.credential) !== "company") return "owner_consented";
  const path = join(options.dataDirectory, collectionNoticeFileName);
  const announced = await readAnnounced(path);
  const sameMachine = announced?.machineId === options.credential.machineId;
  if (sameMachine && announced?.profile === options.profile) return "already_shown";
  const shown = await options.notices.collectionStarted({
    profile: options.profile,
    changed: sameMachine,
    ...(options.credential.enrollmentCodeLabel === undefined
      ? {}
      : { label: options.credential.enrollmentCodeLabel }),
  });
  if (!shown) return "not_shown";
  await writeAnnounced(path, {
    machineId: options.credential.machineId,
    profile: options.profile,
    shownAt: (options.now ?? (() => new Date()))().toISOString(),
  });
  return "shown";
}

async function readAnnounced(path: string): Promise<AnnouncedCollection | undefined> {
  let value: unknown;
  try {
    value = JSON.parse(await readFile(path, "utf8"));
  } catch {
    // Missing or unreadable: the notice is shown again, which is harmless.
    return undefined;
  }
  if (
    typeof value === "object" && value !== null &&
    "machineId" in value && typeof value.machineId === "string" &&
    "profile" in value && (value.profile === "metadata" || value.profile === "full") &&
    "shownAt" in value && typeof value.shownAt === "string"
  ) {
    return { machineId: value.machineId, profile: value.profile, shownAt: value.shownAt };
  }
  return undefined;
}

async function writeAnnounced(path: string, value: AnnouncedCollection): Promise<void> {
  const temporary = `${path}.${process.pid}.${randomUUID()}.tmp`;
  try {
    await writeFile(temporary, `${JSON.stringify(value)}\n`, { encoding: "utf8", flag: "wx", mode: 0o600 });
    await atomicReplace(temporary, path);
    await chmod(path, 0o600);
  } catch (error) {
    await rm(temporary, { force: true });
    throw error;
  }
}
