import { makeDirectoryPrivate } from "./private-directory.js";
import { chmod, mkdir, open, readdir, stat, unlink } from "node:fs/promises";
import { join } from "node:path";
import { bridgePolicyFingerprint, bridgeStorageOptions } from "./activity/bridge-privacy.js";
import { parseLosslessJSON, storableRecord, type StorableRecordOptions } from "./activity/policy.js";

/** Journals the observer writes into the generic activity bridge. */
export const guardianDecisionJournal = "guardian-decisions";
export const managedCommandJournal = "guardian-managed-commands";
type JournalName = typeof guardianDecisionJournal | typeof managedCommandJournal;

/** Each segment of Guardian's decision journal, as a path within its bridge. */
export const guardianDecisionFilePattern = `${guardianDecisionJournal}(?:-\\d{1,16})?\\.jsonl`;

/**
 * Marks the identity of Guardian's decision journal, which is Phigon's own and
 * not an agent. Only the observer sets it, from where the records were read;
 * nothing a record says, and no custom agent, can claim it.
 */
export const phigonGuardianCapability = "phigon-guardian";

// A journal starts a new file past this size, and keeps about this much in
// all when nothing reads it.
const segmentBytes = 4 << 20;
const maxJournalBytes = 10 << 20;

type Segment = Readonly<{ name: string; journal: JournalName; ordinal: number }>;

/**
 * An append-only JSONL journal in a bridge directory, read by the activity
 * collector like any other bridge file. It is written in segments: a full
 * segment is left as it is and later records go to a new file. A file is
 * never renamed or truncated, because the collector's read position belongs
 * to a path: the first segment keeps the journal's plain name, later ones
 * add the time they were started. The collector deletes a closed segment
 * once its records are delivered. If nothing reads the journal, the oldest
 * closed segments are deleted here to keep it near 10 MiB.
 */
export class SegmentedJournal {
  readonly #dataDirectory: string;
  readonly #journal: JournalName;
  readonly #segmentBytes: number;
  readonly #maxBytes: number;
  #storageOptions: StorableRecordOptions | undefined;
  #storageFingerprint = "";

  constructor(
    dataDirectory: string,
    journal: JournalName,
    limits: Readonly<{ segmentBytes?: number; maxBytes?: number }> = {},
  ) {
    this.#dataDirectory = dataDirectory;
    this.#journal = journal;
    this.#segmentBytes = limits.segmentBytes ?? segmentBytes;
    this.#maxBytes = limits.maxBytes ?? maxJournalBytes;
  }

  /**
   * Appends one record, `encoded` JSON without its newline. Like an ingested
   * record it waits on disk for the collector, so its secrets are redacted
   * and, unless content may be collected, only its metadata is kept.
   */
  async append(encoded: string, options: Readonly<{ sync?: boolean }> = {}): Promise<void> {
    const bridges = join(this.#dataDirectory, "bridges");
    const directory = join(bridges, "generic");
    await mkdir(directory, { recursive: true, mode: 0o700 });
    await makeDirectoryPrivate(this.#dataDirectory);
    await chmod(bridges, 0o700);
    await chmod(directory, 0o700);
    const stored = storableRecord(parseLosslessJSON(encoded), await this.#storage());
    const line = `${JSON.stringify(stored)}\n`;
    const path = join(directory, await this.#segmentFor(directory, Buffer.byteLength(line)));
    const handle = await open(path, "a", 0o600);
    try {
      await handle.write(line);
      if (options.sync === true) await handle.sync();
    } finally {
      await handle.close();
    }
    await chmod(path, 0o600);
  }

  /**
   * How records are stored. The policy is read again as soon as the consent
   * or the service settings change, so a narrowed consent applies to the
   * very next record; the check is a stat of each file. The fingerprint is
   * taken before the policy is read, so a change during the read is caught
   * by the next record.
   */
  async #storage(): Promise<StorableRecordOptions> {
    const fingerprint = await bridgePolicyFingerprint(this.#dataDirectory);
    if (this.#storageOptions === undefined || fingerprint !== this.#storageFingerprint) {
      this.#storageOptions = await bridgeStorageOptions(this.#dataDirectory, process.env);
      this.#storageFingerprint = fingerprint;
    }
    return this.#storageOptions;
  }

  /** The segment that takes the next `bytes`, started when the last is full. */
  async #segmentFor(directory: string, bytes: number): Promise<string> {
    const segments = journalSegments(await readdir(directory))
      .filter((segment) => segment.journal === this.#journal);
    const current = segments.at(-1);
    if (current === undefined) return `${this.#journal}.jsonl`;
    const size = await sizeOf(join(directory, current.name));
    if (size === 0 || size + bytes <= this.#segmentBytes) return current.name;
    // Keep the newest closed segments within the bound, leaving room for
    // the new one; anything older was not read in time.
    let kept = 0;
    for (const segment of [...segments].reverse()) {
      kept += await sizeOf(join(directory, segment.name));
      if (kept + this.#segmentBytes <= this.#maxBytes || segment === current) continue;
      await unlink(join(directory, segment.name)).catch(() => undefined);
    }
    return `${this.#journal}-${Math.max(Date.now(), current.ordinal + 1)}.jsonl`;
  }
}

/**
 * The journal segments among `names` that no longer receive records: every
 * segment but the newest of its journal.
 */
export function closedJournalSegments(names: readonly string[]): readonly string[] {
  const segments = journalSegments(names);
  const newest = new Map<JournalName, string>();
  for (const segment of segments) newest.set(segment.journal, segment.name);
  return segments
    .filter((segment) => newest.get(segment.journal) !== segment.name)
    .map((segment) => segment.name);
}

/** The journal segments among `names`, oldest first within each journal. */
function journalSegments(names: readonly string[]): Segment[] {
  const segments: Segment[] = [];
  for (const name of names) {
    const match = /^(guardian-decisions|guardian-managed-commands)(?:-(\d{1,16}))?\.jsonl$/u.exec(name);
    if (match === null) continue;
    segments.push({
      name,
      journal: match[1] as JournalName,
      ordinal: match[2] === undefined ? 0 : Number(match[2]),
    });
  }
  return segments.sort((left, right) => left.ordinal - right.ordinal);
}

async function sizeOf(path: string): Promise<number> {
  try {
    return (await stat(path)).size;
  } catch (error) {
    if (error instanceof Error && "code" in error && error.code === "ENOENT") return 0;
    throw error;
  }
}
