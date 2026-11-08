import { watch } from "node:fs";
import { readdir, realpath, stat } from "node:fs/promises";
import { basename, dirname, isAbsolute, join } from "node:path";

const maxDirectoryDepth = 8;
const maxListedFiles = 16_384;
// A tree this large is walked afresh on every call instead of being kept.
const maxTrackedFiles = 65_536;
const maxTrackedDirectories = 16_384;
const maxDirtyPaths = 1_024;
const maxEventsBetweenScans = 10_000;

export type FileIdentity = Readonly<{
  size: number;
  dev: number;
  ino: number;
  birthtimeMs: number;
}>;

export type ListedFile = Readonly<{
  path: string;
  modifiedMs: number;
  identity: FileIdentity;
}>;

type Entry = Readonly<{ name: string; directory: boolean; file: boolean }>;
type Metadata = Readonly<{
  directory: boolean;
  file: boolean;
  mtimeMs: number;
  size: number;
  dev: number;
  ino: number;
  birthtimeMs: number;
}>;
type Watcher = Readonly<{ close: () => void }>;

/** What the listing needs from the file system; tests count the calls. */
export type LiveListingFileSystem = Readonly<{
  stat: (path: string) => Promise<Metadata>;
  readdir: (path: string) => Promise<readonly Entry[]>;
  realpath: (path: string) => Promise<string>;
  /**
   * Watches a folder and everything below it. Undefined where the system
   * cannot (Linux has no recursive watch of its own).
   */
  watch?: (
    root: string,
    onChange: (event: string, filename: string | null) => void,
    onError: () => void,
  ) => Watcher;
}>;

export const nodeListingFileSystem: LiveListingFileSystem = {
  stat: async (path) => {
    const metadata = await stat(path);
    return {
      directory: metadata.isDirectory(),
      file: metadata.isFile(),
      mtimeMs: metadata.mtimeMs,
      size: metadata.size,
      dev: metadata.dev,
      ino: metadata.ino,
      birthtimeMs: metadata.birthtimeMs,
    };
  },
  readdir: async (path) => (await readdir(path, { withFileTypes: true }))
    .map((entry) => ({ name: entry.name, directory: entry.isDirectory(), file: entry.isFile() })),
  realpath: (path) => realpath(path),
  ...(process.platform === "win32" || process.platform === "darwin"
    ? {
      watch: (root, onChange, onError) => {
        // Never keeps the process alive; closed with the listing.
        const watcher = watch(root, { recursive: true, persistent: false }, (event, filename) => {
          onChange(event, filename === null ? null : String(filename));
        });
        watcher.on("error", onError);
        return watcher;
      },
    }
    : {}),
};

type DirectoryNode = {
  mtimeMs: number;
  listedAt: number;
  /** When this listing saw the folder change; -Infinity before that. */
  changedAt: number;
  files: string[];
  directories: string[];
};

type FileNode = {
  listed: ListedFile;
  changedAt: number;
};

type Tree = {
  readonly root: string;
  realRoot: string | undefined;
  readonly directories: Map<string, DirectoryNode>;
  readonly files: Map<string, FileNode>;
  checkedAt: number;
  relistedAt: number;
  watcher: Watcher | undefined;
  watchRetryAt: number;
  dirty: Set<string>;
  /** Folders a watch reported an entry added, removed or renamed in. */
  renamed: Set<string>;
  allDirty: boolean;
  /** Watch reports since the last pass. */
  events: number;
  /** Too large to keep: walked afresh on every call. */
  untracked: boolean;
  /** The last result, and the files it was sorted from in walk order. */
  walked: readonly ListedFile[];
  result: readonly ListedFile[];
};

/**
 * The JSONL files under live activity roots, kept between scans so an idle
 * scan touches almost nothing on disk. Listing every folder and checking
 * every file each second cost about a sixth of a core on Windows with a few
 * hundred saved sessions, where each check opens the file.
 *
 * - A folder or file that changed in the last ten minutes is hot: it is
 *   checked on every call, so an agent at work is followed as before, and a
 *   new session in an active folder is found on the next scan. A folder is
 *   listed again only when its modified time moved (adding, removing or
 *   renaming an entry moves it) or while that time is too recent to trust.
 * - Everything else is checked by a full pass every ten seconds on Windows
 *   and every three seconds elsewhere, where a check is far cheaper.
 * - On Windows and macOS each root is also watched. A change the system
 *   reports is checked on the next call, and while the watch works the full
 *   pass runs once a minute. A watch is only a hint: it can miss changes (a
 *   network drive, a full event buffer), so the full pass still bounds how
 *   long any new or grown file can go unseen. A watch that fails is closed
 *   and the shorter full pass applies until it is set up again.
 * - Every folder is listed afresh every five minutes in any case.
 * - A root that does not exist is looked for again every five seconds.
 */
export class LiveFileListing {
  static readonly hotMs = 10 * 60_000;
  static readonly settleMs = 2_000;
  static readonly watchedFullCheckMs = 60_000;
  static readonly unwatchedFullCheckMs = process.platform === "win32" ? 10_000 : 3_000;
  static readonly relistMs = 5 * 60_000;
  static readonly missingRootCheckMs = 5_000;
  static readonly watchRetryMs = 60_000;

  readonly #fs: LiveListingFileSystem;
  readonly #now: () => number;
  readonly #unwatchedFullCheckMs: number;
  readonly #trees = new Map<string, Tree>();
  // Roots found missing, with when they were looked for.
  readonly #missing = new Map<string, number>();
  // Whether other sources' roots exist, with when that was looked at.
  readonly #presence = new Map<string, Readonly<{ present: boolean; checkedAt: number }>>();
  // Results of the current scan, so a root that several sources share is
  // checked once per scan.
  #scanResults = new Map<string, readonly ListedFile[]>();
  #hintListeners = new Set<() => void>();
  #hinted = false;

  constructor(options: Readonly<{
    fileSystem?: LiveListingFileSystem;
    now?: () => number;
    unwatchedFullCheckMs?: number;
  }> = {}) {
    this.#fs = options.fileSystem ?? nodeListingFileSystem;
    this.#now = options.now ?? Date.now;
    this.#unwatchedFullCheckMs = options.unwatchedFullCheckMs ?? LiveFileListing.unwatchedFullCheckMs;
  }

  /** Starts a scan: each root is checked again on its next `list`. */
  beginScan(): void {
    this.#scanResults = new Map();
  }

  /** The root's JSONL files, newest first, at most 16,384. */
  async list(root: string): Promise<readonly ListedFile[]> {
    const memo = this.#scanResults.get(root);
    if (memo !== undefined) return memo;
    const now = this.#now();
    let tree = this.#trees.get(root);
    if (tree === undefined) {
      const lookedAt = this.#missing.get(root);
      if (lookedAt !== undefined && now >= lookedAt && now - lookedAt < LiveFileListing.missingRootCheckMs) {
        this.#scanResults.set(root, []);
        return [];
      }
      tree = newTree(root);
    }
    let files: readonly ListedFile[] | undefined;
    try {
      files = await this.#refresh(tree, now);
    } catch (error) {
      this.#forget(root);
      throw error;
    }
    if (files === undefined) {
      this.#forget(root);
      this.#missing.set(root, now);
      files = [];
    } else {
      this.#missing.delete(root);
      this.#trees.set(root, tree);
    }
    this.#scanResults.set(root, files);
    return files;
  }

  /**
   * The roots that exist, for sources this listing does not walk (agent
   * databases and JSON documents). Each root is looked at again at most
   * every five seconds, so the many agents that are not installed cost
   * nothing between.
   */
  async existing(roots: readonly string[]): Promise<string[]> {
    const now = this.#now();
    const result: string[] = [];
    for (const root of roots) {
      const known = this.#presence.get(root);
      let present = known?.present ?? false;
      if (
        known === undefined || now < known.checkedAt ||
        now - known.checkedAt >= LiveFileListing.missingRootCheckMs
      ) {
        present = await optional(this.#fs.stat(root)) !== undefined;
        this.#presence.set(root, { present, checkedAt: now });
      }
      if (present) result.push(root);
    }
    return result;
  }

  /** The root's canonical path, resolved again with each full pass. */
  async realRoot(root: string): Promise<string> {
    const tree = this.#trees.get(root);
    if (tree?.realRoot !== undefined) return tree.realRoot;
    const resolved = await this.#fs.realpath(root);
    if (tree !== undefined) tree.realRoot = resolved;
    return resolved;
  }

  /** Forgets roots no longer configured and closes their watches. */
  retain(roots: ReadonlySet<string>): void {
    for (const root of [...this.#trees.keys()]) {
      if (!roots.has(root)) this.#forget(root);
    }
    for (const root of [...this.#missing.keys()]) {
      if (!roots.has(root)) this.#missing.delete(root);
    }
    for (const root of [...this.#presence.keys()]) {
      if (!roots.has(root)) this.#presence.delete(root);
    }
  }

  /** Closes every watch. A later `list` sets them up again. */
  close(): void {
    for (const root of [...this.#trees.keys()]) this.#forget(root);
    this.#missing.clear();
    this.#presence.clear();
  }

  /**
   * Called whenever a watch reports a change, at most once between scans,
   * so a resting collector can scan at once. Returns its removal.
   */
  onHint(listener: () => void): () => void {
    this.#hintListeners.add(listener);
    return () => this.#hintListeners.delete(listener);
  }

  /** Whether a watch reported a change that `takeHint` has not taken. */
  hinted(): boolean {
    return this.#hinted;
  }

  /** Whether a watch reported a change since the last call. */
  takeHint(): boolean {
    const hinted = this.#hinted;
    this.#hinted = false;
    return hinted;
  }

  metrics(): Readonly<{ roots: number; watchedRoots: number; files: number; directories: number }> {
    let watchedRoots = 0;
    let files = 0;
    let directories = 0;
    for (const tree of this.#trees.values()) {
      if (tree.watcher !== undefined) watchedRoots++;
      files += tree.files.size;
      directories += tree.directories.size;
    }
    return { roots: this.#trees.size, watchedRoots, files, directories };
  }

  async #refresh(tree: Tree, now: number): Promise<readonly ListedFile[] | undefined> {
    if (tree.untracked) {
      const rootMetadata = await optional(this.#fs.stat(tree.root));
      if (rootMetadata?.directory !== true) return undefined;
      return listJSONLFiles(tree.root, this.#fs);
    }
    const watched = tree.watcher !== undefined;
    const fullEvery = watched ? LiveFileListing.watchedFullCheckMs : this.#unwatchedFullCheckMs;
    const full = tree.allDirty || now < tree.checkedAt || now - tree.checkedAt >= fullEvery;
    const relist = now < tree.relistedAt || now - tree.relistedAt >= LiveFileListing.relistMs;
    const dirty = tree.dirty;
    const renamed = tree.renamed;
    tree.dirty = new Set();
    tree.renamed = new Set();
    tree.allDirty = false;
    tree.events = 0;
    const hot = (modifiedMs: number, changedAt: number) =>
      now - Math.max(modifiedMs, changedAt) < LiveFileListing.hotMs;
    const result: ListedFile[] = [];

    const forgetDirectory = (path: string) => {
      const node = tree.directories.get(path);
      tree.directories.delete(path);
      if (node === undefined) return;
      for (const file of node.files) tree.files.delete(file);
      for (const child of node.directories) forgetDirectory(child);
    };

    const visit = async (path: string, depth: number): Promise<boolean> => {
      if (depth > maxDirectoryDepth) return true;
      let node = tree.directories.get(path);
      if (
        node === undefined || full || relist || dirty.has(path) ||
        hot(node.mtimeMs, node.changedAt) ||
        node.listedAt - node.mtimeMs < LiveFileListing.settleMs
      ) {
        const metadata = await optional(this.#fs.stat(path));
        if (metadata?.directory !== true) {
          forgetDirectory(path);
          return false;
        }
        // A folder a watch reported an entry added, removed or renamed in is
        // listed again even when its modified time did not move: a coarse
        // clock can hide the change. Other reports only check it, since
        // listing a folder can itself be reported (its access time).
        if (
          node === undefined || relist || renamed.has(path) || metadata.mtimeMs !== node.mtimeMs ||
          node.listedAt - node.mtimeMs < LiveFileListing.settleMs
        ) {
          // Checked before listing: an entry added while listing moves the time on.
          const entries = await optional(this.#fs.readdir(path));
          if (entries === undefined) {
            forgetDirectory(path);
            return false;
          }
          const files: string[] = [];
          const directories: string[] = [];
          for (const entry of entries) {
            const child = join(path, entry.name);
            if (entry.directory) directories.push(child);
            else if (entry.file && entry.name.toLowerCase().endsWith(".jsonl")) files.push(child);
          }
          if (node !== undefined) {
            const keptFiles = new Set(files);
            for (const file of node.files) if (!keptFiles.has(file)) tree.files.delete(file);
            const keptDirectories = new Set(directories);
            for (const child of node.directories) if (!keptDirectories.has(child)) forgetDirectory(child);
          }
          node = {
            mtimeMs: metadata.mtimeMs,
            listedAt: now,
            changedAt: node === undefined
              ? Number.NEGATIVE_INFINITY
              : metadata.mtimeMs !== node.mtimeMs ? now : node.changedAt,
            files,
            directories,
          };
          tree.directories.set(path, node);
        }
      }
      // Watched from before its folders are read, once the root exists.
      // Whatever changed before the watch started is checked by a full
      // pass, this one or the next.
      if (depth === 0 && tree.watcher === undefined && this.#watch(tree, now) && !full) {
        tree.allDirty = true;
      }
      for (const child of node.directories) await visit(child, depth + 1);
      for (const file of node.files) {
        let fileNode = tree.files.get(file);
        if (
          fileNode === undefined || full || dirty.has(file) ||
          hot(fileNode.listed.modifiedMs, fileNode.changedAt)
        ) {
          const metadata = await optional(this.#fs.stat(file));
          if (metadata === undefined) {
            tree.files.delete(file);
            continue;
          }
          const listed: ListedFile = {
            path: file,
            modifiedMs: metadata.mtimeMs,
            identity: {
              size: metadata.size,
              dev: metadata.dev,
              ino: metadata.ino,
              birthtimeMs: metadata.birthtimeMs,
            },
          };
          if (fileNode === undefined) {
            fileNode = { listed, changedAt: Number.NEGATIVE_INFINITY };
            tree.files.set(file, fileNode);
          } else if (!sameListing(fileNode.listed, listed)) {
            fileNode.listed = listed;
            fileNode.changedAt = now;
          }
        }
        result.push(fileNode.listed);
      }
      return true;
    };

    if (!await visit(tree.root, 0)) return undefined;
    if (full) {
      tree.checkedAt = now;
      tree.realRoot = undefined;
    }
    if (relist) tree.relistedAt = now;
    if (tree.files.size > maxTrackedFiles || tree.directories.size > maxTrackedDirectories) {
      // Bounded memory: a tree this large is listed afresh each time.
      this.#closeWatch(tree);
      tree.files.clear();
      tree.directories.clear();
      tree.untracked = true;
      tree.walked = [];
      tree.result = [];
      return result.sort(recentFileFirst).slice(0, maxListedFiles);
    }
    // Unchanged files keep their objects, so an unchanged tree returns the
    // same array and callers can reuse what they derived from it.
    if (sameFiles(result, tree.walked)) return tree.result;
    tree.walked = result;
    tree.result = [...result].sort(recentFileFirst).slice(0, maxListedFiles);
    return tree.result;
  }

  /** Whether the root is watched; sets the watch up when it is due. */
  #watch(tree: Tree, now: number): boolean {
    if (tree.watcher !== undefined) return true;
    const start = this.#fs.watch;
    if (start === undefined || now < tree.watchRetryAt) return false;
    tree.watchRetryAt = now + LiveFileListing.watchRetryMs;
    try {
      const watcher = start(
        tree.root,
        (event, filename) => {
          // Reports still queued for a watch that was closed are dropped.
          if (tree.watcher === watcher) this.#changed(tree, event, filename);
        },
        () => {
          // Closed at once; the full pass covers what it may have missed.
          if (tree.watcher === watcher) this.#closeWatch(tree);
          tree.allDirty = true;
        },
      );
      tree.watcher = watcher;
    } catch {
      return false;
    }
    return true;
  }

  #changed(tree: Tree, event: string, filename: string | null): void {
    tree.events++;
    if (filename !== null && isAbsolute(filename)) {
      // The root itself was removed or renamed. On Windows its watch then
      // reports that without end, spinning a core and keeping the process
      // alive, so it is closed at once; the next pass looks for the root.
      this.#closeWatch(tree);
      tree.allDirty = true;
    } else if (tree.events > maxEventsBetweenScans) {
      // A watch reporting far more than any agent writes is not helping.
      this.#closeWatch(tree);
      tree.allDirty = true;
    } else if (filename === null || filename === "") {
      // A report that lost what changed (a full event buffer): check and
      // list everything again.
      tree.allDirty = true;
      tree.relistedAt = Number.NEGATIVE_INFINITY;
    } else if (!tree.allDirty) {
      const path = join(tree.root, filename);
      tree.dirty.add(path);
      // An entry added, removed or renamed changes its folder's listing.
      if (event === "rename") {
        tree.dirty.add(dirname(path));
        tree.renamed.add(dirname(path));
      }
      if (tree.dirty.size > maxDirtyPaths) {
        tree.dirty.clear();
        tree.renamed.clear();
        tree.allDirty = true;
        tree.relistedAt = Number.NEGATIVE_INFINITY;
      }
    }
    if (this.#hinted) return;
    this.#hinted = true;
    for (const listener of this.#hintListeners) listener();
  }

  #closeWatch(tree: Tree): void {
    const watcher = tree.watcher;
    tree.watcher = undefined;
    try {
      watcher?.close();
    } catch {
      // Already closed.
    }
  }

  #forget(root: string): void {
    const tree = this.#trees.get(root);
    this.#trees.delete(root);
    if (tree !== undefined) this.#closeWatch(tree);
  }
}

function newTree(root: string): Tree {
  return {
    root,
    realRoot: undefined,
    directories: new Map(),
    files: new Map(),
    checkedAt: Number.NEGATIVE_INFINITY,
    relistedAt: Number.NEGATIVE_INFINITY,
    watcher: undefined,
    watchRetryAt: Number.NEGATIVE_INFINITY,
    dirty: new Set(),
    renamed: new Set(),
    allDirty: false,
    events: 0,
    untracked: false,
    walked: [],
    result: [],
  };
}

function sameFiles(left: readonly ListedFile[], right: readonly ListedFile[]): boolean {
  if (left.length !== right.length) return false;
  for (let index = 0; index < left.length; index++) {
    if (left[index] !== right[index]) return false;
  }
  return true;
}

function sameListing(left: ListedFile, right: ListedFile): boolean {
  return left.modifiedMs === right.modifiedMs &&
    left.identity.size === right.identity.size &&
    left.identity.dev === right.identity.dev &&
    left.identity.ino === right.identity.ino &&
    left.identity.birthtimeMs === right.identity.birthtimeMs;
}

/**
 * Every JSONL file under `root`, newest first, at most 16,384, listing each
 * folder and checking each file. Live collection keeps these between scans
 * with LiveFileListing; history imports walk afresh.
 */
export async function listJSONLFiles(
  root: string,
  fileSystem: LiveListingFileSystem = nodeListingFileSystem,
): Promise<ListedFile[]> {
  const rootMetadata = await optional(fileSystem.stat(root));
  if (rootMetadata?.directory !== true) return [];
  const result: ListedFile[] = [];
  const walk = async (directory: string, depth: number): Promise<void> => {
    if (depth > maxDirectoryDepth) return;
    const entries = await optional(fileSystem.readdir(directory));
    if (entries === undefined) return;
    for (const entry of entries) {
      const path = join(directory, entry.name);
      if (entry.directory) await walk(path, depth + 1);
      else if (entry.file && basename(entry.name).toLowerCase().endsWith(".jsonl")) {
        const metadata = await optional(fileSystem.stat(path));
        if (metadata === undefined) continue;
        result.push({
          path,
          modifiedMs: metadata.mtimeMs,
          identity: {
            size: metadata.size,
            dev: metadata.dev,
            ino: metadata.ino,
            birthtimeMs: metadata.birthtimeMs,
          },
        });
        if (result.length > maxListedFiles * 2) {
          result.sort(recentFileFirst);
          result.length = maxListedFiles;
        }
      }
    }
  };
  await walk(root, 0);
  return result.sort(recentFileFirst).slice(0, maxListedFiles);
}

export function recentFileFirst(
  left: Readonly<{ path: string; modifiedMs: number }>,
  right: Readonly<{ path: string; modifiedMs: number }>,
): number {
  return (
    right.modifiedMs - left.modifiedMs || left.path.localeCompare(right.path)
  );
}

/** The value, or undefined when the path is gone or not readable. */
async function optional<T>(work: Promise<T>): Promise<T | undefined> {
  try {
    return await work;
  } catch (error) {
    if (
      error instanceof Error && "code" in error &&
      ["ENOENT", "EACCES", "EPERM", "ENOTDIR"].includes(String((error as NodeJS.ErrnoException).code))
    ) {
      return undefined;
    }
    throw error;
  }
}
