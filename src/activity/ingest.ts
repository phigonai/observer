import { makeDirectoryPrivate } from "../private-directory.js";
import { randomUUID } from "node:crypto";
import {
  chmod,
  mkdir,
  open,
  readdir,
  stat,
  unlink,
} from "node:fs/promises";
import { join } from "node:path";
import { createInterface } from "node:readline";
import type { Readable } from "node:stream";
import { activityBridgeAgent, activityBridgeAgents } from "./bridges.js";

const maxLineBytes = 1 << 20;
// Bridge files wait for the collector, which deletes them once delivered.
// While no observer runs, agent hooks keep adding files that can hold
// activity content, so past these limits the oldest are deleted.
const maxIngestedBytes = 100 << 20;
const maxIngestedFiles = 2_000;
// A writing marker this old was left by an ingest run that did not finish.
const abandonedWritingMs = 3_600_000;

export type IngestLimits = Readonly<{ maxBytes?: number; maxFiles?: number }>;

/** Beside a bridge file that an `ingest` run is still writing. */
export const bridgeWritingSuffix = ".writing";

/** A file written by one `ingest` run. */
export const ingestedBridgeFile =
  /^\d{1,16}-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\.jsonl$/u;

export type ActivityIngestResult = Readonly<{
  agent: string;
  agentName?: string;
  records: number;
  malformed: number;
  oversized: number;
}>;

export async function ingestActivityJSONL(options: Readonly<{
  agent: string;
  agentName?: string;
  dataDirectory: string;
  input: Readable;
  limits?: IngestLimits;
}>): Promise<ActivityIngestResult> {
  const requestedAgent = options.agent.trim().toLowerCase();
  const customAgentName = requestedAgent === "custom"
    ? validatedAgentName(options.agentName)
    : undefined;
  if (requestedAgent !== "custom" && options.agentName !== undefined) {
    throw new Error("ingest --name is supported only with --agent custom.");
  }
  const agent = activityBridgeAgent(
    requestedAgent === "custom" ? "generic" : requestedAgent,
  );
  if (agent === undefined) {
    throw new Error(
      "ingest --agent must name a supported activity bridge or generic.",
    );
  }
  const bridgeRoot = join(options.dataDirectory, "bridges");
  const agentRoot = join(bridgeRoot, agent.id);
  await mkdir(agentRoot, { recursive: true, mode: 0o700 });
  await makeDirectoryPrivate(options.dataDirectory);
  await chmod(bridgeRoot, 0o700);
  await chmod(agentRoot, 0o700);
  const target = join(
    agentRoot,
    `${Date.now()}-${randomUUID()}.jsonl`,
  );
  // The collector deletes bridge files it has delivered. This marker, which
  // it does not read as activity, says the file may still grow.
  const writing = `${target}${bridgeWritingSuffix}`;
  await (await open(writing, "wx", 0o600)).close();
  let handle;
  try {
    handle = await open(target, "wx", 0o600);
  } catch (error) {
    await unlink(writing);
    throw error;
  }
  let records = 0;
  let malformed = 0;
  let oversized = 0;
  try {
    const lines = createInterface({
      input: options.input,
      crlfDelay: Infinity,
      terminal: false,
    });
    for await (const line of lines) {
      if (line.trim() === "") continue;
      if (Buffer.byteLength(line, "utf8") > maxLineBytes) {
        oversized++;
        continue;
      }
      let serialized = line;
      try {
        const value: unknown = JSON.parse(line);
        if (customAgentName !== undefined) {
          if (
            typeof value !== "object" ||
            value === null ||
            Array.isArray(value)
          ) {
            malformed++;
            continue;
          }
          const existingName = (value as Record<string, unknown>)[
            "phigon_agent_name"
          ];
          if (
            existingName !== undefined &&
            existingName !== customAgentName
          ) {
            malformed++;
            continue;
          }
          serialized = JSON.stringify({
            ...value,
            phigon_agent_name: customAgentName,
          });
        }
      } catch {
        malformed++;
        continue;
      }
      await handle.write(`${serialized}\n`);
      records++;
    }
    await handle.sync();
  } finally {
    await handle.close();
    await unlink(writing).catch(() => undefined);
  }
  if (records === 0) {
    await unlink(target);
  } else {
    await chmod(target, 0o600);
    // Cleanup only frees disk space; the next run tries again.
    await pruneIngestedFiles(bridgeRoot, target, options.limits ?? {})
      .catch(() => undefined);
  }
  return Object.freeze({
    agent: agent.id,
    ...(customAgentName === undefined
      ? {}
      : { agentName: customAgentName }),
    records,
    malformed,
    oversized,
  });
}

/**
 * Deletes the oldest `ingest` files, across every bridge, until the rest fit
 * the byte and file limits. The file just written, and files another run is
 * still writing, stay.
 */
async function pruneIngestedFiles(
  bridgeRoot: string,
  keep: string,
  limits: IngestLimits,
): Promise<void> {
  const maxBytes = limits.maxBytes ?? maxIngestedBytes;
  const maxFiles = limits.maxFiles ?? maxIngestedFiles;
  const now = Date.now();
  const files: Array<{ path: string; bytes: number; createdAt: number; removable: boolean }> = [];
  for (const agent of activityBridgeAgents) {
    const root = join(bridgeRoot, agent.id);
    let names: string[];
    try {
      names = await readdir(root);
    } catch {
      continue;
    }
    const present = new Set(names);
    for (const name of names) {
      if (!ingestedBridgeFile.test(name)) continue;
      const path = join(root, name);
      let bytes: number;
      let modifiedMs: number;
      try {
        ({ size: bytes, mtimeMs: modifiedMs } = await stat(path));
      } catch {
        continue;
      }
      const writing = present.has(`${name}${bridgeWritingSuffix}`) &&
        now - modifiedMs < abandonedWritingMs;
      files.push({
        path,
        bytes,
        // The name starts with the time the run started.
        createdAt: Number(name.slice(0, name.indexOf("-"))),
        removable: path !== keep && !writing,
      });
    }
  }
  let bytes = files.reduce((total, file) => total + file.bytes, 0);
  let count = files.length;
  files.sort((left, right) => left.createdAt - right.createdAt);
  for (const file of files) {
    if (bytes <= maxBytes && count <= maxFiles) return;
    if (!file.removable) continue;
    try {
      await unlink(file.path);
    } catch {
      // Gone already, or locked by another program.
      continue;
    }
    await unlink(`${file.path}${bridgeWritingSuffix}`).catch(() => undefined);
    bytes -= file.bytes;
    count--;
  }
}

function validatedAgentName(value: string | undefined): string {
  const name = value?.trim() ?? "";
  if (
    name.length === 0 ||
    Buffer.byteLength(name, "utf8") > 128 ||
    /[\u0000-\u001f\u007f]/u.test(name) ||
    !/[\p{L}\p{N}]/u.test(name)
  ) {
    throw new Error(
      "ingest --agent custom requires --name with 1-128 printable characters.",
    );
  }
  return name;
}
