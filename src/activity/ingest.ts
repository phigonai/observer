import { randomUUID } from "node:crypto";
import {
  chmod,
  mkdir,
  open,
  unlink,
} from "node:fs/promises";
import { join } from "node:path";
import { createInterface } from "node:readline";
import type { Readable } from "node:stream";
import { activityBridgeAgent } from "./bridges.js";

const maxLineBytes = 1 << 20;

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
  await chmod(options.dataDirectory, 0o700);
  await chmod(bridgeRoot, 0o700);
  await chmod(agentRoot, 0o700);
  const target = join(
    agentRoot,
    `${Date.now()}-${randomUUID()}.jsonl`,
  );
  const handle = await open(target, "wx", 0o600);
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
  }
  if (records === 0) {
    await unlink(target);
  } else {
    await chmod(target, 0o600);
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
