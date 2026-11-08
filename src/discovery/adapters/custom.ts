import { AgentKind } from "../../generated/phigon/v1/common_pb.js";
import type { CustomAgentRegistry } from "../../custom-agent-registry.js";
import {
  combineAdapterResults,
  discoverKnownAgent,
  type KnownAgentSpec,
} from "../known-agent.js";
import type { AgentDiscoveryAdapter } from "../types.js";

/**
 * Sent with the inventory when definitions were skipped. The local warning
 * and `doctor` name the file and the reason; this says only what to do.
 */
export const customAgentProblemNotice =
  "Some custom agent definitions on this computer could not be used and were skipped; run phigon-observer doctor there.";

export function customAgentAdapter(
  registry: CustomAgentRegistry,
): AgentDiscoveryAdapter {
  return {
    id: "custom",
    async discover(evidence, observedAt) {
      // A damaged file skips the definitions it holds, never discovery.
      const { agents: registrations, problem } = await registry.read();
      const results = await Promise.all(
        registrations.map((registration) => {
          const spec: KnownAgentSpec = {
            id: `custom:${registration.id}`,
            kind: AgentKind.GENERIC,
            displayName: registration.displayName,
            executableNames: registration.executableNames,
            processNames: registration.processNames,
            configurationPaths: registration.configurationPaths,
            capabilities: registration.capabilities,
          };
          return discoverKnownAgent(spec, evidence, observedAt);
        }),
      );
      const combined = combineAdapterResults("custom", results);
      if (problem === undefined) return combined;
      // Skipped definitions leave coverage incomplete: their runtimes are
      // unknown, not stopped.
      return {
        ...combined,
        health: {
          adapterId: "custom",
          status: "error",
          notices: [customAgentProblemNotice, ...combined.health.notices].slice(0, 32),
        },
      };
    },
  };
}
