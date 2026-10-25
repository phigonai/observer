import { AgentKind } from "../../generated/phigon/v1/common_pb.js";
import type { CustomAgentRegistry } from "../../custom-agent-registry.js";
import {
  combineAdapterResults,
  discoverKnownAgent,
  type KnownAgentSpec,
} from "../known-agent.js";
import type { AgentDiscoveryAdapter } from "../types.js";

export function customAgentAdapter(
  registry: CustomAgentRegistry,
): AgentDiscoveryAdapter {
  return {
    id: "custom",
    async discover(evidence, observedAt) {
      const registrations = await registry.list();
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
      return combineAdapterResults("custom", results);
    },
  };
}
