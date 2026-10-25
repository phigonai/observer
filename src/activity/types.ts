import type {
  AgentKind,
  PrivacyClass,
} from "../generated/phigon/v1/common_pb.js";
import type { EventEnvelope } from "../generated/phigon/v1/telemetry_pb.js";
import type { LocalPolicyEngine } from "./policy.js";

export type ActivityDraft = Readonly<{
  agentKind: AgentKind;
  sessionId: string;
  observedAt: Date;
  privacyClass: PrivacyClass;
  payload: EventEnvelope["payload"];
}>;

export type ParseContext = Readonly<{
  sessionId: string;
  observedAt: Date;
  policy: LocalPolicyEngine;
}>;

export interface VendorActivityAdapter {
  readonly id: string;
  readonly agentKind: AgentKind;
  parse(record: unknown, context: ParseContext): readonly ActivityDraft[];
}
