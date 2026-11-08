import type { AgentDetection, DetectionEvidence } from "./types.js";

/**
 * `discover --explain`: why each agent was reported, from which adapter and
 * how sure discovery is, then what was set aside. Only names of programs,
 * process IDs, versions and the configuration paths the adapters look for
 * are shown; nothing here is sent anywhere.
 */
export function formatDetections(detections: readonly AgentDetection[]): string {
  const reported = detections.filter((detection) => detection.reported);
  const setAside = detections.filter((detection) => !detection.reported);
  const lines = [
    "Why each agent was detected:",
    ...(reported.length === 0 ? ["  Nothing was detected."] : reported.flatMap(describe)),
  ];
  if (setAside.length > 0) {
    lines.push("", "Set aside, not reported:", ...setAside.flatMap(describe));
  }
  return `${lines.join("\n")}\n`;
}

function describe(detection: AgentDetection): string[] {
  const identifying = detection.evidence.filter((item) => item.identifying);
  const nameOnly = detection.evidence.filter((item) => !item.identifying);
  return [
    `${detection.displayName} (adapter ${detection.adapterId})`,
    ...(detection.reported
      ? [`  Confidence: ${detection.confidence}. Can be stopped from Phigon: ${
        detection.stoppable ? "yes, when this computer allows remote actions" : "no"
      }.`]
      : []),
    ...(identifying.length === 0 ? [] : [`  Evidence: ${list(identifying)}`]),
    ...(nameOnly.length === 0 ? [] : [`  Name only, not proof: ${list(nameOnly)}`]),
    ...detection.notes.map((note) => `  Note: ${note}`),
  ];
}

function list(evidence: readonly DetectionEvidence[]): string {
  return evidence.map((item) => item.detail).join("; ");
}
