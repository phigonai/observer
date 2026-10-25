export type ProbeStatus = "ok" | "permission_denied" | "unknown";

export type ProbeResult<T> =
  | Readonly<{ status: "ok"; value: T }>
  | Readonly<{
      status: "permission_denied" | "unknown";
      notice: string;
    }>;

export type ProcessEvidence = Readonly<{
  // Opaque process-lifetime identity derived from native start evidence.
  // processId remains display metadata and is never a durable key.
  processKey: string;
  processId: number;
  startedAt: Date;
  executableName: string;
  executablePathDigest: string;
}>;

export type ExecutableEvidence = Readonly<{
  executableName: string;
  executablePathDigest: string;
  version: string;
}>;

export type ConfigurationEvidence = Readonly<{
  identifierDigest: string;
}>;

export interface HostEvidenceProvider {
  listProcesses(): Promise<ProbeResult<readonly ProcessEvidence[]>>;
  inspectExecutable(
    candidates: readonly string[],
  ): Promise<ProbeResult<ExecutableEvidence | null>>;
  inspectConfiguration(
    candidates: readonly string[],
  ): Promise<ProbeResult<readonly ConfigurationEvidence[]>>;
}
