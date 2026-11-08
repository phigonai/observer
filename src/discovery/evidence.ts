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
  // For an interpreter process (node, bun, deno): the npm package that owns
  // the script it runs, such as `@google/gemini-cli`. Only this name is kept;
  // the command line it was read from is never stored or sent.
  scriptPackage?: string;
}>;

export type ExecutableEvidence = Readonly<{
  executableName: string;
  executablePathDigest: string;
  version: string;
  /** The npm package the command runs, when its version came from it. */
  packageName?: string;
  /**
   * The first line its `--version` printed, at most 128 characters, such as
   * "GitHub Copilot CLI 1.0.41.". Kept on this computer only, to tell an
   * agent's command from another program's with the same name.
   */
  versionBanner?: string;
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
