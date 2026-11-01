import { spawn } from "node:child_process";
import { join } from "node:path";

/** What the person at this computer is told when Phigon acts on it. */
export type UserNotice = Readonly<{ title: string; body: string }>;

export type NoticeSender = (notice: UserNotice) => Promise<void>;

const repeatWindowMs = 60_000;
const textLimit = 240;

/**
 * Tells the person at this computer what Phigon did to it: an agent stopped,
 * a command run, the computer about to restart. Notices are best effort: a
 * computer with no desktop session, or an observer running as a service
 * with no access to it, shows nothing, and a notice never affects the action.
 */
export class UserNotices {
  readonly #send: NoticeSender | undefined;
  readonly #now: () => number;
  readonly #recent = new Map<string, number>();

  constructor(options: Readonly<{ enabled: boolean; send?: NoticeSender; now?: () => number }>) {
    this.#send = options.enabled ? options.send ?? platformNoticeSender() : undefined;
    this.#now = options.now ?? Date.now;
  }

  /** An agent Phigon stopped, because someone asked or a rule said so. */
  agentStopped(input: Readonly<{ key: string; agent: string; forced: boolean; reason: string }>): void {
    this.#show(input.key, {
      title: `${input.agent} was ${input.forced ? "force-stopped" : "stopped"} by Phigon`,
      body: input.reason.trim() || "Your workspace administrator's rules stopped it.",
    });
  }

  /** A blocked agent Phigon stopped as soon as it started. */
  agentBlocked(input: Readonly<{ key: string; agent: string; reason: string }>): void {
    this.#show(input.key, {
      title: `${input.agent} was stopped by Phigon`,
      body: input.reason.trim() || `${input.agent} is blocked on this computer by your workspace administrator.`,
    });
  }

  commandRan(input: Readonly<{ key: string; program: string; reason: string }>): void {
    this.#show(input.key, {
      title: `Phigon ran ${input.program} on this computer`,
      body: input.reason.trim() || "Your workspace administrator asked for it.",
    });
  }

  powerChange(input: Readonly<{ key: string; restart: boolean; reason: string }>): void {
    this.#show(input.key, {
      title: `Phigon will ${input.restart ? "restart" : "shut down"} this computer in 1 minute`,
      body: `Save your work now. ${input.reason.trim()}`.trim(),
    });
  }

  #show(key: string, notice: UserNotice): void {
    if (this.#send === undefined) return;
    const now = this.#now();
    for (const [seen, at] of this.#recent) if (now - at > repeatWindowMs) this.#recent.delete(seen);
    // A retried action or a review that sees the same process again is
    // announced once.
    if (this.#recent.has(key)) return;
    this.#recent.set(key, now);
    void this.#send({ title: plainText(notice.title, 120), body: plainText(notice.body, textLimit) }).catch(() => undefined);
  }
}

/** One line of plain text: no control characters, and bounded. */
export function plainText(value: string, limit: number): string {
  const text = value.replace(/[\u0000-\u001f\u007f]+/gu, " ").replace(/\s+/gu, " ").trim();
  return text.length <= limit ? text : `${text.slice(0, limit - 1)}…`;
}

/** The name people know an agent by: "Claude Code · PID 4120" is "Claude Code". */
export function noticeAgentName(displayName: string): string {
  return displayName.split(" · ")[0]?.trim() || "An AI agent";
}

/**
 * The operating system's own notification, shown without a shell. The text
 * travels in environment variables, never in the command line or a script.
 */
export function platformNoticeSender(platform: NodeJS.Platform = process.platform): NoticeSender | undefined {
  switch (platform) {
    case "win32":
      return (notice) => run(
        join(process.env["SystemRoot"] ?? "C:\\Windows", "System32", "WindowsPowerShell", "v1.0", "powershell.exe"),
        ["-NoProfile", "-NonInteractive", "-WindowStyle", "Hidden", "-Command", windowsToastScript],
        notice,
      );
    case "darwin":
      return (notice) => run("/usr/bin/osascript", [
        "-e", 'display notification (system attribute "PHIGON_NOTICE_BODY") with title (system attribute "PHIGON_NOTICE_TITLE")',
      ], notice);
    case "linux":
      return (notice) => run("notify-send", ["--app-name=Phigon", "--", notice.title, notice.body], notice);
    default:
      return undefined;
  }
}

// Windows PowerShell's own app id is registered on every Windows 10 and 11,
// so its toasts show without installing anything.
const windowsToastScript = [
  "$ErrorActionPreference = 'Stop'",
  "[void][Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime]",
  "[void][Windows.Data.Xml.Dom.XmlDocument, Windows.Data.Xml.Dom.XmlDocument, ContentType = WindowsRuntime]",
  "$title = [System.Security.SecurityElement]::Escape($env:PHIGON_NOTICE_TITLE)",
  "$body = [System.Security.SecurityElement]::Escape($env:PHIGON_NOTICE_BODY)",
  "$xml = New-Object Windows.Data.Xml.Dom.XmlDocument",
  "$xml.LoadXml(\"<toast><visual><binding template='ToastGeneric'><text>$title</text><text>$body</text></binding></visual></toast>\")",
  "$app = '{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\\WindowsPowerShell\\v1.0\\powershell.exe'",
  "[Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier($app).Show([Windows.UI.Notifications.ToastNotification]::new($xml))",
].join("; ");

function run(executable: string, args: readonly string[], notice: UserNotice): Promise<void> {
  return new Promise((resolve, reject) => {
    const child = spawn(executable, args, {
      env: { ...process.env, PHIGON_NOTICE_TITLE: notice.title, PHIGON_NOTICE_BODY: notice.body },
      stdio: "ignore", windowsHide: true, shell: false,
    });
    const timer = setTimeout(() => child.kill(), 15_000);
    child.once("error", (error) => { clearTimeout(timer); reject(error); });
    child.once("exit", (code) => {
      clearTimeout(timer);
      if (code === 0) resolve();
      else reject(new Error(`notice exited with ${String(code)}`));
    });
  });
}
