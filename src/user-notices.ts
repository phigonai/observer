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
  // Start-of-command notices still being handed over, by action. Each is
  // removed once handed over, so the map holds only commands under way.
  readonly #starting = new Map<string, Promise<void>>();

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

  /**
   * An administrator's command about to start. The command never waits for
   * the notice; the one said when it ends follows this one. It names only
   * what that one names: the program and the administrator's reason.
   */
  commandStarting(input: Readonly<{ key: string; program: string; reason: string }>): void {
    const shown = this.#show(`${input.key}:start`, {
      title: `Phigon is running ${input.program} on this computer`,
      body: input.reason.trim() || "Your workspace administrator asked for it.",
    });
    if (shown === undefined) return;
    this.#starting.set(input.key, shown);
    void shown.then(() => {
      if (this.#starting.get(input.key) === shown) this.#starting.delete(input.key);
    });
  }

  commandRan(input: Readonly<{ key: string; program: string; reason: string }>): void {
    this.#show(input.key, {
      title: `Phigon ran ${input.program} on this computer`,
      body: input.reason.trim() || "Your workspace administrator asked for it.",
    }, this.#startedNotice(input.key));
  }

  /** A command announced as starting that the system could not start. */
  commandNotStarted(input: Readonly<{ key: string; program: string }>): void {
    this.#show(input.key, {
      title: `Phigon could not run ${input.program} on this computer`,
      body: "Nothing ran.",
    }, this.#startedNotice(input.key));
  }

  #startedNotice(key: string): Promise<void> | undefined {
    const started = this.#starting.get(key);
    this.#starting.delete(key);
    return started;
  }

  powerChange(input: Readonly<{ key: string; restart: boolean; reason: string }>): void {
    this.#show(input.key, {
      title: `Phigon will ${input.restart ? "restart" : "shut down"} this computer in 1 minute`,
      body: `Save your work now. ${input.reason.trim()}`.trim(),
    });
  }

  /**
   * Tells the person at a computer whose company consented for it that
   * Phigon records AI agent activity here, and what. Resolves to whether
   * the notice was handed to the system, so the caller can try again on
   * the next start when it was not.
   */
  async collectionStarted(input: Readonly<{ profile: "metadata" | "full"; label?: string; changed: boolean }>): Promise<boolean> {
    if (this.#send === undefined) return false;
    const label = input.label === undefined ? "" : plainText(input.label, 60);
    const what = input.profile === "full"
      ? "It records what AI agents do here, including prompts, replies and commands."
      : "It records which AI agents run and what kinds of actions they take, not what they say.";
    try {
      await this.#send({
        title: input.changed ? "Phigon changed what it records on this computer" : "Phigon is recording AI agent activity",
        body: plainText(
          `Your company turned on Phigon on this computer${label === "" ? "" : ` (${label})`}. ${what} Ask your IT team for details.`,
          textLimit,
        ),
      });
      return true;
    } catch {
      return false;
    }
  }

  /**
   * Hands the notice to the system, after `after` when given, so a notice
   * that a command ended never shows before the one that it started.
   * Resolves once it was handed over or failed; it never rejects.
   */
  #show(key: string, notice: UserNotice, after?: Promise<void>): Promise<void> | undefined {
    const send = this.#send;
    if (send === undefined) return undefined;
    const now = this.#now();
    for (const [seen, at] of this.#recent) if (now - at > repeatWindowMs) this.#recent.delete(seen);
    // A retried action or a review that sees the same process again is
    // announced once.
    if (this.#recent.has(key)) return undefined;
    this.#recent.set(key, now);
    const bounded = { title: plainText(notice.title, 120), body: plainText(notice.body, textLimit) };
    return (after === undefined ? send(bounded) : after.then(() => send(bounded))).catch(() => undefined);
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
