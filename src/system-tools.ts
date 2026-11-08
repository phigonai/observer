import { win32 } from "node:path";

/**
 * Windows looks for a program named without a folder in the current folder
 * before PATH, so a file left there (the folder an agent works in, or a
 * download) would run instead of the system's own tool. The observer starts
 * Windows' tools by their full path under %SystemRoot%.
 */
export function windowsSystemRoot(environment: NodeJS.ProcessEnv = process.env): string {
  const configured = (environment["SystemRoot"] ?? environment["SYSTEMROOT"])?.trim();
  // Only a folder on a local drive, such as C:\Windows; anything else (a
  // relative or network path) is not where Windows keeps its tools.
  return configured !== undefined && /^[A-Za-z]:\\[^"<>|?*]*$/u.test(configured)
    ? win32.normalize(configured).replace(/\\+$/u, "")
    : "C:\\Windows";
}

/** A tool in %SystemRoot%\System32, such as icacls.exe or whoami.exe. */
export function windowsSystemTool(name: string, environment: NodeJS.ProcessEnv = process.env): string {
  return win32.join(windowsSystemRoot(environment), "System32", name);
}

/** Windows PowerShell 5.1, which every supported Windows has. */
export function windowsPowerShell(environment: NodeJS.ProcessEnv = process.env): string {
  return win32.join(windowsSystemRoot(environment), "System32", "WindowsPowerShell", "v1.0", "powershell.exe");
}
