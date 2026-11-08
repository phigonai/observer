import assert from "node:assert/strict";
import { readdir, readFile } from "node:fs/promises";
import { join } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { restrictCommand } from "../src/private-directory.js";
import { windowsPowerShell, windowsSystemRoot, windowsSystemTool } from "../src/system-tools.js";

test("Windows tools are started by their full path under SystemRoot, never found in the current folder", () => {
  assert.equal(windowsSystemTool("icacls.exe", { SystemRoot: "D:\\Win" }), "D:\\Win\\System32\\icacls.exe");
  assert.equal(windowsSystemTool("whoami.exe", { SystemRoot: "C:\\Windows\\" }), "C:\\Windows\\System32\\whoami.exe");
  assert.equal(windowsPowerShell({ SYSTEMROOT: "C:\\Windows" }), "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe");
  // Anything but a folder on a local drive falls back to where Windows keeps them.
  for (const value of [undefined, "", "Windows", ".\\Windows", "\\\\server\\share", "/usr/lib", "C:Windows"]) {
    assert.equal(windowsSystemRoot(value === undefined ? {} : { SystemRoot: value }), "C:\\Windows", String(value));
  }
  assert.equal(restrictCommand("C:\\data", "*S-1-5-21-1").file.toLowerCase(), `${windowsSystemRoot().toLowerCase()}\\system32\\icacls.exe`);
});

test("no source starts a Windows system tool by its bare name", async () => {
  const source = fileURLToPath(new URL("../../src/", import.meta.url));
  const files: string[] = [];
  const walk = async (directory: string): Promise<void> => {
    for (const entry of await readdir(directory, { withFileTypes: true })) {
      const path = join(directory, entry.name);
      if (entry.isDirectory()) {
        if (entry.name !== "generated") await walk(path);
      } else if (entry.name.endsWith(".ts") && entry.name !== "system-tools.ts") {
        files.push(path);
      }
    }
  };
  await walk(source);
  assert.ok(files.length > 20);
  // A bare name is a literal that is neither a path segment (one after a
  // comma) nor given to windowsSystemTool.
  const bare = /(?<!(?:,\s*|windowsSystemTool\())"(?:powershell|icacls|whoami)(?:\.exe)?"/giu;
  const found: string[] = [];
  for (const file of files) {
    for (const match of (await readFile(file, "utf8")).matchAll(bare)) found.push(`${file}: ${match[0]}`);
  }
  assert.deepEqual(found, []);
});
