import assert from "node:assert/strict";
import { mkdtemp, writeFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { spawnSync } from "node:child_process";
import { applicationControlFiles } from "./windows-app-control.mjs";

const configuration = { mode: "enforce", user_or_group_sid: "S-1-5-21-100-200-300-1001", applications: [{ path: "C:\\Program Files\\Example\\agent.exe", rule_type: "hash" }] };
const files = applicationControlFiles(configuration);
assert.equal(Object.keys(files).length, 5);
assert.deepEqual(JSON.parse(files["applications.json"]), configuration);
// Paths stay JSON data, including PowerShell interpolation characters.
const literal = "C:\\Example\\$(not-a-command)`literal.exe";
const escaped = applicationControlFiles({ ...configuration, applications: [{ path: literal, rule_type: "publisher" }] });
assert.equal(JSON.parse(escaped["applications.json"]).applications[0].path, literal);
for (const [name, script] of Object.entries(escaped)) if (name.endsWith(".ps1")) assert.ok(!script.includes(literal));
for (const patch of [{ mode: "unknown" }, { user_or_group_sid: "Everyone; injected" }, { applications: [] }, { applications: Array.from({ length: 65 }, () => configuration.applications[0]) }]) {
  assert.throws(() => applicationControlFiles({ ...configuration, ...patch }));
}
for (const path of ["agent.exe", "C:\\*\\agent.exe", "C:\\[test]\\agent.exe", "C:\\x\\..\\agent.exe", "C:\\x\n\\agent.exe", "C:\\x\\agent.cmd", "\\\\server\\share\\agent.exe"]) {
  assert.throws(() => applicationControlFiles({ ...configuration, applications: [{ path, rule_type: "hash" }] }));
}
assert.throws(() => applicationControlFiles({ ...configuration, applications: [...configuration.applications, { ...configuration.applications[0], path: configuration.applications[0].path.toUpperCase() }] }));

if (process.platform === "win32") {
  const directory = await mkdtemp(join(tmpdir(), "phigon-app-policy-"));
  try {
    for (const [name, script] of Object.entries(files)) await writeFile(join(directory, name), script);
    const checker = join(directory, "Check-Syntax.ps1");
    await writeFile(checker, `param([string]$Directory)
$ErrorActionPreference = 'Stop'
foreach ($file in Get-ChildItem -LiteralPath $Directory -Filter '*GuardianAppControl.ps1') {
  $parseTokens = $null; $parseErrors = $null
  [System.Management.Automation.Language.Parser]::ParseFile($file.FullName, [ref]$parseTokens, [ref]$parseErrors) | Out-Null
  if ($parseErrors.Count -ne 0) { throw ($parseErrors | Out-String) }
}
`);
    const result = spawnSync("powershell.exe", ["-NoProfile", "-NonInteractive", "-File", checker, "-Directory", directory], { encoding: "utf8", windowsHide: true });
    assert.equal(result.status, 0, result.stderr || result.error?.message);
  } finally {
    // mkdtemp returned this task's own isolated directory, never a configuration path.
    await rm(directory, { recursive: true, force: true });
  }
}
process.stdout.write("Guardian application-control configuration and generated script syntax verified; no OS policy applied.\n");
