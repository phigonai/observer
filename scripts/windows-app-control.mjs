// Generates a reviewable AppLocker deployment package. Rendering never changes
// the current machine's policy, services, registry, or firewall.
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

export function applicationControlFiles(config) {
  if (!config || !["audit", "enforce"].includes(config.mode) || !/^S-1-\d+(?:-\d+)+$/u.test(config.user_or_group_sid ?? "") ||
      !Array.isArray(config.applications) || config.applications.length < 1 || config.applications.length > 64) throw new Error("Application control requires an explicit mode, account/group SID and 1–64 applications.");
  const seen = new Set();
  for (const app of config.applications) {
    if (!app || typeof app.path !== "string" || !/^[A-Za-z]:[\\/].+\.exe$/iu.test(app.path) || /[\u0000-\u001f<>"|?*%\[\]]/u.test(app.path) || /(?:^|[\\/])\.{1,2}(?:[\\/]|$)/u.test(app.path) ||
        !["hash", "publisher"].includes(app.rule_type) || seen.has(app.path.toLowerCase())) throw new Error("Applications require unique absolute .exe paths and hash/publisher rule types.");
    seen.add(app.path.toLowerCase());
  }
  const settings = JSON.stringify({ mode: config.mode, user_or_group_sid: config.user_or_group_sid, applications: config.applications }, null, 2);
  return {
    "applications.json": settings + "\n",
    "Build-GuardianAppControl.ps1": `# Windows PowerShell with the AppLocker module. Generates files only.
$ErrorActionPreference = 'Stop'
Import-Module AppLocker -ErrorAction Stop
$configuration = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'applications.json') -Raw | ConvertFrom-Json
$previousPath = Join-Path $PSScriptRoot 'previous-policy.xml'
$policyPath = Join-Path $PSScriptRoot 'guardian-policy.xml'
if ((Test-Path -LiteralPath $previousPath) -or (Test-Path -LiteralPath $policyPath)) { throw 'Use a fresh deployment directory; existing review artifacts will not be overwritten.' }
$previous = Get-AppLockerPolicy -Local -Xml
[xml]$policy = $previous
$mode = if ($configuration.mode -eq 'enforce') { 'Enabled' } else { 'AuditOnly' }
$collection = $policy.SelectSingleNode('/AppLockerPolicy/RuleCollection[@Type="Exe"]')
if (-not $collection) {
  $collection = $policy.CreateElement('RuleCollection')
  $collection.SetAttribute('Type','Exe')
  $policy.DocumentElement.AppendChild($collection) | Out-Null
}
$existingRules = @($collection.SelectNodes('FilePathRule|FileHashRule|FilePublisherRule'))
if ($existingRules.Count -gt 0 -and $collection.EnforcementMode -ne $mode) { throw 'Existing EXE rules use another enforcement mode. Review that policy through company device management before combining it.' }
$collection.SetAttribute('EnforcementMode',$mode)
if ($existingRules.Count -eq 0) {
  # A deny-only deployment must not accidentally become a machine allowlist.
  $allow = $policy.CreateElement('FilePathRule')
  $allow.SetAttribute('Id',[guid]::NewGuid().ToString()); $allow.SetAttribute('Name','Preserve other application access')
  $allow.SetAttribute('Description','Initial default for an otherwise empty EXE collection')
  $allow.SetAttribute('UserOrGroupSid','S-1-1-0'); $allow.SetAttribute('Action','Allow')
  $conditions = $policy.CreateElement('Conditions'); $path = $policy.CreateElement('FilePathCondition'); $path.SetAttribute('Path','*')
  $conditions.AppendChild($path) | Out-Null; $allow.AppendChild($conditions) | Out-Null; $collection.AppendChild($allow) | Out-Null
}
foreach ($app in $configuration.applications) {
  if (-not (Test-Path -LiteralPath $app.path -PathType Leaf)) { throw 'A selected application is missing from this reference machine.' }
  $information = Get-AppLockerFileInformation -Path $app.path
  [xml]$generated = New-AppLockerPolicy -FileInformation $information -RuleType $app.rule_type -User $configuration.user_or_group_sid -Xml
  $rules = @($generated.SelectNodes('/AppLockerPolicy/RuleCollection[@Type="Exe"]/FileHashRule|/AppLockerPolicy/RuleCollection[@Type="Exe"]/FilePublisherRule'))
  if ($rules.Count -eq 0) { throw 'No specific application rule could be generated. Publisher rules require signed application identity.' }
  foreach ($rule in $rules) {
    if (($app.rule_type -eq 'hash' -and $rule.LocalName -ne 'FileHashRule') -or ($app.rule_type -eq 'publisher' -and $rule.LocalName -ne 'FilePublisherRule')) { throw 'Generated application identity does not match the requested rule type.' }
    if ($app.rule_type -eq 'publisher') {
      $identity = $rule.Conditions.FilePublisherCondition
      if (-not $identity) { throw 'Publisher identity is missing.' }
      foreach ($part in @($identity.PublisherName, $identity.ProductName, $identity.BinaryName)) {
        if ([string]::IsNullOrWhiteSpace($part) -or $part.Contains('*') -or $part.Contains('?')) { throw 'Publisher identity must identify one application, not an entire software publisher.' }
      }
      $identity.BinaryVersionRange.SetAttribute('LowSection','0.0.0.0'); $identity.BinaryVersionRange.SetAttribute('HighSection','*')
    }
    $rule.SetAttribute('Action','Deny'); $rule.SetAttribute('Name','Phigon Guardian: application prohibited')
    $collection.AppendChild($policy.ImportNode($rule,$true)) | Out-Null
  }
}
$previous | Set-Content -LiteralPath $previousPath -Encoding UTF8
$policy.Save($policyPath)
Write-Output 'Review guardian-policy.xml and previous-policy.xml before deploying. No OS policy has been applied.'
`,
    "Apply-GuardianAppControl.ps1": `# Deploy the reviewed package as administrator using company device management.
$ErrorActionPreference = 'Stop'
Import-Module AppLocker -ErrorAction Stop
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
if (-not ([Security.Principal.WindowsPrincipal]$identity).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Administrator deployment is required.' }
[xml]$expected = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'previous-policy.xml') -Raw
[xml]$current = Get-AppLockerPolicy -Local -Xml
if ($current.OuterXml -ne $expected.OuterXml) { throw 'Local policy changed after review. Rebuild against the current policy; no changes applied.' }
Set-Service -Name AppIDSvc -StartupType Automatic
Start-Service -Name AppIDSvc
Set-AppLockerPolicy -XmlPolicy (Join-Path $PSScriptRoot 'guardian-policy.xml')
& (Join-Path $PSScriptRoot 'Verify-GuardianAppControl.ps1')
`,
    "Verify-GuardianAppControl.ps1": `param([string]$UserSid)
$ErrorActionPreference = 'Stop'
Import-Module AppLocker -ErrorAction Stop
$configuration = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'applications.json') -Raw | ConvertFrom-Json
if ([string]::IsNullOrWhiteSpace($UserSid)) { $UserSid = $configuration.user_or_group_sid }
if ($UserSid -notmatch '^S-1-\\d+(-\\d+)+$') { throw 'Verification requires an account SID.' }
$effective = Get-AppLockerPolicy -Effective
[xml]$xml = Get-AppLockerPolicy -Effective -Xml
$collection = $xml.SelectSingleNode('/AppLockerPolicy/RuleCollection[@Type="Exe"]')
$decisions = @($effective | Test-AppLockerPolicy -Path @($configuration.applications | ForEach-Object { $_.path }) -User $UserSid)
$denied = @($decisions | Where-Object { $_.PolicyDecision -eq 'Denied' -or $_.PolicyDecision -eq 'DeniedByDefault' })
$verified = $collection.EnforcementMode -eq 'Enabled' -and (Get-Service -Name AppIDSvc).Status -eq 'Running' -and $denied.Count -eq $configuration.applications.Count
@{ evidence='effective_os_policy'; policy_verified=$verified; tested_identity=$UserSid; mode=$collection.EnforcementMode; checked_applications=$decisions.Count; runtime_test_required=$true } | ConvertTo-Json
if ($configuration.mode -eq 'enforce' -and -not $verified) { throw 'Effective enforcement does not match this deployment. Check domain/MDM policy and OS support.' }
`,
    "Rollback-GuardianAppControl.ps1": `$ErrorActionPreference = 'Stop'
Import-Module AppLocker -ErrorAction Stop
[xml]$deployed = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'guardian-policy.xml') -Raw
[xml]$current = Get-AppLockerPolicy -Local -Xml
if ($current.OuterXml -ne $deployed.OuterXml) { throw 'Local policy changed after deployment. Automatic rollback would overwrite other administrator changes.' }
Set-AppLockerPolicy -XmlPolicy (Join-Path $PSScriptRoot 'previous-policy.xml')
Write-Output 'Previous local application policy restored. Application Identity service remains available for other company policies.'
`,
  };
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const [configPath, output] = process.argv.slice(2);
  if (!configPath || !output) throw new Error("Usage: node windows-app-control.mjs <applications.json> <output-directory>");
  const files = applicationControlFiles(JSON.parse(await readFile(configPath, "utf8")));
  const directory = resolve(output); await mkdir(directory, { recursive: true, mode: 0o700 });
  for (const [name, content] of Object.entries(files)) await writeFile(join(directory, name), content, { flag: "wx", mode: 0o600 });
  process.stdout.write(`Generated ${Object.keys(files).length} application-control artifacts in ${directory}.\n`);
}
