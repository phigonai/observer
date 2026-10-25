#!/usr/bin/env node
// Produces reviewable deployment files. It never modifies services or firewalls
// on the developer's machine. Run the generated installer through company MDM.
import { access, mkdir, readFile, writeFile } from "node:fs/promises";
import { join, posix, resolve, win32 } from "node:path";
import { fileURLToPath } from "node:url";

export function serviceFiles(config) {
  const { platform, node, observer, dataDirectory, controlPlane, grpc, serviceUser = "phigon" } = config;
  if (!["windows", "linux", "darwin"].includes(platform)) throw new Error("Unsupported managed platform.");
  const absolute = platform === "windows" ? (value) => /^[A-Za-z]:[\\/]/u.test(value) : posix.isAbsolute;
  for (const path of [node, observer, dataDirectory]) {
    if (typeof path !== "string" || !absolute(path) || /[\u0000\r\n%]/u.test(path)) throw new Error("Managed deployment requires absolute paths without control characters or expansion markers.");
    if (platform === "windows" && /[<>"|?*']/u.test(path)) throw new Error("Windows deployment paths contain unsupported characters.");
  }
  const targetPaths = platform === "windows" ? win32 : posix;
  if (targetPaths.normalize(dataDirectory) === targetPaths.parse(dataDirectory).root) throw new Error("Guardian data requires its own directory, never a filesystem root.");
  for (const endpoint of [controlPlane, grpc]) {
    if (typeof endpoint !== "string" || /[\u0000\r\n]/u.test(endpoint)) throw new Error("Invalid managed endpoint.");
    const url = new URL(endpoint);
    if (url.protocol !== "https:" || url.username || url.password || url.search || url.hash) throw new Error("Managed endpoints require HTTPS without embedded credentials.");
  }
  if (!/^[a-z_][a-z0-9_-]{0,31}$/u.test(serviceUser)) throw new Error("Invalid service account.");
  const ps = (value) => "'" + value.replaceAll("'", "''") + "'";
  if (platform === "windows") {
    return { "install-guardian.ps1": `# Run as administrator through your company's device management.
$ErrorActionPreference = 'Stop'
$taskNode = ${ps(node)}
$taskObserver = ${ps(observer)}
$taskData = ${ps(dataDirectory)}
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
if (-not ([Security.Principal.WindowsPrincipal]$identity).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Administrator deployment is required.' }
if (-not (Test-Path -LiteralPath $taskNode -PathType Leaf) -or -not (Test-Path -LiteralPath $taskObserver -PathType Leaf)) { throw 'Install and verify the release before registering Guardian.' }
$taskAncestor = [IO.Path]::GetFullPath($taskData)
while ($taskAncestor) {
  if ((Test-Path -LiteralPath $taskAncestor) -and ((Get-Item -LiteralPath $taskAncestor -Force).Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'Guardian data path must not traverse reparse points.' }
  $taskAncestor = Split-Path -Path $taskAncestor -Parent
}
[IO.Directory]::CreateDirectory($taskData) | Out-Null
& "$env:SystemRoot\\System32\\icacls.exe" $taskData /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Guardian data ACL could not be secured.' }
# Existing explicit grants are not removed by icacls /grant:r. Reject an
# insecure enrollment directory instead of starting with exposed credentials.
$taskPaths = @((Get-Item -LiteralPath $taskData -Force)) + @(Get-ChildItem -LiteralPath $taskData -Force -Recurse)
foreach ($taskPath in $taskPaths) {
  if ($taskPath.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Guardian data must not contain reparse points.' }
  $taskAcl = Get-Acl -LiteralPath $taskPath.FullName
  foreach ($taskRule in $taskAcl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])) {
    if ($taskRule.AccessControlType -eq [Security.AccessControl.AccessControlType]::Allow -and $taskRule.IdentityReference.Value -notin @('S-1-5-18', 'S-1-5-32-544')) { throw 'Remove non-administrator data access before starting Guardian.' }
  }
  if ($taskAcl.GetOwner([Security.Principal.SecurityIdentifier]).Value -notin @('S-1-5-18', 'S-1-5-32-544')) { throw 'Guardian data ownership must belong to SYSTEM or Administrators.' }
}
# A SYSTEM startup task supervises process review. Per-user collection paths and
# machine pairing must be provisioned separately into the protected data path.
$taskArguments = '"' + $taskObserver + '" run'
$taskAction = New-ScheduledTaskAction -Execute $taskNode -Argument $taskArguments
$taskTrigger = New-ScheduledTaskTrigger -AtStartup
$taskSettings = New-ScheduledTaskSettingsSet -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1) -ExecutionTimeLimit ([TimeSpan]::Zero) -StartWhenAvailable -MultipleInstances IgnoreNew
$taskPrincipal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
# Environment file is used by Node, rather than machine-wide environment changes.
$taskEnv = Join-Path $taskData 'service.env'
@'
PHIGON_DATA_DIR='${dataDirectory}'
PHIGON_CONTROL_PLANE_URL=${controlPlane}
PHIGON_GRPC_URL=${grpc}
'@ | Set-Content -LiteralPath $taskEnv -Encoding utf8
$taskAction = New-ScheduledTaskAction -Execute $taskNode -Argument ('--env-file="' + $taskEnv + '" ' + $taskArguments)
Register-ScheduledTask -TaskName 'PhigonGuardian' -Action $taskAction -Trigger $taskTrigger -Settings $taskSettings -Principal $taskPrincipal -Force | Out-Null
Start-ScheduledTask -TaskName 'PhigonGuardian'
` };
  }
  const xml = (value) => value.replaceAll("&", "&amp;").replaceAll("<", "&lt;").replaceAll(">", "&gt;").replaceAll('"', "&quot;").replaceAll("'", "&apos;");
  if (platform === "darwin") return { "com.phigon.guardian.plist": `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>Label</key><string>com.phigon.guardian</string>
<key>ProgramArguments</key><array><string>${xml(node)}</string><string>${xml(observer)}</string><string>run</string></array>
<key>UserName</key><string>${xml(serviceUser)}</string>
<key>EnvironmentVariables</key><dict><key>PHIGON_DATA_DIR</key><string>${xml(dataDirectory)}</string><key>PHIGON_CONTROL_PLANE_URL</key><string>${xml(controlPlane)}</string><key>PHIGON_GRPC_URL</key><string>${xml(grpc)}</string></dict>
<key>RunAtLoad</key><true/><key>KeepAlive</key><true/><key>ThrottleInterval</key><integer>10</integer>
<key>ProcessType</key><string>Background</string><key>Umask</key><integer>63</integer>
</dict></plist>
` };
  const unit = (value) => '"' + value.replaceAll("\\", "\\\\").replaceAll('"', '\\"').replaceAll("%", "%%") + '"';
  const executableArgument = (value) => unit(value.replaceAll("$", "$$"));
  return { "phigon-guardian.service": `[Unit]
Description=Phigon Guardian enterprise observer
After=network-online.target
Wants=network-online.target
StartLimitIntervalSec=0

[Service]
Type=simple
User=${serviceUser}
Group=${serviceUser}
ExecStart=${executableArgument(node)} ${executableArgument(observer)} run
Environment=${unit("PHIGON_DATA_DIR=" + dataDirectory)}
Environment=${unit("PHIGON_CONTROL_PLANE_URL=" + controlPlane)}
Environment=${unit("PHIGON_GRPC_URL=" + grpc)}
Restart=always
RestartSec=5
UMask=0077
NoNewPrivileges=yes
AmbientCapabilities=CAP_KILL CAP_DAC_READ_SEARCH
CapabilityBoundingSet=CAP_KILL CAP_DAC_READ_SEARCH
ProtectSystem=strict
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictSUIDSGID=yes
LockPersonality=yes
ReadWritePaths=${unit(dataDirectory)}
KillMode=control-group
TimeoutStopSec=15

[Install]
WantedBy=multi-user.target
` };
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const [configPath, output] = process.argv.slice(2);
  if (!configPath || !output) throw new Error("Usage: node managed-service.mjs <deployment.json> <output-directory>");
  const files = serviceFiles(JSON.parse(await readFile(configPath, "utf8")));
  const directory = resolve(output); await mkdir(directory, { recursive: true, mode: 0o700 });
  for (const [name, content] of Object.entries(files)) {
    const destination = join(directory, name);
    try { await access(destination); throw new Error(`Deployment file already exists: ${name}`); } catch (error) { if (error.code !== "ENOENT") throw error; }
    await writeFile(destination, content, { flag: "wx", mode: 0o600 });
    process.stdout.write(`${destination}\n`);
  }
}
