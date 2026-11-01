<#
.SYNOPSIS
    Deploy the afr live recorder to a Windows endpoint (Intune / SCCM / GPO).

.DESCRIPTION
    Runs as SYSTEM. Steps:
      1. copies afr.exe to Program Files
      2. creates a central log folder with one subfolder per user profile
         (see "Log folder permissions" below)
      3. writes the machine policy and the on-policy-error marker
      4. installs machine-scope hook config where the vendor supports it
         (Copilot policy.d, Claude Code managed settings)
      5. installs user-scope hook config into every existing profile for
         agents that only read user config (VS Code, Cursor, Gemini, Codex, OpenCode)

    Every native command is checked; the script stops on the first failure
    and exits non-zero, so a deployment tool reports it as failed.

    Re-running is safe: afr replaces only hook handlers it recognises as its
    own and keeps everything else. New profiles created later need steps 2
    and 5 again (schedule this script or use an Intune remediation). Until
    then a new user's hook cannot write centrally and records to the local
    fallback log in their own profile instead, saying so on stderr.

    Log folder permissions (tested as two standard users on Windows 11, see
    docs/windows-validation.md):
      - SYSTEM and Administrators: full control.
      - Users, on the log root only: list and read attributes. No create
        files, no create folders, no delete-child.
      - logs\<profile>, created here for every local profile found in the
        ProfileList registry key: that profile's SID may create files in
        it. Nobody else may, so a user cannot pre-create another user's log.
      - Files a user creates: owner may read and append data (RD,AD,RA,REA,
        RC,S). No write-data (no overwrite or truncate), no write-attributes,
        no delete. "OWNER RIGHTS" caps the owner's implicit right to change
        the file's permissions. afr opens the log with append+synchronize
        only (see internal/core/logfile_windows.go), because a normal
        append-mode open also asks for write-attributes and would be refused.
    The policy's log_path uses %USERNAME%, which afr expands to the profile
    folder name, so it matches the subfolder created here.
    Known gaps: local administrators can do anything; a user can still remove
    or edit the hook configuration in their own profile for user-scope
    agents; the local fallback log is user-writable. Ship the log to Sentinel
    and treat that copy as authoritative.

.PARAMETER Source
    Folder containing afr.exe and policy.json (defaults to the script folder).
.PARAMETER OnPolicyError
    "allow" (default) or "deny": what pre-tool calls get if the machine
    policy cannot be read or does not validate.
.PARAMETER ProgramDir
    Where afr.exe goes. Default: Program Files\AgentFlightRecorder.
.PARAMETER DataDir
    Policy and central log folder. Default: ProgramData\AgentFlightRecorder,
    which is the only location afr reads as the managed policy. Any other
    value is for isolated testing: the ACLs are applied, but the policy
    written there is not the one afr enforces.
.PARAMETER ProfilesRoot
    Folder whose subfolders are user profiles. Default: <SystemDrive>\Users.
.PARAMETER SkipMachineHooks
    Do not write machine-scope hook files (Copilot policy.d, Claude Code
    managed settings). Use for isolated testing.
#>
[CmdletBinding()]
param(
    [string]$Source = $PSScriptRoot,
    [ValidateSet("allow", "deny")][string]$OnPolicyError = "allow",
    [string]$ProgramDir = (Join-Path $env:ProgramFiles "AgentFlightRecorder"),
    [string]$DataDir = (Join-Path $env:ProgramData "AgentFlightRecorder"),
    [string]$ProfilesRoot = (Join-Path $env:SystemDrive "Users"),
    [switch]$SkipMachineHooks
)

$ErrorActionPreference = "Stop"

function Invoke-Checked {
    param([string]$What, [scriptblock]$Command)
    $out = & $Command 2>&1
    $code = $LASTEXITCODE
    $out | ForEach-Object { Write-Output "   $_" }
    if ($code -ne 0) { throw "$What failed with exit code $code" }
}

$dest = $ProgramDir
$exe = Join-Path $dest "afr.exe"
$data = $DataDir
$logs = Join-Path $data "logs"

New-Item -ItemType Directory -Force -Path $dest, $data, $logs | Out-Null
Copy-Item (Join-Path $Source "afr.exe") $exe -Force
Invoke-Checked "afr version check" { & $exe version }

# Well-known SIDs, so the grants work on every Windows display language:
# S-1-5-18 SYSTEM, S-1-5-32-544 Administrators, S-1-5-32-545 Users,
# S-1-3-0 CREATOR OWNER, S-1-3-4 OWNER RIGHTS.

# Program Files and the policy folder: users read, only admins write.
Invoke-Checked "icacls $data" { icacls $data /inheritance:r /grant:r "*S-1-5-18:(OI)(CI)F" "*S-1-5-32-544:(OI)(CI)F" "*S-1-5-32-545:(OI)(CI)RX" }

# Central log folder, permissions as described above.
Invoke-Checked "icacls $logs" {
    icacls $logs /inheritance:r /grant:r `
        "*S-1-5-18:(OI)(CI)F" "*S-1-5-32-544:(OI)(CI)F" `
        "*S-1-5-32-545:(RD,X,RA,REA,RC,S)" `
        "*S-1-3-0:(OI)(IO)(RD,AD,RA,REA,RC,S)" `
        "*S-1-3-4:(OI)(IO)(RD,AD,RA,REA,RC,S)"
}

# One log folder per local profile, writable (create files) only by that
# profile's SID. Profiles come from the registry, not from folder names, so
# the SID is the account's own. Service and system profiles are skipped.
$profileKey = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList"
foreach ($k in Get-ChildItem $profileKey -ErrorAction SilentlyContinue) {
    $sid = $k.PSChildName
    if ($sid -notmatch '^S-1-(5-21|12-1)-') { continue }
    $img = (Get-ItemProperty -LiteralPath $k.PSPath -ErrorAction SilentlyContinue).ProfileImagePath
    if (-not $img) { continue }
    $userLogs = Join-Path $logs (Split-Path $img -Leaf)
    New-Item -ItemType Directory -Force -Path $userLogs | Out-Null
    Invoke-Checked "icacls $userLogs" { icacls $userLogs /grant:r "*${sid}:(RD,WD,X,RA,REA,RC,S)" }
    Write-Output "log folder for $sid -> $userLogs"
}

# Machine policy. log_path sends every user's events to the central folder.
$policyDst = Join-Path $data "policy.json"
$policySrc = Join-Path $Source "policy.json"
if (Test-Path $policySrc) {
    Copy-Item $policySrc $policyDst -Force
} elseif (-not (Test-Path $policyDst)) {
    @{ log_path = "$logs\%USERNAME%\events.jsonl"; rules = @() } | ConvertTo-Json | Set-Content $policyDst -Encoding UTF8
}
Set-Content (Join-Path $data "on-policy-error") $OnPolicyError -Encoding ASCII -NoNewline

# Machine-scope hooks (cannot be removed by the user)
if (-not $SkipMachineHooks) {
    Invoke-Checked "machine hook install" { & $exe install --bin $exe --scope machine --agents "copilot,claude-code" --apply }
}

# User-scope hooks in every profile
$failed = @()
Get-ChildItem $ProfilesRoot -Directory |
    Where-Object { $_.Name -notin @("Public", "Default", "Default User", "All Users") } |
    ForEach-Object {
        Write-Output "== $($_.FullName)"
        & $exe install --bin $exe --home $_.FullName --scope user --apply
        if ($LASTEXITCODE -ne 0) { $failed += $_.FullName }
    }
if ($failed.Count -gt 0) {
    throw "user-scope install failed for: $($failed -join ', ')"
}
Write-Output "afr installed."
