<#
.SYNOPSIS
    Deploy the afr live recorder to a Windows endpoint (Intune / SCCM / GPO).

.DESCRIPTION
    Runs as SYSTEM. Steps:
      1. copies afr.exe to Program Files
      2. creates a central log folder (see "Log folder permissions" below)
      3. writes the machine policy and the on-policy-error marker
      4. installs machine-scope hook config where the vendor supports it
         (Copilot policy.d, Claude Code managed settings)
      5. installs user-scope hook config into every existing profile for
         agents that only read user config (VS Code, Cursor, Gemini, Codex, OpenCode)

    Every native command is checked; the script stops on the first failure
    and exits non-zero, so a deployment tool reports it as failed.

    Re-running is safe: afr replaces only hook handlers it recognises as its
    own and keeps everything else. New profiles created later need step 5
    again (schedule this script or use an Intune remediation).

    Log folder permissions (NOT VERIFIED on a real Windows host by this
    project; test as a standard user before relying on them):
      - SYSTEM and Administrators: full control.
      - Users, on the folder only: create files, list, read attributes.
        No delete-child, so users cannot delete or rename other files.
      - Files a user creates: owner may read and append data (RD,AD,RA,REA,
        RC,S). No write-data (no overwrite or truncate), no write-attributes,
        no delete. "OWNER RIGHTS" caps the owner's implicit right to change
        the file's permissions. afr opens the log with append+synchronize
        only (see internal/core/logfile_windows.go), because a normal
        append-mode open also asks for write-attributes and would be refused.
    Known gaps: a user can create a file under another user's name before
    that user does; the victim's hook then cannot append (it reports the
    failure), and the squatter can append records that claim to be the
    victim's. Attribute records by the file owner's SID, not by the "user"
    field inside them. Local administrators can do anything; a user can still remove
    or edit the hook configuration in their own profile for user-scope
    agents. Ship the log to Sentinel and treat that copy as authoritative.

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
        "*S-1-5-32-545:(RD,WD,X,RA,REA,RC,S)" `
        "*S-1-3-0:(OI)(IO)(RD,AD,RA,REA,RC,S)" `
        "*S-1-3-4:(OI)(IO)(RD,AD,RA,REA,RC,S)"
}

# Machine policy. log_path sends every user's events to the central folder.
$policyDst = Join-Path $data "policy.json"
$policySrc = Join-Path $Source "policy.json"
if (Test-Path $policySrc) {
    Copy-Item $policySrc $policyDst -Force
} elseif (-not (Test-Path $policyDst)) {
    @{ log_path = "$logs\%USERNAME%.jsonl"; rules = @() } | ConvertTo-Json | Set-Content $policyDst -Encoding UTF8
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
Write-Output "afr installed. Log folder ACL is unverified; test it as a standard user."
