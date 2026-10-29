<#
.SYNOPSIS
    Deploy the afr live recorder to a Windows endpoint (Intune / SCCM / GPO).

.DESCRIPTION
    Runs as SYSTEM. Steps:
      1. copies afr.exe to Program Files
      2. creates a central log folder that users can append to (for the
         Azure Monitor Agent to ship to Sentinel)
      3. writes the machine policy (honeypot alert rules, secret deny rules)
      4. installs machine-scope hook config where the vendor supports it
         (Copilot policy.d, Claude Code managed settings)
      5. installs user-scope hook config into every existing profile for
         agents that only read user config (VS Code, Cursor, Gemini, Codex, OpenCode)

    Re-running is safe: afr replaces its own hook entries and keeps anything else.
    New profiles created later need step 5 again (schedule this script or use
    an Intune remediation).

.PARAMETER Source
    Folder containing afr.exe and policy.json (defaults to the script folder).
#>
[CmdletBinding()]
param([string]$Source = $PSScriptRoot)

$ErrorActionPreference = "Stop"
$dest = Join-Path $env:ProgramFiles "AgentFlightRecorder"
$exe = Join-Path $dest "afr.exe"
$data = Join-Path $env:ProgramData "AgentFlightRecorder"
$logs = Join-Path $data "logs"

New-Item -ItemType Directory -Force -Path $dest, $data, $logs | Out-Null
Copy-Item (Join-Path $Source "afr.exe") $exe -Force

# Central log folder. Users may create and append to files but not delete
# them; CREATOR OWNER gets modify on its own files so the lock file works.
# Test this ACL in your estate before rollout.
icacls $logs /inheritance:r /grant:r "SYSTEM:(OI)(CI)F" "Administrators:(OI)(CI)F" `
    "Users:(CI)(WD,AD,RD,X,RA,REA)" "CREATOR OWNER:(OI)(CI)(IO)M" | Out-Null

# Machine policy. log_path sends every user's events to the central folder.
$policyDst = Join-Path $data "policy.json"
$policySrc = Join-Path $Source "policy.json"
if (Test-Path $policySrc) {
    Copy-Item $policySrc $policyDst -Force
} elseif (-not (Test-Path $policyDst)) {
    @{ log_path = "$logs\%USERNAME%.jsonl"; rules = @() } | ConvertTo-Json | Set-Content $policyDst -Encoding UTF8
}
icacls $policyDst /inheritance:r /grant:r "SYSTEM:F" "Administrators:F" "Users:R" | Out-Null

# Machine-scope hooks (cannot be removed by the user)
& $exe install --bin $exe --scope machine --agents "copilot,claude-code" --apply

# User-scope hooks in every profile
Get-ChildItem (Join-Path $env:SystemDrive "Users") -Directory |
    Where-Object { $_.Name -notin @("Public", "Default", "Default User", "All Users") } |
    ForEach-Object {
        Write-Output "== $($_.FullName)"
        & $exe install --bin $exe --home $_.FullName --scope user --apply
    }
