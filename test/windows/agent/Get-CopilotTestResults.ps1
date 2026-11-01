<#
.SYNOPSIS
    After a Copilot session in the test workspace, verifies the live log and
    builds a bundle and an HTML report from this test only.

.DESCRIPTION
    Your real profile is not collected. The script looks at VS Code's
    workspaceStorage only to find the folder whose workspace.json points at
    the test workspace (it reads those small metadata files, nothing else),
    copies that one folder into a stand-in profile under -Root, and runs
    afr collect against the stand-in. Everything it writes stays under
    -Root\results.
#>
[CmdletBinding()]
param(
    [string]$Root = "C:\afr-copilot-test",
    [string]$Trace = "secrets/credentials"
)

$ErrorActionPreference = "Stop"
$afr = Join-Path $Root "bin\afr.exe"
$log = Join-Path $Root "log\events.jsonl"
$ws = Join-Path $Root "workspace"
$out = Join-Path $Root "results"
$fake = Join-Path $out "profile"
New-Item -ItemType Directory -Force -Path $out | Out-Null

function Run([string]$Label, [string[]]$ArgList) {
    Write-Output "== $Label"
    $savedEap = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    try {
        & $afr @ArgList 2>&1 | ForEach-Object {
            $line = if ($_ -is [System.Management.Automation.ErrorRecord]) { $_.Exception.Message } else { [string]$_ }
            Write-Output "   $line"
        }
        $code = $LASTEXITCODE
    } finally { $ErrorActionPreference = $savedEap }
    Write-Output "   (exit $code)"
}

if (-not (Test-Path -LiteralPath $log)) {
    Write-Output "No live log at $log. The hooks did not fire; see the troubleshooting notes in README.md."
} else {
    Run "verify live log" @("verify", $log)
}

# the VS Code chat transcript for this workspace only
$wsUri = ([Uri]$ws).AbsoluteUri.ToLowerInvariant()
$storage = Join-Path $env:APPDATA "Code\User\workspaceStorage"
$match = $null
if (Test-Path -LiteralPath $storage) {
    foreach ($d in Get-ChildItem -LiteralPath $storage -Directory) {
        $wj = Join-Path $d.FullName "workspace.json"
        if (-not (Test-Path -LiteralPath $wj)) { continue }
        try { $folder = ((Get-Content -Raw -LiteralPath $wj) | ConvertFrom-Json).folder } catch { continue }
        if (-not $folder) { continue }
        $f = [Uri]::UnescapeDataString($folder).ToLowerInvariant().TrimEnd("/")
        if ($f -eq [Uri]::UnescapeDataString($wsUri).TrimEnd("/")) { $match = $d; break }
    }
}
if ($match) {
    $dst = Join-Path $fake "AppData\Roaming\Code\User\workspaceStorage\$($match.Name)"
    New-Item -ItemType Directory -Force -Path (Split-Path $dst) | Out-Null
    Copy-Item -LiteralPath $match.FullName -Destination $dst -Recurse -Force
    Write-Output "== copied VS Code storage for the test workspace: $($match.Name)"
} else {
    New-Item -ItemType Directory -Force -Path $fake | Out-Null
    Write-Output "== no VS Code workspaceStorage folder found for $ws (offline side will be empty)"
}

# Copilot-target sessions (VS Code and Copilot CLI) are kept under
# ~/.copilot/session-state/<session id>. Copy only the sessions whose IDs the
# test's own live log recorded, and only their transcript and workspace file.
$copilotHome = if ($env:COPILOT_HOME) { $env:COPILOT_HOME } else { Join-Path $HOME ".copilot" }
$ids = @()
if (Test-Path -LiteralPath $log) {
    $ids = @(Get-Content -LiteralPath $log | ForEach-Object { try { ($_ | ConvertFrom-Json).session_id } catch {} } |
            Where-Object { $_ -match '^[0-9a-fA-F-]{8,}$' } | Sort-Object -Unique)
}
foreach ($id in $ids) {
    $src = Join-Path $copilotHome "session-state\$id"
    if (-not (Test-Path -LiteralPath $src)) { continue }
    $dst = Join-Path $fake ".copilot\session-state\$id"
    New-Item -ItemType Directory -Force -Path $dst | Out-Null
    foreach ($f in @("events.jsonl", "workspace.yaml")) {
        $from = Join-Path $src $f
        if (-not (Test-Path -LiteralPath $from)) { continue }
        try {
            # open with read sharing: the session may still be open in VS Code
            $in = [IO.File]::Open($from, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete)
            try {
                $outf = [IO.File]::Create((Join-Path $dst $f))
                try { $in.CopyTo($outf) } finally { $outf.Close() }
            } finally { $in.Close() }
        } catch { Write-Output "   could not copy $from : $($_.Exception.Message)" }
    }
    Write-Output "== copied Copilot session-state for $id"
}

$bundle = Join-Path $out "copilot-test.zip"
Remove-Item -LiteralPath $bundle, "$bundle.sha256" -ErrorAction SilentlyContinue
Run "collect (stand-in profile + live log)" @("collect", "--home", $fake, "--live-log", $log, "--full-live-log", "--last", "48h", "--workspace", $ws, "-o", $bundle)
Run "verify bundle" @("verify", $bundle)
$html = Join-Path $out "report.html"
Run "report" @("report", $bundle, "--trace", $Trace, "-o", $html)
Write-Output ""
Write-Output "Report: $html"
Write-Output "Copy the results folder into your shared folder so it can be reviewed:"
Write-Output "  Copy-Item -LiteralPath `"$out`" -Destination `"`$HOME\Desktop\blackbox\copilot-results`" -Recurse"
