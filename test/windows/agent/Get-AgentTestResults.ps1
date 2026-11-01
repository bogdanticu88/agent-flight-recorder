<#
.SYNOPSIS
    After a Codex or Gemini CLI session in an isolated test from
    New-AgentTest.ps1, verifies the live log and builds a bundle and report.

.DESCRIPTION
    Collects the stand-in home under -Root (where the agent kept its
    transcripts) plus the test's live log. Nothing outside -Root is read.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidateSet("codex", "gemini-cli")][string]$Agent,
    [string]$Root,
    [string]$Trace = "secrets/credentials"
)

$ErrorActionPreference = "Stop"
if (-not $Root) { $Root = "C:\afr-$Agent-test" }
$afr = Join-Path $Root "bin\afr.exe"
$log = Join-Path $Root "log\events.jsonl"
$profileDir = Join-Path $Root "profile"
$ws = Join-Path $Root "workspace"
$out = Join-Path $Root "results"
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

if (Test-Path -LiteralPath $log) {
    Run "verify live log" @("verify", $log)
    $n = @(Get-Content -LiteralPath $log).Count
    Write-Output "   $n record(s) in the live log"
} else {
    Write-Output "== no live log at $log: the hooks did not fire"
}

$bundle = Join-Path $out "$Agent-test.zip"
Remove-Item -LiteralPath $bundle, "$bundle.sha256" -ErrorAction SilentlyContinue
$collectArgs = @("collect", "--home", $profileDir, "--last", "48h", "--workspace", $ws, "-o", $bundle)
if (Test-Path -LiteralPath $log) { $collectArgs += @("--live-log", $log, "--full-live-log") }
Run "collect (stand-in home + live log)" $collectArgs
Run "verify bundle" @("verify", $bundle)
Run "report" @("report", $bundle, "--trace", $Trace, "-o", (Join-Path $out "report.html"))
Copy-Item -LiteralPath $log -Destination (Join-Path $out "events.jsonl") -ErrorAction SilentlyContinue
Write-Output ""
Write-Output "Copy the results so they can be reviewed:"
Write-Output "  Copy-Item -LiteralPath `"$out`" -Destination `"`$HOME\Desktop\blackbox\$Agent-results`" -Recurse"
