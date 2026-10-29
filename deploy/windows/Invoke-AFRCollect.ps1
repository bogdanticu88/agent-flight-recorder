<#
.SYNOPSIS
    Collect AI coding agent evidence from a Windows endpoint with afr.

.DESCRIPTION
    Built for Microsoft Defender for Endpoint Live Response, where commands run
    as SYSTEM. It finds afr.exe (installed copy or a Live Response putfile
    upload), works out which user profile to examine, runs the collection in
    SOC mode and prints the bundle path so the analyst can pull it with getfile.

    Live Response usage:
        putfile afr.exe
        run Invoke-AFRCollect.ps1 -parameters "-User jdoe -Around 2026-10-29T13:40:00Z -Case INC0042731"
        getfile "C:\ProgramData\AgentFlightRecorder\collections\<bundle>.zip"
        getfile "C:\ProgramData\AgentFlightRecorder\collections\<bundle>.zip.sha256"

    Can also be run by a user or admin directly in PowerShell.

.PARAMETER User
    Profile folder name under C:\Users. Default: the user owning explorer.exe
    (the interactive user), or every profile if none is logged on.
.PARAMETER Around
    Alert time (ISO 8601, UTC with Z). The window is -Margin either side.
.PARAMETER Margin
    Half-width of the window, Go duration syntax (default 2h).
.PARAMETER Last
    Alternative to -Around: collect the last N (e.g. 24h).
.PARAMETER Case
    Ticket or incident number, stamped into the manifest.
.PARAMETER IncludeRaw
    Also copy raw unredacted source files. SOC only; the bundle will contain secrets.
#>
[CmdletBinding()]
param(
    [string]$User,
    [string]$Around,
    [string]$Margin = "2h",
    [string]$Last,
    [string]$Case,
    [switch]$IncludeRaw
)

$ErrorActionPreference = "Stop"

$candidates = @(
    "$env:ProgramFiles\AgentFlightRecorder\afr.exe",
    "$env:ProgramData\Microsoft\Windows Defender Advanced Threat Protection\Downloads\afr.exe",
    (Join-Path $PSScriptRoot "afr.exe")
)
$afr = $candidates | Where-Object { $_ -and (Test-Path $_) } | Select-Object -First 1
if (-not $afr) { throw "afr.exe not found. Upload it first with: putfile afr.exe" }

if (-not $User) {
    $owner = Get-CimInstance Win32_Process -Filter "Name='explorer.exe'" -ErrorAction SilentlyContinue |
        ForEach-Object { (Invoke-CimMethod -InputObject $_ -MethodName GetOwner).User } |
        Select-Object -First 1
    $User = $owner
}
$profiles = if ($User) { @(Join-Path $env:SystemDrive "Users\$User") } else {
    Get-ChildItem (Join-Path $env:SystemDrive "Users") -Directory |
        Where-Object { $_.Name -notin @("Public", "Default", "Default User", "All Users") } |
        ForEach-Object { $_.FullName }
}

$outDir = Join-Path $env:ProgramData "AgentFlightRecorder\collections"
New-Item -ItemType Directory -Force -Path $outDir | Out-Null

foreach ($profileDir in $profiles) {
    if (-not (Test-Path $profileDir)) { Write-Warning "profile not found: $profileDir"; continue }
    $name = Split-Path $profileDir -Leaf
    $stamp = (Get-Date).ToUniversalTime().ToString("yyyyMMddTHHmmssZ")
    $bundle = Join-Path $outDir "afr-$env:COMPUTERNAME-$name-$stamp.zip"
    $afrArgs = @("collect", "--home", $profileDir, "--mode", "soc", "-o", $bundle)
    if ($Around) { $afrArgs += @("--around", $Around, "--margin", $Margin) }
    elseif ($Last) { $afrArgs += @("--last", $Last) }
    if ($Case) { $afrArgs += @("--case", $Case) }
    if ($IncludeRaw) { $afrArgs += "--include-raw" }

    Write-Output "== collecting $profileDir"
    & $afr @afrArgs 2>&1 | ForEach-Object { Write-Output "   $_" }
    if (Test-Path $bundle) {
        $hash = (Get-FileHash $bundle -Algorithm SHA256).Hash.ToLower()
        Write-Output "BUNDLE: $bundle"
        Write-Output "SHA256: $hash"
    }
}
