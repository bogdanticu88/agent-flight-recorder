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

    Without administrator rights (the usual case when the script is sent to the
    person whose machine is being looked at), it collects only the current
    user's own profile, in user mode, and writes the bundle to their Desktop:

        powershell -NoProfile -ExecutionPolicy Bypass -File .\Invoke-AFRCollect.ps1 -Last 24h

    The user then sends back the .zip and its .zip.sha256. If machine policy
    blocks scripts altogether, running afr.exe directly does the same job:

        .\afr.exe collect --last 24h

    Exit code: 0 all bundles complete, 3 at least one partial bundle,
    1 any collection failed. BUNDLE lines are printed only for bundles whose
    hash matches their sidecar.

.PARAMETER User
    Profile folder name under C:\Users. Elevated, the default is the user owning
    explorer.exe (the interactive user), or every profile if none is logged on.
    Not elevated, only the current user's own profile can be collected.
.PARAMETER Around
    Alert time (ISO 8601, UTC with Z). The window is -Margin either side.
.PARAMETER Margin
    Half-width of the window, Go duration syntax (default 2h).
.PARAMETER Last
    Alternative to -Around: collect the last N (e.g. 24h).
.PARAMETER Case
    Ticket or incident number, stamped into the manifest.
.PARAMETER IncludeRaw
    Also copy raw unredacted source files. Elevated (SOC) runs only; the bundle
    will contain secrets.
.PARAMETER ProfileDir
    Collect this profile folder directly instead of resolving -User under
    <SystemDrive>\Users (testing, or profiles stored elsewhere).
.PARAMETER OutDir
    Where bundles are written. Default when elevated:
    ProgramData\AgentFlightRecorder\collections. Default otherwise: the
    current user's Desktop.
.PARAMETER AfrPath
    Use this afr.exe instead of searching the default locations.
#>
[CmdletBinding()]
param(
    [string]$User,
    [string]$Around,
    [string]$Margin = "2h",
    [string]$Last,
    [string]$Case,
    [switch]$IncludeRaw,
    [string]$ProfileDir,
    [string]$OutDir,
    [string]$AfrPath
)

$ErrorActionPreference = "Stop"

# Administrators and SYSTEM collect in SOC mode and may examine any profile.
# Everyone else collects their own profile in user mode, so a bundle sent
# back by the person under review is labelled as lower assurance.
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$elevated = ([Security.Principal.WindowsPrincipal]$identity).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) -or $identity.IsSystem
$mode = if ($elevated) { "soc" } else { "user" }
# plain message and exit 1, without a PowerShell stack dump for the end user
function Stop-Collect([string]$Message) { [Console]::Error.WriteLine("afr: $Message"); exit 1 }
if (-not $OutDir) {
    $OutDir = if ($elevated) { Join-Path $env:ProgramData "AgentFlightRecorder\collections" } else { [Environment]::GetFolderPath("Desktop") }
}
if (-not $elevated) {
    if ($IncludeRaw) { Stop-Collect "-IncludeRaw is for SOC collections run as administrator or SYSTEM." }
    $own = $env:USERPROFILE
    if ($User -and $User -ne (Split-Path $own -Leaf)) {
        Stop-Collect "Collecting another user's profile ($User) needs administrator rights. Run without -User to collect your own."
    }
    if (-not $ProfileDir) { $ProfileDir = $own }
}

$candidates = @(
    "$env:ProgramFiles\AgentFlightRecorder\afr.exe",
    "$env:ProgramData\Microsoft\Windows Defender Advanced Threat Protection\Downloads\afr.exe",
    (Join-Path $PSScriptRoot "afr.exe")
)
if ($AfrPath) { $candidates = @($AfrPath) }
$afr = $candidates | Where-Object { $_ -and (Test-Path $_) } | Select-Object -First 1
if (-not $afr) { throw "afr.exe not found. Upload it first with: putfile afr.exe" }

if (-not $User -and -not $ProfileDir) {
    $owner = Get-CimInstance Win32_Process -Filter "Name='explorer.exe'" -ErrorAction SilentlyContinue |
        ForEach-Object { (Invoke-CimMethod -InputObject $_ -MethodName GetOwner).User } |
        Select-Object -First 1
    $User = $owner
}
$profiles = if ($ProfileDir) { @($ProfileDir) } elseif ($User) { @(Join-Path $env:SystemDrive "Users\$User") } else {
    Get-ChildItem (Join-Path $env:SystemDrive "Users") -Directory |
        Where-Object { $_.Name -notin @("Public", "Default", "Default User", "All Users") } |
        ForEach-Object { $_.FullName }
}

$outDir = $OutDir
New-Item -ItemType Directory -Force -Path $outDir | Out-Null

$exitCode = 0
foreach ($profileDir in $profiles) {
    if (-not (Test-Path $profileDir)) { Write-Warning "profile not found: $profileDir"; $exitCode = 1; continue }
    $name = Split-Path $profileDir -Leaf
    $stamp = (Get-Date).ToUniversalTime().ToString("yyyyMMddTHHmmssZ")
    # ASCII-only file name, so the BUNDLE line survives any console code page
    $safe = ("afr-$env:COMPUTERNAME-$name-$stamp" -replace '[^A-Za-z0-9._-]', '_')
    $bundle = Join-Path $outDir "$safe.zip"
    $afrArgs = @("collect", "--home", $profileDir, "--mode", $mode, "-o", $bundle)
    if ($Around) { $afrArgs += @("--around", $Around, "--margin", $Margin) }
    elseif ($Last) { $afrArgs += @("--last", $Last) }
    if ($Case) { $afrArgs += @("--case", $Case) }
    if ($IncludeRaw) { $afrArgs += "--include-raw" }

    Write-Output "== collecting $profileDir"
    # afr writes progress to stderr. Under "Stop", Windows PowerShell 5.1 turns
    # the first stderr line of a native command into a terminating error, so
    # relax it for this call only. afr writes UTF-8; decode it as such.
    $savedEap = $ErrorActionPreference
    $savedEnc = $null
    try { $savedEnc = [Console]::OutputEncoding; [Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false) } catch { $savedEnc = $null }
    try {
        $ErrorActionPreference = "Continue"
        & $afr @afrArgs 2>&1 | ForEach-Object {
            # stderr lines arrive as ErrorRecords; an empty one would print its type name
            $line = if ($_ -is [System.Management.Automation.ErrorRecord]) { $_.Exception.Message } else { [string]$_ }
            Write-Output ("   " + $line)
        }
        $code = $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $savedEap
        if ($savedEnc) { try { [Console]::OutputEncoding = $savedEnc } catch {} }
    }
    # afr exit codes: 0 complete, 3 partial (bundle written, some sources failed), anything else failed
    if ($code -ne 0 -and $code -ne 3) {
        Write-Output "FAILED: collection of $profileDir exited with $code; no usable bundle"
        $exitCode = 1
        continue
    }
    $sidecar = "$bundle.sha256"
    if (-not (Test-Path $bundle) -or -not (Test-Path $sidecar)) {
        Write-Output "FAILED: afr reported success but the bundle or its .sha256 is missing"
        $exitCode = 1
        continue
    }
    $hash = (Get-FileHash $bundle -Algorithm SHA256).Hash.ToLower()
    $expected = ((Get-Content $sidecar -Raw) -split '\s+')[0]
    if ($hash -ne $expected) {
        Write-Output "FAILED: bundle hash $hash does not match its sidecar $expected"
        $exitCode = 1
        continue
    }
    if ($code -eq 3) {
        Write-Output "PARTIAL: some sources could not be collected; see sources.json in the bundle"
        if ($exitCode -eq 0) { $exitCode = 3 }
    }
    Write-Output "BUNDLE: $bundle"
    Write-Output "SHA256: $hash"
    if (-not $elevated) {
        Write-Output "Send both files to your security team: $(Split-Path $bundle -Leaf) and $(Split-Path $sidecar -Leaf)"
    }
}
exit $exitCode
