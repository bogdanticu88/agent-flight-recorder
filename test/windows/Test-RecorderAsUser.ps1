<#
.SYNOPSIS
    Recorder permission tests. Runs AS a disposable standard user, started by
    Invoke-WindowsValidation.ps1 through Start-Process -Credential.

.DESCRIPTION
    Every check writes one JSON line to -ResultFile with the expected and the
    observed result. Nothing here needs or uses administrator rights; the point
    is to observe what a standard user can and cannot do to the central log.

    Modes:
      own     work on this user's own log: appends, verify, attacks on it,
              concurrency, lock contention, stale lock recovery, termination
      other   attack another user's existing log
      squat   create a log under another user's name before that user does
      victim  try to record into a log another user has squatted
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidateSet("own", "other", "squat", "victim")][string]$Mode,
    [Parameter(Mandatory)][string]$Afr,
    [Parameter(Mandatory)][string]$LogPath,
    [Parameter(Mandatory)][string]$ResultFile,
    [Parameter(Mandatory)][string]$ScratchDir,
    [int]$Concurrency = 24
)

$ErrorActionPreference = "Continue"
$me = [Security.Principal.WindowsIdentity]::GetCurrent().Name
$utf8 = New-Object System.Text.UTF8Encoding($false)
# non-ASCII built from code points: Windows PowerShell 5.1 misreads UTF-8 scripts without a BOM
$script:Uni = "$([char]0x00FC)n$([char]0x00EF)c$([char]0x00F8)d$([char]0x00E9) $([char]0x2713)"
New-Item -ItemType Directory -Force -Path $ScratchDir | Out-Null

function Add-Result {
    param([string]$Name, [string]$Expected, [string]$Actual, [string]$Status, [string]$Details = "")
    $o = [ordered]@{ phase = "recorder-$Mode"; name = $Name; identity = $me; expected = $Expected; actual = $Actual; status = $Status; details = $Details; time = (Get-Date).ToUniversalTime().ToString("o") }
    $line = ($o | ConvertTo-Json -Compress -Depth 4)
    [IO.File]::AppendAllText($ResultFile, $line + "`n", $utf8)
    Write-Output ("[{0}] {1}: {2}" -f $Status, $Name, $Actual)
}

function Compare-Result {
    param([string]$Name, [string]$Expected, [string]$Actual, [string]$Details = "", [string]$OnMismatch = "FAIL")
    $status = if ($Expected -eq $Actual) { "PASS" } else { $OnMismatch }
    Add-Result -Name $Name -Expected $Expected -Actual $Actual -Status $status -Details $Details
}

# Runs afr with arguments and an optional UTF-8 stdin payload, without the
# console re-encoding the payload (Windows PowerShell 5.1 pipes in ASCII).
# Uses System.Diagnostics.Process directly: a process object returned by
# Start-Process -PassThru (without -Wait) loses its exit code when the child
# exits before PowerShell opens its handle, which happens with short runs.
function Invoke-Afr {
    param([string[]]$ArgList, [string]$Stdin = $null, [switch]$NoWait, [switch]$KillAtOnce)
    $quoted = $ArgList | ForEach-Object { if ($_ -match '[\s"]') { '"' + ($_ -replace '"', '\"') + '"' } else { $_ } }
    $psi = New-Object Diagnostics.ProcessStartInfo
    $psi.FileName = $Afr
    $psi.Arguments = ($quoted -join " ")
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow = $true
    $psi.RedirectStandardInput = $true
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.StandardOutputEncoding = $utf8
    $psi.StandardErrorEncoding = $utf8
    $p = [Diagnostics.Process]::Start($psi)
    $outTask = $p.StandardOutput.ReadToEndAsync()
    $errTask = $p.StandardError.ReadToEndAsync()
    $killed = $false
    if ($KillAtOnce) {
        try { $p.Kill(); $killed = $true } catch {}
    }
    try {
        if ($Stdin) { $b = $utf8.GetBytes($Stdin); $p.StandardInput.BaseStream.Write($b, 0, $b.Length) }
        $p.StandardInput.Close()
    } catch {}
    $h = [pscustomobject]@{ Process = $p; OutTask = $outTask; ErrTask = $errTask; Killed = $killed }
    if ($NoWait) { return $h }
    Complete-Afr $h
}

function Complete-Afr {
    param($H)
    $H.Process.WaitForExit()
    [pscustomobject]@{
        ExitCode = $H.Process.ExitCode
        StdOut   = $H.OutTask.Result
        StdErr   = $H.ErrTask.Result
        Killed   = $H.Killed
    }
}

function New-Payload {
    param([string]$Event = "PreToolUse", [string]$Session = "winval")
    $o = [ordered]@{
        hook_event_name = $Event
        session_id      = $Session
        tool_name       = "Read"
        tool_use_id     = [guid]::NewGuid().ToString("N")
        tool_input      = @{ file_path = "C:\Temp\dossier $script:Uni\notes.txt" }
        prompt          = "pr$([char]0x00FC)fe die Datei $([char]0x2713)"
    }
    $o | ConvertTo-Json -Compress
}

function Invoke-Hook {
    param([string]$Event = "PreToolUse", [switch]$NoWait, [switch]$KillAtOnce)
    $env:AFR_LOG = $LogPath
    $env:AFR_POLICY = ""
    Invoke-Afr -ArgList @("hook", "--agent", "claude-code", "--event", $Event) -Stdin (New-Payload -Event $Event) -NoWait:$NoWait -KillAtOnce:$KillAtOnce
}

function Get-Verify {
    $r = Invoke-Afr -ArgList @("verify", $LogPath)
    $first = ($r.StdOut -split "`r?`n")[0]
    $status = if ($first -match '^(\S+)') { $Matches[1] } else { "?" }
    $count = if ($first -match '\((\d+) records\)') { [int]$Matches[1] } else { -1 }
    [pscustomobject]@{ Exit = $r.ExitCode; Status = $status; Records = $count; Raw = $r.StdOut }
}

# Each attempt returns "allowed" or "denied" plus the error text.
function Test-Op {
    param([string]$Name, [scriptblock]$Op)
    $global:LASTEXITCODE = 0
    try {
        & $Op | Out-Null
        if ($LASTEXITCODE -and $LASTEXITCODE -ne 0) { return @("denied", "exit code $LASTEXITCODE") }
        return @("allowed", "")
    } catch {
        return @("denied", $_.Exception.Message)
    }
}

function Test-Attacks {
    param([string]$Target, [string]$Prefix)
    $ops = [ordered]@{
        "overwrite"       = { [IO.File]::WriteAllText($Target, "overwritten") }
        "truncate"        = { $fs = [IO.File]::Open($Target, [IO.FileMode]::Truncate, [IO.FileAccess]::Write); $fs.Close() }
        "set-length-0"    = { $fs = [IO.File]::Open($Target, [IO.FileMode]::Open, [IO.FileAccess]::ReadWrite); try { $fs.SetLength(0) } finally { $fs.Close() } }
        "delete"          = { Remove-Item -LiteralPath $Target -Force -ErrorAction Stop }
        "rename"          = { Rename-Item -LiteralPath $Target -NewName ("renamed-" + [guid]::NewGuid().ToString("N") + ".jsonl") -ErrorAction Stop }
        "set-acl"         = {
            $acl = Get-Acl -LiteralPath $Target
            $rule = New-Object Security.AccessControl.FileSystemAccessRule($me, "FullControl", "Allow")
            $acl.AddAccessRule($rule)
            Set-Acl -LiteralPath $Target -AclObject $acl -ErrorAction Stop
        }
        "icacls-grant"    = { & icacls.exe $Target /grant "${me}:F" 2>&1 | Out-Null }
        "takeown"         = { & takeown.exe /f $Target 2>&1 | Out-Null }
    }
    foreach ($k in $ops.Keys) {
        $res = Test-Op -Name $k -Op $ops[$k]
        Compare-Result -Name "$Prefix $k" -Expected "denied" -Actual $res[0] -Details $res[1]
    }
}

$lockName = $null
function Get-LockPath {
    # must mirror lockDir/AppendLive: first 8 bytes of SHA-256 over the log path, hex
    $sha = [Security.Cryptography.SHA256]::Create()
    $h = $sha.ComputeHash($utf8.GetBytes($LogPath))
    $hex = -join ($h[0..7] | ForEach-Object { $_.ToString("x2") })
    Join-Path $env:LOCALAPPDATA "AgentFlightRecorder\locks\$hex.lock"
}

switch ($Mode) {
    "own" {
        # 1. creation and repeated appends through the Windows opener
        $fails = 0; $stderrs = @()
        for ($i = 0; $i -lt 3; $i++) {
            $r = Invoke-Hook
            if ($r.ExitCode -ne 0 -or $r.StdErr -match "recording failed") { $fails++; $stderrs += $r.StdErr }
        }
        Compare-Result -Name "append x3 via afr hook" -Expected "0 failures" -Actual "$fails failures" -Details ($stderrs -join " | ")
        $v = Get-Verify
        Compare-Result -Name "own log verifies after appends" -Expected "CONSISTENT/3" -Actual ("{0}/{1}" -f $v.Status, $v.Records) -Details $v.Raw

        # 2. reading own log is allowed
        $read = Test-Op -Name "read" -Op { [IO.File]::ReadAllText($LogPath) }
        Compare-Result -Name "own log read" -Expected "allowed" -Actual $read[0] -Details $read[1]

        # 3. attacks on own log
        Test-Attacks -Target $LogPath -Prefix "own log"
        $dotnetAppend = Test-Op -Name "dotnet-append" -Op { $fs = [IO.File]::Open($LogPath, [IO.FileMode]::Append, [IO.FileAccess]::Write); $fs.Close() }
        Add-Result -Name "own log .NET FileMode.Append open" -Expected "informational" -Actual $dotnetAppend[0] -Status "INFO" -Details ".NET requests generic write; afr uses append-only access. $($dotnetAppend[1])"
        $v = Get-Verify
        Compare-Result -Name "own log intact after attacks" -Expected "CONSISTENT/3" -Actual ("{0}/{1}" -f $v.Status, $v.Records) -Details $v.Raw

        # 4. concurrent recording
        $procs = @()
        for ($i = 0; $i -lt $Concurrency; $i++) { $procs += Invoke-Hook -NoWait }
        $done = @($procs | ForEach-Object { Complete-Afr $_ })
        $failed = @($done | Where-Object { $_.ExitCode -ne 0 -or $_.StdErr -match "recording failed" }).Count
        $v = Get-Verify
        Compare-Result -Name "concurrent appends ($Concurrency)" -Expected ("0 failed, CONSISTENT/{0}" -f (3 + $Concurrency)) -Actual ("{0} failed, {1}/{2}" -f $failed, $v.Status, $v.Records) -Details $v.Raw
        $base = $v.Records

        # 5. lock held by a live (fresh) holder: hook must report failure, not hang or claim success
        $lock = Get-LockPath
        New-Item -ItemType Directory -Force -Path (Split-Path $lock) | Out-Null
        [IO.File]::WriteAllText($lock, "held")
        $sw = [Diagnostics.Stopwatch]::StartNew()
        $r = Invoke-Hook
        $sw.Stop()
        $got = if ($r.StdErr -match "recording failed") { "recording failed" } else { "recorded" }
        Compare-Result -Name "fresh lock held by another writer" -Expected "recording failed" -Actual $got -Details ("{0:n1}s; stderr: {1}" -f $sw.Elapsed.TotalSeconds, $r.StdErr)

        # 6. stale lock (holder killed long ago) is recovered
        (Get-Item -LiteralPath $lock).LastWriteTime = (Get-Date).AddMinutes(-2)
        $r = Invoke-Hook
        $got = if ($r.ExitCode -eq 0 -and $r.StdErr -notmatch "recording failed") { "recorded" } else { "failed" }
        Compare-Result -Name "stale lock recovered" -Expected "recorded" -Actual $got -Details ("exit {0}; stderr: {1}" -f $r.ExitCode, $r.StdErr)
        Compare-Result -Name "stale lock removed afterwards" -Expected "False" -Actual ([string](Test-Path -LiteralPath $lock))

        # 7. termination: kill writers mid-flight, then confirm recording continues
        # every other writer is killed straight after it starts, while it is
        # still initialising, reading the payload or holding the lock
        $procs = @()
        for ($i = 0; $i -lt $Concurrency; $i++) { $procs += Invoke-Hook -NoWait -KillAtOnce:($i % 2 -eq 0) }
        $done = @($procs | ForEach-Object { try { Complete-Afr $_ } catch {} })
        $killed = @($done | Where-Object { $_.Killed }).Count
        Start-Sleep -Seconds 16   # longer than the 15 s stale-lock threshold
        $r = Invoke-Hook
        $got = if ($r.ExitCode -eq 0 -and $r.StdErr -notmatch "recording failed") { "recorded" } else { "failed" }
        if ($killed -eq 0) {
            # every writer finished before the kill; termination was not exercised
            Add-Result -Name "recording continues after killed writers" -Expected "recorded" -Actual "not exercised" -Status "SKIP" -Details "all writers exited before they could be killed"
        } else {
            Compare-Result -Name "recording continues after killed writers" -Expected "recorded" -Actual $got -Details ("killed {0}; stderr: {1}" -f $killed, $r.StdErr)
        }
        $v = Get-Verify
        $state = if ($v.Status -eq "CONSISTENT") { "consistent" } elseif ($v.Status -eq "INVALID") { "invalid (torn record marked)" } else { $v.Status }
        Add-Result -Name "chain state after termination" -Expected "consistent, or invalid with a marked torn record" -Actual $state -Status $(if ($v.Status -in @("CONSISTENT", "INVALID")) { "PASS" } else { "FAIL" }) -Details $v.Raw
    }

    "other" {
        $read = Test-Op -Name "read" -Op { [IO.File]::ReadAllText($LogPath) }
        Compare-Result -Name "other user's log read" -Expected "denied" -Actual $read[0] -Details $read[1]
        $r = Invoke-Hook
        $got = if ($r.StdErr -match "recording failed") { "denied" } else { "allowed" }
        Compare-Result -Name "other user's log append via afr" -Expected "denied" -Actual $got -Details $r.StdErr
        Test-Attacks -Target $LogPath -Prefix "other user's log"
    }

    "squat" {
        $r = Invoke-Hook
        $got = if ($r.ExitCode -eq 0 -and $r.StdErr -notmatch "recording failed") { "allowed" } else { "denied" }
        # documented gap: the expected (current) behaviour is that this succeeds
        Add-Result -Name "pre-create another user's log name" -Expected "allowed (documented gap)" -Actual $got -Status $(if ($got -eq "allowed") { "GAP" } else { "PASS" }) -Details ("exit {0}; stderr: {1}" -f $r.ExitCode, $r.StdErr)
    }

    "victim" {
        $r = Invoke-Hook
        $got = if ($r.StdErr -match "recording failed") { "recording failed" } else { "recorded" }
        Add-Result -Name "victim records into a squatted log" -Expected "recording failed (documented gap)" -Actual $got -Status $(if ($got -eq "recording failed") { "GAP" } else { "FAIL" }) -Details $r.StdErr
        Compare-Result -Name "victim hook still exits 0 (fail-open default)" -Expected "0" -Actual ([string]$r.ExitCode)
    }
}
