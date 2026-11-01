#Requires -Version 5.1
<#
.SYNOPSIS
    Windows validation suite for afr. Must run on the Windows host itself.

.DESCRIPTION
    Phases (each records PASS / FAIL / GAP / SKIP / INFO lines in
    <WorkRoot>\evidence\results.jsonl, plus raw output files):

      env       host facts; refuses to run outside Windows or with a managed
                afr policy present (it would redirect the test logs)
      go        go vet, go test, go test -race (only if cgo + a C compiler are
                available), builds afr.exe and the test stub into a path with
                spaces and non-ASCII characters
      fixture   synthetic fixture workflow: collect, verify, report
      parse     both deployment scripts and these test scripts parsed by every
                PowerShell available (Windows PowerShell 5.1, PowerShell 7)
      deploy    Install-AFR.ps1 and Invoke-AFRCollect.ps1 executed against
                temporary folders and fake profiles only; real agent and
                machine configuration is hashed before and after
      native    both scripts driven into each failure path with a stub afr.exe
      accounts  two disposable standard users run the recorder and attack the
                central log (needs administrator to create the accounts; the
                tests themselves run as the standard users)

    Nothing touches real agent configuration, production policy locations,
    or personal data. Accounts are named afrval1 / afrval2 and removed at
    the end unless -KeepAccounts. Evidence is never deleted automatically.

.EXAMPLE
    # from an elevated Windows PowerShell or PowerShell 7 prompt, in the repo:
    powershell -NoProfile -ExecutionPolicy Bypass -File test\windows\Invoke-WindowsValidation.ps1

.EXAMPLE
    # remove leftover test accounts and profiles from an interrupted run
    powershell -NoProfile -ExecutionPolicy Bypass -File test\windows\Invoke-WindowsValidation.ps1 -CleanupOnly
#>
[CmdletBinding()]
param(
    [string]$RepoRoot,
    [string]$WorkRoot,
    [switch]$SkipGoTests,
    [switch]$SkipFixture,
    [switch]$SkipDeployScripts,
    [switch]$SkipAccounts,
    [switch]$KeepAccounts,
    [switch]$CleanupOnly,
    [int]$Concurrency = 24
)

$ErrorActionPreference = "Stop"
$UserPrefix = "afrval"

# ------------------------------------------------------------------ guards

if ($env:OS -ne "Windows_NT" -or ($PSVersionTable.PSEdition -eq "Core" -and -not $IsWindows)) {
    throw "This suite must run on the Windows host itself, not in WSL, a container or a remote Linux shell."
}
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

function Remove-TestAccounts {
    foreach ($u in @(Get-LocalUser -ErrorAction SilentlyContinue | Where-Object { $_.Name -like "$UserPrefix*" })) {
        $sid = $u.SID.Value
        Write-Output "removing test account $($u.Name) ($sid)"
        Remove-LocalUser -SID $sid -ErrorAction SilentlyContinue
        for ($i = 0; $i -lt 5; $i++) {
            $prof = Get-CimInstance Win32_UserProfile -ErrorAction SilentlyContinue | Where-Object { $_.SID -eq $sid }
            if (-not $prof) { break }
            try { $prof | Remove-CimInstance -ErrorAction Stop; break } catch { Start-Sleep -Seconds 2 }
        }
    }
}

if ($CleanupOnly) {
    if (-not $isAdmin) { throw "-CleanupOnly needs an elevated prompt" }
    Remove-TestAccounts
    Write-Output "Work folders are kept as evidence. Remove them yourself when done:"
    Get-ChildItem "$env:SystemDrive\" -Directory -Filter "afr-winval-*" | ForEach-Object { Write-Output "  Remove-Item -Recurse -Force '$($_.FullName)'" }
    return
}

if (-not $RepoRoot) { $RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path }
if (-not $WorkRoot) { $WorkRoot = Join-Path $env:SystemDrive ("afr-winval-" + (Get-Date -Format "yyyyMMdd-HHmmss")) }
$Uni = "$([char]0x00FC)n$([char]0x00EF)c$([char]0x00F8)d$([char]0x00E9) $([char]0x2713)"
$U = Join-Path $WorkRoot "space dir $Uni"
$Ev = Join-Path $WorkRoot "evidence"
New-Item -ItemType Directory -Force -Path $WorkRoot, $U, $Ev | Out-Null
$Results = Join-Path $Ev "results.jsonl"
$utf8 = New-Object System.Text.UTF8Encoding($false)
Start-Transcript -Path (Join-Path $Ev "transcript.txt") | Out-Null

# Clean environment for every child process this suite starts.
$env:AFR_LOG = ""
$env:AFR_POLICY = ""
$env:AFR_STUB_MODE = ""

# ------------------------------------------------------------------ helpers

function Add-Result {
    param([string]$Phase, [string]$Name, [string]$Expected, [string]$Actual, [string]$Status, [string]$Details = "")
    $o = [ordered]@{ phase = $Phase; name = $Name; identity = [Security.Principal.WindowsIdentity]::GetCurrent().Name; expected = $Expected; actual = $Actual; status = $Status; details = $Details; time = (Get-Date).ToUniversalTime().ToString("o") }
    [IO.File]::AppendAllText($Results, ($o | ConvertTo-Json -Compress -Depth 4) + "`n", $utf8)
    $color = @{ PASS = "Green"; FAIL = "Red"; GAP = "Yellow"; SKIP = "DarkYellow"; INFO = "Gray" }[$Status]
    Write-Host ("[{0}] {1} / {2}: {3}" -f $Status, $Phase, $Name, $Actual) -ForegroundColor $color
}

function Compare-Result {
    param([string]$Phase, [string]$Name, [string]$Expected, [string]$Actual, [string]$Details = "")
    Add-Result -Phase $Phase -Name $Name -Expected $Expected -Actual $Actual -Status $(if ($Expected -eq $Actual) { "PASS" } else { "FAIL" }) -Details $Details
}

function ConvertTo-Arg([string]$a) {
    if ($a -eq "") { return '""' }
    if ($a -notmatch '[\s"]') { return $a }
    $s = $a -replace '(\\*)"', '$1$1\"'
    $s = $s -replace '(\\+)$', '$1$1'
    return '"' + $s + '"'
}

# Runs a native program with output captured to evidence files. Optional
# environment variables are set only for the child.
function Invoke-Native {
    param([string]$Exe, [string[]]$ArgList, [string]$Tag, [hashtable]$Env = @{}, [string]$WorkDir = $RepoRoot)
    $out = Join-Path $Ev "$Tag.out.txt"
    $err = Join-Path $Ev "$Tag.err.txt"
    $saved = @{}
    foreach ($k in $Env.Keys) { $saved[$k] = [Environment]::GetEnvironmentVariable($k); [Environment]::SetEnvironmentVariable($k, $Env[$k]) }
    try {
        $argString = ($ArgList | ForEach-Object { ConvertTo-Arg $_ }) -join " "
        $p = Start-Process -FilePath $Exe -ArgumentList $argString -WorkingDirectory $WorkDir -RedirectStandardOutput $out -RedirectStandardError $err -NoNewWindow -Wait -PassThru
    } finally {
        foreach ($k in $Env.Keys) { [Environment]::SetEnvironmentVariable($k, $saved[$k]) }
    }
    [pscustomobject]@{ ExitCode = $p.ExitCode; StdOut = (Get-Content -Raw -ErrorAction SilentlyContinue $out); StdErr = (Get-Content -Raw -ErrorAction SilentlyContinue $err); Out = $out; Err = $err }
}

$PS51 = Join-Path $env:SystemRoot "System32\WindowsPowerShell\v1.0\powershell.exe"
$PS7 = (Get-Command pwsh -ErrorAction SilentlyContinue).Source

function Invoke-Script {
    param([string]$Host_, [string]$Script, [string[]]$ArgList, [string]$Tag, [hashtable]$Env = @{})
    Invoke-Native -Exe $Host_ -ArgList (@("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", $Script) + $ArgList) -Tag $Tag -Env $Env
}

function Get-FileHashOrAbsent([string]$p) {
    if (Test-Path -LiteralPath $p) { (Get-FileHash -LiteralPath $p -Algorithm SHA256).Hash } else { "absent" }
}

# ------------------------------------------------------------------ env

$phase = "env"
$os = Get-CimInstance Win32_OperatingSystem
Add-Result $phase "host" "Windows" ("{0} {1} build {2}" -f $os.Caption, $os.Version, $os.BuildNumber) "INFO"
Add-Result $phase "powershell" "-" ("{0} {1}; PS7 available: {2}" -f $PSVersionTable.PSEdition, $PSVersionTable.PSVersion, [bool]$PS7) "INFO"
Add-Result $phase "elevated" "-" ([string]$isAdmin) "INFO"
try { Add-Result $phase "join state" "-" ((& dsregcmd.exe /status 2>$null | Select-String "AzureAdJoined|DomainJoined|WorkplaceJoined" | ForEach-Object { $_.ToString().Trim() }) -join "; ") "INFO" } catch {}
foreach ($tool in @("go", "git", "python", "py")) {
    $c = Get-Command $tool -ErrorAction SilentlyContinue
    Add-Result $phase "tool $tool" "-" $(if ($c) { $c.Source } else { "not found" }) "INFO"
}
$managed = Join-Path $env:ProgramData "AgentFlightRecorder\policy.json"
if (Test-Path -LiteralPath $managed) {
    Add-Result $phase "no managed afr policy present" "absent" "present" "FAIL" "A managed policy at $managed overrides AFR_LOG and would send test records into the managed log. Move it aside or run on another machine."
    Stop-Transcript | Out-Null
    exit 1
}
Add-Result $phase "no managed afr policy present" "absent" "absent" "PASS"

if ($isAdmin) {
    # The work root sits at the drive root so the test accounts can reach it.
    # Lock it down: only SYSTEM/Administrators write, Users read and execute.
    $null = & icacls.exe $WorkRoot /inheritance:r /grant:r "*S-1-5-18:(OI)(CI)F" "*S-1-5-32-544:(OI)(CI)F" "*S-1-5-32-545:(OI)(CI)RX"
    if ($LASTEXITCODE -ne 0) { throw "could not set the work root ACL" }
}

# ------------------------------------------------------------------ go

$phase = "go"
$bin = Join-Path $U "bin"
New-Item -ItemType Directory -Force -Path $bin, (Join-Path $WorkRoot "stub") | Out-Null
$Afr = Join-Path $bin "afr.exe"
$Stub = Join-Path $WorkRoot "stub\afr.exe"
$go = (Get-Command go -ErrorAction SilentlyContinue).Source
if (-not $go) { throw "Go is required (go.mod needs 1.26 or newer)" }
Add-Result $phase "go version" "1.26+" ((& $go version) -join "") "INFO"

$r = Invoke-Native $go @("build", "-o", $Afr, ".") "go-build"
Compare-Result $phase "build afr.exe into a path with spaces and non-ASCII" "0" ([string]$r.ExitCode) $r.StdErr
$r = Invoke-Native $go @("build", "-o", $Stub, "./test/windows/stubafr") "go-build-stub"
Compare-Result $phase "build test stub" "0" ([string]$r.ExitCode) $r.StdErr
if (-not (Test-Path -LiteralPath $Afr)) { throw "afr.exe was not built; see evidence\go-build.err.txt" }

if (-not $SkipGoTests) {
    $r = Invoke-Native $go @("vet", "./...") "go-vet"
    Compare-Result $phase "go vet ./..." "0" ([string]$r.ExitCode) $r.StdErr
    $r = Invoke-Native $go @("test", "-count=1", "./...") "go-test"
    Compare-Result $phase "go test ./..." "0" ([string]$r.ExitCode) "see evidence\go-test.out.txt"
    $cgo = ((& $go env CGO_ENABLED) -join "").Trim()
    $cc = Get-Command gcc -ErrorAction SilentlyContinue
    if ($cgo -eq "1" -and $cc) {
        $r = Invoke-Native $go @("test", "-race", "-count=1", "./...") "go-test-race"
        Compare-Result $phase "go test -race ./..." "0" ([string]$r.ExitCode) "see evidence\go-test-race.out.txt"
    } else {
        Add-Result $phase "go test -race ./..." "0" "not run" "SKIP" "The race detector on Windows needs CGO_ENABLED=1 and a C compiler (gcc, e.g. from MSYS2/MinGW-w64). CGO_ENABLED=$cgo, gcc found: $([bool]$cc)."
    }
} else {
    Add-Result $phase "go vet / test / race" "-" "skipped by -SkipGoTests" "SKIP"
}

# ------------------------------------------------------------------ fixture

$phase = "fixture"
$py = (Get-Command python -ErrorAction SilentlyContinue).Source
$pyArgs = @()
if (-not $py) { $py = (Get-Command py -ErrorAction SilentlyContinue).Source; $pyArgs = @("-3") }
if ($SkipFixture) {
    Add-Result $phase "fixture workflow" "-" "skipped by -SkipFixture" "SKIP"
} elseif (-not $py) {
    Add-Result $phase "fixture workflow" "-" "Python 3 not found" "SKIP" "Install Python 3 (python.org or 'winget install Python.Python.3.12')."
} else {
    $F = Join-Path $U "fixtures"
    $r = Invoke-Native $py ($pyArgs + @("testdata/gen_fixtures.py", $F)) "fixture-gen"
    Compare-Result $phase "generate fixtures" "0" ([string]$r.ExitCode) $r.StdErr
    $bundle = Join-Path $U "demo bundle.zip"
    $noLog = @{ AFR_LOG = (Join-Path $U "no-live-log.jsonl"); AFR_POLICY = "" }
    $r = Invoke-Native $Afr @("collect", "--home", (Join-Path $F "home\dev"), "--workspace", (Join-Path $F "src\acme-sdk"), "--around", "2026-10-29T13:44:00Z", "--margin", "1h", "-o", $bundle) "fixture-collect" $noLog
    Compare-Result $phase "collect" "0" ([string]$r.ExitCode) $r.StdErr
    $r = Invoke-Native $Afr @("verify", $bundle) "fixture-verify"
    Compare-Result $phase "verify bundle" "0" ([string]$r.ExitCode) $r.StdOut
    $report = Join-Path $U "report.html"
    $r = Invoke-Native $Afr @("report", $bundle, "--trace", ".aws/credentials", "-o", $report) "fixture-report"
    Compare-Result $phase "report" "0" ([string]$r.ExitCode) $r.StdErr
    $html = if (Test-Path -LiteralPath $report) { Get-Content -Raw -LiteralPath $report -Encoding UTF8 } else { "" }
    Compare-Result $phase "report shows a supported completion" "True" ([string]($html -match "Supported completion")) ""
    if (Test-Path -LiteralPath $bundle) {
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        $z = [IO.Compression.ZipFile]::OpenRead($bundle)
        $hasWs = [bool]($z.Entries | Where-Object { $_.FullName -like "workspace/*AGENTS.md" })
        $z.Dispose()
        Compare-Result $phase "workspace instructions captured" "True" ([string]$hasWs) ""
    }
}

# ------------------------------------------------------------------ parse

$phase = "parse"
$scripts = @(Get-ChildItem (Join-Path $RepoRoot "deploy\windows\*.ps1")) + @(Get-ChildItem (Join-Path $RepoRoot "test\windows\*.ps1"))
$hosts = @(@{ Name = "Windows PowerShell 5.1"; Exe = $PS51 })
if ($PS7) { $hosts += @{ Name = "PowerShell 7"; Exe = $PS7 } } else { Add-Result $phase "PowerShell 7 parse" "-" "pwsh not installed" "SKIP" "winget install Microsoft.PowerShell" }
foreach ($h in $hosts) {
    foreach ($f in $scripts) {
        $cmd = '$e = $null; [void][System.Management.Automation.Language.Parser]::ParseFile($args[0], [ref]$null, [ref]$e); if ($e) { $e | ForEach-Object { $_.ToString() }; exit 1 }'
        $quotedPath = $f.FullName -replace "'", "''"
        $enc = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes("& { $cmd } '" + $quotedPath + "'"))
        $r = Invoke-Native $h.Exe @("-NoProfile", "-EncodedCommand", $enc) ("parse-" + $f.BaseName + "-" + ($h.Name -replace '\W', ''))
        Compare-Result $phase ("{0}: {1}" -f $h.Name, $f.Name) "0" ([string]$r.ExitCode) ($r.StdOut + $r.StdErr)
    }
}

# ------------------------------------------------------------------ deploy (isolated)

$phase = "deploy"
$Data = Join-Path $U "data"
$Logs = Join-Path $Data "logs"
if ($SkipDeployScripts) {
    Add-Result $phase "deployment scripts" "-" "skipped by -SkipDeployScripts" "SKIP"
} elseif (-not $isAdmin) {
    Add-Result $phase "deployment scripts" "-" "not elevated" "SKIP" "Install-AFR.ps1 sets ACLs and is meant to run elevated; rerun from an elevated prompt."
} else {
    $realConfigs = @(
        (Join-Path $HOME ".claude\settings.json"), (Join-Path $HOME ".codex\hooks.json"), (Join-Path $HOME ".cursor\hooks.json"),
        (Join-Path $HOME ".gemini\settings.json"), (Join-Path $HOME ".copilot\hooks\afr.json"), (Join-Path $HOME ".config\opencode\plugin\afr.js"),
        (Join-Path $env:ProgramData "GitHub\Copilot\policy.d\afr.json"), (Join-Path $env:ProgramData "ClaudeCode\managed-settings.json"),
        $managed, (Join-Path $env:ProgramData "AgentFlightRecorder\on-policy-error")
    )
    $before = @{}; foreach ($c in $realConfigs) { $before[$c] = Get-FileHashOrAbsent $c }

    $src = Join-Path $U "source"
    $prof = Join-Path $U "profiles"
    New-Item -ItemType Directory -Force -Path $src, (Join-Path $prof "alice $Uni"), (Join-Path $prof "bob") | Out-Null
    Copy-Item -LiteralPath $Afr -Destination (Join-Path $src "afr.exe") -Force
    $pol = [ordered]@{ log_path = (Join-Path $Logs "%USERNAME%.jsonl"); rules = @(@{ pattern = "**/.ssh/**"; action = "deny"; label = "ssh" }) }
    [IO.File]::WriteAllText((Join-Path $src "policy.json"), ($pol | ConvertTo-Json -Depth 4), $utf8)
    $installArgs = @("-Source", $src, "-ProgramDir", (Join-Path $U "prog"), "-DataDir", $Data, "-ProfilesRoot", $prof, "-SkipMachineHooks")
    $installer = Join-Path $RepoRoot "deploy\windows\Install-AFR.ps1"

    $r = Invoke-Script $PS51 $installer $installArgs "deploy-install-1"
    Compare-Result $phase "Install-AFR.ps1 (isolated) first run" "0" ([string]$r.ExitCode) ($r.StdOut + $r.StdErr)
    $r = Invoke-Script $PS51 $installer $installArgs "deploy-install-2"
    Compare-Result $phase "Install-AFR.ps1 (isolated) second run" "0" ([string]$r.ExitCode) ($r.StdOut + $r.StdErr)
    $settings = Join-Path $prof "alice $Uni\.claude\settings.json"
    $n = if (Test-Path -LiteralPath $settings) { ([regex]::Matches((Get-Content -Raw -LiteralPath $settings), 'hook --agent claude-code --event PreToolUse')).Count } else { -1 }
    Compare-Result $phase "re-install is idempotent (one PreToolUse handler)" "1" ([string]$n) $settings

    # ACL actually applied to the central log folder, checked by SID
    & icacls.exe $Logs | Out-File -Encoding utf8 (Join-Path $Ev "deploy-logs-acl.txt")
    $acl = Get-Acl -LiteralPath $Logs
    function Get-Rights([string]$sid) {
        $rules = $acl.Access | Where-Object { $_.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value -eq $sid -and $_.AccessControlType -eq "Allow" }
        $x = 0; foreach ($ru in $rules) { $x = $x -bor [int]$ru.FileSystemRights }
        [Security.AccessControl.FileSystemRights]$x
    }
    $R = [Security.AccessControl.FileSystemRights]
    foreach ($sid in @("S-1-3-0", "S-1-3-4")) {
        $g = Get-Rights $sid
        $need = $R::ReadData -bor $R::AppendData -bor $R::ReadAttributes -bor $R::ReadExtendedAttributes -bor $R::ReadPermissions -bor $R::Synchronize
        $forbid = $R::WriteData -bor $R::Delete -bor $R::ChangePermissions -bor $R::TakeOwnership -bor $R::WriteAttributes -bor $R::WriteExtendedAttributes
        Compare-Result $phase "log ACL $sid grants read+append+synchronize" "True" ([string](([int]$g -band [int]$need) -eq [int]$need)) ([string]$g)
        Compare-Result $phase "log ACL $sid grants no write/delete/permission change" "True" ([string](([int]$g -band [int]$forbid) -eq 0)) ([string]$g)
    }
    $usersRights = Get-Rights "S-1-5-32-545"
    Compare-Result $phase "Users cannot delete children of the log folder" "True" ([string](([int]$usersRights -band [int]$R::DeleteSubdirectoriesAndFiles) -eq 0)) ([string]$usersRights)
    Compare-Result $phase "log folder does not inherit parent ACEs" "True" ([string]$acl.AreAccessRulesProtected) ""

    # collection script against the fixture profile, output to a temp folder
    if ($py) {
        $collectScript = Join-Path $RepoRoot "deploy\windows\Invoke-AFRCollect.ps1"
        $r = Invoke-Script $PS51 $collectScript @("-ProfileDir", (Join-Path $U "fixtures\home\dev"), "-OutDir", (Join-Path $U "collections"), "-AfrPath", $Afr, "-Around", "2026-10-29T13:44:00Z", "-Margin", "1h", "-Case", "WINVAL") "deploy-collect"
        Compare-Result $phase "Invoke-AFRCollect.ps1 on fixture profile" "0" ([string]$r.ExitCode) ($r.StdOut + $r.StdErr)
        $b = ($r.StdOut -split "`r?`n" | Where-Object { $_ -like "BUNDLE: *" } | Select-Object -First 1)
        # take the file from the output folder: the work root has non-ASCII in
        # it, and the child's redirected stdout is not UTF-8 on every host
        $zip = Get-ChildItem -LiteralPath (Join-Path $U "collections") -Filter "*.zip" -ErrorAction SilentlyContinue | Sort-Object LastWriteTime | Select-Object -Last 1
        if ($b -and $zip) {
            $v = Invoke-Native $Afr @("verify", $zip.FullName) "deploy-collect-verify"
            Compare-Result $phase "bundle from collection script verifies" "0" ([string]$v.ExitCode) $v.StdOut
        } else {
            Add-Result $phase "bundle from collection script verifies" "0" "no BUNDLE line" "FAIL" $r.StdOut
        }
    }

    $changed = @($realConfigs | Where-Object { (Get-FileHashOrAbsent $_) -ne $before[$_] })
    Compare-Result $phase "real agent and machine configuration untouched" "0 changed" ("{0} changed" -f $changed.Count) ($changed -join "; ")
}

# ------------------------------------------------------------------ native command failures

$phase = "native"
if ($SkipDeployScripts -or -not $isAdmin) {
    Add-Result $phase "native failure handling" "-" "skipped (needs -SkipDeployScripts off and an elevated prompt)" "SKIP"
} else {
    $installer = Join-Path $RepoRoot "deploy\windows\Install-AFR.ps1"
    $collectScript = Join-Path $RepoRoot "deploy\windows\Invoke-AFRCollect.ps1"
    $hostsToTry = @(@{ Name = "PS5.1"; Exe = $PS51 })
    if ($PS7) { $hostsToTry += @{ Name = "PS7"; Exe = $PS7 } }
    foreach ($h in $hostsToTry) {
        foreach ($case in @(@{ Mode = "fail-version"; Want = "nonzero" }, @{ Mode = "fail-install"; Want = "nonzero" }, @{ Mode = "ok"; Want = "0" })) {
            $d = Join-Path $WorkRoot ("stubcases\{0}-install-{1}" -f $h.Name, $case.Mode)
            New-Item -ItemType Directory -Force -Path (Join-Path $d "src"), (Join-Path $d "profiles\p1") | Out-Null
            Copy-Item -LiteralPath $Stub -Destination (Join-Path $d "src\afr.exe") -Force
            $r = Invoke-Script $h.Exe $installer @("-Source", (Join-Path $d "src"), "-ProgramDir", (Join-Path $d "prog"), "-DataDir", (Join-Path $d "data"), "-ProfilesRoot", (Join-Path $d "profiles"), "-SkipMachineHooks") ("native-{0}-install-{1}" -f $h.Name, $case.Mode) @{ AFR_STUB_MODE = $case.Mode }
            $got = if ($r.ExitCode -eq 0) { "0" } else { "nonzero" }
            Compare-Result $phase ("{0} Install-AFR with stub {1}" -f $h.Name, $case.Mode) $case.Want $got ("exit {0}: {1}" -f $r.ExitCode, ($r.StdOut + $r.StdErr))
        }
        foreach ($case in @(
                @{ Mode = "collect-fail"; Exit = 1; Bundle = $false }, @{ Mode = "collect-partial"; Exit = 3; Bundle = $true },
                @{ Mode = "collect-nosidecar"; Exit = 1; Bundle = $false }, @{ Mode = "collect-badhash"; Exit = 1; Bundle = $false },
                @{ Mode = "ok"; Exit = 0; Bundle = $true })) {
            $d = Join-Path $WorkRoot ("stubcases\{0}-collect-{1}" -f $h.Name, $case.Mode)
            New-Item -ItemType Directory -Force -Path (Join-Path $d "profile"), (Join-Path $d "out") | Out-Null
            $r = Invoke-Script $h.Exe $collectScript @("-ProfileDir", (Join-Path $d "profile"), "-OutDir", (Join-Path $d "out"), "-AfrPath", $Stub, "-Last", "1h") ("native-{0}-collect-{1}" -f $h.Name, $case.Mode) @{ AFR_STUB_MODE = $case.Mode }
            Compare-Result $phase ("{0} Invoke-AFRCollect exit with stub {1}" -f $h.Name, $case.Mode) ([string]$case.Exit) ([string]$r.ExitCode) $r.StdOut
            Compare-Result $phase ("{0} Invoke-AFRCollect announces a bundle with stub {1}" -f $h.Name, $case.Mode) ([string]$case.Bundle) ([string]($r.StdOut -match "BUNDLE: ")) $r.StdOut
        }
    }
}

# ------------------------------------------------------------------ accounts

$phase = "accounts"
if ($SkipAccounts) {
    Add-Result $phase "standard-user recorder tests" "-" "skipped by -SkipAccounts" "SKIP"
} elseif (-not $isAdmin) {
    Add-Result $phase "standard-user recorder tests" "-" "not elevated" "SKIP" "Creating disposable accounts needs an elevated prompt; the tests themselves run as those accounts."
} elseif (-not (Test-Path -LiteralPath $Logs)) {
    Add-Result $phase "standard-user recorder tests" "-" "no deployed log folder" "SKIP" "The deploy phase creates the log folder with the production ACL; it did not run or failed."
} elseif ((Get-Service seclogon -ErrorAction SilentlyContinue).StartType -eq "Disabled") {
    Add-Result $phase "standard-user recorder tests" "-" "Secondary Logon service disabled" "SKIP" "Start-Process -Credential needs the seclogon service."
} else {
    $created = @()
    try {
        $creds = @{}
        foreach ($name in @("${UserPrefix}1", "${UserPrefix}2")) {
            if (Get-LocalUser -Name $name -ErrorAction SilentlyContinue) { throw "account $name already exists; run with -CleanupOnly first" }
            $chars = [char[]]"ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!#%+=?"
            $rng = [Security.Cryptography.RandomNumberGenerator]::Create()
            $bytes = New-Object byte[] 24; $rng.GetBytes($bytes)
            $pw = "Aa1!" + (-join ($bytes | ForEach-Object { $chars[$_ % $chars.Length] }))
            $sec = ConvertTo-SecureString $pw -AsPlainText -Force
            $pw = $null
            New-LocalUser -Name $name -Password $sec -AccountNeverExpires -PasswordNeverExpires -Description "afr validation, disposable" | Out-Null
            $created += $name
            try { Add-LocalGroupMember -SID "S-1-5-32-545" -Member $name -ErrorAction Stop } catch { } # usually a member already
            try {
                $isAdm = [bool](Get-LocalGroupMember -SID "S-1-5-32-544" -ErrorAction Stop | Where-Object { $_.Name -like "*\$name" })
                Compare-Result $phase "$name is a standard user" "False" ([string]$isAdm) ""
            } catch {
                # Get-LocalGroupMember fails on some Entra-joined machines; the account was created here without admin membership
                Add-Result $phase "$name is a standard user" "False" "not enumerable" "INFO" $_.Exception.Message
            }
            $creds[$name] = New-Object Management.Automation.PSCredential("$env:COMPUTERNAME\$name", $sec)
            $scratch = Join-Path $WorkRoot "users\$name"
            New-Item -ItemType Directory -Force -Path $scratch | Out-Null
            $sid = (Get-LocalUser -Name $name).SID.Value
            $null = & icacls.exe $scratch /grant "*${sid}:(OI)(CI)M"
        }
        # The repository may sit inside an administrator's profile, which the test
        # accounts cannot read; give them a copy under the work root.
        $userScript = Join-Path $WorkRoot "scripts\Test-RecorderAsUser.ps1"
        New-Item -ItemType Directory -Force -Path (Split-Path $userScript) | Out-Null
        Copy-Item -LiteralPath (Join-Path $RepoRoot "test\windows\Test-RecorderAsUser.ps1") -Destination $userScript -Force
        function Invoke-AsUser([string]$name, [string]$mode, [string]$log) {
            $scratch = Join-Path $WorkRoot "users\$name"
            $argString = (@("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", $userScript, "-Mode", $mode, "-Afr", $Afr, "-LogPath", $log,
                    "-ResultFile", (Join-Path $scratch "results.jsonl"), "-ScratchDir", (Join-Path $scratch "tmp-$mode"), "-Concurrency", "$Concurrency") | ForEach-Object { ConvertTo-Arg $_ }) -join " "
            $p = Start-Process -FilePath $PS51 -ArgumentList $argString -Credential $creds[$name] -LoadUserProfile -WorkingDirectory $scratch `
                -RedirectStandardOutput (Join-Path $Ev "user-$name-$mode.out.txt") -RedirectStandardError (Join-Path $Ev "user-$name-$mode.err.txt") -Wait -PassThru
            Add-Result $phase "$name ran mode $mode" "0" ([string]$p.ExitCode) "INFO" "see evidence\user-$name-$mode.*.txt"
        }
        $victimLog = Join-Path $Logs "${UserPrefix}1.jsonl"
        $ownLog = Join-Path $Logs "${UserPrefix}1-own.jsonl"
        Invoke-AsUser "${UserPrefix}2" "squat" $victimLog
        Invoke-AsUser "${UserPrefix}1" "victim" $victimLog
        Invoke-AsUser "${UserPrefix}1" "own" $ownLog
        Invoke-AsUser "${UserPrefix}2" "other" $ownLog

        # the collection script as the person under review would run it: no
        # admin rights, no arguments beyond the window
        $userCollect = Join-Path $WorkRoot "scripts\Invoke-AFRCollect.ps1"
        Copy-Item -LiteralPath (Join-Path $RepoRoot "deploy\windows\Invoke-AFRCollect.ps1") -Destination $userCollect -Force
        $cname = "${UserPrefix}1"
        $cscratch = Join-Path $WorkRoot "users\$cname"
        $cout = Join-Path $Ev "user-$cname-collect.out.txt"
        # seed the test user's profile with the synthetic agent sessions, so the
        # unelevated run has real artifacts to find (the profile exists once
        # the account has logged on through the recorder tests above)
        $cprofile = Join-Path $env:SystemDrive "Users\$cname"
        $fixtureHome = Join-Path $U "fixtures\home\dev"
        $seeded = $false
        if ((Test-Path -LiteralPath $fixtureHome) -and (Test-Path -LiteralPath $cprofile)) {
            Get-ChildItem -LiteralPath $fixtureHome -Force | Copy-Item -Destination $cprofile -Recurse -Force
            $seeded = $true
        }
        $window = if ($seeded) { @("-Around", "2026-10-29T13:44:00Z", "-Margin", "1h") } else { @("-Last", "24h") }
        $argString = (@("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", $userCollect, "-AfrPath", $Afr) + $window | ForEach-Object { ConvertTo-Arg $_ }) -join " "
        $p = Start-Process -FilePath $PS51 -ArgumentList $argString -Credential $creds[$cname] -LoadUserProfile -WorkingDirectory $cscratch `
            -RedirectStandardOutput $cout -RedirectStandardError (Join-Path $Ev "user-$cname-collect.err.txt") -Wait -PassThru
        Compare-Result "collect-user" "standard user runs Invoke-AFRCollect.ps1 on own profile" "0" ([string]$p.ExitCode) (Get-Content -Raw -ErrorAction SilentlyContinue $cout)
        $desk = Join-Path $env:SystemDrive "Users\$cname\Desktop"
        $zip = Get-ChildItem -LiteralPath $desk -Filter "afr-*.zip" -ErrorAction SilentlyContinue | Select-Object -Last 1
        Compare-Result "collect-user" "bundle written to the user's Desktop" "True" ([string]([bool]$zip)) $desk
        if ($zip) {
            # keep a copy: the test profile goes when the account is removed
            Copy-Item -LiteralPath $zip.FullName, ($zip.FullName + ".sha256") -Destination $Ev -ErrorAction SilentlyContinue
            Compare-Result "collect-user" "sidecar written next to it" "True" ([string](Test-Path -LiteralPath ($zip.FullName + ".sha256"))) ""
            $v = Invoke-Native $Afr @("verify", $zip.FullName) "user-collect-verify"
            Compare-Result "collect-user" "user bundle verifies" "0" ([string]$v.ExitCode) $v.StdOut
            Add-Type -AssemblyName System.IO.Compression.FileSystem
            $za = [IO.Compression.ZipFile]::OpenRead($zip.FullName)
            try {
                $me = $za.Entries | Where-Object { $_.FullName -eq "manifest.json" } | Select-Object -First 1
                $sr = New-Object IO.StreamReader($me.Open())
                $man = $sr.ReadToEnd() | ConvertFrom-Json
                $sr.Close()
            } finally { $za.Dispose() }
            Compare-Result "collect-user" "bundle is labelled user mode" "user" ([string]$man.mode) ""
            if ($seeded) {
                Compare-Result "collect-user" "user-mode run finds the seeded agent sessions" "48" ([string]$man.events_in_window) "fixture collection as administrator found 48"
            } else {
                Add-Result "collect-user" "user-mode run finds the seeded agent sessions" "48" "not seeded" "SKIP" "fixtures or the test profile were missing"
            }
            Compare-Result "collect-user" "bundle records the collecting user" "True" ([string]($man.user -like "*\$cname")) ([string]$man.user)
        }
        # and the things a standard user must not be able to do with it
        foreach ($bad in @(
                @{ Name = "another user's profile is refused"; Args = @("-User", "${UserPrefix}2") },
                @{ Name = "-IncludeRaw is refused"; Args = @("-IncludeRaw") })) {
            $argString = (@("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", $userCollect, "-AfrPath", $Afr, "-Last", "24h") + $bad.Args | ForEach-Object { ConvertTo-Arg $_ }) -join " "
            $p = Start-Process -FilePath $PS51 -ArgumentList $argString -Credential $creds[$cname] -LoadUserProfile -WorkingDirectory $cscratch `
                -RedirectStandardOutput (Join-Path $Ev "user-$cname-collect-bad.out.txt") -RedirectStandardError (Join-Path $Ev "user-$cname-collect-bad.err.txt") -Wait -PassThru
            Compare-Result "collect-user" $bad.Name "nonzero" $(if ($p.ExitCode -ne 0) { "nonzero" } else { "0" }) (Get-Content -Raw -ErrorAction SilentlyContinue (Join-Path $Ev "user-$cname-collect-bad.err.txt"))
        }

        foreach ($name in $created) {
            $f = Join-Path $WorkRoot "users\$name\results.jsonl"
            if (Test-Path -LiteralPath $f) { [IO.File]::AppendAllText($Results, [IO.File]::ReadAllText($f, $utf8), $utf8) }
            else { Add-Result $phase "$name produced results" "results.jsonl" "missing" "FAIL" "the user-side script did not run; see evidence\user-$name-*.err.txt" }
        }
        # ownership and effective ACL of the files the users created
        foreach ($pair in @(@($ownLog, "${UserPrefix}1"), @($victimLog, "${UserPrefix}2"))) {
            if (Test-Path -LiteralPath $pair[0]) {
                $ownerSid = (Get-Acl -LiteralPath $pair[0]).GetOwner([Security.Principal.SecurityIdentifier]).Value
                $wantSid = (Get-LocalUser -Name $pair[1]).SID.Value
                Compare-Result $phase ("owner of {0}" -f (Split-Path $pair[0] -Leaf)) $pair[1] $(if ($ownerSid -eq $wantSid) { $pair[1] } else { $ownerSid }) ""
                & icacls.exe $pair[0] | Out-File -Encoding utf8 (Join-Path $Ev ("acl-" + (Split-Path $pair[0] -Leaf) + ".txt"))
                Copy-Item -LiteralPath $pair[0] -Destination (Join-Path $Ev ("log-" + (Split-Path $pair[0] -Leaf))) -Force
            } else {
                Add-Result $phase ("log file {0} exists" -f (Split-Path $pair[0] -Leaf)) "present" "absent" "FAIL" ""
            }
        }
    } catch {
        Add-Result $phase "standard-user recorder tests" "completed" "error" "FAIL" $_.Exception.Message
    } finally {
        if (-not $KeepAccounts) { Remove-TestAccounts }
        else { Add-Result $phase "accounts kept" "-" ($created -join ", ") "INFO" "remove later with -CleanupOnly" }
    }
}

# ------------------------------------------------------------------ summary

$all = Get-Content -LiteralPath $Results -Encoding UTF8 | Where-Object { $_.Trim() } | ForEach-Object { $_ | ConvertFrom-Json }
$counts = $all | Group-Object status | ForEach-Object { "{0}={1}" -f $_.Name, $_.Count }
$md = @("# afr Windows validation", "", "Host: $($os.Caption) $($os.Version), $($PSVersionTable.PSEdition) $($PSVersionTable.PSVersion), elevated: $isAdmin", "Work root: $WorkRoot", "Counts: $($counts -join ', ')", "", "| status | phase | check | expected | actual |", "|---|---|---|---|---|")
foreach ($x in $all) { $md += "| {0} | {1} | {2} | {3} | {4} |" -f $x.status, $x.phase, ($x.name -replace '\|', '/'), ($x.expected -replace '\|', '/'), ($x.actual -replace '\|', '/') }
[IO.File]::WriteAllLines((Join-Path $Ev "summary.md"), $md, $utf8)
Write-Host ""
Write-Host ("Results: {0}" -f ($counts -join ", "))
Write-Host "Evidence: $Ev (kept; delete it yourself when finished)"
Stop-Transcript | Out-Null
if (@($all | Where-Object { $_.status -eq "FAIL" }).Count -gt 0) { exit 1 }
exit 0
