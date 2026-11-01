# Windows validation record

What has actually been run on a Windows host, and what that does not cover.

## Run 5 (commit 91e58a6), 1 November 2026

Same host and setup. Result: 99 pass, 0 fail, 1 skip (race), 2 documented
gaps. With the synthetic sessions seeded into the standard user's profile,
the unelevated `Invoke-AFRCollect.ps1` run finds all 48 steps, the same as
the elevated collection, and the bundle verifies and is labelled user mode.
This closes the gap noted under run 4.

## Run 4 (commit b487bd8), 1 November 2026

Same host and setup as run 3. Result: 98 pass, 0 fail, 1 skip (race), the
same 2 documented gaps. New in this run, executed as the standard user
`afrval1` with no administrator rights:

- `Invoke-AFRCollect.ps1 -Last 24h` exits 0, writes the bundle and its
  sidecar to that user's Desktop, and the bundle verifies.
- The manifest says `mode: user` and names the collecting user.
- `-User afrval2` and `-IncludeRaw` are both refused with a non-zero exit.

Not shown by run 4: that profile held no agent data, so the unelevated run
found nothing to collect. Collection of real artifacts was only exercised
elevated. The suite after b487bd8 seeds the synthetic sessions into the test
profile first and checks that the unelevated run finds all 48 steps.

## Run 3 (commit a858da2), 1 November 2026

Host: Windows 11 Pro 10.0.26300, workgroup machine (not Entra or domain
joined), Windows PowerShell 5.1.26100 and PowerShell 7, Go 1.27.0, no C
compiler. Suite: `test\windows\Invoke-WindowsValidation.ps1` from an
elevated prompt, permission tests executed as two disposable local standard
users (`afrval1`, `afrval2`) through `Start-Process -Credential`.

Result: 90 pass, 0 fail, 1 skip, 2 documented gaps.

Verified on that host:

- `go vet` and `go test ./...` pass natively on windows/amd64.
- afr.exe builds into, and runs from, a path containing spaces and non-ASCII.
- Fixture generation, collection, `verify` and `report` complete end to end.
- All four PowerShell scripts parse under 5.1 and 7.
- `Install-AFR.ps1` runs twice against temporary folders, stays idempotent,
  and produces the intended log ACL (checked by SID, not by localised name).
- `Invoke-AFRCollect.ps1` produces a bundle that `afr verify` accepts, and
  exits 1 or 3 and withholds the BUNDLE line for every stub failure mode,
  under both PowerShell versions.
- As a standard user: the recorder creates and appends to its own log;
  24 concurrent writers lose nothing and keep the chain consistent; a fresh
  lock makes the hook report failure within about 3 s; a stale lock is
  removed and recording continues; after 12 writers are killed mid-start,
  recording continues and the chain verifies.
- As a standard user, against both their own log and another user's log:
  overwrite, truncate, set-length, delete, rename, Set-Acl, icacls grant and
  takeown are all refused. Another user's log cannot be read or appended to.
- A recorder that cannot write still exits 0 (fail-open default).
- Hashes of the operator's real agent and machine configuration files were
  unchanged before and after the run.

Confirmed gaps (behaviour observed, not fixed):

- A standard user can create a log under another user's name before that
  user's first recording. The victim's recorder is then refused and, being
  fail-open, the agent continues with nothing recorded. Attribution must
  rely on the file owner SID, and an absent or foreign-owned log needs
  alerting on.

Not covered by this run:

- The race detector (needs cgo and gcc on Windows).
- Domain or Entra joined machines, roaming profiles, non-English Windows.
- A real install into ProgramData by SYSTEM through Intune or Live Response.
- Any real agent driving the hooks.

## Earlier runs

Run 1 (04257ea) and run 2 (e9f5cf4) found one product bug, the collection
script aborting under Windows PowerShell 5.1 on afr's stderr output, plus
harness and test-portability faults. Fixed in e9f5cf4 and a858da2; the
evidence folders were kept by the operator.

## Real agent: GitHub Copilot in VS Code, 1 November 2026

Isolated test workspace from `test/windows/agent/New-CopilotTest.ps1`, hooks
scoped to that workspace, dummy secrets only. Copilot agent mode, Copilot
session target.

Observed:

- Hooks fire for prompts, session start and end, and every tool call and
  result: 44 records in one session, chain consistent, bundle verifies.
- The deny rule works end to end. Copilot's `view` of `secrets/credentials`
  was refused before it ran; Copilot reported "Denied by preToolUse hook"
  and could not give the line count. Recorded as blocked.
- The canary read of `decoy/deploy_keys.txt` went through and was recorded
  with an alert on both the call and its result.
- Copilot read the planted `CONTRIBUTING.md` unprompted and declined to act
  on it. The report places that read as the first mention of the target and
  the blocked read as the first request, in that order.
- A prompt Copilot refused outright left a prompt and stop records and no
  tool call, which is what the record should show.

Found and fixed:

- Copilot hook payloads carry no tool-call ID, so every call was reported
  with outcome unknown. Calls and results without IDs are now paired by
  identical tool name and arguments, only when exactly one such call is
  open; identical parallel calls stay unknown. Against the recorded session
  all 14 completed calls are now matched.

Open:

- The first prompt of the session was typed while VS Code was on another
  folder; Copilot moved the session into the test workspace and the hooks
  only started then. The record begins with Copilot's own "session is now
  attached" message, not the user's prompt. User-scope hooks
  (`~/.copilot/hooks`), which the installer writes, would not have this gap.
- The offline side found the workspace's `state.vscdb` but no chat
  transcript in it. Copilot-target sessions from VS Code are stored with
  Copilot CLI's, under `~/.copilot/session-state/<id>/events.jsonl`, and
  afr's existing parser reads them: 198 steps from the same session,
  including the first prompt the hooks missed. Found while comparing the
  two: the transcript records a hook-denied call as a failed execution, so
  the offline side said "failed" where the live log said "blocked". Fixed:
  a failure whose error starts "Denied by preToolUse hook" is now read as
  declined. Confirmed on the same host with d216543: both streams now report
  the credentials read as blocked.
