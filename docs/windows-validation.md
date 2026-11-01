# Windows validation record

What has actually been run on a Windows host, and what that does not cover.

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
