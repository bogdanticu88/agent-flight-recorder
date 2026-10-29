# Shipping the live log to Microsoft Sentinel

The hook recorder writes one JSON object per line. With the machine policy from
`Install-AFR.ps1`, every user's events land in
`C:\ProgramData\AgentFlightRecorder\logs\<username>.jsonl`. The Azure Monitor
Agent (AMA) picks those files up and sends them to a custom table.

The local file is the working copy. The Sentinel copy is the record you trust.
A user can delete their own local log, but by then AMA has normally shipped it.
The hash chain shows gaps or edits in whatever is left on disk.

## 1. Create the table

In the Log Analytics workspace behind Sentinel, create a DCR-based custom table
named `AgentFlightRecorder_CL` with these columns (all `string` unless noted):

| column | type | notes |
|---|---|---|
| TimeGenerated | datetime | set from `ts` in the transform |
| ts | datetime | when the step happened |
| agent, origin, session_id, kind, tool, call_id | string | |
| text, input, command, cwd, model | string | already redacted on the device |
| paths | dynamic | array of file paths |
| decision, reason | string | `alert` / `deny` and the matching rule |
| source, source_ref | string | hook event name and vendor transcript path |
| host, user | string | |
| seq | int | |
| prev_hash, hash | string | tamper-evidence chain |

## 2. Create the data collection rule

Data source type: **Custom JSON Logs**

- File pattern: `C:\ProgramData\AgentFlightRecorder\logs\*.jsonl`
- Table: `AgentFlightRecorder_CL`
- Transform:

```kql
source
| extend TimeGenerated = todatetime(ts)
```

Associate the DCR with the device collection that received `Install-AFR.ps1`.

## 3. Rules and hunting

`queries.kql` has the analytic rule for protected-path hits, the session
replay query, the "what was the prompt" join and the correlation with
`DeviceFileEvents` for the honeypot.

## 4. Ticketing

If Sentinel already raises tickets in your ITSM tool (ServiceNow, Jira),
add the output of query 3 (the prompt and the tool call) to the incident
entities. The analyst then opens the ticket with the answer already in it,
instead of starting from "user touched a canary file".
