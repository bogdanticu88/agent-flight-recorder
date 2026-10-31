# Shipping the live log to Microsoft Sentinel

The hook recorder writes one JSON object per line. With the machine policy from
`Install-AFR.ps1`, every user's events land in
`C:\ProgramData\AgentFlightRecorder\logs\<username>.jsonl`. The Azure Monitor
Agent (AMA) picks those files up and sends them to a custom table.

The local file is the working copy. The Sentinel copy is the record you trust.
The hash chain is unkeyed: it shows whether what is left on disk is internally
consistent, not whether records were removed from the end or the chain was
rebuilt. Records already shipped to Sentinel are an independent copy.

## 1. Create the table

In the Log Analytics workspace behind Sentinel, create a DCR-based custom table
named `AgentFlightRecorder_CL` with these columns (all `string` unless noted):

| column | type | notes |
|---|---|---|
| TimeGenerated | datetime | set from `ts` in the transform |
| ts | datetime | when the step happened |
| agent, origin, session_id, kind, tool, call_id | string | |
| status, error | string | vendor-reported result status on tool results |
| text, input, command, cwd, model | string | already redacted on the device |
| paths | dynamic | array of file paths |
| decision, reason | string | `alert` / `deny` and the matching rule |
| source, source_ref | string | hook event name and vendor transcript path |
| host, user | string | |
| seq | int | 0 for live records |
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
`DeviceFileEvents` for a canary file. Session IDs are only unique per agent
on one host for one user, so every join and filter uses host, user, agent
and session_id together.

## 4. Ticketing

If Sentinel already raises tickets in your ITSM tool (ServiceNow, Jira),
add the output of query 3 (the prompt and the tool call) to the incident
entities, so the analyst starts with the recorded context rather than just
"user touched a canary file". The decision field says whether the call was
allowed or blocked; it does not say what the tool did.
