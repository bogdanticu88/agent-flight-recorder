package core

import (
	"html/template"
	"io"
	"strings"
	"time"
)

var funcs = template.FuncMap{
	"ts": func(t time.Time) string {
		if t.IsZero() {
			return "-"
		}
		return t.UTC().Format("2006-01-02 15:04:05Z")
	},
	"kl": kindLabel,
	"short": func(s string, n int) string {
		s = strings.TrimSpace(s)
		if len(s) > n {
			return s[:n] + "..."
		}
		return s
	},
	"inc":  func(i int) int { return i + 1 },
	"join": strings.Join,
	"dur": func(a, b time.Time) string {
		if a.IsZero() || b.IsZero() {
			return ""
		}
		return b.Sub(a).Round(time.Second).String()
	},
	"hit": func(m map[int]bool, i int) bool { return m[i] },
}

// RenderHTML writes a self-contained report (no external assets) so it can be
// attached to an incident ticket and opened offline.
func RenderHTML(w io.Writer, d ReportData) error {
	t := template.Must(template.New("r").Funcs(funcs).Parse(reportTpl))
	return t.Execute(w, d)
}

const reportTpl = `<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{{.Title}}</title>
<style>
:root{--bg:#f7f7f5;--card:#fff;--ink:#1d1d1b;--mut:#6b6b66;--line:#e4e3de;--acc:#1f5f8b;
--prompt:#2d6a4f;--ctx:#7a5c00;--reason:#6b4c9a;--resp:#3d5a80;--call:#b5462a;--res:#5c6b73;--alert:#b00020}
*{box-sizing:border-box}body{margin:0;font:14px/1.5 -apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;background:var(--bg);color:var(--ink)}
header{background:#1d2b36;color:#fff;padding:22px 32px}header h1{margin:0 0 4px;font-size:20px;font-weight:600}
header .sub{color:#b9c4cc;font-size:13px}main{max-width:1200px;margin:0 auto;padding:24px 32px 60px}
h2{font-size:16px;margin:32px 0 12px;font-weight:600}.card{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:16px 20px;margin-bottom:14px}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:12px}.kpi .n{font-size:24px;font-weight:600}.kpi .l{color:var(--mut);font-size:12px;text-transform:uppercase;letter-spacing:.04em}
table{width:100%;border-collapse:collapse}th,td{text-align:left;padding:6px 8px;border-bottom:1px solid var(--line);vertical-align:top}th{font-size:12px;color:var(--mut);font-weight:600}
.meta td:first-child{color:var(--mut);width:190px}code,pre{font:12px/1.45 ui-monospace,SFMono-Regular,Consolas,monospace}
pre{white-space:pre-wrap;word-break:break-word;margin:4px 0;background:#f3f3f0;padding:8px;border-radius:6px;max-height:340px;overflow:auto}
.ok{color:#2d6a4f;font-weight:600}.bad{color:var(--alert);font-weight:600}
.badge{display:inline-block;padding:1px 8px;border-radius:10px;font-size:11px;font-weight:600;color:#fff;white-space:nowrap}
.k-prompt{background:var(--prompt)}.k-context{background:var(--ctx)}.k-reasoning{background:var(--reason)}.k-response{background:var(--resp)}
.k-tool_call{background:var(--call)}.k-tool_result{background:var(--res)}.k-session_start,.k-session_end,.k-other,.k-decision{background:#999}
tr.hit{background:#fff4d6}tr.alert{background:#fde8ea}.finding{border-left:4px solid var(--alert)}.finding h3{margin:0 0 6px;font-size:15px}
.verdict{font-size:14px;margin:8px 0 12px}.step{margin:10px 0;padding-left:12px;border-left:2px solid var(--line)}
.step .h{font-size:12px;color:var(--mut)}details summary{cursor:pointer;font-weight:600;padding:4px 0}.mut{color:var(--mut)}.small{font-size:12px}
.chain{display:flex;align-items:center;gap:8px;flex-wrap:wrap;margin:10px 0}.chain .arrow{color:var(--mut)}
</style></head><body>
<header><h1>{{.Title}}</h1><div class="sub">Agent Flight Recorder {{if .Manifest}}v{{.Manifest.Version}} · case {{if .Manifest.CaseID}}{{.Manifest.CaseID}}{{else}}(none){{end}} · {{.Manifest.Host}} / {{.Manifest.User}}{{end}} · generated {{ts .Generated}}</div></header>
<main>

<div class="grid">
 <div class="card kpi"><div class="n">{{len .Sessions}}</div><div class="l">Sessions</div></div>
 <div class="card kpi"><div class="n">{{.TotalSteps}}</div><div class="l">Steps</div></div>
 <div class="card kpi"><div class="n">{{len .Findings}}</div><div class="l">Trace findings</div></div>
 <div class="card kpi"><div class="n">{{len .Alerts}}</div><div class="l">Policy alerts / denies</div></div>
 <div class="card kpi"><div class="n">{{if .Verified}}<span class="ok">Verified</span>{{else if .Integrity}}<span class="bad">Problems</span>{{else}}<span class="mut">n/a</span>{{end}}</div><div class="l">Evidence integrity</div></div>
</div>

{{if .Manifest}}<h2>Evidence</h2><div class="card"><table class="meta">
<tr><td>Collection mode</td><td><b>{{.Manifest.Mode}}</b>. {{.Manifest.ModeNote}}</td></tr>
<tr><td>Host / user / OS</td><td>{{.Manifest.Host}} / {{.Manifest.User}} / {{.Manifest.OS}}</td></tr>
<tr><td>Profile examined</td><td><code>{{.Manifest.Home}}</code></td></tr>
<tr><td>Collected</td><td>{{ts .Manifest.Started}} → {{ts .Manifest.Finished}}</td></tr>
<tr><td>Time window</td><td>{{if .Manifest.WindowFrom}}{{ts (deref .Manifest.WindowFrom)}}{{else}}open{{end}} → {{if .Manifest.WindowTo}}{{ts (deref .Manifest.WindowTo)}}{{else}}open{{end}}</td></tr>
<tr><td>Redaction</td><td>{{if .Manifest.Redacted}}on, {{.Manifest.RedactionCount}} secret(s) removed on the device{{else}}<span class="bad">off</span>{{end}}{{if .Manifest.RawIncluded}} · raw source files included (unredacted){{end}}</td></tr>
<tr><td>Integrity</td><td>{{if .Verified}}<span class="ok">All {{len .Manifest.Entries}} bundle entries match their recorded SHA-256.</span>{{else}}{{range .Integrity}}<div class="bad">{{.}}</div>{{end}}{{end}}</td></tr>
{{range $k, $v := .LiveChains}}<tr><td>Live log chain</td><td><code>{{$k}}</code>: {{$v.Records}} record(s), {{if eq $v.Status "intact"}}<span class="ok">hash chain intact</span>{{else}}<span class="bad">{{$v.Status}}</span>{{range $v.Breaks}}<div class="small bad">{{.}}</div>{{end}}{{end}}</td></tr>{{end}}
</table></div>{{else}}{{range $k, $v := .LiveChains}}<h2>Live log</h2><div class="card"><code>{{$k}}</code>: {{$v.Records}} record(s), {{if eq $v.Status "intact"}}<span class="ok">hash chain intact</span>{{else}}<span class="bad">{{$v.Status}}</span>{{range $v.Breaks}}<div class="small bad">{{.}}</div>{{end}}{{end}}</div>{{end}}{{end}}

{{if .Targets}}<h2>Trace: {{join .Targets ", "}}</h2>
{{if not .Findings}}<div class="card">No step in any session references the target(s). If EDR shows the access, the agent may have used a tool that did not log arguments, the session may have been deleted, or the access came from something other than an agent (indexer, extension, the user).</div>{{end}}
{{range .Findings}}<div class="card finding">
<h3>{{.Target}} <span class="mut small">· {{.Agent}} · session {{.SessionID}} · {{.AllHits}} matching step(s)</span></h3>
<div class="verdict">{{.Verdict}}</div>
<div class="chain">
{{if and .Introduced .Prompt}}{{if gt .Introduced.Seq .Prompt.Seq}}<span class="badge k-prompt">human prompt #{{.Prompt.Seq}}</span><span class="arrow">→</span>{{end}}{{end}}
{{if .Introduced}}<span class="badge k-{{.Introduced.Kind}}">first seen: {{kl .Introduced.Kind}} #{{.Introduced.Seq}}</span>{{end}}
{{if and .Introduced .Prompt}}{{if lt .Introduced.Seq .Prompt.Seq}}<span class="arrow">→</span><span class="badge k-prompt">human prompt #{{.Prompt.Seq}}</span>{{end}}{{end}}
{{if .FirstAccess}}<span class="arrow">→</span><span class="badge k-tool_call">first access: {{.FirstAccess.Tool}} #{{.FirstAccess.Seq}}</span>{{end}}
</div>
{{if .Prompt}}<div class="step"><div class="h">Human instruction in force · {{ts .Prompt.TS}}</div><pre>{{short .Prompt.Text 3000}}</pre></div>{{end}}
{{if .Introduced}}<div class="step"><div class="h">Where it first appeared · step {{.Introduced.Seq}} · {{kl .Introduced.Kind}} {{.Introduced.Tool}} · {{ts .Introduced.TS}}</div><pre>{{if .Introduced.Input}}{{short .Introduced.Input 1500}}
{{end}}{{short .Introduced.Text 2500}}</pre></div>{{end}}
{{if .FirstAccess}}<div class="step"><div class="h">First access · step {{.FirstAccess.Seq}} · tool <b>{{.FirstAccess.Tool}}</b> · {{ts .FirstAccess.TS}}{{if .FirstAccess.TSInexact}} (timestamp inherited){{end}}</div><pre>{{short .FirstAccess.Input 3000}}</pre>{{if .FirstAccess.Reason}}<div class="small mut">{{.FirstAccess.Reason}}</div>{{end}}</div>
<details><summary>Lead-up: the {{len .Lead}} steps before the access</summary>{{range .Lead}}<div class="step"><div class="h"><span class="badge k-{{.Kind}}">{{kl .Kind}}</span> #{{.Seq}} {{.Tool}} · {{ts .TS}}</div><pre>{{if .Input}}{{short .Input 800}}
{{end}}{{short .Text 1200}}</pre></div>{{end}}</details>{{end}}
</div>{{end}}{{end}}

{{if .Alerts}}<h2>Live policy alerts and denies</h2><div class="card"><table><tr><th>Time</th><th>Agent</th><th>Decision</th><th>Tool</th><th>Reason</th><th>Session</th></tr>
{{range .Alerts}}<tr class="alert"><td>{{ts .TS}}</td><td>{{.Agent}}</td><td><b>{{.Decision}}</b></td><td>{{.Tool}}</td><td class="small">{{.Reason}}</td><td class="small">{{.SessionID}}</td></tr>{{end}}</table></div>{{end}}

<h2>Sessions</h2>
{{range .Sessions}}{{$s := .}}<div class="card"><details {{if .Hits}}open{{end}}>
<summary>{{.Agent}} <span class="mut">({{.Origin}})</span> · {{ts .Start}} {{with dur .Start .End}}· {{.}}{{end}} · {{len .Steps}} steps, {{.Tools}} tool calls{{if .Hits}} · <span class="bad">{{len .Hits}} trace hit(s)</span>{{end}}{{if .Alerts}} · <span class="bad">{{.Alerts}} alert(s)</span>{{end}}</summary>
<div class="small mut">session {{.SessionID}}{{if .Cwd}} · cwd <code>{{.Cwd}}</code>{{end}}{{if .Model}} · model {{.Model}}{{end}}</div>
<table><tr><th>#</th><th>Time (UTC)</th><th>Step</th><th>Tool</th><th>Detail</th></tr>
{{range $i, $e := .Steps}}<tr class="{{if hit $s.Hits $i}}hit{{end}}{{if $e.Decision}} alert{{end}}"><td class="small">{{$e.Seq}}</td><td class="small">{{ts $e.TS}}{{if $e.TSInexact}}*{{end}}</td>
<td><span class="badge k-{{$e.Kind}}">{{kl $e.Kind}}</span>{{if $e.Decision}} <b class="bad">{{$e.Decision}}</b>{{end}}</td><td><code>{{$e.Tool}}</code></td>
<td>{{if $e.Command}}<code>$ {{short $e.Command 400}}</code><br>{{end}}{{if and $e.Input (not $e.Command)}}<code class="small">{{short $e.Input 400}}</code><br>{{end}}{{if $e.Text}}<details><summary class="small mut">{{short $e.Text 160}}</summary><pre>{{short $e.Text 8000}}</pre></details>{{end}}{{if $e.Reason}}<div class="small mut">{{$e.Reason}}</div>{{end}}<div class="small mut">{{$e.SourceRef}}</div></td></tr>{{end}}
</table></details></div>{{end}}

{{if .Sources}}<h2>Artifacts examined</h2><div class="card"><table><tr><th>Agent</th><th>Parser</th><th>Path</th><th>Steps</th><th>SHA-256</th><th>Note</th></tr>
{{range .Sources}}<tr><td>{{.Agent}}</td><td class="small">{{.Parser}}</td><td class="small"><code>{{.Path}}</code></td><td>{{.Events}}</td><td class="small"><code>{{short .SHA256 16}}</code></td><td class="small">{{.Note}}{{if .Error}} <span class="bad">{{.Error}}</span>{{end}}</td></tr>{{end}}</table></div>{{end}}

<p class="small mut">* timestamp inherited from the previous step or the file, not recorded natively for this step. Reasoning shown is only what the model exposed; hidden chain-of-thought is not recoverable.</p>
</main></body></html>`

func init() {
	funcs["deref"] = func(t *time.Time) time.Time {
		if t == nil {
			return time.Time{}
		}
		return *t
	}
}
