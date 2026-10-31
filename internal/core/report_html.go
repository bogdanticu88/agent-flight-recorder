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
	"kl":    kindLabel,
	"short": func(s string, n int) string { return Truncate(strings.TrimSpace(s), n) },
	"prefix": func(s string, n int) string {
		if len(s) <= n {
			return s
		}
		return s[:n] + "..."
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
<header><h1>{{.Title}}</h1><div class="sub">Agent Flight Recorder · {{len .Bundles}} bundle(s), {{len .LiveChains}} live log(s) · generated {{ts .Generated}}</div></header>
<main>

<div class="grid">
 <div class="card kpi"><div class="n">{{len .Sessions}}</div><div class="l">Record streams</div></div>
 <div class="card kpi"><div class="n">{{.TotalSteps}}</div><div class="l">Steps</div></div>
 <div class="card kpi"><div class="n">{{len .Findings}}</div><div class="l">Trace findings</div></div>
 <div class="card kpi"><div class="n">{{len .Alerts}}</div><div class="l">Policy alerts / denies</div></div>
</div>

{{range .Bundles}}<h2>Bundle: <code>{{.Path}}</code></h2><div class="card"><table class="meta">
<tr><td>Checksum consistency</td><td>{{if .Check.ChecksumConsistent}}<span class="ok">Every entry matches the SHA-256 recorded in the manifest.</span>{{else}}<span class="bad">Not consistent.</span>{{end}}{{range .Check.Problems}}<div class="bad small">{{.}}</div>{{end}}</td></tr>
<tr><td>Parsing completeness</td><td>{{if .Check.ParseIssues}}<span class="bad">{{.Check.ParseIssues}} source(s) with errors, malformed records or generic fallback</span> (see Artifacts examined){{else}}No parse errors recorded by the collector.{{end}}{{if .Manifest}}{{if eq .Manifest.Status "partial"}} <span class="bad">Collection was partial.</span>{{end}}{{end}}</td></tr>
<tr><td>Live log in bundle</td><td>{{with .Check.Live}}{{.Status}}: {{.Detail}}{{else}}none{{end}}{{with .Check.LiveCollector}}<div class="small mut">Collector-reported status of the original log at collection time (not re-verifiable from this bundle unless the full log is included): {{.Status}}, {{.Records}} record(s), head {{prefix .HeadHash 16}}</div>{{end}}</td></tr>
<tr><td>Origin</td><td class="small">{{.Check.Origin}}</td></tr>
{{with .Manifest}}<tr><td>Collection mode</td><td><b>{{.Mode}}</b>. {{.ModeNote}}</td></tr>
<tr><td>Case / host / user</td><td>{{if .CaseID}}{{.CaseID}}{{else}}(none){{end}} / {{if .SourceHost}}{{.SourceHost}}{{else}}(unknown){{end}} / {{.ProfileUser}} <span class="small mut">(collected on {{.Host}} as {{.User}}, {{.OS}})</span></td></tr>
<tr><td>Profile examined</td><td><code>{{.Home}}</code>{{if .Root}} under image root <code>{{.Root}}</code>{{end}}</td></tr>
<tr><td>Collected</td><td>{{ts .Started}} → {{ts .Finished}}</td></tr>
<tr><td>Time window</td><td>{{if .WindowFrom}}{{ts (deref .WindowFrom)}}{{else}}open{{end}} → {{if .WindowTo}}{{ts (deref .WindowTo)}}{{else}}open{{end}}</td></tr>
<tr><td>Redaction</td><td>{{if .Redacted}}on, {{.RedactionCount}} replacement(s) made on the device{{else}}<span class="bad">off</span>{{end}}{{if .RawIncluded}} · <span class="bad">raw source files included (unredacted)</span>{{end}}{{if .FullLiveLog}} · <span class="bad">full live log included</span>{{end}}</td></tr>
{{if .Skipped}}<tr><td>Skipped references</td><td class="small">{{range .Skipped}}<div>{{.}}</div>{{end}}</td></tr>{{end}}{{end}}
</table></div>{{end}}

{{range $k, $v := .LiveChains}}<h2>Live log: <code>{{$k}}</code></h2><div class="card"><b>{{$v.Status}}</b>: {{$v.Detail}}{{range $v.Breaks}}<div class="small bad">{{.}}</div>{{end}}
<div class="small mut">An unkeyed hash chain shows internal consistency only. Anyone able to rewrite the file can rebuild a consistent chain, and deletion of the newest records is only detectable against an independently retained checkpoint.</div></div>{{end}}

{{if .Targets}}<h2>Trace: {{join .Targets ", "}}</h2>
{{if not .Findings}}<div class="card">No step in any record stream references the target(s). If endpoint telemetry shows an access, possible explanations include a tool that does not record arguments, a deleted or uncollected session, or access by something other than an agent (an indexer, an extension, the user).</div>{{end}}
{{range .Findings}}<div class="card finding">
<h3>{{.Target}} <span class="mut small">· {{.Agent}} · session {{if .SessionID}}{{.SessionID}}{{else}}(none){{end}}{{if .Host}} · host {{.Host}}{{end}}{{if .User}} · user {{.User}}{{end}} · {{.Hits}} matching step(s)</span></h3>
<div class="small mut">{{.Prov}}{{if .Source}} · {{.Source}}{{end}}</div>
<div class="verdict">{{range .Summary}}<p>{{.}}</p>{{end}}</div>
<div class="chain">
{{with .FirstMention}}<span class="badge k-{{.Kind}}">first mention: {{kl .Kind}} #{{.Pos}}</span>{{end}}
{{with .FirstRequest}}<span class="arrow">→</span><span class="badge k-tool_call">first request: {{.Tool}} #{{.Pos}} ({{.Outcome}})</span>{{end}}
{{with .FirstCompletion}}<span class="arrow">→</span><span class="badge k-tool_result">supported completion: {{.Tool}} #{{.Pos}}</span>{{end}}
</div>
{{with .Prompt}}<div class="step"><div class="h">Most recent human prompt recorded before the first request · #{{.Pos}} · {{ts .TS}}</div><pre>{{short .Text 3000}}</pre></div>{{end}}
{{with .FirstMention}}<div class="step"><div class="h">First observed mention · #{{.Pos}} · {{kl .Kind}} {{.Tool}} · {{ts .TS}}</div><pre>{{if .Input}}{{short .Input 1500}}
{{end}}{{short .Text 2500}}</pre></div>{{end}}
{{with .FirstRequest}}<div class="step"><div class="h">First request · #{{.Pos}} · tool <b>{{.Tool}}</b> · outcome <b>{{.Outcome}}</b> · {{ts .TS}}{{if .TSInexact}} (timestamp inherited){{end}}</div><pre>{{short .Input 3000}}</pre>{{if .Reason}}<div class="small mut">{{.Reason}}</div>{{end}}</div>{{end}}
{{if .Lead}}<details><summary>The {{len .Lead}} steps recorded before the first request</summary>{{range .Lead}}<div class="step"><div class="h"><span class="badge k-{{.Kind}}">{{kl .Kind}}</span> #{{.Pos}} {{.Tool}}{{if .Outcome}} ({{.Outcome}}){{end}} · {{ts .TS}}</div><pre>{{if .Input}}{{short .Input 800}}
{{end}}{{short .Text 1200}}</pre></div>{{end}}</details>{{end}}
</div>{{end}}{{end}}

{{if .Alerts}}<h2>Live policy alerts and denies</h2><div class="card"><table><tr><th>Time</th><th>Host / user</th><th>Agent</th><th>Decision</th><th>Tool</th><th>Reason</th><th>Session</th></tr>
{{range .Alerts}}<tr class="alert"><td>{{ts .TS}}</td><td class="small">{{.Host}} / {{.User}}</td><td>{{.Agent}}</td><td><b>{{.Decision}}</b></td><td>{{.Tool}}</td><td class="small">{{.Reason}}</td><td class="small">{{.SessionID}}</td></tr>{{end}}</table></div>{{end}}

<h2>Record streams</h2>
<p class="small mut">One stream per input, source, host, user, agent and session ID. Streams are never merged, and positions (#) are local to their source. Timestamps from different sources are not used to infer an order between them.</p>
{{range .Sessions}}{{$s := .}}<div class="card"><details {{if .Hits}}open{{end}}>
<summary>{{.Agent}} <span class="mut">({{.Origin}})</span> · {{ts .Start}} {{with dur .Start .End}}· {{.}}{{end}} · {{len .Steps}} steps, {{.Tools}} tool calls{{if .Hits}} · <span class="bad">{{len .Hits}} trace hit(s)</span>{{end}}{{if .Alerts}} · <span class="bad">{{.Alerts}} alert(s)</span>{{end}}</summary>
<div class="small mut">session {{if .SessionID}}{{.SessionID}}{{else}}<b>none recorded</b>{{end}}{{if .Host}} · host {{.Host}}{{end}}{{if .User}} · user {{.User}}{{end}}{{if .Cwd}} · cwd <code>{{.Cwd}}</code>{{end}}{{if .Model}} · model {{.Model}}{{end}}<br>{{.Prov}}{{if .Source}} · <code>{{.Source}}</code>{{end}}</div>
<table><tr><th>#</th><th>Time (UTC)</th><th>Step</th><th>Tool</th><th>Outcome / status</th><th>Detail</th></tr>
{{range $i, $e := .Steps}}<tr class="{{if hit $s.Hits $i}}hit{{end}}{{if $e.Decision}} alert{{end}}"><td class="small">{{$e.Pos}}</td><td class="small">{{ts $e.TS}}{{if $e.TSInexact}}*{{end}}</td>
<td><span class="badge k-{{$e.Kind}}">{{kl $e.Kind}}</span>{{if $e.Decision}} <b class="bad">{{$e.Decision}}</b>{{end}}</td><td><code>{{$e.Tool}}</code>{{if $e.CallID}}<div class="small mut">{{prefix $e.CallID 24}}</div>{{end}}</td>
<td class="small">{{if $e.Outcome}}<b>{{$e.Outcome}}</b>{{end}}{{if $e.Status}}{{$e.Status}}{{end}}</td>
<td>{{if $e.Command}}<code>$ {{short $e.Command 400}}</code><br>{{end}}{{if and $e.Input (not $e.Command)}}<code class="small">{{short $e.Input 400}}</code><br>{{end}}{{if $e.Text}}<details><summary class="small mut">{{short $e.Text 160}}</summary><pre>{{short $e.Text 8000}}</pre></details>{{end}}{{if $e.Error}}<div class="small bad">{{short $e.Error 400}}</div>{{end}}{{if $e.Reason}}<div class="small mut">{{$e.Reason}}</div>{{end}}<div class="small mut">{{$e.SourceRef}}</div></td></tr>{{end}}
</table></details></div>{{end}}

{{if .Sources}}<h2>Artifacts examined</h2><div class="card"><table><tr><th>Agent</th><th>Parser</th><th>Path</th><th>Steps</th><th>SHA-256</th><th>Notes</th></tr>
{{range .Sources}}<tr><td>{{.Agent}}</td><td class="small">{{.Parser}}</td><td class="small"><code>{{.Path}}</code>{{if .Files}}<div class="mut">{{len .Files}} file(s) acquired</div>{{end}}</td><td>{{.Events}}</td><td class="small"><code>{{prefix .SHA256 16}}</code></td><td class="small">{{.Note}}{{if .Malformed}} <span class="bad">{{.Malformed}} malformed record(s)</span>{{end}}{{range .Diags}}<div class="mut">{{.}}</div>{{end}}{{if .Error}} <span class="bad">{{.Error}}</span>{{end}}</td></tr>{{end}}</table></div>{{end}}

<p class="small mut">* timestamp inherited from the previous step or the file, not recorded natively for this step. Outcomes come from vendor-recorded results matched by call ID; a successful result is not proof of every effect implied by a call's arguments. Reasoning shown is only what the model exposed.</p>
</main></body></html>`

func init() {
	funcs["deref"] = func(t *time.Time) time.Time {
		if t == nil {
			return time.Time{}
		}
		return *t
	}
}
