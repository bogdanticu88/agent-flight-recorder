package core

import (
	"fmt"
	"path"
	"sort"
	"strings"
	"time"
)

// Relation describes how a tool call refers to a trace target.
const (
	RelPathArg = "path-argument" // the target is a value of a path-like argument
	RelCommand = "command"       // the target appears inside a shell command string
	RelSearch  = "search"        // the target appears in search terms or patterns
	RelMention = "mention"       // the target appears elsewhere in the call (description, free text)
)

// Tool categories, inferred from tool names across vendors.
const (
	CatRead   = "read"
	CatWrite  = "write"
	CatList   = "list"
	CatSearch = "search"
	CatShell  = "shell"
	CatOther  = "other"
)

// ToolCategory classifies a tool by name. It is a heuristic over vendor
// naming, used only to decide whether a call can count as file access.
func ToolCategory(tool string) string {
	t := strings.ToLower(tool)
	has := func(subs ...string) bool {
		for _, s := range subs {
			if strings.Contains(t, s) {
				return true
			}
		}
		return false
	}
	switch {
	case has("grep", "search", "glob", "find", "codebase", "ripgrep") || t == "rg":
		return CatSearch
	case has("list", "ls_", "readdir", "read_dir") || t == "ls":
		return CatList
	case has("bash", "shell", "terminal", "command", "exec", "powershell"):
		return CatShell
	case has("write", "edit", "replace", "create_file", "patch", "apply", "insert", "notebook"):
		return CatWrite
	case has("read", "view", "open", "cat", "fetch_file", "get_file"):
		return CatRead
	}
	return CatOther
}

// Finding keeps three observations about a trace target apart: where it was
// first mentioned, the first tool call that involved it, and the first call
// whose recorded outcome supports that the target was actually accessed.
type Finding struct {
	Target                       string
	Agent, SessionID, Host, User string
	Prov, Source                 string
	Unscoped                     bool

	FirstMention    *Event
	FirstRequest    *Event
	RequestRelation string
	FirstCompletion *Event
	Prompt          *Event // most recent human prompt recorded before FirstRequest (scoped sessions only)
	Lead            []Event
	Hits            int
	Summary         []string
}

type SessionView struct {
	Agent, SessionID, Host, User string
	Origin, Prov, Source         string
	Unscoped                     bool
	Start, End                   time.Time
	Cwd, Model                   string
	Steps                        []Event
	Hits                         map[int]bool // index in Steps -> matches a trace target
	Alerts, Tools                int
}

// BundleInfo is one input bundle with its own manifest and integrity result.
type BundleInfo struct {
	Path     string
	Manifest *Manifest
	Check    BundleCheck
}

type ReportData struct {
	Title      string
	Generated  time.Time
	Bundles    []BundleInfo
	Sources    []Source
	LiveChains map[string]ChainReport
	Targets    []string
	Findings   []Finding
	Sessions   []SessionView
	TotalSteps int
	Alerts     []Event
}

func normTarget(s string) string { return strings.ToLower(strings.ReplaceAll(s, `\`, "/")) }

// targetNeedles returns the strings that count as a match: the target itself
// and, for paths, its last two segments ("~/.aws/credentials" -> ".aws/credentials");
// for a bare file name, the name.
func targetNeedles(target string) []string {
	t := normTarget(target)
	out := []string{t}
	trimmed := strings.Trim(t, "/")
	if strings.Contains(trimmed, "/") {
		parts := strings.Split(trimmed, "/")
		tail := strings.Join(parts[len(parts)-2:], "/")
		if tail != t {
			out = append(out, tail)
		}
	} else if b := path.Base(t); b != t && len(b) >= 4 {
		out = append(out, b)
	}
	return out
}

func containsTarget(s, target string) bool {
	hn := normTarget(s)
	for _, n := range targetNeedles(target) {
		if n != "" && strings.Contains(hn, n) {
			return true
		}
	}
	return false
}

// eventMatches checks every text field of a step for the target.
func eventMatches(e Event, target string) bool {
	for _, h := range append([]string{e.Input, e.Command, e.Text, e.Reason, e.Error}, e.Paths...) {
		if containsTarget(h, target) {
			return true
		}
	}
	return false
}

// relationOf reports how a tool call refers to the target, strongest first.
func relationOf(e Event, target string) string {
	in := Decode(e.Input)
	for _, p := range PathArgs(in) {
		if containsTarget(p, target) {
			switch ToolCategory(e.Tool) {
			case CatSearch:
				return RelSearch
			case CatShell:
				return RelCommand
			}
			return RelPathArg
		}
	}
	if e.Command != "" && containsTarget(e.Command, target) {
		return RelCommand
	}
	if m, ok := in.(map[string]any); ok {
		for k, v := range m {
			if searchKeys[k] {
				if s, ok := v.(string); ok && containsTarget(s, target) {
					return RelSearch
				}
			}
		}
	}
	return RelMention
}

// correlate sets Outcome on every tool call in a session view from its policy
// decision and the result(s) recorded with the same call ID.
func correlate(steps []Event) {
	results := map[string][]int{}
	unmatched := 0
	for i, e := range steps {
		if e.Kind == KindToolResult {
			if e.CallID != "" {
				results[e.CallID] = append(results[e.CallID], i)
			} else {
				unmatched++
			}
		}
	}
	for i := range steps {
		e := &steps[i]
		if e.Kind != KindToolCall {
			continue
		}
		switch {
		case e.Decision == "deny":
			e.Outcome = OutcomeBlocked
		case e.CallID == "":
			if unmatched > 0 {
				e.Outcome = OutcomeUnknown
			} else {
				e.Outcome = OutcomeRequested
			}
		default:
			idx := results[e.CallID]
			if len(idx) == 0 {
				e.Outcome = OutcomeRequested
				continue
			}
			e.Outcome = OutcomeUnknown
			for _, j := range idx { // a later definitive status wins over an earlier unknown one
				switch steps[j].Status {
				case StatusSuccess:
					e.Outcome = OutcomeCompleted
				case StatusError, StatusCancelled:
					e.Outcome = OutcomeFailed
				case StatusRejected:
					e.Outcome = OutcomeBlocked
				}
			}
		}
	}
}

// BuildReport groups steps into session views (never merging across hosts,
// users, inputs or sources), correlates outcomes and runs trace analysis.
func BuildReport(evs []Event, targets []string) ([]SessionView, []Finding, []Event) {
	SortEvents(evs)
	groups := map[string]*SessionView{}
	var order []string
	var alerts []Event
	for _, e := range evs {
		key := e.ScopeKey()
		sv, ok := groups[key]
		if !ok {
			sv = &SessionView{Agent: e.Agent, SessionID: e.SessionID, Host: e.Host, User: e.User, Origin: e.Origin,
				Prov: e.Prov, Source: e.Source0(), Unscoped: e.SessionID == "", Start: e.TS, Hits: map[int]bool{}}
			groups[key] = sv
			order = append(order, key)
		}
		if !e.TS.IsZero() && (sv.Start.IsZero() || e.TS.Before(sv.Start)) {
			sv.Start = e.TS
		}
		if e.TS.After(sv.End) {
			sv.End = e.TS
		}
		if e.Cwd != "" {
			sv.Cwd = e.Cwd
		}
		if e.Model != "" {
			sv.Model = e.Model
		}
		sv.Steps = append(sv.Steps, e)
	}
	var sessions []SessionView
	var findings []Finding
	for _, k := range order {
		sv := groups[k]
		sort.SliceStable(sv.Steps, func(i, j int) bool { return sv.Steps[i].Pos < sv.Steps[j].Pos })
		correlate(sv.Steps)
		for _, e := range sv.Steps {
			if e.Kind == KindToolCall {
				sv.Tools++
			}
			if e.Decision == "alert" || e.Decision == "deny" {
				sv.Alerts++
				alerts = append(alerts, e)
			}
		}
		for _, t := range targets {
			if f, ok := traceSession(sv, t); ok {
				findings = append(findings, f)
			}
		}
		sessions = append(sessions, *sv)
	}
	sort.SliceStable(sessions, func(i, j int) bool {
		hi, hj := len(sessions[i].Hits) > 0, len(sessions[j].Hits) > 0
		if hi != hj {
			return hi
		}
		if !sessions[i].Start.Equal(sessions[j].Start) {
			return sessions[i].Start.After(sessions[j].Start)
		}
		return sessions[i].Prov+sessions[i].Source+sessions[i].SessionID < sessions[j].Prov+sessions[j].Source+sessions[j].SessionID
	})
	return sessions, findings, alerts
}

func traceSession(sv *SessionView, t string) (Finding, bool) {
	f := Finding{Target: t, Agent: sv.Agent, SessionID: sv.SessionID, Host: sv.Host, User: sv.User,
		Prov: sv.Prov, Source: sv.Source, Unscoped: sv.Unscoped}
	for i := range sv.Steps {
		e := sv.Steps[i]
		if !eventMatches(e, t) {
			continue
		}
		sv.Hits[i] = true
		f.Hits++
		if f.FirstMention == nil {
			ev := e
			f.FirstMention = &ev
		}
		if e.Kind != KindToolCall {
			continue
		}
		rel := relationOf(e, t)
		if f.FirstRequest == nil {
			ev := e
			f.FirstRequest = &ev
			f.RequestRelation = rel
			if !sv.Unscoped {
				for j := i - 1; j >= 0; j-- {
					if sv.Steps[j].Kind == KindPrompt {
						p := sv.Steps[j]
						f.Prompt = &p
						break
					}
				}
			}
			from := i - 6
			if from < 0 {
				from = 0
			}
			f.Lead = append([]Event{}, sv.Steps[from:i]...)
		}
		cat := ToolCategory(e.Tool)
		if f.FirstCompletion == nil && rel == RelPathArg && e.Outcome == OutcomeCompleted && (cat == CatRead || cat == CatWrite) {
			ev := e
			f.FirstCompletion = &ev
		}
	}
	if f.Hits == 0 {
		return f, false
	}
	f.Summary = summarise(f, sv.Steps)
	return f, true
}

func at(e *Event) string {
	s := fmt.Sprintf("#%d", e.Pos)
	if e.SourceRef != "" {
		s += " (" + e.SourceRef + ")"
	}
	return s
}

func relationPhrase(rel string) string {
	switch rel {
	case RelPathArg:
		return "as a path argument"
	case RelCommand:
		return "inside a shell command"
	case RelSearch:
		return "in search terms or patterns"
	}
	return "only in the call's description or free text"
}

func outcomeBasis(e *Event, steps []Event) string {
	switch e.Outcome {
	case OutcomeBlocked:
		if e.Decision == "deny" {
			return "denied by policy before it ran"
		}
		return "the recorded result says the call was declined"
	case OutcomeFailed:
		return "the correlated result reports an error"
	case OutcomeCompleted:
		return "the correlated result reports success"
	case OutcomeRequested:
		return "no result is recorded for this call"
	}
	if e.CallID == "" {
		return "the call has no ID, so recorded results cannot be matched to it"
	}
	return "a result is recorded but without a success or error status"
}

// summarise states what the captured record shows, in order, without claims
// about intent or responsibility.
func summarise(f Finding, steps []Event) []string {
	var out []string
	m := f.FirstMention
	out = append(out, fmt.Sprintf("First observed mention: %s at %s.", kindLabel(m.Kind), at(m)))
	if f.FirstRequest == nil {
		out = append(out, "No tool call involving the target is recorded in this session.")
		return out
	}
	r := f.FirstRequest
	out = append(out, fmt.Sprintf("First request involving the target: %s at %s, with the target %s. Outcome: %s (%s).",
		r.Tool, at(r), relationPhrase(f.RequestRelation), r.Outcome, outcomeBasis(r, steps)))
	if c := f.FirstCompletion; c != nil {
		verb := "read"
		if ToolCategory(c.Tool) == CatWrite {
			verb = "written or modified"
		}
		out = append(out, fmt.Sprintf("Supported completion: %s at %s names the target as a path argument and its correlated result reports success. This supports that the target was %s through that call.",
			c.Tool, at(c), verb))
	} else {
		s := "No completed read or write call with the target as a path argument is recorded, so the record does not establish that the target was accessed."
		if r.Outcome == OutcomeCompleted && f.RequestRelation == RelCommand {
			s += " The shell command referencing it reports success, but what that command did to the target is not established by the record."
		}
		out = append(out, s)
	}
	if m.Pos == r.Pos {
		out = append(out, "No earlier mention of the target is observed in the available evidence for this session. Earlier context may exist that was not captured (compacted history, deleted turns, or attachments and instructions loaded outside the transcript).")
	} else {
		s := fmt.Sprintf("The earliest observed mention (%s) comes before the first request.", kindLabel(m.Kind))
		if m.Kind == KindContext {
			s += " That content was loaded into the agent's context; review it for instructions aimed at the agent."
		}
		out = append(out, s)
	}
	if f.Unscoped {
		out = append(out, "These events carry no session ID; they are listed together because they share a source, not because they are known to belong to one session.")
	}
	return out
}

func kindLabel(k Kind) string {
	return map[Kind]string{
		KindPrompt: "human prompt", KindContext: "injected context", KindReasoning: "model reasoning",
		KindResponse: "model reply", KindToolCall: "tool call", KindToolResult: "tool result",
		KindSessionStart: "session start", KindSessionEnd: "session end", KindDecision: "policy decision", KindOther: "other",
	}[k]
}
