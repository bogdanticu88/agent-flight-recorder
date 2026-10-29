package core

import (
	"fmt"
	"path"
	"sort"
	"strings"
	"time"
)

// Finding answers "why did the agent touch X": where X first entered the
// agent's context, the first time the agent acted on it, and the human prompt
// in force at that moment.
type Finding struct {
	Target      string
	Agent       string
	SessionID   string
	Introduced  *Event  // first step where the target appears at all
	FirstAccess *Event  // first tool call that references it
	Prompt      *Event  // last human prompt before the access
	Lead        []Event // the steps immediately before the access
	AllHits     int
	Verdict     string
}

type SessionView struct {
	Agent     string
	SessionID string
	Origin    string
	Start     time.Time
	End       time.Time
	Cwd       string
	Model     string
	Steps     []Event
	Hits      map[int]bool // index in Steps -> matches a trace target
	Alerts    int
	Tools     int
}

type ReportData struct {
	Title      string
	Generated  time.Time
	Manifest   *Manifest
	Sources    []Source
	Integrity  []string // problems; empty = verified
	Verified   bool
	LiveChains map[string]ChainReport
	Targets    []string
	Findings   []Finding
	Sessions   []SessionView
	TotalSteps int
	Alerts     []Event
}

func normTarget(s string) string { return strings.ToLower(strings.ReplaceAll(s, `\`, "/")) }

// eventMatches checks every text field of a step for the target or its basename.
func eventMatches(e Event, target string) bool {
	t := normTarget(target)
	base := path.Base(t)
	hay := []string{e.Input, e.Command, e.Text, e.Reason}
	hay = append(hay, e.Paths...)
	for _, h := range hay {
		hn := normTarget(h)
		if strings.Contains(hn, t) {
			return true
		}
		if len(base) >= 4 && base != t && strings.Contains(hn, base) {
			return true
		}
	}
	return false
}

// BuildReport groups steps into sessions and runs trace analysis.
func BuildReport(evs []Event, targets []string) ([]SessionView, []Finding, []Event) {
	SortEvents(evs)
	groups := map[string]*SessionView{}
	var order []string
	var alerts []Event
	for _, e := range evs {
		key := e.Agent + "|" + e.Origin + "|" + e.SessionID
		sv, ok := groups[key]
		if !ok {
			sv = &SessionView{Agent: e.Agent, SessionID: e.SessionID, Origin: e.Origin, Start: e.TS, Hits: map[int]bool{}}
			groups[key] = sv
			order = append(order, key)
		}
		if e.TS.Before(sv.Start) && !e.TS.IsZero() {
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
		if e.Kind == KindToolCall {
			sv.Tools++
		}
		if e.Decision == "alert" || e.Decision == "deny" {
			sv.Alerts++
			alerts = append(alerts, e)
		}
		sv.Steps = append(sv.Steps, e)
	}
	var sessions []SessionView
	var findings []Finding
	for _, k := range order {
		sv := groups[k]
		sort.SliceStable(sv.Steps, func(i, j int) bool {
			if sv.Steps[i].Seq != sv.Steps[j].Seq {
				return sv.Steps[i].Seq < sv.Steps[j].Seq
			}
			return sv.Steps[i].TS.Before(sv.Steps[j].TS)
		})
		for _, t := range targets {
			f := Finding{Target: t, Agent: sv.Agent, SessionID: sv.SessionID}
			for i := range sv.Steps {
				e := sv.Steps[i]
				if !eventMatches(e, t) {
					continue
				}
				sv.Hits[i] = true
				f.AllHits++
				if f.Introduced == nil {
					ev := e
					f.Introduced = &ev
				}
				if f.FirstAccess == nil && e.Kind == KindToolCall {
					ev := e
					f.FirstAccess = &ev
					for j := i - 1; j >= 0; j-- {
						if sv.Steps[j].Kind == KindPrompt {
							p := sv.Steps[j]
							f.Prompt = &p
							break
						}
					}
					from := i - 6
					if from < 0 {
						from = 0
					}
					f.Lead = append([]Event{}, sv.Steps[from:i]...)
				}
			}
			if f.AllHits > 0 {
				f.Verdict = verdict(f)
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
		return sessions[i].Start.After(sessions[j].Start)
	})
	return sessions, findings, alerts
}

func verdict(f Finding) string {
	switch {
	case f.FirstAccess == nil && f.Introduced != nil:
		return fmt.Sprintf("The target appears in this session (%s) but the agent never called a tool on it. It was seen, not opened.", kindLabel(f.Introduced.Kind))
	case f.Introduced == nil:
		return ""
	case f.Introduced.Seq == f.FirstAccess.Seq || f.Introduced.Kind == KindToolCall:
		if f.Prompt != nil && eventMatches(*f.Prompt, f.Target) {
			return "The human prompt named the target directly and the agent acted on it."
		}
		return "The agent reached for the target on its own initiative: it appears for the first time in the agent's own tool call, not in anything it was shown before. Check the lead-up steps for what it was looking for (e.g. a broad search for credentials or config)."
	case f.Introduced.Kind == KindToolResult:
		return fmt.Sprintf("The target first entered the agent's context through a tool result (step %d, e.g. a directory listing or search hit). The agent then chose to open it (step %d). This is the typical honeypot pattern: discovery, then curiosity.", f.Introduced.Seq, f.FirstAccess.Seq)
	case f.Introduced.Kind == KindPrompt:
		return fmt.Sprintf("The human prompt referenced the target (step %d) before the agent opened it (step %d).", f.Introduced.Seq, f.FirstAccess.Seq)
	case f.Introduced.Kind == KindContext:
		return fmt.Sprintf("The target was introduced by injected context (step %d: instructions, attachments or environment) before the agent opened it (step %d). Review that context for prompt injection.", f.Introduced.Seq, f.FirstAccess.Seq)
	case f.Introduced.Kind == KindReasoning || f.Introduced.Kind == KindResponse:
		return fmt.Sprintf("The model mentioned the target in its own reasoning or reply (step %d) before opening it (step %d).", f.Introduced.Seq, f.FirstAccess.Seq)
	}
	return ""
}

func kindLabel(k Kind) string {
	return map[Kind]string{
		KindPrompt: "human prompt", KindContext: "injected context", KindReasoning: "model reasoning",
		KindResponse: "model reply", KindToolCall: "tool call", KindToolResult: "tool result",
		KindSessionStart: "session start", KindSessionEnd: "session end", KindDecision: "policy decision", KindOther: "other",
	}[k]
}
