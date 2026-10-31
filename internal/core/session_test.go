package core

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func live(host, user, sid string, pos int, k Kind, ts time.Time) Event {
	return Event{Agent: "claude-code", Origin: "live", Host: host, User: user, SessionID: sid, Pos: pos, Kind: k, TS: ts, Prov: "log"}
}

func TestSameSessionIDOnTwoHostsStaysSeparate(t *testing.T) {
	a := live("host-a", "alice", "s1", 1, KindPrompt, t0)
	b := live("host-b", "bob", "s1", 1, KindPrompt, t0)
	sv, _, _ := BuildReport([]Event{a, b}, nil)
	if len(sv) != 2 {
		t.Fatalf("records from two hosts merged into %d stream(s)", len(sv))
	}
}

func TestMissingSessionIDsAreNotMergedWithNamedSessions(t *testing.T) {
	named := live("h", "u", "s1", 1, KindPrompt, t0)
	anon1 := live("h", "u", "", 2, KindToolCall, t0)
	sv, _, _ := BuildReport([]Event{named, anon1}, nil)
	if len(sv) != 2 {
		t.Fatalf("unscoped event merged into a named session: %d stream(s)", len(sv))
	}
	for _, s := range sv {
		if s.SessionID == "" && !s.Unscoped {
			t.Fatal("stream without session ID not marked unscoped")
		}
	}
}

func TestPromptIsNotBorrowedAcrossScopes(t *testing.T) {
	p := live("h", "u", "s1", 1, KindPrompt, t0)
	p.Text = "do X"
	c := live("h", "u", "", 2, KindToolCall, t0.Add(time.Second))
	c.Tool, c.Input = "Read", `{"file_path":"/home/dev/.aws/credentials"}`
	_, fs, _ := BuildReport([]Event{p, c}, []string{target})
	if len(fs) != 1 || fs[0].Prompt != nil {
		t.Fatal("a prompt from another session was attached to an unscoped call")
	}
	mustContain(t, strings.Join(fs[0].Summary, " "), "carry no session ID")
}

func TestOverlappingSourcesKeepProvenance(t *testing.T) {
	e1 := prompt(1, "same text")
	e2 := prompt(1, "same text")
	e2.Source = "other-source"
	sv, _, _ := BuildReport([]Event{e1, e2}, nil)
	if len(sv) != 2 {
		t.Fatalf("identical events from two sources collapsed: %d", len(sv))
	}
}

func TestOrderingFollowsSourcePositionNotClock(t *testing.T) {
	// clock disagrees with the order the source recorded
	a := prompt(1, "first")
	a.TS = t0.Add(time.Hour)
	b := prompt(2, "second")
	b.TS = t0
	c := prompt(3, "third")
	c.TS = t0.Add(30 * time.Minute)
	evs := []Event{c, a, b}
	for i := 0; i < 3; i++ {
		SortEvents(evs)
		if evs[0].Text != "first" || evs[1].Text != "second" || evs[2].Text != "third" {
			t.Fatalf("order: %s %s %s", evs[0].Text, evs[1].Text, evs[2].Text)
		}
		evs = []Event{evs[2], evs[0], evs[1]}
	}
}

func TestMultiBundleReportKeepsEveryManifest(t *testing.T) {
	h1 := sampleHome(t)
	p1, _ := collectTo(t, CollectOptions{Roots: RootsFor(h1), CaseID: "CASE-A", SourceHost: "a"})
	h2 := sampleHome(t)
	p2, _ := collectTo(t, CollectOptions{Roots: RootsFor(h2), CaseID: "CASE-B", SourceHost: "b"})

	var d ReportData
	var evs []Event
	for _, p := range []string{p1, p2} {
		e, m, _, chk, err := LoadBundle(p, DefaultBundleLimits)
		if err != nil {
			t.Fatal(err)
		}
		d.Bundles = append(d.Bundles, BundleInfo{Path: p, Manifest: m, Check: chk})
		evs = append(evs, e...)
	}
	d.Sessions, d.Findings, d.Alerts = BuildReport(evs, nil)
	if len(d.Sessions) != 2 {
		t.Fatalf("the same session ID from two bundles must stay apart, got %d stream(s)", len(d.Sessions))
	}
	out := filepath.Join(t.TempDir(), "r.html")
	f, _ := os.Create(out)
	if err := RenderHTML(f, d); err != nil {
		t.Fatal(err)
	}
	f.Close()
	b, _ := os.ReadFile(out)
	mustContain(t, string(b), "CASE-A")
	mustContain(t, string(b), "CASE-B")
}
