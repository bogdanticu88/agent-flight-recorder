package core

import (
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

// ---------------------------------------------------------------- Windows ACL vs. what the code opens

// rightsFromACE extracts the simple rights list of an icacls grant such as
// "CREATOR OWNER:(OI)(IO)(RD,AD,RA)".
func rightsFromACE(t *testing.T, script, principal string) map[string]bool {
	t.Helper()
	re := regexp.MustCompile(`"` + regexp.QuoteMeta(principal) + `:((?:\([A-Z]+\))*)\(([A-Z,]+)\)"`)
	m := re.FindStringSubmatch(script)
	if m == nil {
		t.Fatalf("no grant for %s in Install-AFR.ps1", principal)
	}
	out := map[string]bool{}
	for _, r := range strings.Split(m[2], ",") {
		out[r] = true
	}
	return out
}

func TestLogACLGrantsWhatTheRecorderRequests(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("..", "..", "deploy", "windows", "Install-AFR.ps1"))
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	need := append(append([]string{}, LogReadRights...), LogAppendRights...)
	for _, p := range []string{"CREATOR OWNER", "OWNER RIGHTS"} {
		got := rightsFromACE(t, s, p)
		for _, r := range need {
			if !got[r] {
				t.Errorf("%s ACE lacks %s, which the recorder requests when it opens the log", p, r)
			}
		}
		for _, r := range []string{"WD", "D", "DC", "WDAC", "WO", "M", "F", "W", "GW", "GA", "MA"} {
			if got[r] {
				t.Errorf("%s ACE grants %s: users could overwrite, delete or re-permission their log", p, r)
			}
		}
	}
}

// ---------------------------------------------------------------- collector must not follow user-controlled log locations

func TestCollectorIgnoresUserControlledLiveLogLocation(t *testing.T) {
	home := isolate(t)
	t.Setenv("AFR_LOG", "")
	secret := filepath.Join(t.TempDir(), "SAM")
	writeFile(t, secret, "TOPSECRET-HIVE-CONTENT\n")
	// the user writes their own policy pointing the "log" at a privileged file
	writeFile(t, userPolicyPath(RootsFor(home)), `{"log_path":"`+filepath.ToSlash(secret)+`"}`)
	p, _ := collectTo(t, CollectOptions{Roots: RootsFor(home), FullLiveLog: true})
	for _, e := range readZip(t, p) {
		mustNotContain(t, string(e.data), "TOPSECRET")
	}
}

// ---------------------------------------------------------------- excerpts

func TestForgedExcerptHeaderDoesNotHideDeletedPrefix(t *testing.T) {
	p, lines := chainedLog(t, 5)
	hdr := `{"afr_excerpt":{"version":1,"source_path":"x","source_sha256":"y","source_records":3,"source_status":"consistent","records":3}}`
	rewrite(t, p, append([]string{hdr}, lines[2:]...))
	_, rep := ReadLiveLog(p)
	if rep.OK() {
		t.Fatalf("a log with its first records deleted verifies once an excerpt header is prepended: %+v", rep)
	}
}

func TestExcerptDoesNotClaimOmittedRecordsWereOutOfWindow(t *testing.T) {
	p, lines := chainedLog(t, 5)
	hdr := `{"afr_excerpt":{"version":1,"source_path":"x","source_sha256":"y","source_records":5,"source_status":"consistent","records":2}}`
	rewrite(t, p, []string{hdr, lines[0], lines[3]})
	_, rep := ReadLiveLog(p)
	mustNotContain(t, rep.Detail, "records outside the window were left out")
}

func TestExcerptRecordOutsideItsWindowIsRejected(t *testing.T) {
	p, lines := chainedLog(t, 2) // records are stamped t0
	from, to := t0.Add(time.Hour), t0.Add(2*time.Hour)
	hdr := `{"afr_excerpt":{"version":1,"source_path":"x","source_sha256":"y","source_records":2,"source_status":"consistent","window_from":"` + from.Format(time.RFC3339) + `","window_to":"` + to.Format(time.RFC3339) + `","records":1}}`
	rewrite(t, p, []string{hdr, lines[0]})
	if _, rep := ReadLiveLog(p); rep.Status == ChainExcerpt {
		t.Fatalf("excerpt record outside the declared window accepted: %+v", rep)
	}
}

func TestBundleFromBrokenOriginalLogDoesNotVerifyClean(t *testing.T) {
	home := sampleHome(t)
	logp := os.Getenv("AFR_LOG")
	for i := 0; i < 3; i++ {
		e := Event{TS: t0, Agent: "claude-code", Origin: "live", SessionID: "L", Kind: KindOther}
		if err := AppendLive(logp, &e, ""); err != nil {
			t.Fatal(err)
		}
	}
	b, _ := os.ReadFile(logp)
	lines := strings.Split(strings.TrimRight(string(b), "\n"), "\n")
	rewrite(t, logp, append([]string{lines[0]}, lines[2:]...)) // interior deletion
	p, m := collectTo(t, CollectOptions{Roots: RootsFor(home), From: t0.Add(-time.Hour), To: t0.Add(time.Hour)})
	if m.LiveLog == nil || m.LiveLog.Status != ChainBroken {
		t.Fatalf("collector did not see the broken chain: %+v", m.LiveLog)
	}
	if chk := check(t, p); chk.OK() {
		t.Fatal("bundle verified clean although the original live log was broken at collection")
	}
}

// ---------------------------------------------------------------- correlation

func outcomes(evs []Event) map[int]string {
	sv, _, _ := BuildReport(evs, nil)
	out := map[int]string{}
	for _, s := range sv {
		for _, e := range s.Steps {
			if e.Kind == KindToolCall {
				out[e.Pos] = e.Outcome
			}
		}
	}
	return out
}

func TestDuplicateCallIDsAreAmbiguous(t *testing.T) {
	o := outcomes([]Event{
		call(1, "c1", "read_file", map[string]any{"path": "/a"}),
		call(2, "c1", "read_file", map[string]any{"path": "/b"}),
		result(3, "c1", StatusSuccess, "x"),
	})
	if o[1] != OutcomeUnknown || o[2] != OutcomeUnknown {
		t.Fatalf("two calls sharing an ID must both stay unknown, got %v", o)
	}
}

func TestResultBeforeCallIsNotItsResult(t *testing.T) {
	o := outcomes([]Event{
		result(1, "c1", StatusSuccess, "x"),
		call(2, "c1", "read_file", map[string]any{"path": "/a"}),
	})
	if o[2] == OutcomeCompleted {
		t.Fatalf("a result recorded before the call completed it: %v", o)
	}
}

func TestConflictingStatusesAreUnknown(t *testing.T) {
	for name, statuses := range map[string][]string{
		"success then error":   {StatusSuccess, StatusError},
		"error then success":   {StatusError, StatusSuccess},
		"rejected and success": {StatusRejected, StatusSuccess},
	} {
		evs := []Event{call(1, "c1", "read_file", map[string]any{"path": "/a"})}
		for i, st := range statuses {
			evs = append(evs, result(2+i, "c1", st, "x"))
		}
		if o := outcomes(evs); o[1] != OutcomeUnknown {
			t.Errorf("%s: want unknown, got %s", name, o[1])
		}
	}
	if o := outcomes([]Event{
		call(1, "c1", "read_file", map[string]any{"path": "/a"}),
		result(2, "c1", StatusSuccess, "x"),
		result(3, "c1", StatusSuccess, "x"),
	}); o[1] != OutcomeCompleted {
		t.Errorf("repeated identical success must stay completed, got %s", o[1])
	}
}

func TestUnscopedResultsDoNotCompleteCalls(t *testing.T) {
	c := call(1, "c1", "read_file", map[string]any{"path": "/a"})
	r := result(2, "c1", StatusSuccess, "x")
	c.SessionID, r.SessionID = "", ""
	if o := outcomes([]Event{c, r}); o[1] == OutcomeCompleted {
		t.Fatal("without a session ID the result cannot be attributed to this call")
	}
}

func TestSameCallIDInAnotherSessionDoesNotComplete(t *testing.T) {
	a := call(1, "c1", "read_file", map[string]any{"path": "/a"})
	r := result(2, "c1", StatusSuccess, "x")
	r.SessionID = "other"
	if o := outcomes([]Event{a, r}); o[1] != OutcomeRequested {
		t.Fatalf("result from another session completed the call: %v", o)
	}
}

// ---------------------------------------------------------------- tool classification

func TestToolCategoryDoesNotMatchSubstrings(t *testing.T) {
	for tool, want := range map[string]string{
		"certificate_lookup":      CatOther,
		"allocate_buffer":         CatOther,
		"opencode_status":         CatOther,
		"preview_markdown":        CatOther,
		"read_file":               CatRead,
		"copilot_readFile":        CatRead,
		"Read":                    CatRead,
		"view":                    CatRead,
		"list_directory":          CatList,
		"copilot_findTextInFiles": CatSearch,
		"run_in_terminal":         CatShell,
		"copilot_replaceString":   CatWrite,
	} {
		if got := ToolCategory(tool); got != want {
			t.Errorf("%s: got %s want %s", tool, got, want)
		}
	}
	_, fs, _ := BuildReport([]Event{
		call(1, "c1", "certificate_lookup", map[string]any{"path": target}),
		result(2, "c1", StatusSuccess, "ok"),
	}, []string{target})
	if len(fs) != 1 || fs[0].FirstCompletion != nil {
		t.Fatal("a non-file tool was treated as a confirmed read")
	}
}

// ---------------------------------------------------------------- image path mapping

func TestMapPathCannotLeaveTheImageRoot(t *testing.T) {
	root := t.TempDir()
	s := Scope{Root: root}
	for _, p := range []string{`C:\..\..\..\etc\shadow`, "/../../../etc/shadow", `D:\a\..\..\..\x`} {
		got, err := s.MapPath(p)
		if err == nil && !within(got, root) {
			t.Errorf("%s mapped outside the image root: %s", p, got)
		}
	}
}

// ---------------------------------------------------------------- partial vs complete

func TestUnstableAcquisitionMakesCollectionPartial(t *testing.T) {
	home := sampleHome(t)
	acquireHook = func(p string) {
		if strings.HasSuffix(p, ".jsonl") && strings.Contains(p, ".claude") {
			f, _ := os.OpenFile(p, os.O_APPEND|os.O_WRONLY, 0)
			f.WriteString("\n")
			f.Close()
		}
	}
	defer func() { acquireHook = nil }()
	_, m, err := Collect(CollectOptions{Roots: RootsFor(home), Out: filepath.Join(t.TempDir(), "b.zip")})
	if !errors.Is(err, ErrPartial) || m.Status != "partial" {
		t.Fatalf("a source that never stopped changing left the collection marked %q (err %v)", m.Status, err)
	}
}

func TestMalformedRecordsMakeCollectionPartial(t *testing.T) {
	home := sampleHome(t)
	p := filepath.Join(home, ".claude", "projects", "proj", "sess-1.jsonl")
	f, _ := os.OpenFile(p, os.O_APPEND|os.O_WRONLY, 0)
	f.WriteString("{truncated record\n")
	f.Close()
	_, m, err := Collect(CollectOptions{Roots: RootsFor(home), Out: filepath.Join(t.TempDir(), "b.zip")})
	if !errors.Is(err, ErrPartial) || m.Status != "partial" {
		t.Fatalf("malformed records left the collection marked %q", m.Status)
	}
}

// ---------------------------------------------------------------- checkpoints

func TestCheckpointNotEvaluatedOnInvalidLog(t *testing.T) {
	p, lines := chainedLog(t, 3)
	_, full := ReadLiveLog(p)
	cp := Checkpoint{Records: 3, Hash: full.HeadHash}
	rewrite(t, p, append(lines, "{garbage"))
	evs, rep := ReadLiveLog(p)
	ApplyCheckpoint(evs, &rep, cp)
	if rep.OK() || strings.Contains(rep.Checkpoint, "matches") {
		t.Fatalf("checkpoint reported as matching on an invalid log: %+v", rep)
	}
}

func TestCheckpointSurvivesLegitimateAppends(t *testing.T) {
	p, _ := chainedLog(t, 3)
	_, full := ReadLiveLog(p)
	cp := Checkpoint{Records: 3, Hash: full.HeadHash}
	for i := 0; i < 2; i++ {
		e := Event{TS: t0, Agent: "codex", Origin: "live", Kind: KindOther}
		if err := AppendLive(p, &e, ""); err != nil {
			t.Fatal(err)
		}
	}
	evs, rep := ReadLiveLog(p)
	ApplyCheckpoint(evs, &rep, cp)
	if !rep.OK() || !strings.Contains(rep.Checkpoint, "matches") {
		t.Fatalf("appends after a checkpoint broke verification: %+v", rep)
	}
}

func TestMalformedCheckpointHashRejected(t *testing.T) {
	for _, bad := range []string{"3:xyz", "3:" + strings.Repeat("g", 64), "3:" + strings.Repeat("a", 63)} {
		if _, err := ParseCheckpoint(bad); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
}

// ---------------------------------------------------------------- check-then-open race

func TestSymlinkSwapAfterContainmentCheckIsRejected(t *testing.T) {
	home := sampleHome(t)
	secret := filepath.Join(t.TempDir(), "outside.jsonl")
	writeFile(t, secret, `{"type":"user","sessionId":"x","message":{"role":"user","content":"SWAPPED-IN SECRET"}}`+"\n")
	victim := filepath.Join(home, ".claude", "projects", "proj", "sess-1.jsonl")
	swapped := false
	beforeOpenHook = func(p string) {
		if !swapped && strings.HasSuffix(p, "sess-1.jsonl") {
			swapped = true
			os.Remove(p)
			if err := os.Symlink(secret, p); err != nil {
				t.Skip(err)
			}
		}
	}
	defer func() { beforeOpenHook = nil }()
	p, m := collectTo(t, CollectOptions{Roots: RootsFor(home)})
	if !swapped {
		t.Fatal("hook never ran")
	}
	for _, e := range readZip(t, p) {
		mustNotContain(t, string(e.data), "SWAPPED-IN SECRET")
	}
	if m.Status != "partial" {
		t.Fatalf("a source that could not be acquired safely must make the collection partial, got %s", m.Status)
	}
	_ = victim
}

func TestDirectoryChildFailureMakesCollectionPartial(t *testing.T) {
	home := isolate(t)
	st := filepath.Join(home, ".local", "share", "opencode", "storage")
	writeFile(t, filepath.Join(st, "message", "ses_d", "msg_1.json"), `{"id":"msg_1","sessionID":"ses_d","role":"user","time":{"created":1793281800000}}`)
	writeFile(t, filepath.Join(st, "part", "msg_1", "prt_1.json"), `{"id":"prt_1","type":"text","text":"hello"}`)
	beforeOpenHook = func(p string) {
		if strings.HasSuffix(p, "prt_1.json") {
			os.Remove(p) // disappears between listing and reading
		}
	}
	defer func() { beforeOpenHook = nil }()
	_, m, err := Collect(CollectOptions{Roots: RootsFor(home), Agents: map[string]bool{"opencode": true}, Out: filepath.Join(t.TempDir(), "b.zip")})
	if !errors.Is(err, ErrPartial) || m.Status != "partial" {
		t.Fatalf("an unreadable directory child left the collection %q (err %v)", m.Status, err)
	}
}

// ---------------------------------------------------------------- relationships between streams

func TestSameSessionInSeveralSourcesIsLinkedNotMerged(t *testing.T) {
	main := prompt(1, "main transcript")
	sub := call(1, "s1", "read_file", map[string]any{"path": target})
	sub.Source = "subagent.jsonl"
	sv, fs, _ := BuildReport([]Event{main, sub}, []string{target})
	if len(sv) != 2 {
		t.Fatalf("streams from two sources must stay separate, got %d", len(sv))
	}
	for _, s := range sv {
		if len(s.Related) != 1 {
			t.Fatalf("stream %s does not point to the other stream of the same session: %v", s.Source, s.Related)
		}
	}
	if len(fs) != 1 || !strings.Contains(strings.Join(fs[0].Summary, " "), "also appears in 1 other record stream") {
		t.Fatalf("finding does not mention the related stream: %v", fs)
	}
}

func TestMultiBundleReportShowsEachBundleIdentity(t *testing.T) {
	h := sampleHome(t)
	p1, _ := collectTo(t, CollectOptions{Roots: RootsFor(h)})
	p2, _ := collectTo(t, CollectOptions{Roots: RootsFor(h), CaseID: "second run"})
	var d ReportData
	for _, p := range []string{p1, p2} {
		_, m, _, chk, err := LoadBundle(p, DefaultBundleLimits)
		if err != nil {
			t.Fatal(err)
		}
		if len(chk.BundleSHA256) != 64 {
			t.Fatalf("bundle identity not computed: %q", chk.BundleSHA256)
		}
		d.Bundles = append(d.Bundles, BundleInfo{Path: p, Manifest: m, Check: chk})
	}
	out := filepath.Join(t.TempDir(), "r.html")
	f, _ := os.Create(out)
	if err := RenderHTML(f, d); err != nil {
		t.Fatal(err)
	}
	f.Close()
	b, _ := os.ReadFile(out)
	for _, bi := range d.Bundles {
		mustContain(t, string(b), bi.Check.BundleSHA256)
	}
}

func TestBrokenLiveLogMakesCollectionPartial(t *testing.T) {
	home := sampleHome(t)
	logp := os.Getenv("AFR_LOG")
	for i := 0; i < 3; i++ {
		e := Event{TS: t0, Agent: "claude-code", Origin: "live", SessionID: "L", Kind: KindOther}
		AppendLive(logp, &e, "")
	}
	b, _ := os.ReadFile(logp)
	lines := strings.Split(strings.TrimRight(string(b), "\n"), "\n")
	rewrite(t, logp, append([]string{lines[0]}, lines[2:]...))
	_, m, err := Collect(CollectOptions{Roots: RootsFor(home), Out: filepath.Join(t.TempDir(), "b.zip")})
	if !errors.Is(err, ErrPartial) || m.Status != "partial" {
		t.Fatalf("a broken live log was collected as %q", m.Status)
	}
}

// ---------------------------------------------------------------- concurrent hooks

func TestConcurrentAppendsKeepOneChain(t *testing.T) {
	p := filepath.Join(t.TempDir(), "events.jsonl")
	locks := t.TempDir()
	done := make(chan error, 20)
	for i := 0; i < 20; i++ {
		go func() {
			e := Event{TS: t0, Agent: "claude-code", Origin: "live", SessionID: "c", Kind: KindToolCall, Tool: "Read"}
			done <- AppendLive(p, &e, locks)
		}()
	}
	for i := 0; i < 20; i++ {
		if err := <-done; err != nil {
			t.Fatal(err)
		}
	}
	if _, rep := ReadLiveLog(p); rep.Status != ChainConsistent || rep.Records != 20 {
		t.Fatalf("parallel hook calls forked or lost records: %+v", rep)
	}
}
