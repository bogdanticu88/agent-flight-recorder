package core

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const preRead = `{"hook_event_name":"PreToolUse","session_id":"s1","tool_name":"Read","tool_input":{"file_path":"/h/.ssh/id_rsa"}}`

func hook(t *testing.T, home, agent, payload string) HookResult {
	t.Helper()
	return RunHook(agent, "", strings.NewReader(payload), RootsFor(home))
}

func denied(r HookResult) bool {
	return r.ExitCode == 2 || strings.Contains(r.Stdout, `"deny"`)
}

func TestMalformedEnvPolicyIsAnErrorNotEmpty(t *testing.T) {
	home := isolate(t)
	bad := filepath.Join(home, "bad.json")
	writeFile(t, bad, `{not json`)
	t.Setenv("AFR_POLICY", bad)
	st := LoadPolicy(RootsFor(home))
	if st.Err == nil {
		t.Fatal("invalid policy must produce an error")
	}
	r := hook(t, home, "claude-code", preRead)
	mustContain(t, r.Stderr, "policy error")
	if denied(r) {
		t.Fatal("without an on-policy-error marker the default is allow")
	}
}

func TestOnPolicyErrorMarkerDenies(t *testing.T) {
	home := isolate(t)
	writeFile(t, ManagedPolicyPath(), `{"rules":[{"pattern":"x","action":"block"}]}`) // invalid action
	writeFile(t, OnErrorMarkerPath(), "deny\n")
	r := hook(t, home, "claude-code", preRead)
	if !denied(r) {
		t.Fatalf("marker says deny when policy fails to load: %+v", r)
	}
	mustContain(t, r.Stdout, "could not be loaded")
	// post-tool events are never denied
	r = hook(t, home, "claude-code", strings.Replace(preRead, "PreToolUse", "PostToolUse", 1))
	if denied(r) {
		t.Fatal("post event denied")
	}
}

func TestUnreadablePolicy(t *testing.T) {
	home := isolate(t)
	if err := os.MkdirAll(ManagedPolicyPath(), 0o755); err != nil { // a directory cannot be read as a file
		t.Fatal(err)
	}
	st := LoadPolicy(RootsFor(home))
	if st.Err == nil || !strings.Contains(st.Err.Error(), "unreadable") {
		t.Fatalf("want unreadable error, got %v", st.Err)
	}
	if st.Origin != PolicyManaged {
		t.Fatalf("an existing but unreadable managed policy is still the managed policy, got %s", st.Origin)
	}
}

func TestManagedPolicyIgnoresEnvironmentOverrides(t *testing.T) {
	home := isolate(t)
	managedLog := filepath.Join(t.TempDir(), "central.jsonl")
	writeFile(t, ManagedPolicyPath(), `{"log_path":"`+filepath.ToSlash(managedLog)+`","rules":[{"pattern":"**/.ssh/**","action":"deny","label":"ssh"}]}`)
	weak := filepath.Join(home, "weak.json")
	writeFile(t, weak, `{"rules":[]}`)
	t.Setenv("AFR_POLICY", weak)
	redirect := filepath.Join(home, "elsewhere.jsonl")
	t.Setenv("AFR_LOG", redirect)

	r := hook(t, home, "claude-code", preRead)
	if !denied(r) {
		t.Fatal("AFR_POLICY must not weaken a managed policy")
	}
	if _, err := os.Stat(redirect); err == nil {
		t.Fatal("AFR_LOG must not redirect recording away from the managed log")
	}
	evs, rep := ReadLiveLog(managedLog)
	if rep.Status != ChainConsistent || len(evs) != 1 {
		t.Fatalf("managed log: %+v", rep)
	}
	mustContain(t, evs[0].Reason, "AFR_POLICY ignored")
}

func TestDenyBeatsEarlierAlert(t *testing.T) {
	home := isolate(t)
	p := filepath.Join(home, "p.json")
	writeFile(t, p, `{"rules":[{"pattern":"**/id_rsa","action":"alert","label":"canary"},{"pattern":"**/.ssh/**","action":"deny","label":"ssh"}]}`)
	t.Setenv("AFR_POLICY", p)
	r := hook(t, home, "claude-code", preRead)
	if !denied(r) {
		t.Fatal("a matching deny rule must win over an earlier alert rule")
	}
	evs, _ := ReadLiveLog(os.Getenv("AFR_LOG"))
	mustContain(t, evs[0].Reason, "ssh")
	mustContain(t, evs[0].Reason, "canary")
}

func TestPolicyValidation(t *testing.T) {
	for _, bad := range []string{
		`{"rules":[{"pattern":"","action":"deny"}]}`,
		`{"rules":[{"pattern":"x","action":"Deny"}]}`,
		`{"max_text":10}`,
		`{"fail_close":true}`, // misspelled field: refused, not ignored
		`{"rules":[]} {"rules":[]}`,
	} {
		home := isolate(t)
		p := filepath.Join(home, "p.json")
		writeFile(t, p, bad)
		t.Setenv("AFR_POLICY", p)
		if st := LoadPolicy(RootsFor(home)); st.Err == nil {
			t.Errorf("accepted invalid policy %s", bad)
		}
	}
}

func TestEnforcementSeesInputBeyondTruncation(t *testing.T) {
	home := isolate(t)
	p := filepath.Join(home, "p.json")
	writeFile(t, p, `{"max_text":256,"rules":[{"pattern":"**/.ssh/**","action":"deny","label":"ssh"}]}`)
	t.Setenv("AFR_POLICY", p)
	cmd := strings.Repeat("echo padding; ", 100) + "cat /home/dev/.ssh/id_rsa"
	r := hook(t, home, "claude-code", `{"hook_event_name":"PreToolUse","session_id":"s","tool_name":"Bash","tool_input":{"command":"`+cmd+`"}}`)
	if !denied(r) {
		t.Fatal("rule must match the full input, not the truncated copy")
	}
	evs, _ := ReadLiveLog(os.Getenv("AFR_LOG"))
	if len(evs[0].Input) > 256+64 {
		t.Fatalf("stored input not truncated: %d bytes", len(evs[0].Input))
	}
}

func TestOversizedAndMalformedPayloads(t *testing.T) {
	home := isolate(t)
	big := `{"hook_event_name":"PreToolUse","tool_name":"Read","tool_input":{"x":"` + strings.Repeat("a", MaxHookPayload) + `"}}`
	for name, payload := range map[string]string{
		"oversized": big,
		"not json":  "not json",
		"no tool":   `{"hook_event_name":"PreToolUse","session_id":"s"}`,
	} {
		r := hook(t, home, "claude-code", payload)
		if denied(r) {
			t.Errorf("%s: default policy must not deny", name)
		}
		mustContain(t, r.Stderr, "malformed payload")
	}
	evs, rep := ReadLiveLog(os.Getenv("AFR_LOG"))
	if rep.Status != ChainConsistent || len(evs) != 3 {
		t.Fatalf("malformed payloads must still be recorded: %+v", rep)
	}
	for _, e := range evs {
		if len(e.Input) > 0 {
			t.Error("undecoded payload bytes must not be persisted")
		}
	}

	p := filepath.Join(home, "p.json")
	writeFile(t, p, `{"fail_closed":true}`)
	t.Setenv("AFR_POLICY", p)
	if r := hook(t, home, "claude-code", `{"hook_event_name":"PreToolUse","session_id":"s"}`); !denied(r) {
		t.Fatal("fail_closed must deny a malformed pre-tool payload")
	}
}

func TestRecordingFailureIsNotReportedAsLogged(t *testing.T) {
	home := isolate(t)
	blocker := filepath.Join(home, "file")
	writeFile(t, blocker, "x")
	t.Setenv("AFR_LOG", filepath.Join(blocker, "sub", "events.jsonl")) // parent is a file: cannot create
	// and the local fallback cannot be created either
	writeFile(t, filepath.Dir(FallbackLogPath(RootsFor(home))), "x")
	p := filepath.Join(home, "p.json")
	writeFile(t, p, `{"rules":[{"pattern":"**/.ssh/**","action":"deny","label":"ssh"}]}`)
	t.Setenv("AFR_POLICY", p)
	r := hook(t, home, "claude-code", preRead)
	if !denied(r) {
		t.Fatal("deny must still be enforced when recording fails")
	}
	mustNotContain(t, r.Stdout, "was recorded")
	mustContain(t, r.Stdout, "Recording this attempt failed")
	mustContain(t, r.Stderr, "recording failed")

	writeFile(t, p, `{"fail_closed":true}`)
	ok := `{"hook_event_name":"PreToolUse","session_id":"s","tool_name":"Read","tool_input":{"file_path":"/tmp/x"}}`
	if r := hook(t, home, "claude-code", ok); !denied(r) {
		t.Fatal("fail_closed must deny when the call cannot be recorded")
	}
}

func TestUnknownAgentRejected(t *testing.T) {
	home := isolate(t)
	r := hook(t, home, "notepad", preRead)
	if r.ExitCode != 1 || !strings.Contains(r.Stderr, "unknown agent") {
		t.Fatalf("got %+v", r)
	}
}

func TestReasonIsRedactedBeforeStorage(t *testing.T) {
	home := isolate(t)
	p := filepath.Join(home, "p.json")
	writeFile(t, p, `{"rules":[{"pattern":"AKIA","action":"alert","label":"aws key in args"}]}`)
	t.Setenv("AFR_POLICY", p)
	hook(t, home, "claude-code", `{"hook_event_name":"PreToolUse","session_id":"s","tool_name":"Bash","tool_input":{"command":"export K=AKIAIOSFODNN7EXAMPLE"}}`)
	b, _ := os.ReadFile(os.Getenv("AFR_LOG"))
	mustNotContain(t, string(b), "AKIAIOSFODNN7EXAMPLE")
	mustContain(t, string(b), `"decision":"alert"`)
}

func TestVendorDenyProtocols(t *testing.T) {
	cases := map[string]func(HookResult) bool{
		"claude-code": func(r HookResult) bool {
			return strings.Contains(r.Stdout, `"permissionDecision":"deny"`) && r.ExitCode == 0
		},
		"codex": func(r HookResult) bool {
			return strings.Contains(r.Stdout, `"permissionDecision":"deny"`) && r.ExitCode == 0
		},
		"copilot":    func(r HookResult) bool { return strings.Contains(r.Stdout, `"permissionDecision":"deny"`) },
		"cursor":     func(r HookResult) bool { return r.ExitCode == 2 && strings.Contains(r.Stdout, `"permission":"deny"`) },
		"gemini-cli": func(r HookResult) bool { return r.ExitCode == 2 && r.Stderr != "" },
		"opencode":   func(r HookResult) bool { return r.ExitCode == 2 && r.Stderr != "" },
	}
	for agent, ok := range cases {
		r := denyResult(agent, "PreToolUse", "no")
		if !ok(r) {
			t.Errorf("%s deny response %+v does not match its documented protocol", agent, r)
		}
	}
}

// A missing per-user log folder, or a log someone else created first, must not
// silently stop recording: the hook falls back to the user's own log and says so.
func TestUnavailableLogFallsBackToLocalLog(t *testing.T) {
	home := isolate(t)
	blocker := filepath.Join(home, "file")
	writeFile(t, blocker, "x")
	central := filepath.Join(blocker, "sub", "events.jsonl")
	t.Setenv("AFR_LOG", central)
	p := filepath.Join(home, "p.json")
	writeFile(t, p, `{"fail_closed":true,"rules":[{"pattern":"**/.ssh/**","action":"deny","label":"ssh"}]}`)
	t.Setenv("AFR_POLICY", p)

	r := hook(t, home, "claude-code", preRead)
	if !denied(r) {
		t.Fatal("deny must still be enforced")
	}
	mustContain(t, r.Stdout, "was recorded")
	mustContain(t, r.Stderr, "local fallback log")
	mustContain(t, r.Stderr, "the user can modify")
	mustNotContain(t, r.Stderr, "recording failed")

	ok := `{"hook_event_name":"PreToolUse","session_id":"s","tool_name":"Read","tool_input":{"file_path":"/tmp/x"}}`
	if r := hook(t, home, "claude-code", ok); denied(r) {
		t.Fatal("fail_closed must not deny when the fallback recorded the call")
	}
	f, err := os.Open(FallbackLogPath(RootsFor(home)))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	evs, rep := VerifyLiveLog(f)
	if !rep.OK() || len(evs) != 2 {
		t.Fatalf("fallback log: %d records, %+v", len(evs), rep)
	}
}

func TestCollectorUsesFallbackWhenCentralLogMissing(t *testing.T) {
	home := isolate(t)
	central := filepath.Join(t.TempDir(), "logs", "someone", "events.jsonl")
	writeFile(t, filepath.Join(machineDir(), "policy.json"), `{"log_path":`+jsonQuote(central)+`}`)
	ev := Event{TS: t0, Agent: "claude-code", Origin: "live", SessionID: "fb", Kind: KindPrompt, Text: "recorded while the central log was unavailable"}
	if err := AppendLive(FallbackLogPath(RootsFor(home)), &ev, ""); err != nil {
		t.Fatal(err)
	}
	p, m := collectTo(t, CollectOptions{Roots: RootsFor(home), From: t0.Add(-time.Hour), To: t0.Add(time.Hour)})
	if m.LiveLog == nil || m.LiveLog.InWindow != 1 {
		t.Fatalf("fallback log not collected: %+v", m.LiveLog)
	}
	mustContain(t, strings.Join(m.Skipped, "\n"), "local fallback log")
	all := ""
	for _, e := range readZip(t, p) {
		all += string(e.data)
	}
	mustContain(t, all, "recorded while the central log was unavailable")

	// central present as well: central is collected, the fallback is pointed out
	ev2 := Event{TS: t0, Agent: "claude-code", Origin: "live", SessionID: "c", Kind: KindPrompt, Text: "central record"}
	if err := AppendLive(central, &ev2, ""); err != nil {
		t.Fatal(err)
	}
	p, m = collectTo(t, CollectOptions{Roots: RootsFor(home), From: t0.Add(-time.Hour), To: t0.Add(time.Hour)})
	all = ""
	for _, e := range readZip(t, p) {
		all += string(e.data)
	}
	mustContain(t, all, "central record")
	mustContain(t, strings.Join(m.Skipped, "\n"), "collect it separately with --live-log")
}

func jsonQuote(s string) string { b, _ := json.Marshal(s); return string(b) }
