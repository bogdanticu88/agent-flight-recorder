package core

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

// Copilot hook payloads carry no tool-call ID (hooks reference: preToolUse
// has sessionId, timestamp, cwd, toolName, toolArgs; postToolUse adds
// toolResult). Shapes below follow a real VS Code session recorded on
// Windows, including parallel calls issued before any result arrives.
func copilotHook(t *testing.T, home, event string, payload map[string]any) {
	t.Helper()
	payload["sessionId"] = "s-copilot"
	payload["cwd"] = home
	b, _ := json.Marshal(payload)
	if r := RunHook("copilot", event, strings.NewReader(string(b)), RootsFor(home)); r.ExitCode != 0 {
		t.Fatalf("%s: exit %d: %s", event, r.ExitCode, r.Stderr)
	}
}

func liveSteps(t *testing.T) []Event {
	t.Helper()
	f, err := os.Open(os.Getenv("AFR_LOG"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	evs, rep := VerifyLiveLog(f)
	if !rep.OK() {
		t.Fatalf("log: %+v", rep)
	}
	return evs
}

func TestCopilotCallsWithoutIDsMatchResultsByArguments(t *testing.T) {
	home := isolate(t)
	ok := map[string]any{"resultType": "success", "textResultForLlm": "x"}
	a := map[string]any{"path": home + "/app.py"}
	b := map[string]any{"path": home + "/inventory.csv"}
	same := map[string]any{"command": "git status"}

	// two different reads in parallel, then their results in the same order
	copilotHook(t, home, "preToolUse", map[string]any{"toolName": "view", "toolArgs": a})
	copilotHook(t, home, "preToolUse", map[string]any{"toolName": "view", "toolArgs": b})
	copilotHook(t, home, "postToolUse", map[string]any{"toolName": "view", "toolArgs": a, "toolResult": ok})
	copilotHook(t, home, "postToolUse", map[string]any{"toolName": "view", "toolArgs": b,
		"toolResult": map[string]any{"resultType": "failure", "textResultForLlm": "not found"}})
	// two identical commands in parallel: cannot tell which result is whose
	copilotHook(t, home, "preToolUse", map[string]any{"toolName": "powershell", "toolArgs": same})
	copilotHook(t, home, "preToolUse", map[string]any{"toolName": "powershell", "toolArgs": same})
	copilotHook(t, home, "postToolUse", map[string]any{"toolName": "powershell", "toolArgs": same, "toolResult": ok})
	// a call that never got a result
	copilotHook(t, home, "preToolUse", map[string]any{"toolName": "view", "toolArgs": map[string]any{"path": home + "/README.md"}})

	views, _, _ := BuildReport(liveSteps(t), nil)
	if len(views) != 1 {
		t.Fatalf("want one stream, got %d", len(views))
	}
	var got []string
	for _, s := range views[0].Steps {
		if s.Kind == KindToolCall {
			got = append(got, s.Outcome)
		}
	}
	want := []string{OutcomeCompleted, OutcomeFailed, OutcomeUnknown, OutcomeUnknown, OutcomeRequested}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("outcomes = %v, want %v", got, want)
	}
	for _, s := range views[0].Steps {
		if s.Kind == KindToolCall && s.Tool == "view" && s.Outcome == OutcomeCompleted {
			mustContain(t, s.OutcomeNote, "identical tool name and arguments")
		}
		if s.Kind == KindToolCall && s.Tool == "powershell" {
			mustContain(t, s.OutcomeNote, "cannot be matched")
		}
	}
}

// The Copilot transcript records a call refused by a preToolUse hook as a
// failed execution whose error says so. Seen on a real VS Code session: the
// live log said blocked, the transcript parser said failed.
func TestCopilotTranscriptHookDenialIsBlocked(t *testing.T) {
	dir := t.TempDir()
	p := dir + "/session-state/s1/events.jsonl"
	deny := "Denied by preToolUse hook: Tool call denied: blocked by security policy (Test: dummy credentials). This attempt was recorded."
	writeFile(t, p, jsonl(t,
		map[string]any{"type": "tool.execution_start", "timestamp": "2026-11-01T10:16:31Z", "data": map[string]any{"toolCallId": "t1", "toolName": "view", "arguments": map[string]any{"path": target}}},
		map[string]any{"type": "tool.execution_complete", "timestamp": "2026-11-01T10:16:31Z", "data": map[string]any{"toolCallId": "t1", "success": false, "error": map[string]any{"message": deny}}},
		map[string]any{"type": "tool.execution_start", "timestamp": "2026-11-01T10:16:40Z", "data": map[string]any{"toolCallId": "t2", "toolName": "view", "arguments": map[string]any{"path": "/w/missing"}}},
		map[string]any{"type": "tool.execution_complete", "timestamp": "2026-11-01T10:16:41Z", "data": map[string]any{"toolCallId": "t2", "success": false, "error": "ENOENT: no such file"}},
	))
	res, err := ParseSource(Source{Agent: "copilot-cli", Parser: "copilot-cli", Path: p})
	if err != nil {
		t.Fatal(err)
	}
	for i := range res.Events {
		res.Events[i].Prov = "t"
	}
	f := traceOne(t, res.Events)
	if f.FirstRequest == nil || f.FirstRequest.Outcome != OutcomeBlocked {
		t.Fatalf("hook denial in transcript: want blocked, got %+v", f.FirstRequest)
	}
	views, _, _ := BuildReport(res.Events, nil)
	for _, s := range views[0].Steps {
		if s.Kind == KindToolCall && s.CallID == "t2" && s.Outcome != OutcomeFailed {
			t.Fatalf("an ordinary error must stay failed, got %s", s.Outcome)
		}
	}
}
