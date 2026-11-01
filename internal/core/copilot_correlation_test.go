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
