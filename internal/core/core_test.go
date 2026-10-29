package core

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRedact(t *testing.T) {
	in := `token=AKCp8x7Rk2Qm9x7Rk2Qm9x7Rk2Qm9x7Rk2Qm9x7Rk2Qm9x7Rk2Qm9x7Rk2Qm9x7Rk2Qm9 ghp_abcdefghijklmnopqrstuvwxyz0123456789 Authorization: Bearer abcdefghijklmnop1234 https://bob:hunter22@example.com password: "s3cretValue"`
	out, n := Redact(in)
	for _, leak := range []string{"AKCp8x7R", "ghp_abc", "abcdefghijklmnop1234", "hunter22", "s3cretValue"} {
		if strings.Contains(out, leak) {
			t.Errorf("leaked %q in %s", leak, out)
		}
	}
	if n < 5 {
		t.Errorf("expected >=5 redactions, got %d: %s", n, out)
	}
}

func TestNormaliseAndChain(t *testing.T) {
	dir := t.TempDir()
	log := filepath.Join(dir, "events.jsonl")
	payloads := []struct{ agent, event, body string }{
		{"copilot", "preToolUse", `{"sessionId":"s1","toolName":"read_file","toolArgs":"{\"filePath\":\"/x/secret.txt\"}"}`},
		{"claude-code", "", `{"hook_event_name":"PreToolUse","session_id":"s2","tool_name":"Bash","tool_input":{"command":"cat ~/.ssh/id_rsa"}}`},
		{"cursor", "", `{"hook_event_name":"beforeReadFile","conversation_id":"s3","file_path":"/x/y.env"}`},
		{"gemini-cli", "", `{"hook_event_name":"BeforeTool","session_id":"s4","tool_name":"read_file","tool_input":{"absolute_path":"/x/z"}}`},
	}
	for _, p := range payloads {
		e, err := NormaliseHook(p.agent, p.event, []byte(p.body), Policy{})
		if err != nil {
			t.Fatal(err)
		}
		if e.Kind != KindToolCall || e.SessionID == "" || len(e.Paths) == 0 {
			t.Errorf("%s: bad normalisation %+v", p.agent, e)
		}
		if err := AppendLive(log, &e); err != nil {
			t.Fatal(err)
		}
	}
	if _, rep := ReadLiveLog(log); rep.Status != "intact" || rep.Records != 4 {
		t.Fatalf("chain: %+v", rep)
	}
	b, _ := os.ReadFile(log)
	os.WriteFile(log, []byte(strings.Replace(string(b), "secret.txt", "public.txt", 1)), 0o600)
	if _, rep := ReadLiveLog(log); rep.Status != "broken" {
		t.Fatalf("tampering not detected: %+v", rep)
	}
}

func TestDenyOnlyOnPreEvents(t *testing.T) {
	dir := t.TempDir()
	os.Setenv("AFR_LOG", filepath.Join(dir, "l.jsonl"))
	pol := filepath.Join(dir, "p.json")
	os.WriteFile(pol, []byte(`{"rules":[{"pattern":"**/.ssh/**","action":"deny","label":"ssh"}]}`), 0o600)
	os.Setenv("AFR_POLICY", pol)
	defer os.Unsetenv("AFR_LOG")
	defer os.Unsetenv("AFR_POLICY")
	pre := RunHook("claude-code", "", strings.NewReader(`{"hook_event_name":"PreToolUse","tool_name":"Read","tool_input":{"file_path":"/h/.ssh/id"}}`), RootsFor(dir))
	if !strings.Contains(pre.Stdout, `"deny"`) {
		t.Errorf("expected deny, got %+v", pre)
	}
	post := RunHook("claude-code", "", strings.NewReader(`{"hook_event_name":"PostToolUse","tool_name":"Read","tool_input":{"file_path":"/h/.ssh/id"}}`), RootsFor(dir))
	if post.ExitCode != 0 || strings.Contains(post.Stdout, "deny") {
		t.Errorf("post event must not deny: %+v", post)
	}
}
