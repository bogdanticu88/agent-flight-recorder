package core

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const keyBody = "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn"

func privateKey(lines int) string {
	return "-----BEGIN OPENSSH PRIVATE KEY-----\n" + strings.Repeat(keyBody+"\n", lines) + "-----END OPENSSH PRIVATE KEY-----\n"
}

func TestPrivateKeyBeyondTruncationIsRedacted(t *testing.T) {
	home := isolate(t)
	p := filepath.Join(home, "p.json")
	writeFile(t, p, `{"max_text":512}`)
	t.Setenv("AFR_POLICY", p)
	payload, _ := json.Marshal(map[string]any{"hook_event_name": "PostToolUse", "session_id": "s", "tool_name": "Read",
		"tool_input": map[string]any{"file_path": "/x"}, "tool_response": privateKey(300)})
	RunHook("claude-code", "", strings.NewReader(string(payload)), RootsFor(home))
	b, _ := os.ReadFile(os.Getenv("AFR_LOG"))
	mustNotContain(t, string(b), keyBody[:40])
	mustNotContain(t, string(b), "BEGIN OPENSSH PRIVATE KEY")
	mustContain(t, string(b), "REDACTED:private-key")
}

func TestIncompleteKeyBlock(t *testing.T) {
	cut := privateKey(5)
	cut = cut[:len(cut)-40] // closing marker lost
	out, n := Redact("before\n" + cut)
	if n == 0 || strings.Contains(out, keyBody[:20]) || !strings.HasPrefix(out, "before") {
		t.Fatalf("incomplete key not handled: %q", out)
	}
}

func TestEscapedAndStructuredSecrets(t *testing.T) {
	cases := map[string]string{
		"json escaped newlines": `{"content":"-----BEGIN RSA PRIVATE KEY-----\nMIIEow` + keyBody + `\n-----END RSA PRIVATE KEY-----"}`,
		"escaped quotes":        `{\"token\": \"ghs_` + strings.Repeat("A", 36) + `\"}`,
		"secret key name":       `{"env":{"DB_PASSWORD":"correct-horse-battery"}}`,
		"nested json string":    `{"output":"{\"api_key\":\"zz-very-secret-value-123\"}"}`,
	}
	for name, in := range cases {
		out, n := RedactValue(in)
		if n == 0 {
			t.Errorf("%s: nothing redacted in %s", name, in)
		}
		for _, leak := range []string{"MIIEow", "AAAAAAAAAAAA", "correct-horse", "very-secret"} {
			if strings.Contains(out, leak) {
				t.Errorf("%s: leaked %q: %s", name, leak, out)
			}
		}
		if strings.HasPrefix(in, "{\"") {
			var v any
			if err := json.Unmarshal([]byte(out), &v); err != nil {
				t.Errorf("%s: redaction broke JSON: %s", name, out)
			}
		}
	}
	if out, n := RedactValue(`{"max_tokens":"4096","path":"/a"}`); n != 0 || out != `{"max_tokens":"4096","path":"/a"}` {
		t.Errorf("non-secret JSON must pass through unchanged, got %s", out)
	}
}

func TestEveryPersistedFieldIsRedacted(t *testing.T) {
	secret := "AKIAIOSFODNN7EXAMPLE"
	e := Event{Text: secret, Input: `{"x":"` + secret + `"}`, Command: "echo " + secret, Reason: "matched " + secret,
		Error: "failed for " + secret, Cwd: "/tmp/" + secret, SourceRef: "/t/" + secret, Paths: []string{"/p/" + secret}}
	RedactEvent(&e)
	b, _ := json.Marshal(e)
	mustNotContain(t, string(b), secret)
}

func TestOutOfWindowLiveContentIsNotExported(t *testing.T) {
	home := isolate(t)
	logp := os.Getenv("AFR_LOG")
	old := Event{TS: t0.Add(-48 * time.Hour), Agent: "claude-code", Origin: "live", SessionID: "old", Kind: KindPrompt, Text: "unrelated private conversation"}
	in := Event{TS: t0, Agent: "claude-code", Origin: "live", SessionID: "new", Kind: KindPrompt, Text: "fix the build"}
	later := Event{TS: t0.Add(48 * time.Hour), Agent: "claude-code", Origin: "live", SessionID: "later", Kind: KindPrompt, Text: "another private matter"}
	for _, e := range []*Event{&old, &in, &later} {
		if err := AppendLive(logp, e, ""); err != nil {
			t.Fatal(err)
		}
	}
	p, m := collectTo(t, CollectOptions{Roots: RootsFor(home), From: t0.Add(-time.Hour), To: t0.Add(time.Hour)})
	all := ""
	for _, e := range readZip(t, p) {
		all += string(e.data)
	}
	mustNotContain(t, all, "unrelated private conversation")
	mustNotContain(t, all, "another private matter")
	mustContain(t, all, "fix the build")
	if m.LiveLog.Mode != "excerpt" || m.LiveLog.InWindow != 1 || m.LiveLog.Records != 3 {
		t.Fatalf("live metadata: %+v", m.LiveLog)
	}
	evs, _, _, chk, _ := LoadBundle(p, DefaultBundleLimits)
	if !chk.OK() || chk.Live.Status != ChainExcerpt {
		t.Fatalf("excerpt must verify as an excerpt: %+v %+v", chk.Problems, chk.Live)
	}
	n := 0
	for _, e := range evs {
		if e.Origin == "live" {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("live record appears %d times", n)
	}

	// opting in exports everything, and says so
	p2, m2 := collectTo(t, CollectOptions{Roots: RootsFor(home), From: t0.Add(-time.Hour), To: t0.Add(time.Hour), FullLiveLog: true})
	all = ""
	for _, e := range readZip(t, p2) {
		all += string(e.data)
	}
	mustContain(t, all, "unrelated private conversation")
	if !m2.FullLiveLog || m2.LiveLog.Mode != "full" {
		t.Fatal("full live log not flagged in the manifest")
	}
}

func TestCollectorRedactsBeforeTruncating(t *testing.T) {
	home := isolate(t)
	claudeSession(t, home, "k", home, t0,
		map[string]any{"role": "assistant", "content": []any{map[string]any{"type": "tool_use", "id": "t1", "name": "Read", "input": map[string]any{"file_path": "/k"}}}},
		map[string]any{"role": "user", "content": []any{map[string]any{"type": "tool_result", "tool_use_id": "t1", "content": privateKey(400)}}},
	)
	p, _ := collectTo(t, CollectOptions{Roots: RootsFor(home), MaxField: 300})
	for _, e := range readZip(t, p) {
		mustNotContain(t, string(e.data), keyBody[:40])
	}
}
