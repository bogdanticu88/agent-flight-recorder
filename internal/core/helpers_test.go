package core

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// writeFile creates parent directories and writes data.
func writeFile(t *testing.T, p string, data string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(data), 0o644); err != nil {
		t.Fatal(err)
	}
}

func jsonl(t *testing.T, rows ...map[string]any) string {
	t.Helper()
	var b strings.Builder
	for _, r := range rows {
		j, err := json.Marshal(r)
		if err != nil {
			t.Fatal(err)
		}
		b.Write(j)
		b.WriteByte('\n')
	}
	return b.String()
}

// claudeSession writes a minimal Claude Code transcript into home and returns its path.
func claudeSession(t *testing.T, home, sid, cwd string, ts time.Time, msgs ...map[string]any) string {
	t.Helper()
	var rows []map[string]any
	for i, m := range msgs {
		rows = append(rows, map[string]any{"sessionId": sid, "cwd": cwd, "type": m["role"],
			"timestamp": ts.Add(time.Duration(i) * time.Second).Format(time.RFC3339), "message": m})
	}
	p := filepath.Join(home, ".claude", "projects", "proj", sid+".jsonl")
	writeFile(t, p, jsonl(t, rows...))
	return p
}

// isolate gives a test its own profile, live log and empty machine policy dir.
func isolate(t *testing.T) (home string) {
	t.Helper()
	home = t.TempDir()
	// the collector ignores AFR_LOG, so the test log has to sit at the
	// default location for this OS (LOCALAPPDATA on Windows)
	t.Setenv("AFR_LOG", filepath.Join(userStateDir(RootsFor(home)), "events.jsonl"))
	t.Setenv("AFR_POLICY", "")
	md := t.TempDir()
	old := machineDirOverride
	machineDirOverride = md
	t.Cleanup(func() { machineDirOverride = old })
	return home
}

func mustContain(t *testing.T, hay, needle string) {
	t.Helper()
	if !strings.Contains(hay, needle) {
		t.Errorf("expected %q in:\n%s", needle, hay)
	}
}

func mustNotContain(t *testing.T, hay, needle string) {
	t.Helper()
	if strings.Contains(hay, needle) {
		t.Errorf("did not expect %q in:\n%s", needle, hay)
	}
}

var t0 = time.Date(2026, 10, 29, 13, 40, 0, 0, time.UTC)

func call(pos int, id, tool string, input map[string]any) Event {
	b, _ := json.Marshal(input)
	return Event{Pos: pos, Agent: "test", Origin: "offline", SessionID: "s", Source: "src", Kind: KindToolCall, Tool: tool, CallID: id, Input: string(b),
		Command: CommandFrom(input), Paths: ExtractPaths(input, ""), TS: t0.Add(time.Duration(pos) * time.Second)}
}

func result(pos int, id, status, text string) Event {
	return Event{Pos: pos, Agent: "test", Origin: "offline", SessionID: "s", Source: "src", Kind: KindToolResult, CallID: id, Status: status, Text: text,
		Paths: ExtractPaths(nil, text), TS: t0.Add(time.Duration(pos) * time.Second)}
}

func prompt(pos int, text string) Event {
	return Event{Pos: pos, Agent: "test", Origin: "offline", SessionID: "s", Source: "src", Kind: KindPrompt, Text: text, TS: t0.Add(time.Duration(pos) * time.Second)}
}

func sha(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}
