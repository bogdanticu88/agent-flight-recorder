package core

import (
	"database/sql"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestSymlinkedSourceOutsideProfileIsNotFollowed(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation needs privileges on Windows")
	}
	home := isolate(t)
	outside := filepath.Join(t.TempDir(), "secret.jsonl")
	writeFile(t, outside, `{"type":"user","sessionId":"x","message":{"role":"user","content":"PRIVILEGED CONTENT"}}`+"\n")
	link := filepath.Join(home, ".claude", "projects", "p", "evil.jsonl")
	os.MkdirAll(filepath.Dir(link), 0o755)
	if err := os.Symlink(outside, link); err != nil {
		t.Skip(err)
	}
	p, m := collectTo(t, CollectOptions{Roots: RootsFor(home)})
	for _, e := range readZip(t, p) {
		mustNotContain(t, string(e.data), "PRIVILEGED CONTENT")
	}
	mustContain(t, strings.Join(m.Skipped, "\n"), "outside the acquisition roots")
}

func TestWorkspaceOutsideRootsIsSkipped(t *testing.T) {
	home := isolate(t)
	elsewhere := t.TempDir()
	writeFile(t, filepath.Join(elsewhere, "AGENTS.md"), "OUTSIDE INSTRUCTIONS")
	inside := filepath.Join(home, "src", "repo")
	writeFile(t, filepath.Join(inside, "AGENTS.md"), "INSIDE INSTRUCTIONS")
	claudeSession(t, home, "a", elsewhere, t0, map[string]any{"role": "user", "content": "hi"})
	claudeSession(t, home, "b", inside, t0, map[string]any{"role": "user", "content": "hi"})
	p, m := collectTo(t, CollectOptions{Roots: RootsFor(home)})
	all := ""
	for _, e := range readZip(t, p) {
		all += string(e.data)
	}
	mustContain(t, all, "INSIDE INSTRUCTIONS")
	mustNotContain(t, all, "OUTSIDE INSTRUCTIONS")
	mustContain(t, strings.Join(m.Skipped, "\n"), elsewhere)
}

func TestSymlinkedInstructionFileEscapeIsSkipped(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation needs privileges on Windows")
	}
	home := isolate(t)
	target := filepath.Join(t.TempDir(), "shadow")
	writeFile(t, target, "root:SECRETHASH")
	ws := filepath.Join(home, "repo")
	os.MkdirAll(ws, 0o755)
	if err := os.Symlink(target, filepath.Join(ws, "AGENTS.md")); err != nil {
		t.Skip(err)
	}
	claudeSession(t, home, "s", ws, t0, map[string]any{"role": "user", "content": "hi"})
	p, _ := collectTo(t, CollectOptions{Roots: RootsFor(home)})
	for _, e := range readZip(t, p) {
		mustNotContain(t, string(e.data), "SECRETHASH")
	}
}

func TestMountedImagePathMapping(t *testing.T) {
	root := t.TempDir()
	s := Scope{Root: root}
	for in, want := range map[string]string{
		`C:\Users\jdoe\src\app`: filepath.Join(root, "Users", "jdoe", "src", "app"),
		"/home/dev/src/app":     filepath.Join(root, "home", "dev", "src", "app"),
	} {
		got, err := s.MapPath(in)
		if err != nil || got != want {
			t.Errorf("%s -> %s (%v), want %s", in, got, err, want)
		}
	}
	for _, bad := range []string{`\\server\share\x`, "relative/dir", ""} {
		if _, err := s.MapPath(bad); err == nil {
			t.Errorf("%q mapped without a defined location", bad)
		}
	}

	// end to end: a Windows-style cwd recorded in the image resolves inside it
	home := filepath.Join(root, "Users", "jdoe")
	repo := filepath.Join(home, "src", "app")
	writeFile(t, filepath.Join(repo, "AGENTS.md"), "IMAGE INSTRUCTIONS")
	t.Setenv("AFR_LOG", filepath.Join(t.TempDir(), "none.jsonl"))
	claudeSession(t, home, "img", `C:\Users\jdoe\src\app`, t0, map[string]any{"role": "user", "content": "hi"})
	p, m := collectTo(t, CollectOptions{Roots: RootsFor(home), Root: root, SourceHost: "LAPTOP-7"})
	all := ""
	for _, e := range readZip(t, p) {
		all += string(e.data)
	}
	mustContain(t, all, "IMAGE INSTRUCTIONS")
	if m.SourceHost != "LAPTOP-7" || m.Root != root {
		t.Fatalf("image provenance not recorded: %+v", m)
	}
}

func TestOpLogIndicesAreValidated(t *testing.T) {
	home := isolate(t)
	p := filepath.Join(home, ".config", "Code", "User", "workspaceStorage", "w", "chatSessions", "s.jsonl")
	writeFile(t, p, jsonl(t,
		map[string]any{"kind": 0, "v": map[string]any{"sessionId": "s", "requests": []any{}}},
		map[string]any{"kind": 1, "k": []any{"requests", -1}, "v": 1},
		map[string]any{"kind": 1, "k": []any{"requests", 1e15}, "v": 1},
		map[string]any{"kind": 2, "k": []any{"requests"}, "v": []any{}, "i": 1e12},
		map[string]any{"kind": 2, "k": []any{"requests"}, "v": []any{map[string]any{"requestId": "r", "message": map[string]any{"text": "still parsed"}}}},
	))
	res, err := ParseSource(Source{Agent: "copilot-vscode", Parser: "vscode-chat", Path: p})
	if err != nil {
		t.Fatal(err)
	}
	if res.Malformed != 3 {
		t.Fatalf("want 3 rejected operations, got %d (%v)", res.Malformed, res.Diags)
	}
	if len(res.Events) == 0 || res.Events[0].Text != "still parsed" {
		t.Fatalf("valid operations after invalid ones must still apply: %+v", res.Events)
	}
}

func TestDeepJSONDoesNotRecurseUnbounded(t *testing.T) {
	home := isolate(t)
	deep := strings.Repeat(`{"a":`, 5000) + `"x"` + strings.Repeat("}", 5000)
	p := filepath.Join(home, ".gemini", "tmp", "h", "chats", "session-deep.json")
	writeFile(t, p, deep)
	res, _ := ParseSource(Source{Agent: "gemini-cli", Parser: "gemini", Path: p})
	_ = res // must return without stack exhaustion
	out, _ := RedactValue(deep)
	if out == "" {
		t.Fatal("redaction returned nothing")
	}
}

func TestMalformedJSONLIsCounted(t *testing.T) {
	home := isolate(t)
	p := filepath.Join(home, ".claude", "projects", "p", "s.jsonl")
	writeFile(t, p, `{"type":"user","sessionId":"s","message":{"role":"user","content":"ok"}}`+"\n{broken\n[1,2]\n")
	res, err := ParseSource(Source{Agent: "claude-code", Parser: "claude-code", Path: p})
	if err != nil {
		t.Fatal(err)
	}
	if res.Malformed != 2 || len(res.Diags) != 2 || len(res.Events) != 1 {
		t.Fatalf("malformed lines must be counted, got %+v", res)
	}
}

func TestUnusualSQLiteIdentifiers(t *testing.T) {
	home := isolate(t)
	dbp := filepath.Join(home, ".local", "share", "opencode", "odd.db")
	os.MkdirAll(filepath.Dir(dbp), 0o755)
	db, err := sql.Open("sqlite", "file:"+dbp)
	if err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{
		`CREATE TABLE "we""ird; DROP TABLE x; --" ("col ""q""" TEXT)`,
		`INSERT INTO "we""ird; DROP TABLE x; --" VALUES ('{"role":"user","content":"from odd table"}')`,
		`CREATE TABLE nr (k TEXT PRIMARY KEY, v TEXT) WITHOUT ROWID`,
		`INSERT INTO nr VALUES ('a','{"role":"user","content":"from without-rowid"}')`,
	} {
		if _, err := db.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	db.Close()
	res, err := ParseSource(Source{Agent: "opencode", Parser: "opencode-db", Path: dbp})
	if err != nil {
		t.Fatal(err)
	}
	got := ""
	for _, e := range res.Events {
		got += e.Text + "|"
	}
	mustContain(t, got, "from odd table")
	mustContain(t, got, "from without-rowid")
}
