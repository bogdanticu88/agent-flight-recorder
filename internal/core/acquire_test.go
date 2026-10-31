package core

import (
	"database/sql"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestMutationDuringAcquisitionIsRetriedAndReported(t *testing.T) {
	src := filepath.Join(t.TempDir(), "s.jsonl")
	writeFile(t, src, "one\n")
	n := 0
	acquireHook = func(p string) {
		n++
		if n == 1 { // writer appends once during the first copy
			f, _ := os.OpenFile(p, os.O_APPEND|os.O_WRONLY, 0)
			f.WriteString("two\n")
			f.Close()
		}
	}
	defer func() { acquireHook = nil }()
	ev, notes, err := acquireSet([]string{src}, []string{"main"}, t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if ev[0].Changed || ev[0].Size != 8 || !strings.Contains(strings.Join(notes, " "), "attempt 2") {
		t.Fatalf("expected a stable second attempt: %+v %v", ev, notes)
	}

	acquireHook = func(p string) { // writer never stops
		f, _ := os.OpenFile(p, os.O_APPEND|os.O_WRONLY, 0)
		f.WriteString("more\n")
		f.Close()
	}
	ev, notes, err = acquireSet([]string{src}, []string{"main"}, t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if !ev[0].Changed || !strings.Contains(strings.Join(notes, " "), "may be internally inconsistent") {
		t.Fatalf("continuous change not reported: %+v %v", ev, notes)
	}
}

func TestSQLiteWALIsAcquiredAndParsed(t *testing.T) {
	home := isolate(t)
	dir := filepath.Join(home, ".local", "share", "opencode")
	os.MkdirAll(dir, 0o755)
	dbp := filepath.Join(dir, "opencode.db")
	db, err := sql.Open("sqlite", "file:"+dbp+"?_pragma=journal_mode(WAL)&_pragma=wal_autocheckpoint(0)")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	for _, q := range []string{
		`CREATE TABLE session (id TEXT PRIMARY KEY, directory TEXT)`,
		`CREATE TABLE message (id TEXT PRIMARY KEY, session_id TEXT, data TEXT)`,
		`CREATE TABLE part (id TEXT PRIMARY KEY, message_id TEXT, session_id TEXT, data TEXT)`,
		`INSERT INTO session VALUES ('ses_w', '` + home + `')`,
		`INSERT INTO message VALUES ('m1','ses_w','{"role":"user","time":{"created":1793281800000}}')`,
		`INSERT INTO part VALUES ('p1','m1','ses_w','{"type":"text","text":"only in the WAL"}')`,
	} {
		if _, err := db.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	if st, err := os.Stat(dbp + "-wal"); err != nil || st.Size() == 0 {
		t.Skip("driver did not leave a WAL file; cannot exercise WAL acquisition")
	}
	p, _ := collectTo(t, CollectOptions{Roots: RootsFor(home), Agents: map[string]bool{"opencode": true}})
	evs, _, srcs, chk, _ := LoadBundle(p, DefaultBundleLimits)
	if !chk.OK() {
		t.Fatal(chk.Problems)
	}
	found := false
	for _, e := range evs {
		if strings.Contains(e.Text, "only in the WAL") {
			found = true
		}
	}
	if !found {
		t.Fatal("rows that exist only in the WAL were not read")
	}
	var roles []string
	for _, s := range srcs {
		if s.Parser == "opencode-db" {
			for _, f := range s.Files {
				roles = append(roles, f.Role)
				if f.SHA256 == "" {
					t.Error("sidecar without hash")
				}
			}
			mustContain(t, s.Note, "not an atomic snapshot")
		}
	}
	if !strings.Contains(strings.Join(roles, ","), "wal") {
		t.Fatalf("WAL not recorded as evidence: %v", roles)
	}
}

func TestDirectoryChildrenNewerThanDirectoryAreIncluded(t *testing.T) {
	home := isolate(t)
	st := filepath.Join(home, ".local", "share", "opencode", "storage")
	writeFile(t, filepath.Join(st, "message", "ses_d", "msg_1.json"), `{"id":"msg_1","sessionID":"ses_d","role":"user","time":{"created":1793281800000}}`)
	writeFile(t, filepath.Join(st, "part", "msg_1", "prt_1.json"), `{"id":"prt_1","type":"text","text":"child written later"}`)
	old := time.Now().Add(-30 * 24 * time.Hour)
	for _, d := range []string{st, filepath.Join(st, "message"), filepath.Join(st, "part")} {
		os.Chtimes(d, old, old)
	}
	p, _ := collectTo(t, CollectOptions{Roots: RootsFor(home), Agents: map[string]bool{"opencode": true},
		From: time.Now().Add(-24 * time.Hour).Add(-24 * 365 * time.Hour)})
	evs, _, srcs, _, _ := LoadBundle(p, DefaultBundleLimits)
	ok := false
	for _, e := range evs {
		if e.Text == "child written later" {
			ok = true
		}
	}
	if !ok {
		t.Fatal("directory mtime was used to skip newer children")
	}
	for _, s := range srcs {
		if s.Parser == "opencode-storage" && (len(s.Files) != 2 || s.SHA256 == "") {
			t.Fatalf("per-file evidence missing: %+v", s)
		}
	}
}

type failAfter struct {
	w io.Writer
	n int
}

func (f *failAfter) Write(p []byte) (int, error) {
	if f.n <= 0 {
		return 0, fmt.Errorf("disk full")
	}
	f.n -= len(p)
	return f.w.Write(p)
}

func TestFailedWritesAreFatalAndLeaveNoBundle(t *testing.T) {
	home := sampleHome(t)
	out := filepath.Join(t.TempDir(), "b.zip")
	zipWriterHook = func(w io.Writer) io.Writer { return &failAfter{w: w, n: 0} }
	defer func() { zipWriterHook = nil }()
	_, _, err := Collect(CollectOptions{Roots: RootsFor(home), Out: out})
	if err == nil || errors.Is(err, ErrPartial) {
		t.Fatalf("write failure must be fatal, got %v", err)
	}
	if _, serr := os.Stat(out); serr == nil {
		t.Fatal("a failed collection left a bundle behind")
	}
	left, _ := filepath.Glob(filepath.Join(filepath.Dir(out), ".afr-bundle-*"))
	if len(left) > 0 {
		t.Fatalf("temp files left behind: %v", left)
	}
	zipWriterHook = nil

	blocker := filepath.Join(t.TempDir(), "file")
	writeFile(t, blocker, "x")
	if _, _, err := Collect(CollectOptions{Roots: RootsFor(home), Out: filepath.Join(blocker, "b.zip")}); err == nil {
		t.Fatal("unwritable output must be fatal")
	}
}

func TestSnapshotBytesAreWhatGetsHashed(t *testing.T) {
	home := sampleHome(t)
	p, _ := collectTo(t, CollectOptions{Roots: RootsFor(home), IncludeRaw: true})
	_, _, srcs, _, _ := LoadBundle(p, DefaultBundleLimits)
	raw := map[string][]byte{}
	for _, e := range readZip(t, p) {
		raw[e.name] = e.data
	}
	for _, s := range srcs {
		if s.Parser != "claude-code" {
			continue
		}
		b, ok := raw["raw/"+rawName(s.Path)]
		if !ok {
			t.Fatalf("raw copy missing for %s", s.Path)
		}
		if sha(b) != s.SHA256 {
			t.Fatal("raw bytes in the bundle differ from the hashed acquisition")
		}
	}
}
