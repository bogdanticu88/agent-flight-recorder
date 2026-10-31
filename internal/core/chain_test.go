package core

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// chainedLog writes n records through AppendLive and returns the path and lines.
func chainedLog(t *testing.T, n int) (string, []string) {
	t.Helper()
	p := filepath.Join(t.TempDir(), "events.jsonl")
	for i := 0; i < n; i++ {
		e := Event{TS: t0, Agent: "claude-code", Origin: "live", SessionID: "s", Kind: KindToolCall, Tool: "Read", Input: `{"n":` + string(rune('0'+i)) + `}`}
		if err := AppendLive(p, &e, ""); err != nil {
			t.Fatal(err)
		}
	}
	b, _ := os.ReadFile(p)
	return p, strings.Split(strings.TrimRight(string(b), "\n"), "\n")
}

func rewrite(t *testing.T, p string, lines []string) {
	t.Helper()
	if err := os.WriteFile(p, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestChainStates(t *testing.T) {
	p, lines := chainedLog(t, 5)
	if _, rep := ReadLiveLog(p); rep.Status != ChainConsistent || rep.Records != 5 {
		t.Fatalf("fresh log: %+v", rep)
	}
	mustContain(t, func() string { _, r := ReadLiveLog(p); return r.Detail }(), "independently kept checkpoint")

	cases := map[string]struct {
		lines []string
		want  string
	}{
		"edited":            {append(append([]string{}, lines[:2]...), append([]string{strings.Replace(lines[2], `"Read"`, `"Write"`, 1)}, lines[3:]...)...), ChainBroken},
		"interior deletion": {append(append([]string{}, lines[:2]...), lines[3:]...), ChainBroken},
		"prefix deletion":   {lines[2:], ChainUnanchored},
		"malformed line":    {append(append([]string{}, lines[:2]...), append([]string{"{oops"}, lines[2:]...)...), ChainInvalid},
		"reordered":         {[]string{lines[0], lines[2], lines[1], lines[3], lines[4]}, ChainBroken},
	}
	for name, c := range cases {
		q := filepath.Join(t.TempDir(), "l.jsonl")
		rewrite(t, q, c.lines)
		if _, rep := ReadLiveLog(q); rep.Status != c.want {
			t.Errorf("%s: want %s, got %s (%s)", name, c.want, rep.Status, rep.Detail)
		}
	}
}

func TestTailDeletionNeedsCheckpoint(t *testing.T) {
	p, lines := chainedLog(t, 5)
	_, full := ReadLiveLog(p)
	cp := Checkpoint{Records: 5, Hash: full.HeadHash}

	rewrite(t, p, lines[:3]) // newest two records removed
	evs, rep := ReadLiveLog(p)
	if rep.Status != ChainConsistent {
		t.Fatalf("without a checkpoint tail deletion is not detectable, and the report must not claim otherwise: %s", rep.Status)
	}
	ApplyCheckpoint(evs, &rep, cp)
	if rep.Status != ChainBroken || !strings.Contains(rep.Checkpoint, "removed from the end") {
		t.Fatalf("checkpoint must catch tail deletion: %+v", rep)
	}

	// full rewrite: rebuild a consistent chain with different content
	q := filepath.Join(t.TempDir(), "rebuilt.jsonl")
	for i := 0; i < 5; i++ {
		e := Event{TS: t0, Agent: "claude-code", Origin: "live", SessionID: "s", Kind: KindOther, Text: "innocent"}
		if err := AppendLive(q, &e, ""); err != nil {
			t.Fatal(err)
		}
	}
	evs, rep = ReadLiveLog(q)
	if rep.Status != ChainConsistent {
		t.Fatal("a rebuilt chain is internally consistent; that is the documented limit")
	}
	ApplyCheckpoint(evs, &rep, cp)
	if rep.Status != ChainBroken || !strings.Contains(rep.Checkpoint, "rewritten") {
		t.Fatalf("checkpoint must catch a rebuilt chain: %+v", rep)
	}
}

func TestMissingUnreadableEmpty(t *testing.T) {
	if _, rep := ReadLiveLog(filepath.Join(t.TempDir(), "nope.jsonl")); rep.Status != ChainMissing || rep.OK() {
		t.Fatalf("missing: %+v", rep)
	}
	if _, rep := ReadLiveLog(t.TempDir()); rep.Status != ChainUnreadable || rep.OK() {
		t.Fatalf("directory: %+v", rep)
	}
	e := filepath.Join(t.TempDir(), "e.jsonl")
	writeFile(t, e, "")
	if _, rep := ReadLiveLog(e); rep.Status != ChainEmpty {
		t.Fatalf("empty: %+v", rep)
	}
}

type failingReader struct{ r io.Reader }

func (f failingReader) Read(p []byte) (int, error) {
	n, err := f.r.Read(p)
	if err == io.EOF {
		return n, errors.New("disk error")
	}
	return n, err
}

func TestScannerErrorIsUnreadable(t *testing.T) {
	p, _ := chainedLog(t, 2)
	b, _ := os.ReadFile(p)
	_, rep := VerifyLiveLog(failingReader{bytes.NewReader(b)})
	if rep.Status != ChainUnreadable {
		t.Fatalf("read error must surface, got %+v", rep)
	}
}

func TestPositionsDoNotAlterHashes(t *testing.T) {
	p, _ := chainedLog(t, 3)
	evs, _ := ReadLiveLog(p)
	for i, e := range evs {
		if e.Pos != i+1 || e.Prov != p {
			t.Fatalf("display metadata not set: %+v", e)
		}
		if e.ComputeHash() != e.Hash {
			t.Fatal("display metadata changed the hashed content")
		}
	}
}

func TestExcerptVerification(t *testing.T) {
	p, lines := chainedLog(t, 5)
	_, full := ReadLiveLog(p)
	hdr := `{"afr_excerpt":{"version":1,"source_path":"x","source_sha256":"y","source_records":5,"source_head_hash":"` + full.HeadHash + `","source_status":"consistent","records":2}}`
	q := filepath.Join(t.TempDir(), "ex.jsonl")
	rewrite(t, q, []string{hdr, lines[1], lines[3]})
	_, rep := ReadLiveLog(q)
	if rep.Status != ChainExcerpt || !rep.OK() {
		t.Fatalf("excerpt: %+v", rep)
	}
	mustContain(t, rep.Detail, "predecessor is external")

	rewrite(t, q, []string{hdr, lines[1], strings.Replace(lines[3], `"Read"`, `"Write"`, 1)})
	if _, rep := ReadLiveLog(q); rep.Status != ChainBroken {
		t.Fatalf("edited excerpt record: %+v", rep)
	}
	rewrite(t, q, []string{hdr, lines[1]})
	if _, rep := ReadLiveLog(q); rep.Status != ChainBroken {
		t.Fatalf("excerpt with a missing record: %+v", rep)
	}
}

func TestAppendRefusesUnparseableTail(t *testing.T) {
	p, lines := chainedLog(t, 2)
	rewrite(t, p, append(lines, "garbage"))
	e := Event{TS: t0, Agent: "codex", Origin: "live", Kind: KindOther}
	if err := AppendLive(p, &e, ""); err == nil {
		t.Fatal("appending after a corrupt tail would fork the chain silently")
	}
}

func TestCheckpointParsing(t *testing.T) {
	if _, err := ParseCheckpoint("3:abc"); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"", "abc", "0:abc", "x:abc", "3:"} {
		if _, err := ParseCheckpoint(bad); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
}
