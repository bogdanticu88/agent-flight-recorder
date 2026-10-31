//go:build !windows

package core

import (
	"errors"
	"path/filepath"
	"syscall"
	"testing"
)

func TestUnreadableSourceMakesCollectionPartial(t *testing.T) {
	home := isolate(t)
	claudeSession(t, home, "ok", home, t0, map[string]any{"role": "user", "content": "hello"})
	fifo := filepath.Join(home, ".claude", "projects", "proj", "pipe.jsonl")
	if err := syscall.Mkfifo(fifo, 0o644); err != nil {
		t.Skip("mkfifo unavailable:", err)
	}
	out := filepath.Join(t.TempDir(), "b.zip")
	_, m, err := Collect(CollectOptions{Roots: RootsFor(home), Out: out})
	if !errors.Is(err, ErrPartial) || m.Status != "partial" || m.SourceErrors != 1 {
		t.Fatalf("want partial with one source error, got err=%v status=%s errors=%d", err, m.Status, m.SourceErrors)
	}
	if chk := check(t, out); !chk.OK() || chk.ParseIssues == 0 {
		t.Fatalf("a partial bundle is still a valid bundle and must report its gaps: %+v", chk)
	}
}
