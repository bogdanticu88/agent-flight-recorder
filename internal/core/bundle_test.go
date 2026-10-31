package core

import (
	"archive/zip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func sampleHome(t *testing.T) string {
	home := isolate(t)
	claudeSession(t, home, "sess-1", home, t0,
		map[string]any{"role": "user", "content": "please fix the tests"},
		map[string]any{"role": "assistant", "content": []any{map[string]any{"type": "tool_use", "id": "t1", "name": "Read", "input": map[string]any{"file_path": "/w/main.go"}}}},
		map[string]any{"role": "user", "content": []any{map[string]any{"type": "tool_result", "tool_use_id": "t1", "content": "package main"}}},
	)
	return home
}

func collectTo(t *testing.T, o CollectOptions) (string, *Manifest) {
	t.Helper()
	if o.Out == "" {
		o.Out = filepath.Join(t.TempDir(), "b.zip")
	}
	if o.Roots.Home == "" {
		t.Fatal("no home")
	}
	_, m, err := Collect(o)
	if err != nil && !errors.Is(err, ErrPartial) {
		t.Fatal(err)
	}
	return o.Out, m
}

type entry struct {
	name string
	data []byte
}

func readZip(t *testing.T, p string) []entry {
	t.Helper()
	zr, err := zip.OpenReader(p)
	if err != nil {
		t.Fatal(err)
	}
	defer zr.Close()
	var out []entry
	for _, f := range zr.File {
		rc, _ := f.Open()
		b, _ := io.ReadAll(rc)
		rc.Close()
		out = append(out, entry{f.Name, b})
	}
	return out
}

func writeZip(t *testing.T, p string, es []entry) {
	t.Helper()
	f, err := os.Create(p)
	if err != nil {
		t.Fatal(err)
	}
	zw := zip.NewWriter(f)
	for _, e := range es {
		w, err := zw.CreateHeader(&zip.FileHeader{Name: e.name, Method: zip.Deflate})
		if err != nil {
			t.Fatal(err)
		}
		w.Write(e.data)
	}
	zw.Close()
	f.Close()
}

func check(t *testing.T, p string) BundleCheck {
	t.Helper()
	_, _, _, chk, err := LoadBundle(p, DefaultBundleLimits)
	if err != nil {
		t.Fatal(err)
	}
	return chk
}

func TestValidBundleVerifies(t *testing.T) {
	home := sampleHome(t)
	p, m := collectTo(t, CollectOptions{Roots: RootsFor(home)})
	chk := check(t, p)
	if !chk.OK() {
		t.Fatalf("fresh bundle failed: %+v", chk.Problems)
	}
	if m.Events != 3 || m.Status != "complete" {
		t.Fatalf("manifest: %+v", m)
	}
	mustContain(t, chk.Origin, "do not show who produced it")
}

func TestEmptyCollectionIsStillValid(t *testing.T) {
	home := isolate(t)
	p, m := collectTo(t, CollectOptions{Roots: RootsFor(home)})
	if m.Events != 0 {
		t.Fatal("expected no events")
	}
	if chk := check(t, p); !chk.OK() {
		t.Fatalf("empty but well-formed bundle must verify: %v", chk.Problems)
	}
}

func TestManifestOnlyBundleRejected(t *testing.T) {
	p := filepath.Join(t.TempDir(), "m.zip")
	writeZip(t, p, []entry{{"manifest.json", []byte("{}")}})
	if chk := check(t, p); chk.OK() || len(chk.Problems) == 0 {
		t.Fatal("manifest-only bundle accepted")
	}
}

func TestBundleTampering(t *testing.T) {
	home := sampleHome(t)
	good, _ := collectTo(t, CollectOptions{Roots: RootsFor(home)})
	orig := readZip(t, good)

	mutate := func(name string, f func([]entry) []entry) {
		t.Run(name, func(t *testing.T) {
			p := filepath.Join(t.TempDir(), "x.zip")
			writeZip(t, p, f(append([]entry{}, orig...)))
			chk := check(t, p)
			if chk.OK() {
				t.Fatalf("%s accepted", name)
			}
		})
	}
	mutate("missing events.jsonl", func(es []entry) []entry {
		var out []entry
		for _, e := range es {
			if e.name != "events.jsonl" {
				out = append(out, e)
			}
		}
		return out
	})
	mutate("duplicate entry", func(es []entry) []entry { return append(es, es[0]) })
	mutate("corrupt content", func(es []entry) []entry {
		for i := range es {
			if es[i].name == "events.jsonl" {
				es[i].data = []byte(strings.Replace(string(es[i].data), "please fix", "please hack", 1))
			}
		}
		return es
	})
	mutate("extra unlisted entry", func(es []entry) []entry { return append(es, entry{"notes.txt", []byte("x")}) })
	mutate("path traversal name", func(es []entry) []entry { return append(es, entry{"../evil", []byte("x")}) })
	mutate("malformed jsonl with consistent hashes", func(es []entry) []entry {
		// rewrite events.jsonl with a broken line AND fix up the manifest hash,
		// as someone forging a bundle would
		var man Manifest
		for _, e := range es {
			if e.name == "manifest.json" {
				json.Unmarshal(e.data, &man)
			}
		}
		for i := range es {
			if es[i].name == "events.jsonl" {
				es[i].data = append(es[i].data, []byte("{not an event\n")...)
				s := sha256.Sum256(es[i].data)
				man.Entries["events.jsonl"] = hex.EncodeToString(s[:])
			}
		}
		for i := range es {
			if es[i].name == "manifest.json" {
				es[i].data, _ = json.Marshal(man)
			}
		}
		return es
	})
	mutate("legacy manifest", func(es []entry) []entry {
		for i := range es {
			if es[i].name == "manifest.json" {
				var raw map[string]any
				json.Unmarshal(es[i].data, &raw)
				delete(raw, "format")
				es[i].data, _ = json.Marshal(raw)
			}
		}
		return es
	})

	// sidecar mismatch
	p := filepath.Join(t.TempDir(), "s.zip")
	writeZip(t, p, orig)
	writeFile(t, p+".sha256", strings.Repeat("0", 64)+"  s.zip\n")
	if check(t, p).ChecksumConsistent {
		t.Fatal("sidecar mismatch not reported")
	}
}

func TestBundleSizeLimits(t *testing.T) {
	home := sampleHome(t)
	p, _ := collectTo(t, CollectOptions{Roots: RootsFor(home)})
	for name, lim := range map[string]BundleLimits{
		"entries":   {MaxEntries: 2, MaxEntryBytes: 1 << 30, MaxTotalBytes: 1 << 30},
		"per-entry": {MaxEntries: 1000, MaxEntryBytes: 10, MaxTotalBytes: 1 << 30},
		"total":     {MaxEntries: 1000, MaxEntryBytes: 1 << 30, MaxTotalBytes: 100},
	} {
		_, _, _, chk, err := LoadBundle(p, lim)
		if err != nil || chk.OK() {
			t.Errorf("%s limit not enforced (err=%v)", name, err)
		}
	}
}

func TestEmbeddedChainMetadataMustMatch(t *testing.T) {
	home := sampleHome(t)
	ev := Event{TS: t0, Agent: "claude-code", Origin: "live", SessionID: "L", Kind: KindToolCall, Tool: "Read"}
	if err := AppendLive(os.Getenv("AFR_LOG"), &ev, ""); err != nil {
		t.Fatal(err)
	}
	p, m := collectTo(t, CollectOptions{Roots: RootsFor(home), FullLiveLog: true})
	if m.LiveLog == nil || m.LiveLog.Mode != "full" {
		t.Fatalf("live log not captured: %+v", m.LiveLog)
	}
	if chk := check(t, p); !chk.OK() || chk.Live == nil || chk.Live.Status != ChainConsistent {
		t.Fatalf("live chain not recomputed: %+v", chk)
	}
	// claim a different record count in the manifest, keeping hashes consistent
	es := readZip(t, p)
	for i := range es {
		if es[i].name == "manifest.json" {
			var mm Manifest
			json.Unmarshal(es[i].data, &mm)
			mm.LiveLog.Records = 99
			mm.LiveLog.Status = ChainConsistent
			es[i].data, _ = json.Marshal(mm)
		}
	}
	q := filepath.Join(t.TempDir(), "x.zip")
	writeZip(t, q, es)
	chk := check(t, q)
	if chk.OK() {
		t.Fatal("manifest live metadata that disagrees with the captured log was accepted")
	}
}
