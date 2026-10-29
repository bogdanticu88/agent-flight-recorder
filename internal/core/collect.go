package core

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"
)

// CollectOptions controls an offline evidence collection.
type CollectOptions struct {
	Roots      Roots
	Agents     map[string]bool
	From, To   time.Time // zero = unbounded
	Out        string    // bundle path (.zip)
	IncludeRaw bool      // also copy raw source files (unredacted). SOC use only.
	NoRedact   bool
	Mode       string // soc | user
	CaseID     string
	Workspaces []string
	Log        io.Writer
}

// Manifest describes a bundle: who/where/when, what was found, and hashes.
type Manifest struct {
	Tool           string            `json:"tool"`
	Version        string            `json:"version"`
	CaseID         string            `json:"case_id,omitempty"`
	Mode           string            `json:"mode"`
	ModeNote       string            `json:"mode_note"`
	Host           string            `json:"host"`
	User           string            `json:"user"`
	OS             string            `json:"os"`
	Home           string            `json:"home"`
	Started        time.Time         `json:"collection_started"`
	Finished       time.Time         `json:"collection_finished"`
	WindowFrom     *time.Time        `json:"window_from,omitempty"`
	WindowTo       *time.Time        `json:"window_to,omitempty"`
	Redacted       bool              `json:"redacted"`
	RedactionCount int               `json:"redaction_count"`
	RawIncluded    bool              `json:"raw_included"`
	Sources        int               `json:"sources_found"`
	Events         int               `json:"events_in_window"`
	Sessions       int               `json:"sessions_in_window"`
	Agents         map[string]int    `json:"events_per_agent"`
	LiveChain      *ChainReport      `json:"live_chain,omitempty"`
	Entries        map[string]string `json:"entry_sha256"`
}

func (o CollectOptions) inWindow(t time.Time) bool {
	if t.IsZero() {
		return true
	}
	if !o.From.IsZero() && t.Before(o.From) {
		return false
	}
	if !o.To.IsZero() && t.After(o.To) {
		return false
	}
	return true
}

func logf(w io.Writer, f string, a ...any) {
	if w != nil {
		fmt.Fprintf(w, f+"\n", a...)
	}
}

// Collect runs discovery, parsing, redaction and packaging.
func Collect(o CollectOptions) (string, *Manifest, error) {
	var logBuf bytes.Buffer
	lw := io.MultiWriter(&logBuf, nonNil(o.Log))
	host, _ := os.Hostname()
	uname := ""
	if u, err := user.Current(); err == nil {
		uname = u.Username
	}
	m := &Manifest{Tool: "afr (Agent Flight Recorder)", Version: Version, CaseID: o.CaseID, Mode: o.Mode,
		Host: host, User: uname, OS: runtime.GOOS + "/" + runtime.GOARCH, Home: o.Roots.Home,
		Started: time.Now().UTC(), Redacted: !o.NoRedact, RawIncluded: o.IncludeRaw, Agents: map[string]int{},
		Entries: map[string]string{}}
	switch o.Mode {
	case "soc":
		m.ModeNote = "Collected by SOC (e.g. Defender Live Response). User did not handle the evidence."
	default:
		m.Mode = "user"
		m.ModeNote = "Collected by the end user. The user is part of the events under review; treat as lower assurance and corroborate with EDR telemetry."
	}
	if !o.From.IsZero() {
		f := o.From.UTC()
		m.WindowFrom = &f
	}
	if !o.To.IsZero() {
		t := o.To.UTC()
		m.WindowTo = &t
	}

	f, err := os.Create(o.Out)
	if err != nil {
		return "", nil, err
	}
	zw := zip.NewWriter(f)
	put := func(name string, data []byte) error {
		w, err := zw.CreateHeader(&zip.FileHeader{Name: name, Method: zip.Deflate, Modified: time.Now()})
		if err != nil {
			return err
		}
		if _, err := w.Write(data); err != nil {
			return err
		}
		s := sha256.Sum256(data)
		m.Entries[name] = hex.EncodeToString(s[:])
		return nil
	}

	logf(lw, "afr %s collecting from %s (mode=%s)", Version, o.Roots.Home, m.Mode)
	sources := Discover(o.Roots, o.Agents)
	m.Sources = len(sources)
	logf(lw, "discovered %d artifact(s)", len(sources))

	var all []Event
	cwds := map[string]bool{}
	for _, ws := range o.Workspaces {
		cwds[ws] = true
	}
	for i := range sources {
		s := &sources[i]
		mt, _ := time.Parse(time.RFC3339, s.ModTime)
		if !o.From.IsZero() && mt.Before(o.From) {
			s.Note = "last modified before the window, skipped"
			continue
		}
		s.SHA256, _ = hashFile(s.Path)
		if (s.Parser == "config" || s.Parser == "logfile") && s.Size < 20<<20 {
			// agent settings (auto-approve, MCP servers, hooks) and extension logs are
			// evidence in their own right; keep a redacted copy
			if b, err := os.ReadFile(s.Path); err == nil {
				txt := string(b)
				if !o.NoRedact {
					var n int
					txt, n = Redact(txt)
					m.RedactionCount += n
				}
				_ = put("config/"+rawName(s.Path), []byte(txt))
			}
		}
		evs, note, perr := ParseSource(*s)
		if note != "" {
			s.Note = note
		}
		if perr != nil {
			s.Error = perr.Error()
			logf(lw, "  ! %s: %v", s.Path, perr)
		}
		kept := 0
		for _, e := range evs {
			if !o.inWindow(e.TS) {
				continue
			}
			if !o.NoRedact {
				m.RedactionCount += RedactEvent(&e)
			}
			if e.Cwd != "" {
				cwds[e.Cwd] = true
			}
			all = append(all, e)
			kept++
		}
		s.Events = kept
		logf(lw, "  %-15s %-17s %5d step(s)  %s", s.Agent, s.Parser, kept, s.Path)
		if o.IncludeRaw {
			for _, suf := range []string{"", "-wal", "-shm"} {
				if st, err := os.Stat(s.Path + suf); err == nil && !st.IsDir() {
					if b, err := os.ReadFile(s.Path + suf); err == nil {
						_ = put("raw/"+rawName(s.Path+suf), b)
					}
				}
			}
			if st, err := os.Stat(s.Path); err == nil && st.IsDir() {
				_ = addDir(put, s.Path, "raw/"+rawName(s.Path))
			}
		}
	}

	// live recorder log, if this device has one
	if lp := LiveLogPath(o.Roots); fileExists(lp) {
		evs, rep := ReadLiveLog(lp)
		m.LiveChain = &rep
		logf(lw, "live recorder log %s: %d record(s), chain %s", lp, rep.Records, rep.Status)
		h, _ := hashFile(lp)
		sources = append(sources, Source{Agent: "afr-live", Parser: "live", Path: lp, SHA256: h, Events: len(evs), Note: "chain " + rep.Status})
		for _, e := range evs {
			if o.inWindow(e.TS) {
				all = append(all, e)
				if e.Cwd != "" {
					cwds[e.Cwd] = true
				}
			}
		}
		if b, err := os.ReadFile(lp); err == nil {
			_ = put("live/events.jsonl", b) // already redacted at write time
		}
	}

	// instruction and config files for every workspace the agents worked in
	var wsList []string
	for d := range cwds {
		wsList = append(wsList, d)
	}
	sort.Strings(wsList)
	var wsIndex []map[string]string
	for _, ws := range wsList {
		for _, p := range WorkspaceArtifacts(ws) {
			b, err := os.ReadFile(p)
			if err != nil {
				continue
			}
			h := sha256.Sum256(b)
			txt := string(b)
			if !o.NoRedact {
				var n int
				txt, n = Redact(txt)
				m.RedactionCount += n
			}
			name := "workspace/" + rawName(p)
			_ = put(name, []byte(txt))
			st, _ := os.Stat(p)
			wsIndex = append(wsIndex, map[string]string{"path": p, "sha256_original": hex.EncodeToString(h[:]),
				"mtime": st.ModTime().UTC().Format(time.RFC3339), "bundle_entry": name})
		}
	}
	if len(wsIndex) > 0 {
		logf(lw, "captured %d workspace instruction/config file(s)", len(wsIndex))
	}

	SortEvents(all)
	sessions := map[string]bool{}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	for _, e := range all {
		m.Agents[e.Agent]++
		sessions[e.Agent+"|"+e.SessionID] = true
		_ = enc.Encode(e)
	}
	m.Events, m.Sessions = len(all), len(sessions)
	_ = put("events.jsonl", buf.Bytes())
	sb, _ := json.MarshalIndent(sources, "", "  ")
	_ = put("sources.json", sb)
	if len(wsIndex) > 0 {
		wb, _ := json.MarshalIndent(wsIndex, "", "  ")
		_ = put("workspace_index.json", wb)
	}
	logf(lw, "%d step(s) across %d session(s) in window, %d secret(s) redacted", m.Events, m.Sessions, m.RedactionCount)
	m.Finished = time.Now().UTC()
	_ = put("collector.log", logBuf.Bytes())
	mb, _ := json.MarshalIndent(m, "", "  ")
	if err := put("manifest.json", mb); err != nil {
		return "", nil, err
	}
	if err := zw.Close(); err != nil {
		return "", nil, err
	}
	f.Close()
	bh, err := hashFile(o.Out)
	if err != nil {
		return "", nil, err
	}
	_ = os.WriteFile(o.Out+".sha256", []byte(bh+"  "+filepath.Base(o.Out)+"\n"), 0o644)
	return bh, m, nil
}

func nonNil(w io.Writer) io.Writer {
	if w == nil {
		return io.Discard
	}
	return w
}

func hashFile(p string) (string, error) {
	f, err := os.Open(p)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func fileExists(p string) bool { st, err := os.Stat(p); return err == nil && !st.IsDir() }

// rawName turns an absolute path into a safe relative zip entry name.
func rawName(p string) string {
	p = filepath.ToSlash(p)
	p = strings.ReplaceAll(p, ":", "")
	return strings.TrimLeft(p, "/")
}

func addDir(put func(string, []byte) error, dir, prefix string) error {
	return filepath.Walk(dir, func(p string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || info.Size() > 64<<20 {
			return nil
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return nil
		}
		rel, _ := filepath.Rel(dir, p)
		return put(prefix+"/"+filepath.ToSlash(rel), b)
	})
}

// LoadBundle reads events and manifest back from a bundle zip (used by report/verify).
func LoadBundle(path string) ([]Event, *Manifest, []Source, map[string][]byte, error) {
	zr, err := zip.OpenReader(path)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	defer zr.Close()
	files := map[string][]byte{}
	for _, f := range zr.File {
		rc, err := f.Open()
		if err != nil {
			continue
		}
		b, _ := io.ReadAll(rc)
		rc.Close()
		files[f.Name] = b
	}
	var m Manifest
	if err := json.Unmarshal(files["manifest.json"], &m); err != nil {
		return nil, nil, nil, nil, fmt.Errorf("manifest.json missing or invalid: %w", err)
	}
	var evs []Event
	for _, line := range bytes.Split(files["events.jsonl"], []byte("\n")) {
		var e Event
		if len(bytes.TrimSpace(line)) > 0 && json.Unmarshal(line, &e) == nil {
			evs = append(evs, e)
		}
	}
	var srcs []Source
	_ = json.Unmarshal(files["sources.json"], &srcs)
	return evs, &m, srcs, files, nil
}

// VerifyBundle re-hashes every entry against the manifest.
func VerifyBundle(path string) ([]string, error) {
	_, m, _, files, err := LoadBundle(path)
	if err != nil {
		return nil, err
	}
	var problems []string
	for name, want := range m.Entries {
		b, ok := files[name]
		if !ok {
			problems = append(problems, "missing entry: "+name)
			continue
		}
		s := sha256.Sum256(b)
		if hex.EncodeToString(s[:]) != want {
			problems = append(problems, "hash mismatch: "+name)
		}
	}
	for name := range files {
		if _, ok := m.Entries[name]; !ok && name != "manifest.json" {
			problems = append(problems, "entry not in manifest: "+name)
		}
	}
	if b, err := os.ReadFile(path + ".sha256"); err == nil {
		h, _ := hashFile(path)
		if !strings.HasPrefix(strings.TrimSpace(string(b)), h) {
			problems = append(problems, "bundle hash does not match "+filepath.Base(path)+".sha256")
		}
	}
	sort.Strings(problems)
	return problems, nil
}
