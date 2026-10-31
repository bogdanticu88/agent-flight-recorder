package core

import (
	"archive/zip"
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/user"
	"path"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"
)

// Bundle format identifiers. Version 2 is the first with a validated schema;
// version 0.1 bundles (no format field) are not accepted.
const (
	BundleFormat        = "afr-bundle"
	BundleFormatVersion = 2
)

// CollectOptions controls an offline evidence collection.
type CollectOptions struct {
	Roots       Roots
	Root        string // mounted image root; "" means the running system
	SourceHost  string // host the evidence came from, when collecting from an image
	Agents      map[string]bool
	From, To    time.Time // zero = unbounded
	Out         string    // bundle path (.zip)
	IncludeRaw  bool      // also copy raw source files (unredacted). SOC use only.
	FullLiveLog bool      // include the whole live log, not just the window
	LiveLog     string    // operator-supplied live log path (overrides the default location)
	NoRedact    bool
	Mode        string // soc | user
	CaseID      string
	Workspaces  []string
	MaxField    int // per-field cap after redaction (default 65536)
	Log         io.Writer
}

// LiveLogInfo is what the collector saw of the live log on the device.
type LiveLogInfo struct {
	Path     string `json:"path"`
	SHA256   string `json:"sha256"`
	Records  int    `json:"records"`
	Status   string `json:"status"`
	HeadHash string `json:"head_hash,omitempty"`
	InWindow int    `json:"in_window"`
	Mode     string `json:"mode"`  // excerpt | full
	Entry    string `json:"entry"` // bundle entry holding it
}

// Manifest describes a bundle: who/where/when, what was found, and hashes.
type Manifest struct {
	Format           string            `json:"format"`
	FormatVersion    int               `json:"format_version"`
	Tool             string            `json:"tool"`
	Version          string            `json:"version"`
	Status           string            `json:"status"` // complete | partial
	CaseID           string            `json:"case_id,omitempty"`
	Mode             string            `json:"mode"`
	ModeNote         string            `json:"mode_note"`
	Host             string            `json:"host"` // where the collector ran
	User             string            `json:"user"` // who ran it
	OS               string            `json:"os"`
	Root             string            `json:"image_root,omitempty"`
	Home             string            `json:"home"`
	SourceHost       string            `json:"source_host,omitempty"` // host the evidence belongs to, if known
	ProfileUser      string            `json:"profile_user"`
	Started          time.Time         `json:"collection_started"`
	Finished         time.Time         `json:"collection_finished"`
	WindowFrom       *time.Time        `json:"window_from,omitempty"`
	WindowTo         *time.Time        `json:"window_to,omitempty"`
	Redacted         bool              `json:"redacted"`
	RedactionCount   int               `json:"redaction_count"`
	RawIncluded      bool              `json:"raw_included"`
	FullLiveLog      bool              `json:"full_live_log"`
	Sources          int               `json:"sources_found"`
	SourceErrors     int               `json:"source_errors"`
	MalformedRecords int               `json:"malformed_records"`
	Events           int               `json:"events_in_window"`
	Sessions         int               `json:"sessions_in_window"`
	Agents           map[string]int    `json:"events_per_agent"`
	LiveLog          *LiveLogInfo      `json:"live_log,omitempty"`
	Skipped          []string          `json:"skipped,omitempty"`
	Captures         []string          `json:"captures"`
	Entries          map[string]string `json:"entry_sha256"`
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

// zipWriterHook lets tests inject write failures into bundle output.
var zipWriterHook func(io.Writer) io.Writer

// bundleWriter accumulates entries and remembers the first write error.
type bundleWriter struct {
	zw      *zip.Writer
	entries map[string]string
	err     error
}

func (b *bundleWriter) put(name string, data []byte) {
	if b.err != nil {
		return
	}
	if _, dup := b.entries[name]; dup {
		b.err = fmt.Errorf("duplicate bundle entry %s", name)
		return
	}
	w, err := b.zw.CreateHeader(&zip.FileHeader{Name: name, Method: zip.Deflate, Modified: time.Now()})
	if err != nil {
		b.err = err
		return
	}
	if _, err := w.Write(data); err != nil {
		b.err = err
		return
	}
	s := sha256.Sum256(data)
	b.entries[name] = hex.EncodeToString(s[:])
}

func (b *bundleWriter) putFile(name, src string) {
	data, err := os.ReadFile(src)
	if err != nil {
		if b.err == nil {
			b.err = err
		}
		return
	}
	b.put(name, data)
}

// ErrPartial is returned (wrapped) when the bundle was written but one or more
// sources could not be acquired or parsed.
var ErrPartial = errors.New("partial collection")

// Collect runs discovery, acquisition, parsing, redaction and packaging. It
// returns ErrPartial (with a complete, valid bundle written) when some sources
// failed, and any other error when no trustworthy bundle could be produced.
func Collect(o CollectOptions) (string, *Manifest, error) {
	if o.MaxField <= 0 {
		o.MaxField = 65536
	}
	var logBuf bytes.Buffer
	lw := io.MultiWriter(&logBuf, nonNil(o.Log))
	host, _ := os.Hostname()
	uname := ""
	if u, err := user.Current(); err == nil {
		uname = u.Username
	}
	srcHost := o.SourceHost
	if srcHost == "" && o.Root == "" {
		srcHost = host
	}
	m := &Manifest{Format: BundleFormat, FormatVersion: BundleFormatVersion, Tool: "afr (Agent Flight Recorder)", Version: Version,
		CaseID: o.CaseID, Mode: o.Mode, Host: host, User: uname, OS: runtime.GOOS + "/" + runtime.GOARCH,
		Root: o.Root, Home: o.Roots.Home, SourceHost: srcHost, ProfileUser: filepath.Base(o.Roots.Home),
		Started: time.Now().UTC(), Redacted: !o.NoRedact, RawIncluded: o.IncludeRaw, FullLiveLog: o.FullLiveLog,
		Agents: map[string]int{}, Entries: map[string]string{},
		Captures: []string{
			"Session records from agent artifacts, filtered to the time window.",
			"Agent settings files (editor settings, MCP and hook configuration), redacted, whatever their age.",
			"Instruction and configuration files from session working directories inside the acquisition roots (AGENTS.md, CLAUDE.md, .github/copilot-instructions.md and similar), redacted, whatever their age.",
		}}
	switch o.Mode {
	case "soc":
		m.ModeNote = "Collector run reported as SOC (e.g. Defender Live Response). This is what the operator declared; the bundle cannot prove it."
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

	home := resolveDir(o.Roots.Home)
	if st, err := os.Stat(home); err != nil || !st.IsDir() {
		return "", nil, fmt.Errorf("profile directory %s not found", o.Roots.Home)
	}
	scope := Scope{Root: o.Root, Bases: []string{home}}
	for _, ws := range o.Workspaces {
		mp := ws
		if o.Root != "" {
			if p, err := scope.MapPath(ws); err == nil {
				mp = p
			}
		}
		scope.Bases = append(scope.Bases, resolveDir(mp))
	}

	snap, err := os.MkdirTemp("", "afr-acq-*")
	if err != nil {
		return "", nil, err
	}
	defer os.RemoveAll(snap)

	outDir := filepath.Dir(o.Out)
	tmp, err := os.CreateTemp(outDir, ".afr-bundle-*.tmp")
	if err != nil {
		return "", nil, fmt.Errorf("cannot create output in %s: %w", outDir, err)
	}
	tmpName := tmp.Name()
	committed := false
	defer func() {
		if !committed {
			tmp.Close()
			os.Remove(tmpName)
		}
	}()
	var w io.Writer = tmp
	if zipWriterHook != nil {
		w = zipWriterHook(w)
	}
	bw := &bundleWriter{zw: zip.NewWriter(w), entries: m.Entries}

	logf(lw, "afr %s collecting from %s (mode=%s)", Version, o.Roots.Home, m.Mode)
	sources := Discover(o.Roots, o.Agents)
	m.Sources = len(sources)
	logf(lw, "discovered %d artifact(s)", len(sources))

	var all []Event
	cwds := map[string]bool{}
	for i := range sources {
		s := &sources[i]
		dst := filepath.Join(snap, fmt.Sprintf("%04d", i))
		real, st, err := scope.Check(s.Path)
		if err != nil {
			s.Error = err.Error()
			m.Skipped = append(m.Skipped, err.Error())
			logf(lw, "  ! %v", err)
			continue
		}
		if !st.IsDir() && !o.From.IsZero() && st.ModTime().Before(o.From) {
			s.Note = "file last modified before the window; not acquired"
			continue
		}
		const unstable = "files kept changing during acquisition; the snapshot may be internally inconsistent"
		switch {
		case st.IsDir():
			fe, notes, failed, err := acquireDir(real, dst, &scope)
			s.Files, s.Diags = fe, append(s.Diags, notes...)
			s.SHA256 = digestFiles(fe)
			s.Note = fmt.Sprintf("directory: %d file(s) acquired; sha256 is a digest over per-file hashes", len(fe))
			switch {
			case err != nil:
				s.Error = err.Error()
			case failed > 0:
				s.Error = fmt.Sprintf("%d file(s) in the directory could not be acquired or kept changing (see diagnostics)", failed)
			}
			s.snapshot = dst
		case isSQLiteParser(s.Parser):
			fe, notes, err := acquireSet([]string{real, real + "-wal", real + "-shm"}, []string{"main", "wal", "shm"}, dst, &scope)
			s.Files, s.Diags = fe, append(s.Diags, notes...)
			if err != nil {
				s.Error = err.Error()
				break
			}
			if anyChanged(fe) {
				s.Error = unstable
			}
			s.SHA256 = fe[0].SHA256
			s.snapshot = filepath.Join(dst, filepath.Base(real))
			s.Note = "SQLite: database and sidecars copied sequentially (not an atomic snapshot); see per-file evidence"
		default:
			fe, notes, err := acquireSet([]string{real}, []string{"main"}, dst, &scope)
			s.Diags = append(s.Diags, notes...)
			if err != nil {
				s.Error = err.Error()
				break
			}
			s.SHA256 = fe[0].SHA256
			if fe[0].Changed {
				s.Files = fe
				s.Error = unstable
			}
			s.snapshot = filepath.Join(dst, filepath.Base(real))
		}
		if s.snapshot == "" {
			logf(lw, "  ! %s: %s", s.Path, s.Error)
			continue
		}
		if (s.Parser == "config" || s.Parser == "logfile") && st.Size() < 20<<20 {
			if b, err := os.ReadFile(s.snapshot); err == nil {
				txt := string(b)
				if !o.NoRedact {
					var n int
					txt, n = RedactValue(txt)
					m.RedactionCount += n
				}
				bw.put("config/"+rawName(s.Path), []byte(txt))
			}
		}
		res, perr := ParseSource(*s)
		if res.Note != "" {
			s.Note = strings.TrimSpace(s.Note + " " + res.Note)
		}
		s.Malformed = res.Malformed
		m.MalformedRecords += res.Malformed
		s.Diags = append(s.Diags, res.Diags...)
		if perr != nil {
			s.Error = perr.Error()
			logf(lw, "  ! %s: %v", s.Path, perr)
		}
		kept := 0
		for _, e := range res.Events {
			if !o.inWindow(e.TS) {
				continue
			}
			e.Host, e.User = srcHost, m.ProfileUser
			if !o.NoRedact {
				m.RedactionCount += RedactEvent(&e)
			}
			TruncateEvent(&e, o.MaxField)
			if e.Cwd != "" {
				cwds[e.Cwd] = true
			}
			all = append(all, e)
			kept++
		}
		s.Events = kept
		logf(lw, "  %-15s %-17s %5d step(s)  %s", s.Agent, s.Parser, kept, s.Path)
		if o.IncludeRaw {
			switch {
			case st.IsDir():
				for _, f := range s.Files {
					r, _ := filepath.Rel(real, f.Path)
					bw.putFile("raw/"+rawName(f.Path), filepath.Join(dst, r))
				}
			case len(s.Files) > 0:
				for _, f := range s.Files {
					bw.putFile("raw/"+rawName(f.Path), filepath.Join(dst, filepath.Base(f.Path)))
				}
			default:
				bw.putFile("raw/"+rawName(real), s.snapshot)
			}
		}
	}

	// live recorder log, if this device has one
	// The live log location is taken only from sources the operator or the
	// administrator controls: --live-log, or the managed policy on the
	// running system. The user's own policy and environment are ignored, so a
	// collector running as SYSTEM cannot be pointed at an arbitrary file.
	lp := filepath.Join(userStateDir(o.Roots), "events.jsonl")
	liveScope := scope
	switch {
	case o.LiveLog != "":
		lp = o.LiveLog
		liveScope.Bases = append(append([]string{}, scope.Bases...), resolveDir(filepath.Dir(lp)))
	case o.Root == "":
		if mp := managedLogPath(o.Roots); mp != "" {
			lp = mp
			liveScope.Bases = append(append([]string{}, scope.Bases...), resolveDir(filepath.Dir(lp)))
		}
	}
	if real, _, err := liveScope.Check(lp); err == nil {
		collectLive(o, m, bw, real, filepath.Join(snap, "live"), cwds, lw)
	} else if !errors.Is(err, os.ErrNotExist) {
		m.Skipped = append(m.Skipped, "live log: "+err.Error())
	}

	// instruction and config files for every workspace the agents worked in
	wsIndex := collectWorkspaces(o, m, bw, scope, cwds, filepath.Join(snap, "ws"), lw)

	SortEvents(all)
	sessions := map[string]bool{}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	for _, e := range all {
		m.Agents[e.Agent]++
		sessions[e.ScopeKey()] = true
		if err := enc.Encode(e); err != nil {
			return "", nil, err
		}
	}
	m.Events, m.Sessions = len(all), len(sessions)
	bw.put("events.jsonl", buf.Bytes())
	for _, s := range sources {
		if s.Error != "" {
			m.SourceErrors++
		}
	}
	sb, _ := json.MarshalIndent(sources, "", "  ")
	bw.put("sources.json", sb)
	if len(wsIndex) > 0 {
		wb, _ := json.MarshalIndent(wsIndex, "", "  ")
		bw.put("workspace_index.json", wb)
	}
	m.Status = "complete"
	if m.SourceErrors > 0 || m.MalformedRecords > 0 {
		m.Status = "partial"
	}
	logf(lw, "%d step(s) across %d record stream(s) in window, %d redaction(s), %d source error(s)", m.Events, m.Sessions, m.RedactionCount, m.SourceErrors)
	m.Finished = time.Now().UTC()
	bw.put("collector.log", logBuf.Bytes())
	mb, _ := json.MarshalIndent(m, "", "  ")
	manifestEntries := m.Entries
	bw.entries = map[string]string{}
	bw.put("manifest.json", mb)
	m.Entries = manifestEntries
	if bw.err != nil {
		return "", nil, fmt.Errorf("writing bundle: %w", bw.err)
	}
	if err := bw.zw.Close(); err != nil {
		return "", nil, fmt.Errorf("finalising bundle: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		return "", nil, fmt.Errorf("syncing bundle: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return "", nil, fmt.Errorf("closing bundle: %w", err)
	}
	bh, err := hashFile(tmpName)
	if err != nil {
		return "", nil, err
	}
	side := o.Out + ".sha256"
	sideTmp := side + ".tmp"
	if err := os.WriteFile(sideTmp, []byte(bh+"  "+filepath.Base(o.Out)+"\n"), 0o644); err != nil {
		return "", nil, fmt.Errorf("writing checksum sidecar: %w", err)
	}
	if err := os.Rename(tmpName, o.Out); err != nil {
		os.Remove(sideTmp)
		return "", nil, fmt.Errorf("placing bundle: %w", err)
	}
	committed = true
	if err := os.Rename(sideTmp, side); err != nil {
		return bh, m, fmt.Errorf("bundle written but checksum sidecar could not be placed: %w", err)
	}
	if m.Status == "partial" {
		return bh, m, fmt.Errorf("%w: %d source error(s), %d malformed record(s) (listed in sources.json)", ErrPartial, m.SourceErrors, m.MalformedRecords)
	}
	return bh, m, nil
}

// managedLogPath returns the log location set by a valid managed policy, or "".
func managedLogPath(r Roots) string {
	st := LoadPolicy(r)
	if st.Origin == PolicyManaged && st.Err == nil && st.Policy.LogPath != "" {
		return expandUser(st.Policy.LogPath, r)
	}
	return ""
}

func isSQLiteParser(p string) bool {
	return p == "opencode-db" || p == "cursor-db" || p == "vscode-statedb"
}

// collectLive acquires the live log once, verifies the acquired bytes, and
// exports either the records inside the window (default) or the whole log.
// Exported records keep their original bytes and hashes; nothing is
// re-chained. Live records are carried only in the live entry, not copied
// into events.jsonl, so a reader never sees them twice.
func collectLive(o CollectOptions, m *Manifest, bw *bundleWriter, lp, dst string, cwds map[string]bool, lw io.Writer) {
	fe, notes, err := acquireSet([]string{lp}, []string{"main"}, dst, nil)
	if err != nil {
		m.Skipped = append(m.Skipped, "live log: "+err.Error())
		m.SourceErrors++
		return
	}
	if anyChanged(fe) {
		m.Skipped = append(m.Skipped, "live log: kept changing during acquisition; exported records come from an unstable copy")
		m.SourceErrors++
	}
	snapPath := filepath.Join(dst, filepath.Base(lp))
	f, err := os.Open(snapPath)
	if err != nil {
		m.SourceErrors++
		return
	}
	evs, rep := VerifyLiveLog(f)
	f.Close()
	info := &LiveLogInfo{Path: lp, SHA256: fe[0].SHA256, Records: rep.Records, Status: rep.Status, HeadHash: rep.HeadHash}
	if !rep.OK() {
		m.Skipped = append(m.Skipped, fmt.Sprintf("live log: %s (%s)", rep.Status, rep.Detail))
		m.SourceErrors++
	}
	for _, n := range notes {
		m.Skipped = append(m.Skipped, "live log: "+n)
	}
	logf(lw, "live recorder log %s: %d record(s), %s", lp, rep.Records, rep.Status)

	raw, _ := os.ReadFile(snapPath)
	lines := splitRecordLines(raw)
	var excerpt bytes.Buffer
	inWin := 0
	for _, e := range evs {
		if !o.inWindow(e.TS) {
			continue
		}
		inWin++
		if e.Cwd != "" {
			cwds[e.Cwd] = true
		}
		if l, ok := lines[e.Pos]; ok {
			excerpt.Write(l)
			excerpt.WriteByte('\n')
		}
	}
	info.InWindow = inWin
	if o.FullLiveLog {
		info.Mode, info.Entry = "full", "live/events.jsonl"
		bw.put(info.Entry, raw)
	} else {
		info.Mode, info.Entry = "excerpt", "live/excerpt.jsonl"
		hdr := ExcerptHeader{Version: 1, SourcePath: lp, SourceSHA256: info.SHA256, SourceRecords: rep.Records,
			SourceHeadHash: rep.HeadHash, SourceStatus: rep.Status, WindowFrom: m.WindowFrom, WindowTo: m.WindowTo, Records: inWin}
		hb, _ := json.Marshal(map[string]any{"afr_excerpt": hdr})
		bw.put(info.Entry, append(append(hb, '\n'), excerpt.Bytes()...))
	}
	m.LiveLog = info
}

// splitRecordLines maps 1-based line numbers to the raw bytes of each line,
// so exported records are byte-identical to the original.
func splitRecordLines(b []byte) map[int][]byte {
	out := map[int][]byte{}
	sc := bufio.NewScanner(bytes.NewReader(b))
	sc.Buffer(make([]byte, 64*1024), maxLineBytes)
	n := 0
	for sc.Scan() {
		n++
		out[n] = append([]byte(nil), sc.Bytes()...)
	}
	return out
}

// collectWorkspaces captures instruction/config files for working directories
// seen in the sessions. Each cwd is mapped into the image (if any) and must
// resolve inside the acquisition roots; anything else is listed as skipped.
func collectWorkspaces(o CollectOptions, m *Manifest, bw *bundleWriter, scope Scope, cwds map[string]bool, dst string, lw io.Writer) []map[string]string {
	cands := map[string]string{} // mapped -> as recorded
	for _, ws := range o.Workspaces {
		cands[ws] = ws
	}
	for d := range cwds {
		mp, err := scope.MapPath(d)
		if err != nil {
			m.Skipped = append(m.Skipped, fmt.Sprintf("workspace %q: %v", d, err))
			continue
		}
		cands[mp] = d
	}
	keys := make([]string, 0, len(cands))
	for k := range cands {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var index []map[string]string
	n := 0
	for _, ws := range keys {
		realWS, st, err := scope.Check(ws)
		if err != nil {
			if !errors.Is(err, os.ErrNotExist) {
				m.Skipped = append(m.Skipped, fmt.Sprintf("workspace %q: %v", cands[ws], err))
			}
			continue
		}
		if !st.IsDir() {
			continue
		}
		for _, rel := range instructionFiles {
			p := filepath.Join(realWS, rel)
			real, fst, err := scope.Check(p)
			if err != nil {
				if !errors.Is(err, os.ErrNotExist) {
					m.Skipped = append(m.Skipped, err.Error())
				}
				continue
			}
			files := []string{real}
			if fst.IsDir() {
				files = nil
				_ = filepath.WalkDir(real, func(q string, d os.DirEntry, err error) error {
					if err == nil && !d.IsDir() {
						if d.Type()&os.ModeSymlink != 0 || !d.Type().IsRegular() {
							m.Skipped = append(m.Skipped, q+": link or special file in workspace, not followed")
							return nil
						}
						files = append(files, q)
					}
					return nil
				})
			}
			for _, fpath := range files {
				if info, err := os.Stat(fpath); err != nil || info.Size() > 2<<20 {
					continue
				}
				n++
				fe, _, err := acquireSet([]string{fpath}, []string{"main"}, filepath.Join(dst, fmt.Sprintf("%05d", n)), &scope)
				if err != nil {
					m.Skipped = append(m.Skipped, err.Error())
					if !errors.Is(err, ErrOutsideRoots) {
						m.SourceErrors++
					}
					continue
				}
				b, err := os.ReadFile(filepath.Join(dst, fmt.Sprintf("%05d", n), filepath.Base(fpath)))
				if err != nil {
					continue
				}
				txt := string(b)
				if !o.NoRedact {
					var c int
					txt, c = RedactValue(txt)
					m.RedactionCount += c
				}
				name := "workspace/" + rawName(fpath)
				if _, dup := bw.entries[name]; dup {
					continue
				}
				bw.put(name, []byte(txt))
				index = append(index, map[string]string{"path": fpath, "recorded_cwd": cands[ws], "sha256_original": fe[0].SHA256,
					"mtime": fe[0].ModTime, "bundle_entry": name})
			}
		}
	}
	if len(index) > 0 {
		logf(lw, "captured %d workspace instruction/config file(s)", len(index))
	}
	return index
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

// rawName turns an absolute path into a safe relative zip entry name.
func rawName(p string) string {
	p = filepath.ToSlash(p)
	p = strings.ReplaceAll(p, ":", "")
	parts := strings.Split(p, "/")
	var out []string
	for _, s := range parts {
		if s == "" || s == "." || s == ".." {
			continue
		}
		out = append(out, s)
	}
	return strings.Join(out, "/")
}

// ------------------------------------------------------------------ verification

// BundleLimits bound what verification will read from an untrusted zip.
type BundleLimits struct {
	MaxEntries    int
	MaxEntryBytes int64
	MaxTotalBytes int64
}

// DefaultBundleLimits are generous for real collections and still stop a zip bomb.
var DefaultBundleLimits = BundleLimits{MaxEntries: 100_000, MaxEntryBytes: 1 << 30, MaxTotalBytes: 4 << 30}

// BundleCheck keeps the different things a verifier can say apart.
type BundleCheck struct {
	ChecksumConsistent bool         // every entry matches the manifest and the sidecar (if present)
	Problems           []string     // structural or integrity problems; any problem makes the bundle invalid
	Live               *ChainReport // recomputed from the live log bytes inside the bundle
	LiveCollector      *ChainReport // what the collector reported about the original log (not re-verifiable for excerpts)
	LiveMode           string       // excerpt | full, as declared by the manifest
	BundleSHA256       string       // hash of the bundle file itself, for comparison with a value kept elsewhere
	ParseIssues        int          // sources with errors, malformed records or generic fallback
	Origin             string       // what the bundle can and cannot say about who produced it
}

// OK reports whether the bundle passed every structural and integrity check.
// A live excerpt is accepted only when the manifest declares the live log
// as an excerpt and the excerpt's records check out.
func (b BundleCheck) OK() bool {
	liveOK := b.Live == nil || b.Live.OK() || (b.LiveMode == "excerpt" && b.Live.Status == ChainExcerpt)
	return b.ChecksumConsistent && len(b.Problems) == 0 && liveOK
}

const originNote = "A matching manifest and sidecar show the bundle is internally consistent and unchanged since it was hashed. They do not show who produced it or that it was collected the way the manifest says; anyone can create a consistent bundle. Keep the sidecar hash somewhere the collector's user cannot change (for example the ticket) to detect later modification."

var requiredEntries = []string{"events.jsonl", "sources.json", "collector.log"}

func validEntryName(n string) error {
	switch {
	case n == "" || len(n) > 1024:
		return errors.New("empty or overlong name")
	case strings.HasPrefix(n, "/") || strings.Contains(n, `\`) || winDrive.MatchString(n) || strings.Contains(n, ":"):
		return errors.New("absolute path, drive letter or backslash")
	}
	for _, r := range n {
		if r < 0x20 || r == 0x7f {
			return errors.New("control character")
		}
	}
	for _, seg := range strings.Split(n, "/") {
		if seg == ".." || seg == "." || seg == "" {
			return errors.New("relative or empty path segment")
		}
	}
	return nil
}

// LoadBundle reads, validates and returns a bundle. It returns an error only
// when the file cannot be opened as a zip at all; every other problem is
// listed in the BundleCheck, and malformed records are never silently dropped
// from a bundle reported as valid.
func LoadBundle(p string, lim BundleLimits) ([]Event, *Manifest, []Source, BundleCheck, error) {
	chk := BundleCheck{Origin: originNote}
	chk.BundleSHA256, _ = hashFile(p)
	zr, err := zip.OpenReader(p)
	if err != nil {
		return nil, nil, nil, chk, err
	}
	defer zr.Close()
	bad := func(f string, a ...any) { chk.Problems = append(chk.Problems, fmt.Sprintf(f, a...)) }

	if len(zr.File) > lim.MaxEntries {
		bad("%d entries, limit %d; not read", len(zr.File), lim.MaxEntries)
		return nil, nil, nil, chk, nil
	}
	files := map[string][]byte{}
	var total int64
	for _, f := range zr.File {
		if err := validEntryName(f.Name); err != nil {
			bad("entry %q: invalid name (%v)", f.Name, err)
			continue
		}
		if _, dup := files[f.Name]; dup {
			bad("entry %q appears more than once", f.Name)
			continue
		}
		if f.FileInfo().IsDir() {
			bad("entry %q is a directory", f.Name)
			continue
		}
		if int64(f.UncompressedSize64) > lim.MaxEntryBytes {
			bad("entry %q declares %d bytes, over the per-entry limit %d", f.Name, f.UncompressedSize64, lim.MaxEntryBytes)
			continue
		}
		rc, err := f.Open()
		if err != nil {
			bad("entry %q: %v", f.Name, err)
			continue
		}
		b, err := io.ReadAll(io.LimitReader(rc, lim.MaxEntryBytes+1))
		cerr := rc.Close()
		if err == nil {
			err = cerr
		}
		if err != nil {
			bad("entry %q: read failed (%v)", f.Name, err)
			continue
		}
		if int64(len(b)) > lim.MaxEntryBytes {
			bad("entry %q exceeds the per-entry limit %d", f.Name, lim.MaxEntryBytes)
			continue
		}
		total += int64(len(b))
		if total > lim.MaxTotalBytes {
			bad("bundle exceeds the total size limit %d; reading stopped", lim.MaxTotalBytes)
			return nil, nil, nil, chk, nil
		}
		files[f.Name] = b
	}

	mb, ok := files["manifest.json"]
	if !ok {
		bad("manifest.json missing")
		return nil, nil, nil, chk, nil
	}
	var m Manifest
	if err := json.Unmarshal(mb, &m); err != nil {
		bad("manifest.json invalid: %v", err)
		return nil, nil, nil, chk, nil
	}
	switch {
	case m.Format != BundleFormat:
		bad("manifest format %q, expected %q (bundles from afr 0.1 are not supported)", m.Format, BundleFormat)
	case m.FormatVersion != BundleFormatVersion:
		bad("manifest format_version %d, expected %d", m.FormatVersion, BundleFormatVersion)
	}
	if m.Version == "" || m.Started.IsZero() || m.Finished.IsZero() {
		bad("manifest lacks tool version or collection times")
	}
	if m.Status != "complete" && m.Status != "partial" {
		bad("manifest status %q, expected complete or partial", m.Status)
	}
	hashOK := true
	for _, r := range requiredEntries {
		if _, ok := m.Entries[r]; !ok {
			bad("manifest does not list required entry %s", r)
			hashOK = false
		}
	}
	names := make([]string, 0, len(m.Entries))
	for n := range m.Entries {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, name := range names {
		want := m.Entries[name]
		if len(want) != 64 {
			bad("manifest hash for %s is not a SHA-256", name)
			hashOK = false
			continue
		}
		b, ok := files[name]
		if !ok {
			bad("entry %s listed in the manifest is missing", name)
			hashOK = false
			continue
		}
		s := sha256.Sum256(b)
		if hex.EncodeToString(s[:]) != want {
			bad("entry %s does not match its manifest hash", name)
			hashOK = false
		}
	}
	for name := range files {
		if _, ok := m.Entries[name]; !ok && name != "manifest.json" {
			bad("entry %s is not listed in the manifest", name)
			hashOK = false
		}
	}
	if b, err := os.ReadFile(p + ".sha256"); err == nil {
		if f := strings.Fields(string(b)); len(f) == 0 || f[0] != chk.BundleSHA256 {
			bad("bundle hash does not match %s", path.Base(filepath.ToSlash(p))+".sha256")
			hashOK = false
		}
	}
	chk.ChecksumConsistent = hashOK

	var evs []Event
	if b, ok := files["events.jsonl"]; ok {
		sc := bufio.NewScanner(bytes.NewReader(b))
		sc.Buffer(make([]byte, 64*1024), maxLineBytes)
		line := 0
		for sc.Scan() {
			line++
			if len(bytes.TrimSpace(sc.Bytes())) == 0 {
				continue
			}
			var e Event
			dec := json.NewDecoder(bytes.NewReader(sc.Bytes()))
			if err := dec.Decode(&e); err != nil || e.Agent == "" || kindLabel(e.Kind) == "" {
				bad("events.jsonl line %d is not a valid event", line)
				continue
			}
			e.Prov = p
			evs = append(evs, e)
		}
		if err := sc.Err(); err != nil {
			bad("events.jsonl: reading stopped after line %d: %v", line, err)
		}
		if len(evs) != m.Events {
			bad("manifest says %d events, events.jsonl holds %d valid ones", m.Events, len(evs))
		}
	}
	var srcs []Source
	if b, ok := files["sources.json"]; ok {
		if err := json.Unmarshal(b, &srcs); err != nil {
			bad("sources.json invalid: %v", err)
		}
	}
	for _, s := range srcs {
		if s.Error != "" || s.Malformed > 0 || strings.Contains(s.Note, "generic extractor") {
			chk.ParseIssues++
		}
	}

	if li := m.LiveLog; li != nil {
		chk.LiveCollector = &ChainReport{Status: li.Status, Records: li.Records, HeadHash: li.HeadHash}
		chk.LiveMode = li.Mode
		if li.Status != ChainConsistent && li.Status != ChainEmpty {
			bad("the original live log was %s at collection (collector-reported); the exported records cannot be relied on as a complete record", li.Status)
		}
		b, ok := files[li.Entry]
		if !ok {
			bad("manifest lists live log entry %q but it is missing", li.Entry)
		} else {
			lev, rep := VerifyLiveLog(bytes.NewReader(b))
			chk.Live = &rep
			switch li.Mode {
			case "full":
				s := sha256.Sum256(b)
				if hex.EncodeToString(s[:]) != li.SHA256 || rep.Records != li.Records || rep.Status != li.Status || rep.HeadHash != li.HeadHash {
					bad("live log in bundle does not match what the manifest reports about it (status %s/%s, records %d/%d)", rep.Status, li.Status, rep.Records, li.Records)
				}
			case "excerpt":
				h := rep.Excerpt
				if h == nil {
					bad("live excerpt has no excerpt header")
				} else if h.SourceSHA256 != li.SHA256 || h.SourceRecords != li.Records || h.SourceStatus != li.Status || h.SourceHeadHash != li.HeadHash || h.Records != li.InWindow {
					bad("live excerpt header disagrees with the manifest's live log metadata")
				}
			default:
				bad("live log mode %q unknown", li.Mode)
			}
			for i := range lev {
				lev[i].Prov = p + ":" + li.Entry
			}
			evs = append(evs, lev...)
		}
	}
	return evs, &m, srcs, chk, nil
}
