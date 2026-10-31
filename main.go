// afr (Agent Flight Recorder) reconstructs what AI coding agents did on an
// endpoint: prompts, context, reasoning, tool calls and results.
//
//	afr collect   offline: gather agent session artifacts into a hashed, redacted bundle
//	afr hook      live: called by agent hooks, records every step to a hash-chained log
//	afr install   live: generate/install hook config for each agent
//	afr report    build an HTML timeline from bundles and/or live logs, trace a path
//	afr verify    check bundle hashes and live log chains
//	afr discover  list agent artifacts on this machine without collecting
package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/bogdanticu88/agent-flight-recorder/internal/core"
)

func usage() {
	fmt.Fprintf(os.Stderr, `afr %s - Agent Flight Recorder

Offline (after an incident):
  afr collect  [--around TIME --margin 2h | --from TIME --to TIME | --last 24h]
               [--agents all|copilot-vscode,claude-code,...] [--mode soc|user]
               [--case INC0012345] [--home DIR] [--root IMAGE --source-host NAME]
               [--workspace DIR] [--include-raw] [--full-live-log] [-o FILE]
  afr report   BUNDLE.zip|events.jsonl ... [--trace PATH]... [-o report.html]
  afr verify   BUNDLE.zip|events.jsonl ... [--checkpoint RECORDS:HASH]
  afr checkpoint LOG.jsonl
  afr discover [--home DIR]

Live (before the next one):
  afr install  --bin PATH [--scope user|machine] [--agents ...] [--os windows|darwin|linux]
               [--apply | --emit DIR]
  afr hook     --agent NAME [--event NAME]     (called by the agent, reads JSON on stdin)

Exit codes: 0 ok; 1 usage or fatal error; 2 verification found problems;
3 collect wrote a bundle but some sources failed (partial).

Agents: %s
`, core.Version, strings.Join(core.AgentNames(), ", "))
}

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(1)
	}
	cmd, args := os.Args[1], os.Args[2:]
	var err error
	switch cmd {
	case "collect":
		os.Exit(cmdCollect(args))
	case "hook":
		cmdHook(args) // never returns an error to the agent
	case "install":
		err = cmdInstall(args)
	case "report":
		os.Exit(cmdReport(args))
	case "verify":
		os.Exit(cmdVerify(args))
	case "checkpoint":
		os.Exit(cmdCheckpoint(args))
	case "discover":
		err = cmdDiscover(args)
	case "version", "--version", "-v":
		fmt.Println("afr", core.Version, runtime.GOOS+"/"+runtime.GOARCH)
	case "help", "-h", "--help":
		usage()
	default:
		usage()
		os.Exit(1)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "afr:", err)
		os.Exit(1)
	}
}

type multi []string

func (m *multi) String() string     { return strings.Join(*m, ",") }
func (m *multi) Set(v string) error { *m = append(*m, v); return nil }

func agentSet(s string) map[string]bool {
	out := map[string]bool{}
	for _, a := range strings.Split(s, ",") {
		if a = strings.TrimSpace(a); a != "" {
			out[a] = true
		}
	}
	if out["copilot"] { // convenience alias
		out["copilot-vscode"], out["copilot-cli"] = true, true
	}
	return out
}

func parseWhen(s string) (time.Time, error) {
	if s == "" {
		return time.Time{}, nil
	}
	for _, l := range []string{time.RFC3339Nano, time.RFC3339, "2006-01-02T15:04:05", "2006-01-02T15:04", "2006-01-02 15:04:05", "2006-01-02 15:04", "2006-01-02"} {
		if t, err := time.ParseInLocation(l, s, time.Local); err == nil {
			return t.UTC(), nil
		}
	}
	return time.Time{}, fmt.Errorf("cannot parse time %q (use RFC3339, e.g. 2026-10-29T14:03:00Z)", s)
}

func rootsFrom(home string) core.Roots {
	if home == "" {
		return core.DefaultRoots()
	}
	return core.RootsFor(home)
}

// ------------------------------------------------------------------ collect

func cmdCollect(args []string) int {
	fs := flag.NewFlagSet("collect", flag.ExitOnError)
	from := fs.String("from", "", "window start")
	to := fs.String("to", "", "window end")
	around := fs.String("around", "", "alert time; window is --margin either side")
	margin := fs.Duration("margin", 2*time.Hour, "window half-width when using --around")
	last := fs.Duration("last", 0, "window = now minus this duration")
	agents := fs.String("agents", "all", "comma-separated agents or 'all'")
	mode := fs.String("mode", "user", "soc | user (who is running the collection)")
	caseID := fs.String("case", "", "incident / ticket number")
	home := fs.String("home", "", "profile directory to examine (default: current user). With --root, a path inside the image")
	root := fs.String("root", "", "mounted image root; recorded paths (cwd, home) are mapped into it")
	srcHost := fs.String("source-host", "", "host name the image came from (with --root)")
	raw := fs.Bool("include-raw", false, "also copy raw, UNREDACTED source files (SOC only)")
	fullLive := fs.Bool("full-live-log", false, "include the WHOLE live log, not just records in the window (privacy: exports activity outside the incident)")
	noRedact := fs.Bool("no-redact", false, "disable secret redaction (not recommended)")
	out := fs.String("o", "", "output bundle path (default afr-<host>-<time>.zip)")
	var ws multi
	fs.Var(&ws, "workspace", "extra workspace folder whose agent instruction files to capture (repeatable)")
	fs.Parse(args)

	roots := rootsFrom(*home)
	scope := core.Scope{Root: *root}
	if *root != "" {
		if *home == "" {
			fmt.Fprintln(os.Stderr, "afr: --root needs --home (the profile path as it appears inside the image)")
			return 1
		}
		mapped, err := scope.MapPath(*home)
		if err != nil {
			fmt.Fprintln(os.Stderr, "afr:", err)
			return 1
		}
		roots = core.RootsFor(mapped)
	}
	o := core.CollectOptions{Roots: roots, Root: *root, SourceHost: *srcHost, Agents: agentSet(*agents), Mode: *mode, CaseID: *caseID,
		IncludeRaw: *raw, FullLiveLog: *fullLive, NoRedact: *noRedact, Workspaces: ws, Log: os.Stderr}
	var err error
	switch {
	case *around != "":
		t, e := parseWhen(*around)
		if e != nil {
			fmt.Fprintln(os.Stderr, "afr:", e)
			return 1
		}
		o.From, o.To = t.Add(-*margin), t.Add(*margin)
	case *last > 0:
		o.From, o.To = time.Now().UTC().Add(-*last), time.Now().UTC()
	default:
		if o.From, err = parseWhen(*from); err == nil {
			o.To, err = parseWhen(*to)
		}
		if err != nil {
			fmt.Fprintln(os.Stderr, "afr:", err)
			return 1
		}
	}
	if *fullLive {
		fmt.Fprintln(os.Stderr, "warning: --full-live-log exports every recorded prompt and tool call in the live log, including activity unrelated to this window.")
	}
	if *out == "" {
		h, _ := os.Hostname()
		*out = fmt.Sprintf("afr-%s-%s.zip", h, time.Now().UTC().Format("20060102T150405Z"))
	}
	o.Out = *out
	hash, m, err := core.Collect(o)
	partial := errors.Is(err, core.ErrPartial)
	if err != nil && !partial {
		fmt.Fprintln(os.Stderr, "afr: collection failed:", err)
		if m != nil && hash != "" {
			fmt.Fprintln(os.Stderr, "afr: the bundle file exists but its checksum sidecar is missing; treat it as unverified")
		}
		return 1
	}
	status := "complete"
	if partial {
		status = "PARTIAL (" + err.Error() + ")"
	}
	fmt.Fprintf(os.Stderr, "\nbundle:  %s\nsha256:  %s\nstatus:  %s\nsteps:   %d in %d record stream(s)\n", o.Out, hash, status, m.Events, m.Sessions)
	if m.LiveLog != nil {
		fmt.Fprintf(os.Stderr, "live:    %d of %d record(s) in window, exported as %s\n", m.LiveLog.InWindow, m.LiveLog.Records, m.LiveLog.Mode)
	}
	if m.Events == 0 && (m.LiveLog == nil || m.LiveLog.InWindow == 0) {
		fmt.Fprintln(os.Stderr, "note:    nothing in the window. Widen it (--margin / --last) or check --home.")
	}
	fmt.Println(o.Out)
	if partial {
		return 3
	}
	return 0
}

// ------------------------------------------------------------------ hook

func cmdHook(args []string) {
	fs := flag.NewFlagSet("hook", flag.ContinueOnError)
	agent := fs.String("agent", "unknown", "agent name")
	event := fs.String("event", "", "hook event name (if not in payload)")
	_ = fs.Parse(args)
	res := core.RunHook(*agent, *event, os.Stdin, core.DefaultRoots())
	if res.Stdout != "" {
		fmt.Fprintln(os.Stdout, res.Stdout)
	}
	if res.Stderr != "" {
		fmt.Fprintln(os.Stderr, res.Stderr)
	}
	os.Exit(res.ExitCode)
}

// ------------------------------------------------------------------ install

func cmdInstall(args []string) error {
	fs := flag.NewFlagSet("install", flag.ExitOnError)
	bin := fs.String("bin", "", "absolute path of afr on the endpoint (default: this binary)")
	scope := fs.String("scope", "user", "user | machine")
	agents := fs.String("agents", "all", "copilot,claude-code,codex,cursor,gemini-cli,opencode or all")
	targetOS := fs.String("os", runtime.GOOS, "target OS for paths: windows | darwin | linux")
	home := fs.String("home", "", "user profile to install into (default: current user)")
	apply := fs.Bool("apply", false, "write the files (default is a dry run)")
	emit := fs.String("emit", "", "write all configs into DIR for packaging (Intune/MDM)")
	fs.Parse(args)
	if *bin == "" {
		exe, _ := os.Executable()
		*bin, _ = filepath.Abs(exe)
	}
	o := core.InstallOptions{Roots: rootsFrom(*home), Agents: agentSet(*agents), Scope: *scope, Bin: *bin, OS: *targetOS}
	plans, err := core.Plan(o)
	if err != nil {
		return err
	}
	switch {
	case *emit != "":
		files, err := core.Emit(plans, *emit)
		for _, f := range files {
			fmt.Println("wrote", f)
		}
		return err
	case *apply:
		done, err := core.Apply(plans, *bin)
		for _, f := range done {
			fmt.Println("installed", f)
		}
		for _, p := range plans {
			if p.Note != "" {
				fmt.Printf("  [%s] %s\n", p.Agent, p.Note)
			}
		}
		fmt.Println("live log:", core.LiveLogPath(o.Roots))
		return err
	default:
		for _, p := range plans {
			verb := "write"
			if p.Merge {
				verb = "merge into"
			}
			vs := core.VendorFor(p.Agent)
			fmt.Printf("── %s: %s %s  [%s]\n%s", p.Agent, verb, p.Path, vs.Status, p.Content)
			if p.Note != "" {
				fmt.Printf("   note: %s\n", p.Note)
			}
			fmt.Println()
		}
		fmt.Println("dry run. Re-run with --apply to install, or --emit DIR to package.")
		return nil
	}
}

// ------------------------------------------------------------------ report / verify

func limitFlags(fs *flag.FlagSet) *core.BundleLimits {
	l := core.DefaultBundleLimits
	fs.IntVar(&l.MaxEntries, "max-entries", l.MaxEntries, "bundle: maximum number of zip entries")
	fs.Int64Var(&l.MaxEntryBytes, "max-entry-bytes", l.MaxEntryBytes, "bundle: maximum uncompressed size of one entry")
	fs.Int64Var(&l.MaxTotalBytes, "max-total-bytes", l.MaxTotalBytes, "bundle: maximum total uncompressed size")
	return &l
}

func isBundle(p string) bool { return strings.HasSuffix(strings.ToLower(p), ".zip") }

func loadInputs(paths, targets []string, lim core.BundleLimits) (core.ReportData, bool, error) {
	d := core.ReportData{LiveChains: map[string]core.ChainReport{}, Generated: time.Now().UTC(), Targets: targets}
	var evs []core.Event
	ok := true
	for _, p := range paths {
		if isBundle(p) {
			e, m, srcs, chk, err := core.LoadBundle(p, lim)
			if err != nil {
				return d, false, fmt.Errorf("%s: %w", p, err)
			}
			ok = ok && chk.OK()
			d.Bundles = append(d.Bundles, core.BundleInfo{Path: p, Manifest: m, Check: chk})
			d.Sources = append(d.Sources, srcs...)
			evs = append(evs, e...)
			continue
		}
		e, rep := core.ReadLiveLog(p)
		d.LiveChains[p] = rep
		ok = ok && rep.OK()
		evs = append(evs, e...)
	}
	d.TotalSteps = len(evs)
	d.Sessions, d.Findings, d.Alerts = core.BuildReport(evs, targets)
	return d, ok, nil
}

func cmdReport(args []string) int {
	fs := flag.NewFlagSet("report", flag.ExitOnError)
	var traces multi
	fs.Var(&traces, "trace", "path, file name or string to trace (repeatable)")
	out := fs.String("o", "afr-report.html", "output HTML")
	title := fs.String("title", "Agent activity reconstruction", "report title")
	lim := limitFlags(fs)
	inputs := reorder(fs, args)
	if len(inputs) == 0 {
		fmt.Fprintln(os.Stderr, "afr: give at least one bundle (.zip) or live log (.jsonl)")
		return 1
	}
	d, ok, err := loadInputs(inputs, traces, *lim)
	if err != nil {
		fmt.Fprintln(os.Stderr, "afr:", err)
		return 1
	}
	d.Title = *title
	f, err := os.Create(*out)
	if err != nil {
		fmt.Fprintln(os.Stderr, "afr:", err)
		return 1
	}
	if err := core.RenderHTML(f, d); err != nil {
		f.Close()
		fmt.Fprintln(os.Stderr, "afr:", err)
		return 1
	}
	if err := f.Close(); err != nil {
		fmt.Fprintln(os.Stderr, "afr:", err)
		return 1
	}
	fmt.Fprintf(os.Stderr, "%d record stream(s), %d step(s), %d trace finding(s), %d alert(s)\n", len(d.Sessions), d.TotalSteps, len(d.Findings), len(d.Alerts))
	for _, fd := range d.Findings {
		fmt.Fprintf(os.Stderr, "\n[%s] %s session %s (%s)\n", fd.Target, fd.Agent, fd.SessionID, fd.Host)
		for _, s := range fd.Summary {
			fmt.Fprintln(os.Stderr, "  "+s)
		}
	}
	fmt.Println(*out)
	if !ok {
		fmt.Fprintln(os.Stderr, "\nwarning: one or more inputs failed verification; see the report header or run afr verify")
		return 2
	}
	return 0
}

// reorder lets flags appear after positional args (afr report b.zip --trace x).
func reorder(fs *flag.FlagSet, args []string) []string {
	var pos []string
	for len(args) > 0 {
		fs.Parse(args)
		args = fs.Args()
		if len(args) > 0 {
			pos = append(pos, args[0])
			args = args[1:]
		}
	}
	return pos
}

func cmdVerify(args []string) int {
	fs := flag.NewFlagSet("verify", flag.ExitOnError)
	cpFlag := fs.String("checkpoint", "", "RECORDS:HASH retained independently (from afr checkpoint); detects tail deletion and rewrites")
	lim := limitFlags(fs)
	inputs := reorder(fs, args)
	if len(inputs) == 0 {
		fmt.Fprintln(os.Stderr, "afr: verify needs at least one bundle (.zip) or live log (.jsonl)")
		return 1
	}
	var cp *core.Checkpoint
	if *cpFlag != "" {
		c, err := core.ParseCheckpoint(*cpFlag)
		if err != nil {
			fmt.Fprintln(os.Stderr, "afr:", err)
			return 1
		}
		cp = &c
	}
	bad := false
	for _, p := range inputs {
		if isBundle(p) {
			_, m, _, chk, err := core.LoadBundle(p, *lim)
			if err != nil {
				bad = true
				fmt.Printf("FAILED   %s\n         not a readable zip: %v\n", p, err)
				continue
			}
			state := "OK"
			if !chk.OK() {
				state, bad = "FAILED", true
			}
			fmt.Printf("%-8s %s\n", state, p)
			fmt.Printf("         checksums: %s\n", map[bool]string{true: "consistent with manifest", false: "NOT consistent"}[chk.ChecksumConsistent])
			for _, pr := range chk.Problems {
				fmt.Println("         problem:", pr)
			}
			if chk.Live != nil {
				fmt.Printf("         live log (recomputed from bundle bytes): %s, %s\n", chk.Live.Status, chk.Live.Detail)
			}
			if m != nil {
				fmt.Printf("         collection: %s; %d source(s) with parse issues\n", m.Status, chk.ParseIssues)
			}
			fmt.Println("         origin: not authenticated; a consistent bundle does not prove who collected it")
			continue
		}
		evs, rep := core.ReadLiveLog(p)
		if cp != nil {
			core.ApplyCheckpoint(evs, &rep, *cp)
		}
		if !rep.OK() {
			bad = true
		}
		fmt.Printf("%-8s %s (%d records)\n         %s\n", strings.ToUpper(rep.Status), p, rep.Records, rep.Detail)
		if rep.Checkpoint != "" {
			fmt.Println("         checkpoint:", rep.Checkpoint)
		}
		for _, b := range rep.Breaks {
			fmt.Println("        ", b)
		}
	}
	if bad {
		return 2
	}
	return 0
}

func cmdCheckpoint(args []string) int {
	if len(args) != 1 {
		fmt.Fprintln(os.Stderr, "afr: checkpoint takes exactly one live log")
		return 1
	}
	_, rep := core.ReadLiveLog(args[0])
	if rep.Status != core.ChainConsistent {
		fmt.Fprintf(os.Stderr, "afr: log is %s (%s); not taking a checkpoint from it\n", rep.Status, rep.Detail)
		return 2
	}
	fmt.Printf("%d:%s\n", rep.Records, rep.HeadHash)
	fmt.Fprintln(os.Stderr, "Store this value somewhere the log's writer cannot change (ticket, SIEM, another host). Later: afr verify LOG --checkpoint <value>")
	return 0
}

func cmdDiscover(args []string) error {
	fs := flag.NewFlagSet("discover", flag.ExitOnError)
	home := fs.String("home", "", "profile directory")
	fs.Parse(args)
	r := rootsFrom(*home)
	srcs := core.Discover(r, nil)
	if len(srcs) == 0 {
		fmt.Println("no agent artifacts found under", r.Home)
	}
	for _, s := range srcs {
		fmt.Printf("%-15s %-17s %10d  %s  %s\n", s.Agent, s.Parser, s.Size, s.ModTime, s.Path)
	}
	lp := core.LiveLogPath(r)
	if st, err := os.Stat(lp); err == nil {
		fmt.Printf("%-15s %-17s %10d  %s  %s\n", "afr-live", "live", st.Size(), st.ModTime().UTC().Format(time.RFC3339), lp)
	}
	return nil
}
