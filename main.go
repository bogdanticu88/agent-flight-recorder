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
               [--case INC0012345] [--home DIR] [--workspace DIR] [--include-raw] [-o FILE]
  afr report   BUNDLE.zip|events.jsonl ... [--trace PATH]... [-o report.html]
  afr verify   BUNDLE.zip|events.jsonl ...
  afr discover [--home DIR]

Live (before the next one):
  afr install  --bin PATH [--scope user|machine] [--agents ...] [--os windows|darwin|linux]
               [--apply | --emit DIR]
  afr hook     --agent NAME [--event NAME]     (called by the agent, reads JSON on stdin)

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
		err = cmdCollect(args)
	case "hook":
		cmdHook(args) // never returns an error to the agent
	case "install":
		err = cmdInstall(args)
	case "report":
		err = cmdReport(args)
	case "verify":
		err = cmdVerify(args)
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

func cmdCollect(args []string) error {
	fs := flag.NewFlagSet("collect", flag.ExitOnError)
	from := fs.String("from", "", "window start")
	to := fs.String("to", "", "window end")
	around := fs.String("around", "", "alert time; window is --margin either side")
	margin := fs.Duration("margin", 2*time.Hour, "window half-width when using --around")
	last := fs.Duration("last", 0, "window = now minus this duration")
	agents := fs.String("agents", "all", "comma-separated agents or 'all'")
	mode := fs.String("mode", "user", "soc | user (who is running the collection)")
	caseID := fs.String("case", "", "incident / ticket number")
	home := fs.String("home", "", "profile directory to examine (default: current user; use for mounted images)")
	raw := fs.Bool("include-raw", false, "also copy raw, UNREDACTED source files (SOC only)")
	noRedact := fs.Bool("no-redact", false, "disable secret redaction (not recommended)")
	out := fs.String("o", "", "output bundle path (default afr-<host>-<time>.zip)")
	var ws multi
	fs.Var(&ws, "workspace", "extra workspace folder whose agent instruction files to capture (repeatable)")
	fs.Parse(args)

	o := core.CollectOptions{Roots: rootsFrom(*home), Agents: agentSet(*agents), Mode: *mode, CaseID: *caseID,
		IncludeRaw: *raw, NoRedact: *noRedact, Workspaces: ws, Log: os.Stderr}
	var err error
	switch {
	case *around != "":
		t, e := parseWhen(*around)
		if e != nil {
			return e
		}
		o.From, o.To = t.Add(-*margin), t.Add(*margin)
	case *last > 0:
		o.From, o.To = time.Now().UTC().Add(-*last), time.Now().UTC()
	default:
		if o.From, err = parseWhen(*from); err != nil {
			return err
		}
		if o.To, err = parseWhen(*to); err != nil {
			return err
		}
	}
	if *out == "" {
		h, _ := os.Hostname()
		*out = fmt.Sprintf("afr-%s-%s.zip", h, time.Now().UTC().Format("20060102T150405Z"))
	}
	o.Out = *out
	hash, m, err := core.Collect(o)
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "\nbundle:  %s\nsha256:  %s\nsteps:   %d in %d session(s)\n", o.Out, hash, m.Events, m.Sessions)
	if m.Events == 0 {
		fmt.Fprintln(os.Stderr, "note:    nothing in the window. Widen it (--margin / --last) or check --home.")
	}
	fmt.Println(o.Out)
	return nil
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
		done, err := core.Apply(plans)
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
			fmt.Printf("── %s: %s %s\n%s", p.Agent, verb, p.Path, p.Content)
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

func loadInputs(paths []string) (core.ReportData, error) {
	d := core.ReportData{LiveChains: map[string]core.ChainReport{}, Generated: time.Now().UTC()}
	var evs []core.Event
	allOK := true
	for _, p := range paths {
		if strings.HasSuffix(strings.ToLower(p), ".zip") {
			e, m, srcs, _, err := core.LoadBundle(p)
			if err != nil {
				return d, fmt.Errorf("%s: %w", p, err)
			}
			probs, _ := core.VerifyBundle(p)
			d.Integrity = append(d.Integrity, probs...)
			if len(probs) > 0 {
				allOK = false
			}
			if d.Manifest == nil {
				d.Manifest = m
			}
			if m.LiveChain != nil {
				d.LiveChains[filepath.Base(p)+":live/events.jsonl"] = *m.LiveChain
			}
			d.Sources = append(d.Sources, srcs...)
			evs = append(evs, e...)
			continue
		}
		e, rep := core.ReadLiveLog(p)
		d.LiveChains[p] = rep
		evs = append(evs, e...)
	}
	d.Verified = d.Manifest != nil && allOK
	d.TotalSteps = len(evs)
	d.Sessions, d.Findings, d.Alerts = core.BuildReport(evs, d.Targets)
	return d, nil
}

func cmdReport(args []string) error {
	fs := flag.NewFlagSet("report", flag.ExitOnError)
	var traces multi
	fs.Var(&traces, "trace", "path or file name to trace (repeatable), e.g. the honeypot")
	out := fs.String("o", "afr-report.html", "output HTML")
	title := fs.String("title", "Agent activity reconstruction", "report title")
	inputs := reorder(fs, args)
	if len(inputs) == 0 {
		return fmt.Errorf("give at least one bundle (.zip) or live log (.jsonl)")
	}
	d, err := loadInputsWithTargets(inputs, traces)
	if err != nil {
		return err
	}
	d.Title = *title
	f, err := os.Create(*out)
	if err != nil {
		return err
	}
	defer f.Close()
	if err := core.RenderHTML(f, d); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "%d session(s), %d step(s), %d trace finding(s), %d alert(s)\n", len(d.Sessions), d.TotalSteps, len(d.Findings), len(d.Alerts))
	for _, fd := range d.Findings {
		fmt.Fprintf(os.Stderr, "\n[%s] %s session %s\n  %s\n", fd.Target, fd.Agent, fd.SessionID, fd.Verdict)
	}
	fmt.Println(*out)
	return nil
}

func loadInputsWithTargets(inputs, targets []string) (core.ReportData, error) {
	d, err := loadInputs(inputs)
	if err != nil {
		return d, err
	}
	if len(targets) > 0 { // rebuild with trace targets
		var evs []core.Event
		for _, s := range d.Sessions {
			evs = append(evs, s.Steps...)
		}
		d.Targets = targets
		d.Sessions, d.Findings, d.Alerts = core.BuildReport(evs, targets)
	}
	return d, nil
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

func cmdVerify(args []string) error {
	bad := false
	for _, p := range args {
		if strings.HasSuffix(strings.ToLower(p), ".zip") {
			probs, err := core.VerifyBundle(p)
			if err != nil {
				return err
			}
			if len(probs) == 0 {
				fmt.Printf("OK      %s\n", p)
			} else {
				bad = true
				fmt.Printf("FAILED  %s\n", p)
				for _, pr := range probs {
					fmt.Println("        ", pr)
				}
			}
			continue
		}
		_, rep := core.ReadLiveLog(p)
		fmt.Printf("%-7s %s (%d records)\n", strings.ToUpper(rep.Status), p, rep.Records)
		for _, b := range rep.Breaks {
			fmt.Println("        ", b)
		}
		if rep.Status == "broken" {
			bad = true
		}
	}
	if bad {
		os.Exit(2)
	}
	return nil
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
