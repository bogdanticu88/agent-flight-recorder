package core

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// ------------------------------------------------------------------ policy

// Rule protects a path pattern. Action "alert" records and lets the agent
// continue (right for honeypots, which must still fire). "deny" blocks the
// tool call before it runs (right for real secrets like token files).
type Rule struct {
	Pattern string `json:"pattern"` // glob on normalised path (** allowed) or plain substring
	Action  string `json:"action"`  // alert | deny
	Label   string `json:"label"`
}

// Policy configures the live recorder. Loaded from AFR_POLICY, then the
// machine-wide path, then the per-user path. Missing policy = record only.
type Policy struct {
	LogPath        string `json:"log_path,omitempty"`
	MaxText        int    `json:"max_text,omitempty"`        // cap stored text per field (default 8000)
	CaptureResults *bool  `json:"capture_results,omitempty"` // store tool output text (default true)
	FailClosed     bool   `json:"fail_closed,omitempty"`     // deny tool calls if the recorder itself errors
	Rules          []Rule `json:"rules,omitempty"`
}

func machineDir() string {
	switch runtime.GOOS {
	case "windows":
		pd := os.Getenv("ProgramData")
		if pd == "" {
			pd = `C:\ProgramData`
		}
		return filepath.Join(pd, "AgentFlightRecorder")
	case "darwin":
		return "/Library/Application Support/AgentFlightRecorder"
	default:
		return "/etc/afr"
	}
}

// PolicyPaths lists where policy is looked up, highest precedence first.
func PolicyPaths(r Roots) []string {
	var p []string
	if e := os.Getenv("AFR_POLICY"); e != "" {
		p = append(p, e)
	}
	p = append(p, filepath.Join(machineDir(), "policy.json"), filepath.Join(userStateDir(r), "policy.json"))
	return p
}

func LoadPolicy(r Roots) (Policy, string) {
	for _, p := range PolicyPaths(r) {
		b, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		var pol Policy
		if json.Unmarshal(b, &pol) == nil {
			return pol, p
		}
	}
	return Policy{}, ""
}

func userStateDir(r Roots) string {
	if runtime.GOOS == "windows" || strings.Contains(r.LocalAppData, "AppData") && dirExists(r.LocalAppData) {
		return filepath.Join(r.LocalAppData, "AgentFlightRecorder")
	}
	return filepath.Join(r.Home, ".local", "state", "afr")
}

func dirExists(p string) bool { st, err := os.Stat(p); return err == nil && st.IsDir() }

// LiveLogPath is where the hook recorder appends events for this user.
func LiveLogPath(r Roots) string {
	if e := os.Getenv("AFR_LOG"); e != "" {
		return e
	}
	if pol, _ := LoadPolicy(r); pol.LogPath != "" {
		return expandUser(pol.LogPath, r)
	}
	return filepath.Join(userStateDir(r), "events.jsonl")
}

func expandUser(p string, r Roots) string {
	p = strings.ReplaceAll(p, "%USERNAME%", filepath.Base(r.Home))
	p = strings.ReplaceAll(p, "${USER}", filepath.Base(r.Home))
	if strings.HasPrefix(p, "~") {
		p = filepath.Join(r.Home, p[1:])
	}
	return os.ExpandEnv(p)
}

// Match returns the first rule that matches any path or the command text.
func (p Policy) Match(e Event) (*Rule, string) {
	cands := append([]string{}, e.Paths...)
	if e.Command != "" {
		cands = append(cands, e.Command)
	}
	if e.Input != "" {
		cands = append(cands, e.Input)
	}
	for i := range p.Rules {
		r := &p.Rules[i]
		for _, c := range cands {
			if MatchPattern(r.Pattern, c) {
				return r, c
			}
		}
	}
	return nil, ""
}

// MatchPattern does glob matching on slash-normalised, lower-cased paths and
// falls back to substring for patterns without wildcards.
func MatchPattern(pattern, s string) bool {
	pn := strings.ToLower(filepath.ToSlash(strings.ReplaceAll(pattern, `\`, "/")))
	sn := strings.ToLower(strings.ReplaceAll(s, `\`, "/"))
	if !strings.ContainsAny(pn, "*?[") {
		return strings.Contains(sn, pn)
	}
	re := globToRegex(pn)
	return re.MatchString(sn)
}

// ------------------------------------------------------------------ hook

// HookResult is what goes back to the agent: stdout, stderr and exit code.
type HookResult struct {
	Stdout   string
	Stderr   string
	ExitCode int
}

var eventKinds = map[string]Kind{
	"sessionstart": KindSessionStart, "session.created": KindSessionStart,
	"sessionend": KindSessionEnd, "agentstop": KindSessionEnd, "stop": KindSessionEnd, "afteragent": KindSessionEnd, "session.idle": KindSessionEnd,
	"userpromptsubmitted": KindPrompt, "userpromptsubmit": KindPrompt, "beforesubmitprompt": KindPrompt, "beforeagent": KindPrompt, "prompt": KindPrompt,
	"pretooluse": KindToolCall, "beforetool": KindToolCall, "beforeshellexecution": KindToolCall, "beforereadfile": KindToolCall, "beforemcpexecution": KindToolCall,
	"posttooluse": KindToolResult, "aftertool": KindToolResult, "aftershellexecution": KindToolResult, "afterfileedit": KindToolResult, "aftermcpexecution": KindToolResult, "posttoolusefailure": KindToolResult,
	"afteragentresponse": KindResponse, "afteragentthought": KindReasoning,
	"subagentstart": KindOther, "subagentstop": KindOther, "precompact": KindOther, "precompress": KindOther, "notification": KindOther,
}

func isPreEvent(ev string) bool {
	switch strings.ToLower(ev) {
	case "pretooluse", "beforetool", "beforeshellexecution", "beforereadfile", "beforemcpexecution":
		return true
	}
	return false
}

// NormaliseHook turns a vendor hook payload into an Event. Vendors disagree on
// field names, so every known spelling is tried.
func NormaliseHook(agent, eventName string, raw []byte, pol Policy) (Event, error) {
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		return Event{}, fmt.Errorf("hook payload is not JSON: %w", err)
	}
	if eventName == "" {
		eventName = Str(m, "hook_event_name", "hookEventName", "event", "eventName")
	}
	e := Event{Agent: agent, Origin: "live", Source: eventName, TS: time.Now().UTC()}
	if ts, ok := ParseTime(m["timestamp"]); ok {
		e.TS = ts
	}
	e.Kind = eventKinds[strings.ToLower(eventName)]
	if e.Kind == "" {
		e.Kind = KindOther
	}
	e.SessionID = Str(m, "session_id", "sessionId", "sessionID", "conversation_id", "thread_id")
	e.Cwd = Str(m, "cwd", "workspace", "directory")
	if wr, ok := m["workspace_roots"].([]any); ok && e.Cwd == "" && len(wr) > 0 {
		e.Cwd, _ = wr[0].(string)
	}
	e.Model = Str(m, "model", "model_name")
	e.CallID = Str(m, "tool_use_id", "toolCallId", "call_id", "callID", "tool_call_id")
	e.Tool = Str(m, "tool_name", "toolName", "tool")

	var input any
	for _, k := range []string{"tool_input", "toolArgs", "tool_args", "toolInput", "input", "args", "arguments"} {
		if v, ok := m[k]; ok && v != nil {
			input = Decode(v)
			break
		}
	}
	// Cursor's dedicated shell/file hooks carry the fields at top level
	if c := Str(m, "command"); c != "" && input == nil {
		input = map[string]any{"command": c}
		if e.Tool == "" {
			e.Tool = "shell"
		}
	}
	if fp := Str(m, "file_path", "filePath"); fp != "" && input == nil {
		input = map[string]any{"file_path": fp}
		if e.Tool == "" {
			e.Tool = map[bool]string{true: "read_file", false: "edit_file"}[strings.HasPrefix(strings.ToLower(eventName), "before")]
		}
	}
	if input != nil {
		e.Input = JSONString(input)
		e.Command = CommandFrom(input)
	}

	captureResults := pol.CaptureResults == nil || *pol.CaptureResults
	switch e.Kind {
	case KindPrompt:
		e.Text = Str(m, "prompt", "initialPrompt", "initial_prompt", "user_prompt", "message")
		if e.Text == "" {
			e.Text = textOf(m["llm_request"])
		}
	case KindToolResult:
		if captureResults {
			for _, k := range []string{"tool_response", "toolResult", "tool_output", "output", "result", "error"} {
				if v, ok := m[k]; ok && v != nil {
					t := textOf(Decode(v))
					if t == "" {
						t = JSONString(v)
					}
					e.Text = t
					break
				}
			}
		}
	case KindResponse, KindReasoning:
		e.Text = Str(m, "text", "response", "prompt_response", "last_assistant_message")
	case KindSessionStart:
		e.Text = "source=" + Str(m, "source", "reason") + " " + Str(m, "initialPrompt", "initial_prompt")
	case KindSessionEnd:
		e.Text = Str(m, "reason", "stop_reason", "last_assistant_message", "prompt_response")
	}
	if tp := Str(m, "transcript_path", "transcriptPath"); tp != "" {
		e.SourceRef = tp // pointer to the vendor transcript for later offline collection
	}
	e.Paths = ExtractPaths(input, map[bool]string{true: e.Text}[e.Kind == KindToolResult || e.Kind == KindPrompt])
	max := pol.MaxText
	if max <= 0 {
		max = 8000
	}
	e.Text = Truncate(e.Text, max)
	e.Input = Truncate(e.Input, max)
	RedactEvent(&e)
	return e, nil
}

// RunHook is the whole live path: normalise, apply policy, append to the
// chained log, and answer the agent in its own dialect. It never panics the
// agent: any recorder error results in "no decision" unless fail_closed.
func RunHook(agent, eventName string, stdin io.Reader, r Roots) HookResult {
	pol, _ := LoadPolicy(r)
	raw, _ := io.ReadAll(io.LimitReader(stdin, 64<<20))
	e, err := NormaliseHook(agent, eventName, raw, pol)
	if err != nil {
		return failResult(agent, eventName, pol, err)
	}
	host, _ := os.Hostname()
	e.Host = host
	if u, err := user.Current(); err == nil {
		e.User = u.Username
	}
	eventName = e.Source // may have come from the payload rather than --event
	var deny *Rule
	if rule, hit := pol.Match(e); rule != nil {
		action := strings.ToLower(rule.Action)
		if action == "deny" && isPreEvent(eventName) {
			e.Decision = "deny"
			deny = rule
		} else {
			e.Decision = "alert"
		}
		e.Reason = fmt.Sprintf("policy rule %q (%s) matched %s", rule.Label, rule.Pattern, Truncate(hit, 300))
	}
	if err := AppendLive(LiveLogPath(r), &e); err != nil {
		res := failResult(agent, eventName, pol, err)
		if deny == nil {
			return res
		}
	}
	if deny != nil {
		return denyResult(agent, eventName, "Blocked by security policy ("+deny.Label+"). This access has been logged.")
	}
	return okResult(agent, eventName)
}

func failResult(agent, eventName string, pol Policy, err error) HookResult {
	if pol.FailClosed && isPreEvent(eventName) {
		return denyResult(agent, eventName, "Agent flight recorder unavailable and policy is fail-closed: "+err.Error())
	}
	res := okResult(agent, eventName)
	res.Stderr = "afr: " + err.Error()
	return res
}

func okResult(agent, eventName string) HookResult {
	switch {
	case agent == "cursor" && strings.EqualFold(eventName, "beforeSubmitPrompt"):
		return HookResult{Stdout: `{"continue":true}`}
	case agent == "copilot" || agent == "cursor":
		return HookResult{Stdout: "{}"}
	}
	return HookResult{}
}

// denyResult speaks each vendor's blocking protocol.
func denyResult(agent, eventName, reason string) HookResult {
	j := func(v any) string { b, _ := json.Marshal(v); return string(b) }
	switch agent {
	case "copilot":
		return HookResult{Stdout: j(map[string]any{"permissionDecision": "deny", "permissionDecisionReason": reason})}
	case "claude-code":
		return HookResult{Stdout: j(map[string]any{"hookSpecificOutput": map[string]any{
			"hookEventName": "PreToolUse", "permissionDecision": "deny", "permissionDecisionReason": reason}})}
	case "cursor":
		return HookResult{Stdout: j(map[string]any{"permission": "deny", "user_message": reason, "agent_message": reason}), Stderr: reason, ExitCode: 2}
	case "gemini-cli":
		return HookResult{Stdout: j(map[string]any{"decision": "deny", "reason": reason}), Stderr: reason, ExitCode: 2}
	default: // codex, opencode plugin, anything Claude-compatible: exit 2 + reason on stderr
		return HookResult{Stderr: reason, ExitCode: 2}
	}
}

// ------------------------------------------------------------------ chained log

// AppendLive appends one event to the JSONL log with a hash chain. Several hook
// processes can fire at once (parallel tool calls), so appends take a lock file.
func AppendLive(path string, e *Event) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	unlock, err := lockFile(path + ".lock")
	if err != nil {
		return err
	}
	defer unlock()
	e.PrevHash = lastHash(path)
	e.Hash = e.ComputeHash()
	b, err := json.Marshal(e)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.Write(append(b, '\n'))
	return err
}

func lockFile(p string) (func(), error) {
	deadline := time.Now().Add(3 * time.Second)
	for {
		f, err := os.OpenFile(p, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err == nil {
			f.Close()
			return func() { os.Remove(p) }, nil
		}
		if st, serr := os.Stat(p); serr == nil && time.Since(st.ModTime()) > 15*time.Second {
			os.Remove(p) // stale lock from a killed process
			continue
		}
		if time.Now().After(deadline) {
			return nil, errors.New("could not lock " + p)
		}
		time.Sleep(15 * time.Millisecond)
	}
}

func lastHash(path string) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	st, _ := f.Stat()
	size := st.Size()
	if size == 0 {
		return ""
	}
	chunk := int64(256 * 1024)
	if chunk > size {
		chunk = size
	}
	buf := make([]byte, chunk)
	if _, err := f.ReadAt(buf, size-chunk); err != nil && err != io.EOF {
		return ""
	}
	lines := bytes.Split(bytes.TrimRight(buf, "\n"), []byte("\n"))
	var e Event
	if json.Unmarshal(lines[len(lines)-1], &e) == nil {
		return e.Hash
	}
	return "BROKEN"
}

// ChainReport says whether a live log is intact.
type ChainReport struct {
	Records int      `json:"records"`
	Status  string   `json:"status"` // intact | broken | empty
	Breaks  []string `json:"breaks,omitempty"`
}

// ReadLiveLog parses a live log and verifies the hash chain.
func ReadLiveLog(path string) ([]Event, ChainReport) {
	f, err := os.Open(path)
	rep := ChainReport{Status: "empty"}
	if err != nil {
		return nil, rep
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1024*1024), 128*1024*1024)
	var evs []Event
	prev := ""
	n := 0
	for sc.Scan() {
		n++
		if len(bytes.TrimSpace(sc.Bytes())) == 0 {
			continue
		}
		var e Event
		if err := json.Unmarshal(sc.Bytes(), &e); err != nil {
			rep.Breaks = append(rep.Breaks, fmt.Sprintf("line %d: not valid JSON", n))
			prev = "BROKEN"
			continue
		}
		if e.PrevHash != prev && !(prev == "" && n == 1) {
			rep.Breaks = append(rep.Breaks, fmt.Sprintf("line %d: prev_hash does not match line before (record removed, reordered or edited)", n))
		}
		if e.ComputeHash() != e.Hash {
			rep.Breaks = append(rep.Breaks, fmt.Sprintf("line %d: content hash mismatch (record edited)", n))
		}
		prev = e.Hash
		e.Seq = n
		evs = append(evs, e)
	}
	rep.Records = len(evs)
	switch {
	case len(rep.Breaks) > 0:
		rep.Status = "broken"
	case len(evs) > 0:
		rep.Status = "intact"
	}
	return evs, rep
}
