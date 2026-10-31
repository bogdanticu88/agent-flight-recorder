package core

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"
)

// ------------------------------------------------------------------ policy

// Rule protects a path pattern. Action "alert" records and lets the agent
// continue (right for canary files, which must still fire). "deny" blocks the
// tool call before it runs (right for real secrets like token files).
//
// Pattern matching is a string check over the recorded tool arguments. It is
// not a filesystem sandbox: symlinks, path aliases, environment variables,
// globbing in a shell, encodings and multi-step commands can all reach a file
// without its protected path appearing literally in the arguments.
type Rule struct {
	Pattern string `json:"pattern"` // glob on normalised path (** allowed) or plain substring
	Action  string `json:"action"`  // alert | deny
	Label   string `json:"label"`
}

// Policy configures the live recorder.
type Policy struct {
	LogPath        string `json:"log_path,omitempty"`
	MaxText        int    `json:"max_text,omitempty"`        // cap stored text per field after redaction (default 8000)
	CaptureResults *bool  `json:"capture_results,omitempty"` // store tool output text (default true)
	FailClosed     bool   `json:"fail_closed,omitempty"`     // deny pre-tool calls when the payload is malformed or recording fails
	Rules          []Rule `json:"rules,omitempty"`
}

// Policy origins, highest authority first.
const (
	PolicyManaged = "managed" // machine policy file, admin-controlled
	PolicyEnv     = "env"     // AFR_POLICY (only when no managed policy exists)
	PolicyUser    = "user"    // per-user policy file
	PolicyDefault = "default" // nothing configured: record only
)

// PolicyState is the result of resolving which policy applies and whether it loaded.
type PolicyState struct {
	Policy  Policy
	Origin  string
	Path    string
	Err     error    // set when a configured policy is unreadable or invalid
	OnError string   // deny | allow: what pre-tool calls get while Err is set
	Notes   []string // ignored overrides and similar
}

// machineDirOverride lets tests point the managed location at a temp dir.
var machineDirOverride string

func machineDir() string {
	if machineDirOverride != "" {
		return machineDirOverride
	}
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

// ManagedPolicyPath is the admin-controlled policy file.
func ManagedPolicyPath() string { return filepath.Join(machineDir(), "policy.json") }

// OnErrorMarkerPath holds the admin's choice for when a configured policy
// cannot be loaded: the single word "deny" or "allow". It is a separate file
// so the choice does not depend on parsing the file that just failed to parse.
func OnErrorMarkerPath() string { return filepath.Join(machineDir(), "on-policy-error") }

func userPolicyPath(r Roots) string { return filepath.Join(userStateDir(r), "policy.json") }

func onErrorAction() string {
	b, err := os.ReadFile(OnErrorMarkerPath())
	if err == nil && strings.TrimSpace(strings.ToLower(string(b))) == "deny" {
		return "deny"
	}
	return "allow"
}

// LoadPolicy resolves the policy with this precedence:
//
//  1. A managed (machine) policy, if the file exists. It is authoritative:
//     AFR_POLICY, AFR_LOG and the user policy are ignored.
//  2. Otherwise AFR_POLICY, if set.
//  3. Otherwise the user policy, if the file exists.
//  4. Otherwise the default: record everything, enforce nothing.
//
// A configured policy that cannot be read or does not validate is an error,
// never an empty policy. What pre-tool calls get in that case comes from the
// on-policy-error marker, not from the broken file.
func LoadPolicy(r Roots) PolicyState {
	st := PolicyState{OnError: onErrorAction()}
	mp := ManagedPolicyPath()
	if _, err := os.Stat(mp); err == nil || !errors.Is(err, fs.ErrNotExist) {
		st.Origin, st.Path = PolicyManaged, mp
		st.Policy, st.Err = readPolicy(mp)
		if os.Getenv("AFR_POLICY") != "" {
			st.Notes = append(st.Notes, "AFR_POLICY ignored: a managed policy is present")
		}
		if os.Getenv("AFR_LOG") != "" {
			st.Notes = append(st.Notes, "AFR_LOG ignored: a managed policy is present")
		}
		return st
	}
	if p := os.Getenv("AFR_POLICY"); p != "" {
		st.Origin, st.Path = PolicyEnv, p
		st.Policy, st.Err = readPolicy(p)
		return st
	}
	up := userPolicyPath(r)
	if _, err := os.Stat(up); err == nil || !errors.Is(err, fs.ErrNotExist) {
		st.Origin, st.Path = PolicyUser, up
		st.Policy, st.Err = readPolicy(up)
		return st
	}
	st.Origin = PolicyDefault
	return st
}

func readPolicy(path string) (Policy, error) {
	var p Policy
	b, err := os.ReadFile(path)
	if err != nil {
		return Policy{}, fmt.Errorf("policy %s unreadable: %w", path, err)
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&p); err != nil {
		return Policy{}, fmt.Errorf("policy %s invalid: %w", path, err)
	}
	if dec.More() {
		return Policy{}, fmt.Errorf("policy %s invalid: trailing data after the JSON object", path)
	}
	if err := p.Validate(); err != nil {
		return Policy{}, fmt.Errorf("policy %s invalid: %w", path, err)
	}
	return p, nil
}

// Validate checks limits and rule shapes.
func (p Policy) Validate() error {
	if p.MaxText != 0 && (p.MaxText < 256 || p.MaxText > 1<<20) {
		return fmt.Errorf("max_text %d out of range (256..1048576, or 0 for the default)", p.MaxText)
	}
	if len(p.Rules) > 10000 {
		return fmt.Errorf("%d rules, limit is 10000", len(p.Rules))
	}
	for i, r := range p.Rules {
		switch {
		case strings.TrimSpace(r.Pattern) == "":
			return fmt.Errorf("rule %d: empty pattern", i)
		case len(r.Pattern) > 4096:
			return fmt.Errorf("rule %d: pattern longer than 4096 bytes", i)
		case r.Action != "alert" && r.Action != "deny":
			return fmt.Errorf("rule %d: action %q, must be \"alert\" or \"deny\"", i, r.Action)
		case len(r.Label) > 200:
			return fmt.Errorf("rule %d: label longer than 200 bytes", i)
		}
	}
	return nil
}

func userStateDir(r Roots) string {
	if runtime.GOOS == "windows" || strings.Contains(r.LocalAppData, "AppData") && dirExists(r.LocalAppData) {
		return filepath.Join(r.LocalAppData, "AgentFlightRecorder")
	}
	return filepath.Join(r.Home, ".local", "state", "afr")
}

func dirExists(p string) bool { st, err := os.Stat(p); return err == nil && st.IsDir() }

// LiveLogPathFor resolves where the recorder writes. A managed policy decides
// it outright; AFR_LOG is honoured only when no managed policy exists.
func LiveLogPathFor(st PolicyState, r Roots) string {
	if st.Origin == PolicyManaged {
		if st.Err == nil && st.Policy.LogPath != "" {
			return expandUser(st.Policy.LogPath, r)
		}
		return filepath.Join(userStateDir(r), "events.jsonl")
	}
	if e := os.Getenv("AFR_LOG"); e != "" {
		return e
	}
	if st.Err == nil && st.Policy.LogPath != "" {
		return expandUser(st.Policy.LogPath, r)
	}
	return filepath.Join(userStateDir(r), "events.jsonl")
}

// LiveLogPath is LiveLogPathFor with the policy resolved for r.
func LiveLogPath(r Roots) string { return LiveLogPathFor(LoadPolicy(r), r) }

func expandUser(p string, r Roots) string {
	p = strings.ReplaceAll(p, "%USERNAME%", filepath.Base(r.Home))
	p = strings.ReplaceAll(p, "${USER}", filepath.Base(r.Home))
	if strings.HasPrefix(p, "~") {
		p = filepath.Join(r.Home, p[1:])
	}
	return os.ExpandEnv(p)
}

// Match returns every rule that matches the event, deny rules first, then in
// policy order. Deny always takes precedence over alert, wherever it appears.
func (p Policy) Match(e Event) []Rule {
	cands := append([]string{}, e.Paths...)
	if e.Command != "" {
		cands = append(cands, e.Command)
	}
	if e.Input != "" {
		cands = append(cands, e.Input)
	}
	var deny, alert []Rule
	for _, r := range p.Rules {
		for _, c := range cands {
			if MatchPattern(r.Pattern, c) {
				if r.Action == "deny" {
					deny = append(deny, r)
				} else {
					alert = append(alert, r)
				}
				break
			}
		}
	}
	return append(deny, alert...)
}

// MatchPattern does glob matching on slash-normalised, lower-cased paths and
// falls back to substring for patterns without wildcards.
func MatchPattern(pattern, s string) bool {
	pn := strings.ToLower(filepath.ToSlash(strings.ReplaceAll(pattern, `\`, "/")))
	sn := strings.ToLower(strings.ReplaceAll(s, `\`, "/"))
	if !strings.ContainsAny(pn, "*?[") {
		return strings.Contains(sn, pn)
	}
	return globToRegex(pn).MatchString(sn)
}

// ------------------------------------------------------------------ hook

// HookResult is what goes back to the agent: stdout, stderr and exit code.
type HookResult struct {
	Stdout   string
	Stderr   string
	ExitCode int
}

// HookAgents are the agent identifiers the hook accepts. Each one speaks a
// different response protocol, so an unknown name cannot be answered safely.
var HookAgents = map[string]bool{"copilot": true, "claude-code": true, "codex": true, "cursor": true, "gemini-cli": true, "opencode": true}

// MaxHookPayload bounds what is read from stdin.
const MaxHookPayload = 16 << 20

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

// normaliseRaw turns a vendor hook payload into a complete Event: nothing is
// redacted or truncated, so policy sees exactly what the agent sent.
func normaliseRaw(agent, eventName string, m map[string]any, captureResults bool) Event {
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

	switch e.Kind {
	case KindPrompt:
		e.Text = Str(m, "prompt", "initialPrompt", "initial_prompt", "user_prompt", "message")
		if e.Text == "" {
			e.Text = textOf(m["llm_request"])
		}
	case KindToolResult:
		e.Status = liveResultStatus(agent, eventName, m)
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
	return e
}

// liveResultStatus applies what each vendor documents about its post-tool event.
func liveResultStatus(agent, eventName string, m map[string]any) string {
	ev := strings.ToLower(eventName)
	if ev == "posttoolusefailure" {
		return StatusError
	}
	switch agent {
	case "claude-code", "cursor":
		if ev == "posttooluse" { // documented to fire after a successful call
			return StatusSuccess
		}
	case "copilot":
		if tr, ok := m["toolResult"].(map[string]any); ok {
			return NormStatus(tr["resultType"])
		}
	case "gemini-cli":
		if tr, ok := Decode(m["tool_response"]).(map[string]any); ok && tr["error"] != nil {
			return StatusError
		}
	}
	return ""
}

// NormaliseHook returns the event exactly as it would be persisted:
// redacted first, then truncated.
func NormaliseHook(agent, eventName string, raw []byte, pol Policy) (Event, error) {
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		return Event{}, fmt.Errorf("hook payload is not a JSON object: %w", err)
	}
	e := normaliseRaw(agent, eventName, m, pol.CaptureResults == nil || *pol.CaptureResults)
	RedactEvent(&e)
	TruncateEvent(&e, maxText(pol))
	return e, nil
}

func maxText(p Policy) int {
	if p.MaxText > 0 {
		return p.MaxText
	}
	return 8000
}

// RunHook is the whole live path. Order of operations:
//
//  1. validate the agent name and resolve the policy (errors are explicit)
//  2. read and decode the payload under a size limit
//  3. evaluate rules against the complete, unredacted event
//  4. redact, then truncate, then append to the chained log
//  5. answer in the agent's protocol, saying whether the record was written
//
// Anything that goes wrong is recorded where possible and reported on stderr.
// Pre-tool calls are denied on failure only when policy says so: fail_closed
// for payload and recording problems, the on-policy-error marker when the
// policy itself cannot be loaded.
func RunHook(agent, eventName string, stdin io.Reader, r Roots) HookResult {
	if !HookAgents[agent] {
		return HookResult{Stderr: fmt.Sprintf("afr: unknown agent %q (expected one of %s); nothing recorded", agent, strings.Join(sortedKeys(HookAgents), ", ")), ExitCode: 1}
	}
	st := LoadPolicy(r)
	pol := st.Policy
	logPath := LiveLogPathFor(st, r)
	var problems []string
	problems = append(problems, st.Notes...)

	raw, rerr := io.ReadAll(io.LimitReader(stdin, MaxHookPayload+1))
	var payloadErr error
	switch {
	case rerr != nil:
		payloadErr = fmt.Errorf("reading payload: %w", rerr)
	case len(raw) > MaxHookPayload:
		payloadErr = fmt.Errorf("payload larger than %d bytes", MaxHookPayload)
	}
	var m map[string]any
	if payloadErr == nil {
		if err := json.Unmarshal(raw, &m); err != nil || m == nil {
			payloadErr = fmt.Errorf("payload is not a JSON object")
		}
	}
	if eventName == "" && m != nil {
		eventName = Str(m, "hook_event_name", "hookEventName", "event", "eventName")
	}
	pre := isPreEvent(eventName)

	var e Event
	if payloadErr == nil {
		e = normaliseRaw(agent, eventName, m, pol.CaptureResults == nil || *pol.CaptureResults)
		if pre && e.Tool == "" && e.Input == "" {
			payloadErr = fmt.Errorf("pre-tool payload has neither a tool name nor tool input")
		}
	}
	if payloadErr != nil {
		// keep the event shape we have, but never persist undecoded payload bytes
		e = Event{Agent: agent, Origin: "live", Source: eventName, TS: time.Now().UTC(), Kind: KindOther,
			SessionID: e.SessionID, Tool: e.Tool, CallID: e.CallID}
		if pre {
			e.Kind = KindToolCall
		}
		problems = append(problems, "malformed payload: "+payloadErr.Error())
	}
	host, _ := os.Hostname()
	e.Host = host
	if u, err := user.Current(); err == nil {
		e.User = u.Username
	}

	deny := false
	var denyWhy string
	switch {
	case st.Err != nil:
		problems = append(problems, "policy error: "+st.Err.Error())
		if pre && st.OnError == "deny" {
			deny, denyWhy = true, "the security policy could not be loaded and this machine is set to deny tool calls in that case"
		}
	case payloadErr != nil:
		if pre && pol.FailClosed {
			deny, denyWhy = true, "the hook payload could not be validated and policy is fail-closed"
		}
	default:
		if hits := pol.Match(e); len(hits) > 0 {
			labels := make([]string, 0, len(hits))
			for _, h := range hits {
				labels = append(labels, h.Label)
			}
			if hits[0].Action == "deny" && pre {
				e.Decision = "deny"
				deny, denyWhy = true, "blocked by security policy ("+hits[0].Label+")"
			} else {
				e.Decision = "alert"
			}
			e.Reason = fmt.Sprintf("policy rules matched: %s", strings.Join(labels, "; "))
		}
	}
	if len(problems) > 0 {
		if e.Reason != "" {
			e.Reason += " | "
		}
		e.Reason += strings.Join(problems, " | ")
	}
	if deny && e.Decision == "" {
		e.Decision = "deny"
	}

	RedactEvent(&e)
	TruncateEvent(&e, maxText(pol))
	appendErr := AppendLive(logPath, &e, lockDir(r))
	var resumed *ChainResumedError
	if errors.As(appendErr, &resumed) {
		problems = append(problems, resumed.Error())
		appendErr = nil
	}

	if appendErr != nil && pre && pol.FailClosed && st.Err == nil && !deny {
		deny, denyWhy = true, "the call could not be recorded and policy is fail-closed"
	}
	var stderr []string
	for _, p := range problems {
		stderr = append(stderr, "afr: "+p)
	}
	if appendErr != nil {
		stderr = append(stderr, "afr: recording failed: "+appendErr.Error())
	}
	res := okResult(agent, eventName)
	if deny {
		msg := "Tool call denied: " + denyWhy + "."
		if appendErr == nil {
			msg += " This attempt was recorded."
		} else {
			msg += " Recording this attempt failed."
		}
		res = denyResult(agent, eventName, msg)
	}
	if len(stderr) > 0 {
		if res.Stderr != "" {
			stderr = append([]string{res.Stderr}, stderr...)
		}
		res.Stderr = strings.Join(stderr, "\n")
	}
	return res
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
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

// denyResult speaks each vendor's documented blocking protocol. See
// VendorSupport in install.go for the documentation each one was checked against.
func denyResult(agent, eventName, reason string) HookResult {
	j := func(v any) string { b, _ := json.Marshal(v); return string(b) }
	switch agent {
	case "copilot":
		return HookResult{Stdout: j(map[string]any{"permissionDecision": "deny", "permissionDecisionReason": reason})}
	case "claude-code", "codex":
		return HookResult{Stdout: j(map[string]any{"hookSpecificOutput": map[string]any{
			"hookEventName": "PreToolUse", "permissionDecision": "deny", "permissionDecisionReason": reason}})}
	case "cursor":
		return HookResult{Stdout: j(map[string]any{"permission": "deny", "user_message": reason, "agent_message": reason}), Stderr: reason, ExitCode: 2}
	default: // gemini-cli, opencode plugin: exit 2 + reason on stderr
		return HookResult{Stderr: reason, ExitCode: 2}
	}
}

// ------------------------------------------------------------------ chained log

// Windows access rights (icacls names) the recorder needs on its own log file:
// reading the last record to extend the chain, and appending. The deployment
// ACL in deploy/windows/Install-AFR.ps1 must grant exactly these and nothing
// that allows overwriting, deleting or re-permissioning the file.
var (
	LogReadRights   = []string{"RD", "RA", "REA", "RC", "S"}
	LogAppendRights = []string{"AD", "S"}
)

// lockDir is a directory the hook's user can always write to and delete from.
// The lock is kept out of the (possibly append-only) log directory.
func lockDir(r Roots) string { return filepath.Join(userStateDir(r), "locks") }

// AppendLive appends one event to the JSONL log with a hash chain. Several hook
// processes can fire at once (parallel tool calls), so appends take a lock file.
func AppendLive(path string, e *Event, lockDirectory string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	if lockDirectory == "" {
		lockDirectory = filepath.Dir(path)
	}
	if err := os.MkdirAll(lockDirectory, 0o700); err != nil {
		return err
	}
	sum := sha256.Sum256([]byte(path))
	unlock, err := lockFile(filepath.Join(lockDirectory, hex.EncodeToString(sum[:8])+".lock"))
	if err != nil {
		return err
	}
	defer unlock()
	prev, torn, needNL, err := lastHash(path)
	if err != nil {
		return err
	}
	e.PrevHash = prev
	if torn {
		e.PrevHash = TornTailPrevHash
	}
	e.Pos, e.Prov, e.Outcome, e.OutcomeNote = 0, "", "", ""
	e.Hash = e.ComputeHash()
	b, err := json.Marshal(e)
	if err != nil {
		return err
	}
	if needNL {
		b = append([]byte("\n"), b...)
	}
	f, err := openAppend(path)
	if err != nil {
		return err
	}
	if _, err := f.Write(append(b, '\n')); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if torn {
		return &ChainResumedError{Path: path}
	}
	return nil
}

// TornTailPrevHash is written as prev_hash when the log's last line could not
// be parsed (typically a writer killed mid-record). It is deliberately not a
// hash, so verification reports the break instead of hiding it.
const TornTailPrevHash = "unparseable-tail"

// ChainResumedError reports that a record was written after an unparseable
// tail. The record is on disk; the chain is visibly broken at that point.
type ChainResumedError struct{ Path string }

func (e *ChainResumedError) Error() string {
	return "the last line of " + e.Path + " was not a valid record (torn write or tampering); recording resumed and the chain break is marked"
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

// lastHash returns the hash of the last record ("" for a new or empty log),
// whether the last line is unparseable (torn), and whether the file lacks a
// final newline. A torn tail does not stop recording: stopping would turn one
// killed hook into a permanent loss of evidence. The caller marks the break.
func lastHash(path string) (hash string, torn, needNewline bool, err error) {
	f, err := os.Open(path)
	if errors.Is(err, fs.ErrNotExist) {
		return "", false, false, nil
	}
	if err != nil {
		return "", false, false, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return "", false, false, err
	}
	size := st.Size()
	if size == 0 {
		return "", false, false, nil
	}
	chunk := int64(1 << 20)
	if chunk > size {
		chunk = size
	}
	buf := make([]byte, chunk)
	if _, err := f.ReadAt(buf, size-chunk); err != nil && err != io.EOF {
		return "", false, false, err
	}
	needNewline = buf[len(buf)-1] != '\n'
	lines := bytes.Split(bytes.TrimRight(buf, "\n"), []byte("\n"))
	var e Event
	if err := json.Unmarshal(lines[len(lines)-1], &e); err != nil || e.Hash == "" {
		return "", true, needNewline, nil
	}
	return e.Hash, false, needNewline, nil
}

// Chain verification states.
const (
	ChainMissing    = "missing"    // no file at that path
	ChainUnreadable = "unreadable" // the file exists but could not be read completely
	ChainEmpty      = "empty"      // readable, no records
	ChainInvalid    = "invalid"    // malformed records
	ChainBroken     = "broken"     // a record's hash or link does not match
	ChainUnanchored = "unanchored" // internally consistent, but the first record points to a predecessor that is not present
	ChainConsistent = "consistent" // internally consistent from the genesis record
	ChainExcerpt    = "excerpt"    // an exported subset: each record's hash checks; links checked where records are adjacent
)

// ChainReport says what a live log does and does not establish.
type ChainReport struct {
	Status     string         `json:"status"`
	Detail     string         `json:"detail"`
	Records    int            `json:"records"`
	HeadHash   string         `json:"head_hash,omitempty"`
	Breaks     []string       `json:"breaks,omitempty"`
	Excerpt    *ExcerptHeader `json:"excerpt,omitempty"`
	Checkpoint string         `json:"checkpoint,omitempty"`
}

// OK reports whether the input is a complete, internally consistent log (or
// an empty one). An excerpt is never OK on its own: its records can match
// their hashes while records inside its window are missing. Bundles accept an
// excerpt only when their manifest declares one (see BundleCheck).
func (c ChainReport) OK() bool {
	return c.Status == ChainConsistent || c.Status == ChainEmpty
}

// ExcerptHeader is the first line of a windowed export of a live log. Records
// keep their original hashes; nothing is re-chained.
type ExcerptHeader struct {
	Version        int        `json:"version"`
	SourcePath     string     `json:"source_path"`
	SourceSHA256   string     `json:"source_sha256"`
	SourceRecords  int        `json:"source_records"`
	SourceHeadHash string     `json:"source_head_hash,omitempty"`
	SourceStatus   string     `json:"source_status"`
	WindowFrom     *time.Time `json:"window_from,omitempty"`
	WindowTo       *time.Time `json:"window_to,omitempty"`
	Records        int        `json:"records"`
}

// Checkpoint is an independently retained (records, head hash) pair. It is the
// only thing that lets verification detect deletion of the newest records or a
// full rewrite of the chain.
type Checkpoint struct {
	Records int
	Hash    string
}

// ParseCheckpoint reads "N:HASH".
func ParseCheckpoint(s string) (Checkpoint, error) {
	n, h, ok := strings.Cut(s, ":")
	var cp Checkpoint
	if !ok || h == "" {
		return cp, fmt.Errorf("checkpoint must be RECORDS:HASH")
	}
	if _, err := fmt.Sscanf(n, "%d", &cp.Records); err != nil || cp.Records < 1 {
		return cp, fmt.Errorf("checkpoint record count %q invalid", n)
	}
	if len(h) != 64 || strings.Trim(strings.ToLower(h), "0123456789abcdef") != "" {
		return cp, fmt.Errorf("checkpoint hash must be 64 hex characters")
	}
	cp.Hash = strings.ToLower(h)
	return cp, nil
}

// ReadLiveLog opens and verifies a live log or excerpt file.
func ReadLiveLog(path string) ([]Event, ChainReport) {
	f, err := os.Open(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, ChainReport{Status: ChainMissing, Detail: "no file at " + path}
	}
	if err != nil {
		return nil, ChainReport{Status: ChainUnreadable, Detail: err.Error()}
	}
	defer f.Close()
	evs, rep := VerifyLiveLog(f)
	for i := range evs {
		evs[i].Prov = path
	}
	return evs, rep
}

// VerifyLiveLog reads records from r and checks the chain. Positions are kept
// in Pos; hashed fields are left exactly as read.
func VerifyLiveLog(r io.Reader) ([]Event, ChainReport) {
	rep := ChainReport{}
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), maxLineBytes)
	var evs []Event
	var hdr *ExcerptHeader
	prev := ""
	line, malformed, contiguousBreaks, nonEmpty := 0, 0, 0, 0
	for sc.Scan() {
		line++
		b := bytes.TrimSpace(sc.Bytes())
		if len(b) == 0 {
			continue
		}
		nonEmpty++
		if nonEmpty == 1 && bytes.Contains(b, []byte(`"afr_excerpt"`)) {
			var w struct {
				H *ExcerptHeader `json:"afr_excerpt"`
			}
			if json.Unmarshal(b, &w) == nil && w.H != nil {
				hdr = w.H
				continue
			}
		}
		var e Event
		if err := json.Unmarshal(b, &e); err != nil || e.Hash == "" {
			malformed++
			rep.Breaks = append(rep.Breaks, fmt.Sprintf("line %d: not a chained record", line))
			prev = "\x00"
			continue
		}
		if e.ComputeHash() != e.Hash {
			rep.Breaks = append(rep.Breaks, fmt.Sprintf("line %d: content does not match its hash (record edited)", line))
		}
		if hdr != nil && ((hdr.WindowFrom != nil && e.TS.Before(*hdr.WindowFrom)) || (hdr.WindowTo != nil && e.TS.After(*hdr.WindowTo))) {
			rep.Breaks = append(rep.Breaks, fmt.Sprintf("line %d: record is outside the window the excerpt header declares", line))
		}
		switch {
		case len(evs) == 0:
			// first record: genesis check below
		case hdr != nil:
			if e.PrevHash != prev {
				contiguousBreaks++ // expected in an excerpt: records outside the window were left out
			}
		case e.PrevHash != prev:
			rep.Breaks = append(rep.Breaks, fmt.Sprintf("line %d: prev_hash does not match the record before it (record removed, reordered or inserted)", line))
		}
		prev = e.Hash
		e.Pos = line
		evs = append(evs, e)
	}
	rep.Records = len(evs)
	if len(evs) > 0 {
		rep.HeadHash = evs[len(evs)-1].Hash
	}
	if err := sc.Err(); err != nil {
		rep.Status = ChainUnreadable
		rep.Detail = fmt.Sprintf("reading stopped after line %d: %v", line, err)
		return evs, rep
	}
	if hdr != nil {
		rep.Excerpt = hdr
		if hdr.Records != len(evs) {
			rep.Breaks = append(rep.Breaks, fmt.Sprintf("excerpt header lists %d records, file holds %d", hdr.Records, len(evs)))
		}
	}
	switch {
	case malformed > 0:
		rep.Status = ChainInvalid
		rep.Detail = fmt.Sprintf("%d malformed record(s)", malformed)
	case len(rep.Breaks) > 0:
		rep.Status = ChainBroken
		rep.Detail = fmt.Sprintf("%d integrity problem(s)", len(rep.Breaks))
	case len(evs) == 0:
		rep.Status = ChainEmpty
		rep.Detail = "no records"
	case hdr != nil:
		rep.Status = ChainExcerpt
		rep.Detail = fmt.Sprintf("excerpt of %d record(s) said to come from %s. Each included record matches its own hash; %d gap(s) where records were omitted, and whether the omitted records really fell outside the window cannot be checked from the excerpt; the first record's predecessor is external. This is not a complete log and does not show that nothing in the window was left out. Header claims about the original (%s, %d record(s)) are as recorded by whoever wrote the excerpt.",
			len(evs), hdr.SourcePath, contiguousBreaks, hdr.SourceStatus, hdr.SourceRecords)
	case evs[0].PrevHash != "":
		rep.Status = ChainUnanchored
		rep.Detail = fmt.Sprintf("%d record(s) internally consistent, but the first record points to a predecessor that is not in this file (earlier records deleted, or the log was rotated)", len(evs))
	default:
		rep.Status = ChainConsistent
		rep.Detail = fmt.Sprintf("%d record(s) internally consistent from the first record. This does not show that newer records were not removed from the end, or that the whole chain was not rebuilt; that needs an independently kept checkpoint.", len(evs))
	}
	return evs, rep
}

// ApplyCheckpoint checks a log against an independently retained checkpoint.
// It is only evaluated on a log that is consistent from its genesis record;
// on anything else the record numbering cannot be trusted.
func ApplyCheckpoint(evs []Event, rep *ChainReport, cp Checkpoint) {
	switch {
	case rep.Excerpt != nil:
		rep.Checkpoint = "not evaluated: an excerpt cannot be checked against a checkpoint"
	case rep.Status != ChainConsistent:
		rep.Checkpoint = "not evaluated: the log is " + rep.Status
	case len(evs) < cp.Records:
		rep.Checkpoint = fmt.Sprintf("FAILED: log has %d record(s), checkpoint expects at least %d (records removed from the end)", len(evs), cp.Records)
		rep.Status = ChainBroken
	case evs[cp.Records-1].Hash != cp.Hash:
		rep.Checkpoint = fmt.Sprintf("FAILED: record %d does not match the checkpoint hash (log rewritten, or not the log the checkpoint was taken from)", cp.Records)
		rep.Status = ChainBroken
	default:
		rep.Checkpoint = fmt.Sprintf("matches the checkpoint at record %d", cp.Records)
	}
}
