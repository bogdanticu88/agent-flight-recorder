// Package core holds the normalised event model, the per-agent adapters,
// the offline collector, the live hook recorder and the report builder.
package core

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

// Version is stamped into every manifest and live event.
const Version = "0.2.0"

// Kind is the normalised type of a step in an agent session.
type Kind string

const (
	KindSessionStart Kind = "session_start"
	KindSessionEnd   Kind = "session_end"
	KindPrompt       Kind = "prompt"      // what the human asked
	KindContext      Kind = "context"     // instructions/attachments loaded into context
	KindReasoning    Kind = "reasoning"   // visible reasoning / thinking text
	KindResponse     Kind = "response"    // model text answer
	KindToolCall     Kind = "tool_call"   // the agent asked to run a tool
	KindToolResult   Kind = "tool_result" // what the tool returned to the agent
	KindDecision     Kind = "decision"    // a hook allowed/denied something (live only)
	KindOther        Kind = "other"
)

// Vendor-reported status of a tool result, normalised.
const (
	StatusSuccess   = "success"
	StatusError     = "error"
	StatusCancelled = "cancelled"
	StatusRejected  = "rejected" // the user (not policy) declined the call
	StatusRunning   = "running"
)

// Outcome of a tool call as established by the captured record. Derived at
// report time from the call, any policy decision and any correlated result.
const (
	OutcomeRequested = "requested" // call recorded, no result recorded
	OutcomeBlocked   = "blocked"   // denied by policy or rejected by the user
	OutcomeFailed    = "failed"    // a correlated result reports an error
	OutcomeCompleted = "completed" // a correlated result reports success
	OutcomeUnknown   = "unknown"   // a result exists but its status is not recorded, or it cannot be correlated
)

// Event is one step on the reconstructed timeline. Offline adapters and the
// live hook recorder both emit this shape, so the report works on either.
//
// Fields marked "not hashed" are provenance or derived data. They are cleared
// before computing the live-log chain hash, so they can be filled in later
// without invalidating a record.
type Event struct {
	TS        time.Time `json:"ts"`
	Agent     string    `json:"agent"`  // copilot-vscode, claude-code, codex, opencode...
	Origin    string    `json:"origin"` // offline | live
	SessionID string    `json:"session_id,omitempty"`
	Seq       int       `json:"seq"` // source-local sequence as emitted by the parser (0 for live records)
	Kind      Kind      `json:"kind"`
	Tool      string    `json:"tool,omitempty"`
	CallID    string    `json:"call_id,omitempty"`
	Text      string    `json:"text,omitempty"`  // prompt / response / reasoning / tool result
	Input     string    `json:"input,omitempty"` // tool arguments, JSON as string
	Command   string    `json:"command,omitempty"`
	Paths     []string  `json:"paths,omitempty"` // file paths referenced by input or output
	Cwd       string    `json:"cwd,omitempty"`
	Model     string    `json:"model,omitempty"`
	Decision  string    `json:"decision,omitempty"` // deny | alert (live policy)
	Reason    string    `json:"reason,omitempty"`
	Source    string    `json:"source,omitempty"` // source file (offline) or hook event name (live)
	SourceRef string    `json:"source_ref,omitempty"`
	Host      string    `json:"host,omitempty"`
	User      string    `json:"user,omitempty"`
	TSInexact bool      `json:"ts_inexact,omitempty"` // timestamp inherited, not native to the step
	Status    string    `json:"status,omitempty"`     // vendor-reported result status (tool_result)
	Error     string    `json:"error,omitempty"`      // vendor-reported error text, if separate

	// Live-only chain: hash of previous record + this record.
	PrevHash string `json:"prev_hash,omitempty"`
	Hash     string `json:"hash,omitempty"`

	Pos     int    `json:"pos,omitempty"`     // not hashed: position within its input (line or emission order)
	Prov    string `json:"prov,omitempty"`    // not hashed: input the event was read from (bundle entry, log path)
	Outcome string `json:"outcome,omitempty"` // not hashed: derived at report time
}

// ComputeHash returns the chain hash for a live event. Provenance and derived
// fields are excluded so that display metadata never changes signed content.
func (e Event) ComputeHash() string {
	c := e
	c.Hash, c.Pos, c.Prov, c.Outcome = "", 0, "", ""
	b, _ := json.Marshal(c)
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

// ScopeKey identifies the record stream an event belongs to. Sessions are
// never merged across hosts, users, origins, agents or input sources, and
// events without a session ID are kept apart from every named session.
func (e Event) ScopeKey() string {
	sid := e.SessionID
	if sid == "" {
		sid = "\x00unscoped"
	}
	return strings.Join([]string{e.Prov, e.Origin, e.Host, e.User, e.Agent, e.Source0(), sid}, "\x1f")
}

// Source0 is the source used for scoping: the artifact path for offline
// events. Live events share one log, so their hook event name is not used.
func (e Event) Source0() string {
	if e.Origin == "live" {
		return ""
	}
	return e.Source
}

// SortEvents applies a deterministic order: grouped by scope, then by the
// position each event had in its own input. It does not interleave different
// sources by timestamp, because timestamps across sources do not establish a
// causal order.
func SortEvents(evs []Event) {
	sort.SliceStable(evs, func(i, j int) bool {
		ki, kj := evs[i].ScopeKey(), evs[j].ScopeKey()
		if ki != kj {
			return ki < kj
		}
		return evs[i].Pos < evs[j].Pos
	})
}

// ---------- helpers shared by adapters and hooks ----------

var pathRe = regexp.MustCompile(`(?:[A-Za-z]:\\|\\\\|/|~[/\\]|\.{1,2}[/\\])[^\s"'<>|*?\x60,;()\[\]{}]+`)

// pathKeys are argument names agents use for file locations.
var pathKeys = map[string]bool{
	"path": true, "file_path": true, "filepath": true, "filePath": true, "file": true,
	"filename": true, "target_file": true, "absolute_path": true, "uri": true, "fsPath": true,
	"directory": true, "dir": true, "dirPath": true, "dir_path": true,
	"notebook_path": true, "paths": true, "files": true,
	"relative_workspace_path": true, "target_directory": true, "source": true, "destination": true,
}

// searchKeys hold search terms or patterns, not locations that were accessed.
var searchKeys = map[string]bool{
	"query": true, "pattern": true, "includePattern": true, "glob": true, "regex": true, "search": true,
}

// maxWalkDepth bounds recursion over untrusted JSON.
const maxWalkDepth = 64

// PathArgs returns string values held under path-like argument keys only,
// i.e. locations the tool was asked to operate on, as opposed to search
// patterns, commands or free text.
func PathArgs(v any) []string {
	set := map[string]bool{}
	var walk func(key string, x any, depth int)
	walk = func(key string, x any, depth int) {
		if depth > maxWalkDepth {
			return
		}
		switch t := x.(type) {
		case map[string]any:
			for k, vv := range t {
				walk(k, vv, depth+1)
			}
		case []any:
			for _, vv := range t {
				walk(key, vv, depth+1)
			}
		case string:
			if pathKeys[key] && t != "" && len(t) < 4096 {
				set[cleanPath(t)] = true
			}
		}
	}
	walk("", v, 0)
	out := make([]string, 0, len(set))
	for p := range set {
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}

// ExtractPaths finds file paths in a decoded JSON value (by key) and in free text.
func ExtractPaths(v any, text string) []string {
	set := map[string]bool{}
	var walk func(key string, x any, depth int)
	walk = func(key string, x any, depth int) {
		if depth > maxWalkDepth {
			return
		}
		switch t := x.(type) {
		case map[string]any:
			for k, vv := range t {
				walk(k, vv, depth+1)
			}
		case []any:
			for _, vv := range t {
				walk(key, vv, depth+1)
			}
		case string:
			if pathKeys[key] && t != "" && len(t) < 1024 {
				set[cleanPath(t)] = true
			}
			if key == "command" || key == "cmd" || key == "script" || searchKeys[key] {
				for _, m := range pathRe.FindAllString(t, 20) {
					set[cleanPath(m)] = true
				}
			}
		}
	}
	walk("", v, 0)
	if text != "" {
		t := text
		if len(t) > 200000 {
			t = t[:200000]
		}
		for _, m := range pathRe.FindAllString(t, 200) {
			if len(m) > 3 {
				set[cleanPath(m)] = true
			}
		}
	}
	out := make([]string, 0, len(set))
	for p := range set {
		if p != "" && p != "/" && p != "." {
			out = append(out, p)
		}
	}
	sort.Strings(out)
	return out
}

func cleanPath(p string) string {
	p = strings.TrimPrefix(p, "file://")
	p = strings.TrimRight(p, ".:")
	return p
}

// CommandFrom pulls a shell command out of tool arguments, if any.
func CommandFrom(v any) string {
	m, ok := v.(map[string]any)
	if !ok {
		return ""
	}
	for _, k := range []string{"command", "cmd", "script", "commandLine", "command_line"} {
		switch c := m[k].(type) {
		case string:
			return c
		case []any:
			parts := make([]string, 0, len(c))
			for _, p := range c {
				if s, ok := p.(string); ok {
					parts = append(parts, s)
				}
			}
			return strings.Join(parts, " ")
		}
	}
	return ""
}

// JSONString renders any value compactly; strings that already hold JSON pass through.
func JSONString(v any) string {
	if v == nil {
		return ""
	}
	if s, ok := v.(string); ok {
		return s
	}
	b, err := json.Marshal(v)
	if err != nil {
		return ""
	}
	return string(b)
}

// Decode tries to turn a JSON-looking string into a value; otherwise returns the input.
func Decode(v any) any {
	s, ok := v.(string)
	if !ok {
		return v
	}
	s = strings.TrimSpace(s)
	if len(s) > 1 && (s[0] == '{' || s[0] == '[') {
		var out any
		if json.Unmarshal([]byte(s), &out) == nil {
			return out
		}
	}
	return v
}

// ParseTime accepts RFC3339 strings, unix seconds or unix milliseconds.
func ParseTime(v any) (time.Time, bool) {
	switch t := v.(type) {
	case string:
		if t == "" {
			return time.Time{}, false
		}
		for _, l := range []string{time.RFC3339Nano, "2006-01-02T15:04:05.999999999", "2006-01-02 15:04:05.999999999", "2006-01-02 15:04:05"} {
			if ts, err := time.Parse(l, t); err == nil {
				return ts.UTC(), true
			}
		}
	case float64:
		return unixAny(int64(t))
	case int64:
		return unixAny(t)
	case int:
		return unixAny(int64(t))
	case json.Number:
		if n, err := t.Int64(); err == nil {
			return unixAny(n)
		}
	}
	return time.Time{}, false
}

func unixAny(n int64) (time.Time, bool) {
	switch {
	case n <= 0:
		return time.Time{}, false
	case n > 1e17: // nanoseconds
		return time.Unix(0, n).UTC(), true
	case n > 1e14: // microseconds
		return time.UnixMicro(n).UTC(), true
	case n > 1e11: // milliseconds
		return time.UnixMilli(n).UTC(), true
	default:
		return time.Unix(n, 0).UTC(), true
	}
}

// Str returns the first non-empty string found under any of the keys.
func Str(m map[string]any, keys ...string) string {
	for _, k := range keys {
		if s, ok := m[k].(string); ok && s != "" {
			return s
		}
	}
	return ""
}

// Get walks a dotted path through nested maps.
func Get(m map[string]any, path string) any {
	var cur any = m
	for _, p := range strings.Split(path, ".") {
		mm, ok := cur.(map[string]any)
		if !ok {
			return nil
		}
		cur = mm[p]
	}
	return cur
}

// Truncate caps long strings so reports and logs stay readable. It cuts on a
// UTF-8 boundary. Callers must redact before truncating: a cut can split a
// secret so that redaction patterns no longer match.
func Truncate(s string, n int) string {
	if n <= 0 || len(s) <= n {
		return s
	}
	cut := n
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut] + "\n...[truncated " + strconv.Itoa(len(s)-cut) + " bytes]"
}

// NormStatus maps the many ways vendors report a tool result into one of the
// Status constants, or "" when nothing conclusive is recorded.
func NormStatus(v any) string {
	switch t := v.(type) {
	case bool:
		if t {
			return StatusSuccess
		}
		return StatusError
	case string:
		switch strings.ToLower(strings.TrimSpace(t)) {
		case "success", "succeeded", "completed", "complete", "ok", "done":
			return StatusSuccess
		case "error", "failed", "failure", "errored":
			return StatusError
		case "cancelled", "canceled", "aborted", "interrupted":
			return StatusCancelled
		case "rejected", "denied", "declined":
			return StatusRejected
		case "running", "pending", "in_progress":
			return StatusRunning
		}
	}
	return ""
}
