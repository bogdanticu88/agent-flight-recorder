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
)

// Version is stamped into every manifest and live event.
const Version = "0.1.0"

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

// Event is one step on the reconstructed timeline. Offline adapters and the
// live hook recorder both emit this shape, so the report works on either.
type Event struct {
	TS        time.Time `json:"ts"`
	Agent     string    `json:"agent"`  // copilot-vscode, claude-code, codex, opencode...
	Origin    string    `json:"origin"` // offline | live
	SessionID string    `json:"session_id,omitempty"`
	Seq       int       `json:"seq"` // order inside the session as found in the source
	Kind      Kind      `json:"kind"`
	Tool      string    `json:"tool,omitempty"`
	CallID    string    `json:"call_id,omitempty"`
	Text      string    `json:"text,omitempty"`  // prompt / response / reasoning / tool result
	Input     string    `json:"input,omitempty"` // tool arguments, JSON as string
	Command   string    `json:"command,omitempty"`
	Paths     []string  `json:"paths,omitempty"` // file paths referenced by input or output
	Cwd       string    `json:"cwd,omitempty"`
	Model     string    `json:"model,omitempty"`
	Decision  string    `json:"decision,omitempty"` // allow | deny | alert (live)
	Reason    string    `json:"reason,omitempty"`
	Source    string    `json:"source,omitempty"` // source file (offline) or hook event name (live)
	SourceRef string    `json:"source_ref,omitempty"`
	Host      string    `json:"host,omitempty"`
	User      string    `json:"user,omitempty"`
	TSInexact bool      `json:"ts_inexact,omitempty"` // timestamp inherited, not native to the step

	// Live-only tamper evidence: hash of previous record + this record.
	PrevHash string `json:"prev_hash,omitempty"`
	Hash     string `json:"hash,omitempty"`
}

// ComputeHash returns the chain hash for a live event (Hash field excluded).
func (e Event) ComputeHash() string {
	c := e
	c.Hash = ""
	b, _ := json.Marshal(c)
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

// SortEvents orders events by session then sequence, falling back to time.
func SortEvents(evs []Event) {
	sort.SliceStable(evs, func(i, j int) bool {
		a, b := evs[i], evs[j]
		if !a.TS.Equal(b.TS) && !(a.SessionID == b.SessionID && a.Agent == b.Agent) {
			return a.TS.Before(b.TS)
		}
		if a.SessionID == b.SessionID && a.Agent == b.Agent && a.Seq != b.Seq {
			return a.Seq < b.Seq
		}
		return a.TS.Before(b.TS)
	})
}

// ---------- helpers shared by adapters and hooks ----------

var pathRe = regexp.MustCompile(`(?:[A-Za-z]:\\|\\\\|/|~[/\\]|\.{1,2}[/\\])[^\s"'<>|*?\x60,;()\[\]{}]+`)

// pathKeys are argument names agents use for file locations.
var pathKeys = map[string]bool{
	"path": true, "file_path": true, "filepath": true, "filePath": true, "file": true,
	"filename": true, "target_file": true, "absolute_path": true, "uri": true,
	"directory": true, "dir": true, "dirPath": true, "dir_path": true, "cwd": true,
	"notebook_path": true, "paths": true, "files": true, "includePattern": true,
	"relative_workspace_path": true, "target_directory": true, "source": true, "destination": true,
}

// ExtractPaths finds file paths in a decoded JSON value (by key) and in free text.
func ExtractPaths(v any, text string) []string {
	set := map[string]bool{}
	var walk func(key string, x any)
	walk = func(key string, x any) {
		switch t := x.(type) {
		case map[string]any:
			for k, vv := range t {
				walk(k, vv)
			}
		case []any:
			for _, vv := range t {
				walk(key, vv)
			}
		case string:
			if pathKeys[key] && t != "" && len(t) < 1024 {
				set[cleanPath(t)] = true
			}
			if key == "command" || key == "cmd" || key == "script" || key == "query" || key == "pattern" {
				for _, m := range pathRe.FindAllString(t, 20) {
					set[cleanPath(m)] = true
				}
			}
		}
	}
	walk("", v)
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

// Truncate caps long strings so reports and logs stay readable.
func Truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "\n...[truncated " + strconv.Itoa(len(s)-n) + " bytes]"
}
