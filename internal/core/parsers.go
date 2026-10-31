package core

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// pctx builds events for one source file, keeping order and inheriting a
// timestamp when a step has none of its own.
type pctx struct {
	agent     string
	source    string
	session   string
	cwd       string
	model     string
	seq       int
	lastTS    time.Time
	fileTS    time.Time
	events    []Event
	malformed int      // records that could not be decoded
	diags     []string // parse problems worth reporting (capped)
}

func newCtx(s Source) *pctx {
	c := &pctx{agent: s.Agent, source: s.Path}
	if t, err := time.Parse(time.RFC3339, s.ModTime); err == nil {
		c.fileTS = t.UTC()
	}
	return c
}

func (c *pctx) diag(format string, a ...any) {
	if len(c.diags) < 50 {
		c.diags = append(c.diags, fmt.Sprintf(format, a...))
	}
}

// Limits for untrusted artifacts.
const (
	maxLineBytes   = 64 << 20  // one JSONL record
	maxJSONBytes   = 512 << 20 // one JSON document
	maxOpLogOps    = 1_000_000
	maxOpLogIndex  = 1_000_000
	maxDirFiles    = 200_000
	maxTextOfDepth = 32
)

func (c *pctx) touch(v any) {
	if ts, ok := ParseTime(v); ok {
		c.lastTS = ts
	}
}

func (c *pctx) emit(e Event, rawInput any, ref string) {
	c.seq++
	e.Seq = c.seq
	e.Agent = c.agent
	e.Origin = "offline"
	e.Source = c.source
	e.SourceRef = ref
	if e.SessionID == "" {
		e.SessionID = c.session
	}
	if e.Cwd == "" {
		e.Cwd = c.cwd
	}
	if e.Model == "" {
		e.Model = c.model
	}
	if e.TS.IsZero() {
		e.TS = c.lastTS
		e.TSInexact = true
		if e.TS.IsZero() {
			e.TS = c.fileTS
		}
	} else {
		c.lastTS = e.TS
	}
	if e.Command == "" && rawInput != nil {
		e.Command = CommandFrom(Decode(rawInput))
	}
	text := ""
	if e.Kind == KindToolResult || e.Kind == KindPrompt || e.Kind == KindContext {
		text = e.Text
	}
	if rawInput != nil || text != "" {
		e.Paths = ExtractPaths(Decode(rawInput), text)
	}
	e.Pos = c.seq
	c.events = append(c.events, e)
}

func tsOf(m map[string]any, keys ...string) time.Time {
	for _, k := range keys {
		if t, ok := ParseTime(Get(m, k)); ok {
			return t
		}
	}
	return time.Time{}
}

// textOf flattens the many shapes "content" takes across providers.
func textOf(v any) string { return textOfDepth(v, 0) }

func textOfDepth(v any, depth int) string {
	if depth > maxTextOfDepth {
		return ""
	}
	switch t := v.(type) {
	case nil:
		return ""
	case string:
		return t
	case []any:
		var parts []string
		for _, x := range t {
			if s := textOfDepth(x, depth+1); s != "" {
				parts = append(parts, s)
			}
		}
		return strings.Join(parts, "\n")
	case map[string]any:
		for _, k := range []string{"text", "value", "content", "output", "message", "thinking", "data", "result"} {
			if x, ok := t[k]; ok {
				if s := textOfDepth(x, depth+1); s != "" {
					return s
				}
			}
		}
	}
	return ""
}

// readJSONL calls fn for each decodable object line. Lines that are not JSON
// objects are counted and reported through c, never silently dropped.
func readJSONL(path string, c *pctx, fn func(line int, m map[string]any)) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), maxLineBytes)
	n := 0
	for sc.Scan() {
		n++
		b := sc.Bytes()
		if len(strings.TrimSpace(string(b))) == 0 {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal(b, &m); err != nil {
			if c != nil {
				c.malformed++
				c.diag("line %d: not a JSON object (%v)", n, err)
			}
			continue
		}
		fn(n, m)
	}
	if err := sc.Err(); err != nil {
		return fmt.Errorf("stopped after line %d: %w", n, err)
	}
	return nil
}

func readJSON(path string) (any, error) {
	st, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if st.Size() > maxJSONBytes {
		return nil, fmt.Errorf("file is %d bytes, over the %d byte parse limit", st.Size(), maxJSONBytes)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var v any
	if err := json.Unmarshal(b, &v); err != nil {
		return nil, err
	}
	return v, nil
}

func ref(path string, line int) string { return fmt.Sprintf("%s:%d", filepath.Base(path), line) }

// isContextBlob spots injected instructions/environment rather than the human prompt.
func isContextBlob(s string) bool {
	t := strings.TrimSpace(s)
	for _, p := range []string{"<environment_context", "<user_instructions", "# AGENTS.md", "<INSTRUCTIONS>", "<system-reminder", "<context>", "<attachments>", "Caveat: The messages below", "<command-name>", "<local-command"} {
		if strings.HasPrefix(t, p) {
			return true
		}
	}
	return false
}

// ParseSource dispatches to the right parser. Every parser falls back to the
// generic extractor when it recognises nothing, so an unknown format version
// still yields something instead of silently returning zero.
// ParseResult carries the events from one source plus everything the analyst
// needs to judge how complete the parse was.
type ParseResult struct {
	Events    []Event
	Note      string
	Malformed int
	Diags     []string
	Generic   bool // the dedicated parser recognised nothing; generic extraction used
}

var parsers = map[string]func(Source, *pctx) error{
	"claude-code":      parseClaudeCode,
	"codex":            parseCodex,
	"copilot-cli":      parseCopilotCLI,
	"vscode-chat":      parseVSCodeChatFile,
	"vscode-statedb":   parseVSCodeStateDB,
	"gemini":           parseGemini,
	"cline":            parseCline,
	"opencode-db":      parseOpenCodeDB,
	"opencode-storage": parseOpenCodeStorage,
	"cursor-db":        parseCursorDB,
}

// ParseSource dispatches to the right parser. When a dedicated parser finds
// nothing in a file it should understand, the generic extractor runs, so an
// unknown format version still yields something; the result says so.
func ParseSource(s Source) (ParseResult, error) {
	if s.Parser == "logfile" || s.Parser == "config" {
		return ParseResult{Note: "captured for evidence, not parsed into steps"}, nil
	}
	fn, ok := parsers[s.Parser]
	if !ok {
		return ParseResult{}, fmt.Errorf("no parser %q", s.Parser)
	}
	c := newCtx(s)
	err := fn(s, c)
	res := ParseResult{Events: c.events, Malformed: c.malformed, Diags: c.diags}
	if err == nil && len(c.events) == 0 && s.Parser != "vscode-statedb" && s.Parser != "cursor-db" && s.Parser != "opencode-db" && s.Parser != "opencode-storage" {
		g := newCtx(s)
		if gerr := parseGeneric(s, g); gerr == nil && len(g.events) > 0 {
			res = ParseResult{Events: g.events, Malformed: g.malformed + c.malformed, Diags: append(c.diags, g.diags...), Generic: true,
				Note: "dedicated parser found nothing; generic extractor used (format may have changed)"}
		}
	}
	return res, err
}

// ---------------------------------------------------------------- Claude Code

func parseClaudeCode(s Source, c *pctx) error {
	err := readJSONL(s.rp(), c, func(n int, m map[string]any) {
		if sid := Str(m, "sessionId"); sid != "" {
			c.session = sid
		}
		if cwd := Str(m, "cwd"); cwd != "" {
			c.cwd = cwd
		}
		ts := tsOf(m, "timestamp")
		typ := Str(m, "type")
		msg, _ := m["message"].(map[string]any)
		if msg == nil {
			if typ == "summary" {
				c.emit(Event{TS: ts, Kind: KindContext, Text: "Session summary: " + Str(m, "summary")}, nil, ref(s.Path, n))
			}
			return
		}
		if mdl := Str(msg, "model"); mdl != "" {
			c.model = mdl
		}
		role := Str(msg, "role")
		switch content := msg["content"].(type) {
		case string:
			k := KindResponse
			if role == "user" {
				k = KindPrompt
				if isContextBlob(content) || m["isMeta"] == true {
					k = KindContext
				}
			}
			c.emit(Event{TS: ts, Kind: k, Text: content}, nil, ref(s.Path, n))
		case []any:
			for _, b := range content {
				blk, _ := b.(map[string]any)
				if blk == nil {
					continue
				}
				switch Str(blk, "type") {
				case "text":
					k := KindResponse
					if role == "user" {
						k = KindPrompt
						if isContextBlob(Str(blk, "text")) {
							k = KindContext
						}
					}
					c.emit(Event{TS: ts, Kind: k, Text: Str(blk, "text")}, nil, ref(s.Path, n))
				case "thinking", "redacted_thinking":
					c.emit(Event{TS: ts, Kind: KindReasoning, Text: Str(blk, "thinking")}, nil, ref(s.Path, n))
				case "tool_use", "server_tool_use":
					in := blk["input"]
					c.emit(Event{TS: ts, Kind: KindToolCall, Tool: Str(blk, "name"), CallID: Str(blk, "id"), Input: JSONString(in)}, in, ref(s.Path, n))
				case "tool_result":
					st := StatusSuccess // Claude Code marks failures with is_error
					if blk["is_error"] == true {
						st = StatusError
					}
					c.emit(Event{TS: ts, Kind: KindToolResult, CallID: Str(blk, "tool_use_id"), Text: textOf(blk["content"]), Status: st}, nil, ref(s.Path, n))
				}
			}
		}
	})
	return err
}

// ---------------------------------------------------------------- OpenAI Codex

func parseCodex(s Source, c *pctx) error {
	err := readJSONL(s.rp(), c, func(n int, m map[string]any) {
		ts := tsOf(m, "timestamp")
		typ := Str(m, "type")
		p, _ := m["payload"].(map[string]any)
		if p == nil { // older rollouts: the line is the item itself
			p = m
			if typ == "" {
				return
			}
		}
		switch typ {
		case "session_meta":
			c.session = Str(p, "id")
			c.cwd = Str(p, "cwd")
			c.emit(Event{TS: ts, Kind: KindSessionStart, Text: "Codex session " + Str(p, "id") + " originator=" + Str(p, "originator") + " cli=" + Str(p, "cli_version")}, nil, ref(s.Path, n))
			if instr := Str(p, "instructions"); instr != "" {
				c.emit(Event{TS: ts, Kind: KindContext, Text: instr}, nil, ref(s.Path, n))
			}
			return
		case "turn_context":
			if mdl := Str(p, "model"); mdl != "" {
				c.model = mdl
			}
			if cwd := Str(p, "cwd"); cwd != "" {
				c.cwd = cwd
			}
			return
		case "event_msg", "compacted":
			return // duplicates of response_item entries
		}
		if typ == "response_item" || p["type"] != nil {
			c.codexItem(p, ts, ref(s.Path, n))
		}
	})
	return err
}

func (c *pctx) codexItem(p map[string]any, ts time.Time, r string) {
	switch Str(p, "type") {
	case "message":
		txt := textOf(p["content"])
		k := KindResponse
		if role := Str(p, "role"); role == "user" {
			k = KindPrompt
			if isContextBlob(txt) {
				k = KindContext
			}
		} else if role == "developer" || role == "system" {
			k = KindContext
		}
		c.emit(Event{TS: ts, Kind: k, Text: txt}, nil, r)
	case "reasoning":
		txt := textOf(p["summary"])
		if txt == "" {
			txt = textOf(p["content"])
		}
		if txt != "" {
			c.emit(Event{TS: ts, Kind: KindReasoning, Text: txt}, nil, r)
		}
	case "function_call", "custom_tool_call":
		in := p["arguments"]
		if in == nil {
			in = p["input"]
		}
		c.emit(Event{TS: ts, Kind: KindToolCall, Tool: Str(p, "name"), CallID: Str(p, "call_id", "id"), Input: JSONString(in)}, in, r)
	case "local_shell_call":
		act := p["action"]
		c.emit(Event{TS: ts, Kind: KindToolCall, Tool: "local_shell", CallID: Str(p, "call_id", "id"), Input: JSONString(act)}, act, r)
	case "function_call_output", "custom_tool_call_output", "local_shell_call_output":
		out := p["output"]
		dec := Decode(out)
		txt := textOf(dec)
		if txt == "" {
			txt = JSONString(out)
		}
		st := ""
		if dm, ok := dec.(map[string]any); ok {
			if code, ok := Get(dm, "metadata.exit_code").(float64); ok {
				st = StatusError
				if code == 0 {
					st = StatusSuccess
				}
			}
		}
		c.emit(Event{TS: ts, Kind: KindToolResult, CallID: Str(p, "call_id"), Text: txt, Status: st}, nil, r)
	case "web_search_call":
		c.emit(Event{TS: ts, Kind: KindToolCall, Tool: "web_search", Input: JSONString(p["action"])}, p["action"], r)
	}
}

// ---------------------------------------------------------------- GitHub Copilot CLI

func parseCopilotCLI(s Source, c *pctx) error {
	c.session = filepath.Base(filepath.Dir(s.Path))
	if strings.HasSuffix(s.Path, ".json") { // legacy history-session-state
		return nil
	}
	err := readJSONL(s.rp(), c, func(n int, m map[string]any) {
		ts := tsOf(m, "timestamp", "data.timestamp")
		d, _ := m["data"].(map[string]any)
		if d == nil {
			d, _ = m["payload"].(map[string]any)
		}
		if d == nil {
			d = m
		}
		r := ref(s.Path, n)
		switch Str(m, "type") {
		case "session.start":
			if sid := Str(d, "sessionId"); sid != "" {
				c.session = sid
			}
			if cwd, _ := Get(d, "context.cwd").(string); cwd != "" {
				c.cwd = cwd
			}
			c.emit(Event{TS: ts, Kind: KindSessionStart, Text: "Copilot CLI session, version " + Str(d, "copilotVersion")}, nil, r)
		case "session.model_change":
			c.model = Str(d, "newModel", "model")
		case "user.message":
			txt := Str(d, "content", "transformedContent", "message")
			k := KindPrompt
			if isContextBlob(txt) {
				k = KindContext
			}
			c.emit(Event{TS: ts, Kind: k, Text: txt}, nil, r)
		case "assistant.message":
			if rt := Str(d, "reasoningText"); rt != "" {
				c.emit(Event{TS: ts, Kind: KindReasoning, Text: rt}, nil, r)
			}
			if txt := Str(d, "content"); txt != "" {
				c.emit(Event{TS: ts, Kind: KindResponse, Text: txt}, nil, r)
			}
		case "assistant.reasoning":
			c.emit(Event{TS: ts, Kind: KindReasoning, Text: Str(d, "content", "text")}, nil, r)
		case "tool.execution_start":
			in := d["arguments"]
			c.emit(Event{TS: ts, Kind: KindToolCall, Tool: Str(d, "toolName", "name"), CallID: Str(d, "toolCallId"), Input: JSONString(in)}, in, r)
		case "tool.execution_complete":
			txt := textOf(d["result"])
			errTxt := textOf(d["error"])
			if txt == "" {
				txt = errTxt
			}
			c.emit(Event{TS: ts, Kind: KindToolResult, CallID: Str(d, "toolCallId"), Text: txt, Status: NormStatus(d["success"]), Error: errTxt}, nil, r)
		case "subagent.started", "subagent.start":
			c.emit(Event{TS: ts, Kind: KindOther, Text: "Subagent started: " + Str(d, "agentName", "name")}, nil, r)
		case "hook.start", "hook.end":
			c.emit(Event{TS: ts, Kind: KindOther, Text: "Hook " + Str(m, "type") + ": " + JSONString(d)}, nil, r)
		}
	})
	return err
}

// ---------------------------------------------------------------- Gemini CLI

func parseGemini(s Source, c *pctx) error {
	v, err := readJSON(s.rp())
	if err != nil {
		return err
	}
	c.session = strings.TrimSuffix(filepath.Base(s.Path), ".json")
	var msgs []any
	switch t := v.(type) {
	case map[string]any:
		if sid := Str(t, "sessionId"); sid != "" {
			c.session = sid
		}
		msgs, _ = t["messages"].([]any)
		if msgs == nil {
			msgs, _ = t["history"].([]any)
		}
	case []any: // logs.json or checkpoint history
		msgs = t
	}
	for i, x := range msgs {
		m, _ := x.(map[string]any)
		if m == nil {
			continue
		}
		r := fmt.Sprintf("%s#%d", filepath.Base(s.Path), i)
		ts := tsOf(m, "timestamp")
		if sid := Str(m, "sessionId"); sid != "" {
			c.session = sid
		}
		if mdl := Str(m, "model"); mdl != "" {
			c.model = mdl
		}
		typ := Str(m, "type", "role")
		for _, th := range asSlice(m["thoughts"]) {
			if tm, ok := th.(map[string]any); ok {
				c.emit(Event{TS: tsOf(tm, "timestamp"), Kind: KindReasoning, Text: strings.TrimSpace(Str(tm, "subject") + ": " + Str(tm, "description"))}, nil, r)
			}
		}
		txt := Str(m, "message")
		if txt == "" {
			txt = textOf(m["content"])
		}
		if txt == "" {
			txt = textOf(m["parts"])
		}
		switch typ {
		case "user":
			if txt != "" {
				c.emit(Event{TS: ts, Kind: KindPrompt, Text: txt}, nil, r)
			}
		case "gemini", "model", "assistant":
			if txt != "" {
				c.emit(Event{TS: ts, Kind: KindResponse, Text: txt}, nil, r)
			}
		case "info", "error", "warning":
			c.emit(Event{TS: ts, Kind: KindOther, Text: typ + ": " + txt}, nil, r)
		}
		for _, tc := range asSlice(m["toolCalls"]) {
			t, _ := tc.(map[string]any)
			if t == nil {
				continue
			}
			tts := tsOf(t, "timestamp")
			in := t["args"]
			c.emit(Event{TS: tts, Kind: KindToolCall, Tool: Str(t, "name"), CallID: Str(t, "id"), Input: JSONString(in)}, in, r)
			res := textOf(t["result"])
			if res == "" {
				res = Str(t, "resultDisplay")
			}
			if res != "" || t["status"] != nil {
				c.emit(Event{TS: tts, Kind: KindToolResult, CallID: Str(t, "id"), Text: res, Status: NormStatus(t["status"])}, nil, r)
			}
		}
	}
	return nil
}

func asSlice(v any) []any { s, _ := v.([]any); return s }

// ---------------------------------------------------------------- Cline / Roo Code

func parseCline(s Source, c *pctx) error {
	v, err := readJSON(s.rp())
	if err != nil {
		return err
	}
	c.session = filepath.Base(filepath.Dir(s.Path))
	for i, x := range asSlice(v) {
		m, _ := x.(map[string]any)
		if m == nil {
			continue
		}
		r := fmt.Sprintf("%s#%d", filepath.Base(s.Path), i)
		ts := tsOf(m, "ts")
		sub := Str(m, "say", "ask")
		txt := Str(m, "text")
		switch sub {
		case "task", "user_feedback":
			c.emit(Event{TS: ts, Kind: KindPrompt, Text: txt}, nil, r)
		case "text", "completion_result":
			c.emit(Event{TS: ts, Kind: KindResponse, Text: txt}, nil, r)
		case "reasoning":
			c.emit(Event{TS: ts, Kind: KindReasoning, Text: txt}, nil, r)
		case "tool", "use_mcp_server", "mcp_server_request_started":
			d := Decode(txt)
			name := ""
			if dm, ok := d.(map[string]any); ok {
				name = Str(dm, "tool", "toolName", "serverName")
			}
			c.emit(Event{TS: ts, Kind: KindToolCall, Tool: name, Input: txt}, d, r)
		case "command":
			c.emit(Event{TS: ts, Kind: KindToolCall, Tool: "execute_command", Command: txt, Input: JSONString(map[string]any{"command": txt})}, map[string]any{"command": txt}, r)
		case "command_output", "mcp_server_response":
			c.emit(Event{TS: ts, Kind: KindToolResult, Text: txt}, nil, r)
		case "api_req_started":
			// carries the full request incl. tool results; keep paths only via generic text
		}
	}
	return nil
}

// ---------------------------------------------------------------- VS Code Copilot Chat

func parseVSCodeChatFile(s Source, c *pctx) error {
	var state any
	if strings.HasSuffix(s.Path, ".jsonl") {
		st, err := replayVSCodeOpLog(s.rp(), c)
		if err != nil {
			return err
		}
		state = st
	} else {
		v, err := readJSON(s.rp())
		if err != nil {
			return err
		}
		state = v
	}
	c.session = strings.TrimSuffix(strings.TrimSuffix(filepath.Base(s.Path), ".jsonl"), ".json")
	if m, ok := state.(map[string]any); ok {
		c.vscodeSession(m, filepath.Base(s.Path))
	}
	return nil
}

// replayVSCodeOpLog rebuilds session state from the newer append-only format:
// kind 0 = full snapshot, kind 1 = set value at key path, kind 2 = append/splice
// array. Operations are untrusted: invalid paths or indices are rejected and
// reported instead of being applied.
func replayVSCodeOpLog(path string, c *pctx) (any, error) {
	var state any
	ops := 0
	var stopErr error
	err := readJSONL(path, c, func(n int, m map[string]any) {
		if stopErr != nil {
			return
		}
		ops++
		if ops > maxOpLogOps {
			stopErr = fmt.Errorf("more than %d operations; replay stopped at line %d", maxOpLogOps, n)
			return
		}
		kind, _ := m["kind"].(float64)
		keys, _ := m["k"].([]any)
		var (
			next any
			err  error
		)
		switch int(kind) {
		case 0:
			next = m["v"]
		case 1:
			next, err = setPath(state, keys, m["v"], false, -1, 0)
		case 2:
			idx := -1
			if i, ok := m["i"].(float64); ok {
				if i < 0 || i != float64(int(i)) {
					err = fmt.Errorf("invalid splice index %v", i)
				}
				idx = int(i)
			}
			if err == nil {
				next, err = setPath(state, keys, m["v"], true, idx, 0)
			}
		default:
			err = fmt.Errorf("unknown operation kind %v", m["kind"])
		}
		if err != nil {
			c.malformed++
			c.diag("op-log line %d: %v (operation skipped)", n, err)
			return
		}
		state = next
	})
	if err == nil {
		err = stopErr
	}
	return state, err
}

// setPath applies one op-log operation and returns the new value, or an error
// for indices that are negative, non-integral, or beyond the end of the array
// (appending at len is allowed). Rejected operations leave root untouched.
func setPath(root any, keys []any, val any, appendArr bool, idx int, depth int) (any, error) {
	if depth > maxWalkDepth {
		return nil, fmt.Errorf("key path deeper than %d", maxWalkDepth)
	}
	if len(keys) == 0 {
		if !appendArr {
			return val, nil
		}
		arr, _ := root.([]any)
		if idx >= 0 {
			if idx > len(arr) {
				return nil, fmt.Errorf("splice index %d beyond array length %d", idx, len(arr))
			}
			arr = arr[:idx:idx]
		}
		if items, ok := val.([]any); ok {
			return append(arr, items...), nil
		}
		return append(arr, val), nil
	}
	switch k := keys[0].(type) {
	case string:
		m, _ := root.(map[string]any)
		cp := make(map[string]any, len(m)+1)
		for kk, vv := range m {
			cp[kk] = vv
		}
		v, err := setPath(cp[k], keys[1:], val, appendArr, idx, depth+1)
		if err != nil {
			return nil, err
		}
		cp[k] = v
		return cp, nil
	case float64:
		arr, _ := root.([]any)
		if k < 0 || k != float64(int(k)) || k > maxOpLogIndex {
			return nil, fmt.Errorf("invalid array index %v", k)
		}
		i := int(k)
		if i > len(arr) {
			return nil, fmt.Errorf("array index %d beyond length %d", i, len(arr))
		}
		cp := make([]any, len(arr), len(arr)+1)
		copy(cp, arr)
		if i == len(cp) {
			cp = append(cp, nil)
		}
		v, err := setPath(cp[i], keys[1:], val, appendArr, idx, depth+1)
		if err != nil {
			return nil, err
		}
		cp[i] = v
		return cp, nil
	}
	return nil, fmt.Errorf("invalid key %v", keys[0])
}

func (c *pctx) vscodeSession(sess map[string]any, refBase string) {
	if sid := Str(sess, "sessionId"); sid != "" {
		c.session = sid
	}
	c.touch(sess["creationDate"])
	for ri, rq := range asSlice(sess["requests"]) {
		req, _ := rq.(map[string]any)
		if req == nil {
			continue
		}
		r := fmt.Sprintf("%s#request%d", refBase, ri)
		ts := tsOf(req, "timestamp")
		if mdl := Str(req, "modelId"); mdl != "" {
			c.model = mdl
		}
		// attached context: files, selections, instructions the user or VS Code added
		for _, vv := range asSlice(Get(req, "variableData.variables")) {
			vm, _ := vv.(map[string]any)
			if vm == nil {
				continue
			}
			name := Str(vm, "name", "id")
			c.emit(Event{TS: ts, Kind: KindContext, Text: "Attached: " + name, Input: JSONString(vm["value"])}, vm["value"], r)
		}
		msg := ""
		if mm, ok := req["message"].(map[string]any); ok {
			msg = Str(mm, "text")
		} else if s, ok := req["message"].(string); ok {
			msg = s
		}
		agentName := Str(req, "agent.id")
		if a, ok := req["agent"].(map[string]any); ok {
			agentName = Str(a, "id", "name")
		}
		c.emit(Event{TS: ts, Kind: KindPrompt, Text: msg, Reason: agentName}, nil, r)

		// Real tool arguments live in result.metadata.toolCallRounds when present.
		meta, _ := Get(req, "result.metadata").(map[string]any)
		results, _ := meta["toolCallResults"].(map[string]any)
		invMsgs := map[string]string{}
		invStatus := map[string]string{}
		for _, part := range asSlice(req["response"]) {
			pm, _ := part.(map[string]any)
			if pm != nil && Str(pm, "kind") == "toolInvocationSerialized" {
				invMsgs[Str(pm, "toolCallId")] = textOf(pm["pastTenseMessage"]) + " " + textOf(pm["invocationMessage"])
				invStatus[Str(pm, "toolCallId")] = vscodeInvStatus(pm)
			}
		}
		usedRounds := false
		for _, rd := range asSlice(meta["toolCallRounds"]) {
			round, _ := rd.(map[string]any)
			if round == nil {
				continue
			}
			usedRounds = true
			if t := Str(round, "thinking"); t != "" {
				c.emit(Event{TS: ts, Kind: KindReasoning, Text: t}, nil, r)
			} else if th, ok := round["thinking"].(map[string]any); ok {
				c.emit(Event{TS: ts, Kind: KindReasoning, Text: textOf(th)}, nil, r)
			}
			if t := Str(round, "response"); t != "" {
				c.emit(Event{TS: ts, Kind: KindResponse, Text: t}, nil, r)
			}
			for _, tc := range asSlice(round["toolCalls"]) {
				t, _ := tc.(map[string]any)
				if t == nil {
					continue
				}
				id := Str(t, "id")
				in := Decode(t["arguments"])
				c.emit(Event{TS: ts, Kind: KindToolCall, Tool: Str(t, "name"), CallID: id, Input: JSONString(t["arguments"]), Reason: strings.TrimSpace(invMsgs[id])}, in, r)
				if res, ok := results[id]; ok {
					c.emit(Event{TS: ts, Kind: KindToolResult, CallID: id, Text: textOf(res), Status: invStatus[id]}, nil, r)
				} else if st := invStatus[id]; st == StatusRejected {
					c.emit(Event{TS: ts, Kind: KindToolResult, CallID: id, Status: st}, nil, r)
				}
			}
		}
		// Otherwise reconstruct from the rendered response parts.
		var answer []string
		for _, part := range asSlice(req["response"]) {
			pm, _ := part.(map[string]any)
			if pm == nil {
				continue
			}
			switch Str(pm, "kind") {
			case "toolInvocationSerialized", "toolInvocation":
				if usedRounds {
					continue
				}
				in := Get(pm, "resultDetails.input")
				if in == nil {
					in = pm["toolSpecificData"]
				}
				msgTxt := strings.TrimSpace(textOf(pm["pastTenseMessage"]) + " " + textOf(pm["invocationMessage"]))
				c.emit(Event{TS: ts, Kind: KindToolCall, Tool: Str(pm, "toolId"), CallID: Str(pm, "toolCallId"), Input: JSONString(in), Reason: msgTxt, Text: msgTxt}, map[string]any{"in": in, "msg": msgTxt, "uris": pm["resultDetails"]}, r)
				if out := Get(pm, "resultDetails.output"); out != nil || vscodeInvStatus(pm) != "" {
					c.emit(Event{TS: ts, Kind: KindToolResult, CallID: Str(pm, "toolCallId"), Text: textOf(out), Status: vscodeInvStatus(pm)}, nil, r)
				}
			case "thinking":
				if !usedRounds {
					c.emit(Event{TS: ts, Kind: KindReasoning, Text: textOf(pm["value"])}, nil, r)
				}
			case "textEditGroup":
				c.emit(Event{TS: ts, Kind: KindToolCall, Tool: "edit (textEditGroup)", Input: JSONString(pm["uri"])}, pm["uri"], r)
			case "markdownContent", "":
				if t := textOf(pm["content"]); t != "" {
					answer = append(answer, t)
				} else if t := textOf(pm["value"]); t != "" {
					answer = append(answer, t)
				}
			case "inlineReference":
				answer = append(answer, "`"+JSONString(pm["inlineReference"])+"`")
			}
		}
		if len(answer) > 0 && !usedRounds {
			c.emit(Event{TS: ts, Kind: KindResponse, Text: strings.Join(answer, "")}, nil, r)
		}
	}
}

// ---------------------------------------------------------------- OpenCode JSON storage

func parseOpenCodeStorage(s Source, c *pctx) error {
	type msgInfo struct {
		id, session, role, model string
		created                  time.Time
	}
	msgs := map[string]msgInfo{}
	var order []msgInfo
	files, _ := filepath.Glob(filepath.Join(s.rp(), "message", "*", "*.json"))
	for _, f := range files {
		v, err := readJSON(f)
		m, _ := v.(map[string]any)
		if err != nil || m == nil {
			continue
		}
		mi := msgInfo{id: Str(m, "id"), session: Str(m, "sessionID"), role: Str(m, "role"), model: Str(m, "modelID")}
		mi.created = tsOf(m, "time.created")
		msgs[mi.id] = mi
		order = append(order, mi)
	}
	sort.Slice(order, func(i, j int) bool {
		if order[i].session != order[j].session {
			return order[i].session < order[j].session
		}
		return order[i].created.Before(order[j].created) || (order[i].created.Equal(order[j].created) && order[i].id < order[j].id)
	})
	for _, mi := range order {
		parts, _ := filepath.Glob(filepath.Join(s.rp(), "part", filepath.Base(mi.id), "*.json"))
		sort.Strings(parts)
		c.session, c.model, c.lastTS = mi.session, mi.model, mi.created
		for _, pf := range parts {
			v, err := readJSON(pf)
			pm, _ := v.(map[string]any)
			if err == nil && pm != nil {
				c.openCodePart(pm, mi.role, "storage/part/"+mi.id+"/"+filepath.Base(pf))
			}
		}
	}
	return nil
}

// openCodePart handles both the current TS schema (part.type = text|tool|reasoning)
// and the older Go schema (parts[].type = text|tool_call|tool_result with data).
func (c *pctx) openCodePart(p map[string]any, role, r string) {
	ts := tsOf(p, "time.start", "state.time.start")
	switch Str(p, "type") {
	case "text":
		txt := Str(p, "text")
		if txt == "" {
			txt = textOf(p["data"])
		}
		k := KindResponse
		if role == "user" {
			k = KindPrompt
			if p["synthetic"] == true || isContextBlob(txt) {
				k = KindContext
			}
		}
		c.emit(Event{TS: ts, Kind: k, Text: txt}, nil, r)
	case "reasoning":
		c.emit(Event{TS: ts, Kind: KindReasoning, Text: Str(p, "text")}, nil, r)
	case "file":
		c.emit(Event{TS: ts, Kind: KindContext, Text: "Attached file: " + Str(p, "filename", "url"), Input: JSONString(p["source"])}, map[string]any{"path": Str(p, "url", "filename")}, r)
	case "tool":
		st, _ := p["state"].(map[string]any)
		in := st["input"]
		title := Str(st, "title")
		c.emit(Event{TS: ts, Kind: KindToolCall, Tool: Str(p, "tool"), CallID: Str(p, "callID"), Input: JSONString(in), Reason: title}, in, r)
		out := Str(st, "output", "error")
		if out != "" || Str(st, "status") != "" {
			c.emit(Event{TS: tsOf(st, "time.end"), Kind: KindToolResult, CallID: Str(p, "callID"), Text: out, Status: NormStatus(st["status"]), Error: Str(st, "error")}, nil, r)
		}
	case "tool_call":
		d, _ := p["data"].(map[string]any)
		in := d["input"]
		c.emit(Event{TS: ts, Kind: KindToolCall, Tool: Str(d, "name"), CallID: Str(d, "id"), Input: JSONString(in)}, in, r)
	case "tool_result":
		d, _ := p["data"].(map[string]any)
		st := StatusSuccess
		if d["is_error"] == true {
			st = StatusError
		}
		c.emit(Event{TS: ts, Kind: KindToolResult, CallID: Str(d, "tool_call_id"), Text: Str(d, "content"), Status: st}, nil, r)
	case "subtask", "agent":
		c.emit(Event{TS: ts, Kind: KindOther, Text: "Subagent: " + Str(p, "agent", "name") + " " + Str(p, "prompt", "description")}, nil, r)
	}
}

// vscodeInvStatus reads the completion flags VS Code keeps on a serialised
// tool invocation. isComplete only says the tool finished; an explicit error
// flag or a declined confirmation takes precedence.
func vscodeInvStatus(pm map[string]any) string {
	switch {
	case pm["isConfirmed"] == false:
		return StatusRejected
	case Get(pm, "resultDetails.isError") == true:
		return StatusError
	case pm["isComplete"] == true:
		return StatusSuccess
	}
	return ""
}
