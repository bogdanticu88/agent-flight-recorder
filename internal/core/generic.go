package core

import (
	"path/filepath"
	"sort"
	"strings"
)

// The generic extractor walks arbitrary JSON looking for things shaped like
// agent steps. It exists for two reasons: vendors change their storage formats
// without notice, and new agents appear faster than adapters get written.
// Output from here is marked so the analyst knows it's best-effort.

func parseGeneric(s Source) ([]Event, error) {
	c := newCtx(s.Agent, s.Path)
	if strings.HasSuffix(s.Path, ".jsonl") {
		err := readJSONL(s.Path, func(n int, m map[string]any) { c.genericWalk(m, ref(s.Path, n)) })
		return c.events, err
	}
	v, err := readJSON(s.Path)
	if err != nil {
		return nil, err
	}
	c.genericWalk(v, filepath.Base(s.Path))
	return c.events, nil
}

var (
	toolNameKeys = []string{"tool_name", "toolName", "toolId", "tool", "functionName", "name"}
	toolArgKeys  = []string{"tool_input", "toolArgs", "toolInput", "arguments", "args", "input", "parameters", "params", "rawArgs"}
	toolResKeys  = []string{"tool_response", "toolResult", "tool_result", "result", "output", "response"}
	callIDKeys   = []string{"tool_use_id", "toolCallId", "tool_call_id", "call_id", "callID", "id"}
	tsKeys       = []string{"timestamp", "ts", "time", "createdAt", "created_at", "created", "date", "startTime"}
)

func (c *pctx) genericWalk(v any, r string) {
	switch t := v.(type) {
	case []any:
		for _, x := range t {
			c.genericWalk(x, r)
		}
	case map[string]any:
		for _, k := range tsKeys {
			c.touch(t[k])
		}
		if sid := Str(t, "sessionId", "session_id", "sessionID", "conversation_id"); sid != "" {
			c.session = sid
		}
		if c.genericClassify(t, r) {
			return
		}
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			switch t[k].(type) {
			case map[string]any, []any:
				c.genericWalk(t[k], r)
			case string:
				if d := Decode(t[k]); d != t[k] {
					c.genericWalk(d, r)
				}
			}
		}
	}
}

func firstKey(m map[string]any, keys []string) (string, any) {
	for _, k := range keys {
		if v, ok := m[k]; ok && v != nil && v != "" {
			return k, v
		}
	}
	return "", nil
}

func (c *pctx) genericClassify(m map[string]any, r string) bool {
	typ := strings.ToLower(Str(m, "type", "kind"))
	role := strings.ToLower(Str(m, "role"))
	_, args := firstKey(m, toolArgKeys)
	nameKey, name := firstKey(m, toolNameKeys)
	_, cid := firstKey(m, callIDKeys)
	callID, _ := cid.(string)
	ts := tsOf(m, tsKeys...)
	r = r + " (generic)"

	isToolType := strings.Contains(typ, "tool_use") || strings.Contains(typ, "function_call") && !strings.Contains(typ, "output") ||
		typ == "tool_call" || typ == "tool" || strings.Contains(typ, "toolinvocation") || strings.Contains(typ, "pretooluse")
	isResultType := strings.Contains(typ, "tool_result") || strings.Contains(typ, "output") || strings.Contains(typ, "posttooluse")

	if isResultType {
		_, res := firstKey(m, append(toolResKeys, "content", "text"))
		c.emit(Event{TS: ts, Kind: KindToolResult, CallID: callID, Text: textOf(Decode(res))}, nil, r)
		return true
	}
	if ns, ok := name.(string); ok && (isToolType || (args != nil && nameKey != "name") || (args != nil && nameKey == "name" && typ != "")) {
		c.emit(Event{TS: ts, Kind: KindToolCall, Tool: ns, CallID: callID, Input: JSONString(args)}, Decode(args), r)
		if _, res := firstKey(m, toolResKeys); res != nil {
			c.emit(Event{TS: ts, Kind: KindToolResult, CallID: callID, Text: textOf(Decode(res))}, nil, r)
		}
		return true
	}
	if role == "user" || role == "assistant" || role == "model" || typ == "user" || typ == "assistant" {
		content := m["content"]
		if content == nil {
			content = m["text"]
		}
		if content == nil {
			content = m["parts"]
		}
		// content arrays may hold tool blocks: walk them rather than flatten
		if arr, ok := content.([]any); ok {
			hasTool := false
			for _, x := range arr {
				if xm, ok := x.(map[string]any); ok {
					xt := strings.ToLower(Str(xm, "type"))
					if strings.Contains(xt, "tool") || strings.Contains(xt, "function") {
						hasTool = true
					}
				}
			}
			if hasTool {
				for _, x := range arr {
					if xm, ok := x.(map[string]any); ok && !c.genericClassify(xm, r) {
						if txt := textOf(xm); txt != "" {
							c.emit(Event{TS: ts, Kind: roleKind(role, typ, txt), Text: txt}, nil, r)
						}
					}
				}
				return true
			}
		}
		if txt := textOf(content); txt != "" {
			c.emit(Event{TS: ts, Kind: roleKind(role, typ, txt), Text: txt}, nil, r)
			return true
		}
	}
	if typ == "text" && m["text"] != nil {
		// orphan text block; let the parent role decide when possible
		return false
	}
	if p := Str(m, "prompt"); p != "" && (strings.Contains(typ, "prompt") || Str(m, "hook_event_name") != "") {
		c.emit(Event{TS: ts, Kind: KindPrompt, Text: p}, nil, r)
		return true
	}
	return false
}

func roleKind(role, typ, txt string) Kind {
	if role == "user" || typ == "user" {
		if isContextBlob(txt) {
			return KindContext
		}
		return KindPrompt
	}
	return KindResponse
}
