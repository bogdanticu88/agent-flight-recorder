package core

import (
	"database/sql"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	_ "modernc.org/sqlite"
)

// openSnapshot copies a SQLite database together with its -wal/-shm files to a
// temp directory and opens the copy. The original is never opened, so we don't
// checkpoint the WAL or change timestamps on the evidence, and we still see
// writes that only exist in the WAL.
func openSnapshot(path string) (*sql.DB, func(), error) {
	dir, err := os.MkdirTemp("", "afr-db-*")
	if err != nil {
		return nil, nil, err
	}
	cleanup := func() { os.RemoveAll(dir) }
	dst := filepath.Join(dir, "snap.db")
	for _, suf := range []string{"", "-wal", "-shm"} {
		if err := copyFile(path+suf, dst+suf); err != nil && suf == "" {
			cleanup()
			return nil, nil, err
		}
	}
	db, err := sql.Open("sqlite", "file:"+filepath.ToSlash(dst)+"?_pragma=busy_timeout(5000)")
	if err != nil {
		cleanup()
		return nil, nil, err
	}
	return db, func() { db.Close(); cleanup() }, nil
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()
	_, err = io.Copy(out, in)
	return err
}

func tables(db *sql.DB) map[string]bool {
	t := map[string]bool{}
	rows, err := db.Query(`SELECT name FROM sqlite_master WHERE type='table'`)
	if err != nil {
		return t
	}
	defer rows.Close()
	for rows.Next() {
		var n string
		if rows.Scan(&n) == nil {
			t[n] = true
		}
	}
	return t
}

func kvRows(db *sql.DB, table, where string) ([][2]string, error) {
	rows, err := db.Query(fmt.Sprintf(`SELECT key, CAST(value AS TEXT) FROM %s WHERE %s ORDER BY rowid`, table, where))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out [][2]string
	for rows.Next() {
		var k string
		var v sql.NullString
		if rows.Scan(&k, &v) == nil && v.Valid {
			out = append(out, [2]string{k, v.String})
		}
	}
	return out, rows.Err()
}

// ---------------------------------------------------------------- VS Code state.vscdb

func parseVSCodeStateDB(s Source) ([]Event, error) {
	db, done, err := openSnapshot(s.Path)
	if err != nil {
		return nil, err
	}
	defer done()
	if !tables(db)["ItemTable"] {
		return nil, nil
	}
	kvs, err := kvRows(db, "ItemTable", `key LIKE '%interactive%' OR key LIKE '%chat%'`)
	if err != nil {
		return nil, err
	}
	c := newCtx(s.Agent, s.Path)
	for _, kv := range kvs {
		v := Decode(kv[1])
		var walk func(x any)
		walk = func(x any) {
			switch t := x.(type) {
			case map[string]any:
				if _, ok := t["requests"].([]any); ok {
					c.session = ""
					c.vscodeSession(t, "state.vscdb:"+kv[0])
					return
				}
				for _, vv := range t {
					walk(vv)
				}
			case []any:
				for _, vv := range t {
					walk(vv)
				}
			}
		}
		walk(v)
	}
	return c.events, nil
}

// ---------------------------------------------------------------- Cursor

func parseCursorDB(s Source) ([]Event, error) {
	db, done, err := openSnapshot(s.Path)
	if err != nil {
		return nil, err
	}
	defer done()
	t := tables(db)
	c := newCtx(s.Agent, s.Path)
	switch {
	case t["cursorDiskKV"]:
		// composer order: composerData:<id>.fullConversationHeadersOnly[].bubbleId
		order := map[string]int{}
		if comps, err := kvRows(db, "cursorDiskKV", `key LIKE 'composerData:%'`); err == nil {
			for _, kv := range comps {
				m, _ := Decode(kv[1]).(map[string]any)
				for i, h := range asSlice(m["fullConversationHeadersOnly"]) {
					if hm, ok := h.(map[string]any); ok {
						order[Str(hm, "bubbleId")] = i
					}
				}
			}
		}
		bubbles, err := kvRows(db, "cursorDiskKV", `key LIKE 'bubbleId:%'`)
		if err != nil {
			return nil, err
		}
		type bub struct {
			comp, id string
			m        map[string]any
		}
		var bs []bub
		for _, kv := range bubbles {
			parts := strings.SplitN(kv[0], ":", 3)
			m, _ := Decode(kv[1]).(map[string]any)
			if len(parts) == 3 && m != nil {
				bs = append(bs, bub{parts[1], parts[2], m})
			}
		}
		sort.SliceStable(bs, func(i, j int) bool {
			if bs[i].comp != bs[j].comp {
				return bs[i].comp < bs[j].comp
			}
			oi, iok := order[bs[i].id]
			oj, jok := order[bs[j].id]
			if iok && jok {
				return oi < oj
			}
			return false
		})
		for _, b := range bs {
			c.session = b.comp
			r := "cursorDiskKV:bubbleId:" + b.comp + ":" + b.id
			ts := tsOf(b.m, "createdAt", "timingInfo.clientStartTime")
			if th := textOf(b.m["thinking"]); th != "" {
				c.emit(Event{TS: ts, Kind: KindReasoning, Text: th}, nil, r)
			}
			txt := Str(b.m, "text")
			typ, _ := b.m["type"].(float64)
			if txt != "" {
				k := KindResponse
				if typ == 1 {
					k = KindPrompt
				}
				c.emit(Event{TS: ts, Kind: k, Text: txt}, nil, r)
			}
			if tf, ok := b.m["toolFormerData"].(map[string]any); ok && len(tf) > 0 {
				in := Decode(tf["rawArgs"])
				if in == nil || in == "" {
					in = Decode(tf["params"])
				}
				c.emit(Event{TS: ts, Kind: KindToolCall, Tool: Str(tf, "name", "tool"), CallID: Str(tf, "toolCallId"), Input: JSONString(in)}, in, r)
				if res := tf["result"]; res != nil {
					rt := textOf(Decode(res))
					if rt == "" {
						rt = JSONString(res)
					}
					c.emit(Event{TS: ts, Kind: KindToolResult, CallID: Str(tf, "toolCallId"), Text: rt}, nil, r)
				}
			}
		}
	default:
		return genericSQLite(s, db)
	}
	return c.events, nil
}

// ---------------------------------------------------------------- OpenCode SQLite

func parseOpenCodeDB(s Source) ([]Event, error) {
	db, done, err := openSnapshot(s.Path)
	if err != nil {
		return nil, err
	}
	defer done()
	t := tables(db)
	c := newCtx(s.Agent, s.Path)
	switch {
	case t["part"] && t["message"]: // current TypeScript releases: JSON in data columns
		rows, err := db.Query(`SELECT p.id, p.session_id, CAST(p.data AS TEXT), CAST(m.data AS TEXT)
			FROM part p JOIN message m ON m.id = p.message_id
			ORDER BY p.session_id, m.id, p.id`)
		if err != nil {
			return nil, err
		}
		defer rows.Close()
		for rows.Next() {
			var pid, sid string
			var pd, md sql.NullString
			if rows.Scan(&pid, &sid, &pd, &md) != nil {
				continue
			}
			pm, _ := Decode(pd.String).(map[string]any)
			mm, _ := Decode(md.String).(map[string]any)
			if pm == nil {
				continue
			}
			c.session = sid
			if mdl := Str(mm, "modelID"); mdl != "" {
				c.model = mdl
			}
			c.touch(Get(mm, "time.created"))
			c.openCodePart(pm, Str(mm, "role"), "opencode.db:part:"+pid)
		}
		c.attachOpenCodeDirs(db)
	case t["messages"]: // original Go implementation: parts JSON array per message
		rows, err := db.Query(`SELECT id, session_id, role, CAST(parts AS TEXT), created_at FROM messages ORDER BY session_id, created_at, rowid`)
		if err != nil {
			return nil, err
		}
		defer rows.Close()
		for rows.Next() {
			var id, sid, role string
			var parts sql.NullString
			var created any
			if rows.Scan(&id, &sid, &role, &parts, &created) != nil {
				continue
			}
			c.session = sid
			c.touch(created)
			for _, p := range asSlice(Decode(parts.String)) {
				if pm, ok := p.(map[string]any); ok {
					c.openCodePart(pm, role, "opencode.db:messages:"+id)
				}
			}
		}
	default:
		return genericSQLite(s, db)
	}
	return c.events, nil
}

func (c *pctx) attachOpenCodeDirs(db *sql.DB) {
	rows, err := db.Query(`SELECT id, directory FROM session`)
	if err != nil {
		return
	}
	defer rows.Close()
	dirs := map[string]string{}
	for rows.Next() {
		var id string
		var d sql.NullString
		if rows.Scan(&id, &d) == nil {
			dirs[id] = d.String
		}
	}
	for i := range c.events {
		if d := dirs[c.events[i].SessionID]; d != "" && c.events[i].Cwd == "" {
			c.events[i].Cwd = d
		}
	}
}

// genericSQLite dumps every JSON-looking text cell through the generic extractor.
func genericSQLite(s Source, db *sql.DB) ([]Event, error) {
	c := newCtx(s.Agent, s.Path)
	for tbl := range tables(db) {
		rows, err := db.Query(fmt.Sprintf(`SELECT * FROM "%s" ORDER BY rowid LIMIT 200000`, tbl))
		if err != nil {
			continue
		}
		cols, _ := rows.Columns()
		for rows.Next() {
			vals := make([]any, len(cols))
			ptrs := make([]any, len(cols))
			for i := range vals {
				ptrs[i] = &vals[i]
			}
			if rows.Scan(ptrs...) != nil {
				continue
			}
			for i, v := range vals {
				var sv string
				switch t := v.(type) {
				case string:
					sv = t
				case []byte:
					sv = string(t)
				default:
					continue
				}
				if d := Decode(sv); d != nil {
					if _, isStr := d.(string); !isStr {
						c.genericWalk(d, fmt.Sprintf("%s:%s.%s", filepath.Base(s.Path), tbl, cols[i]))
					}
				}
			}
		}
		rows.Close()
	}
	return c.events, nil
}
