package core

import (
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"
)

// Roots describes the user profile being examined. It can be the live
// profile or a mounted copy (disk image, triage collection) via --home.
type Roots struct {
	Home         string
	AppData      string // Windows %APPDATA% (Roaming)
	LocalAppData string // Windows %LOCALAPPDATA%
}

// DefaultRoots returns the profile of the user running the tool.
func DefaultRoots() Roots {
	h, _ := os.UserHomeDir()
	return RootsFor(h)
}

// RootsFor derives OS-specific roots from a home directory. All candidates are
// tried regardless of the current OS, so a Windows profile copied to a Linux
// analysis box is still discovered.
func RootsFor(home string) Roots {
	r := Roots{Home: home}
	if runtime.GOOS == "windows" && home == mustHome() {
		r.AppData = os.Getenv("APPDATA")
		r.LocalAppData = os.Getenv("LOCALAPPDATA")
	}
	if r.AppData == "" {
		r.AppData = filepath.Join(home, "AppData", "Roaming")
	}
	if r.LocalAppData == "" {
		r.LocalAppData = filepath.Join(home, "AppData", "Local")
	}
	return r
}

func mustHome() string { h, _ := os.UserHomeDir(); return h }

// Source is one artifact on disk that an adapter knows how to read.
type Source struct {
	Agent   string `json:"agent"`
	Parser  string `json:"parser"`
	Path    string `json:"path"`
	Size    int64  `json:"size"`
	ModTime string `json:"mtime"`
	SHA256  string `json:"sha256,omitempty"`
	Events  int    `json:"events"`
	Error   string `json:"error,omitempty"`
	Note    string `json:"note,omitempty"`
}

type sourceSpec struct {
	agent  string
	parser string
	globs  []string // may contain ** (any depth)
	isDir  bool
}

// editorUserDirs lists VS Code-family "User" directories (Stable, Insiders,
// VSCodium, Cursor, Windsurf) on Windows, macOS and Linux.
func editorUserDirs(r Roots, products ...string) []string {
	var out []string
	for _, p := range products {
		out = append(out,
			filepath.Join(r.AppData, p, "User"),
			filepath.Join(r.Home, "Library", "Application Support", p, "User"),
			filepath.Join(r.Home, ".config", p, "User"),
			filepath.Join(r.Home, ".vscode-server", "data", "User"), // remote/WSL server side
		)
	}
	return out
}

func specs(r Roots) []sourceSpec {
	vs := editorUserDirs(r, "Code", "Code - Insiders", "VSCodium")
	cur := editorUserDirs(r, "Cursor")
	all := editorUserDirs(r, "Code", "Code - Insiders", "VSCodium", "Cursor", "Windsurf")
	j := func(bases []string, rel ...string) []string {
		var g []string
		for _, b := range bases {
			for _, x := range rel {
				g = append(g, filepath.Join(b, x))
			}
		}
		return g
	}
	logs := func(bases []string) []string {
		var g []string
		for _, b := range bases {
			g = append(g, filepath.Join(filepath.Dir(b), "logs", "**", "GitHub.copilot-chat", "*.log"))
		}
		return g
	}
	h := r.Home
	return []sourceSpec{
		// GitHub Copilot in VS Code
		{agent: "copilot-vscode", parser: "vscode-chat", globs: j(vs,
			filepath.Join("workspaceStorage", "*", "chatSessions", "*.json"),
			filepath.Join("workspaceStorage", "*", "chatSessions", "*.jsonl"),
			filepath.Join("globalStorage", "emptyWindowChatSessions", "*.json"),
			filepath.Join("globalStorage", "emptyWindowChatSessions", "*.jsonl"))},
		{agent: "copilot-vscode", parser: "vscode-statedb", globs: j(vs,
			filepath.Join("workspaceStorage", "*", "state.vscdb"),
			filepath.Join("globalStorage", "state.vscdb"))},
		{agent: "copilot-vscode", parser: "logfile", globs: logs(vs)},
		{agent: "copilot-vscode", parser: "config", globs: j(all, "settings.json", "mcp.json")},
		// GitHub Copilot CLI
		{agent: "copilot-cli", parser: "copilot-cli", globs: []string{
			filepath.Join(h, ".copilot", "session-state", "*", "events.jsonl"),
			filepath.Join(h, ".copilot", "history-session-state", "*.json")}},
		{agent: "copilot-cli", parser: "config", globs: []string{
			filepath.Join(h, ".copilot", "config.json"), filepath.Join(h, ".copilot", "settings.json"),
			filepath.Join(h, ".copilot", "mcp-config.json"), filepath.Join(h, ".copilot", "hooks", "*.json")}},
		// Claude Code
		{agent: "claude-code", parser: "claude-code", globs: []string{
			filepath.Join(h, ".claude", "projects", "*", "*.jsonl"),
			filepath.Join(h, ".claude", "projects", "*", "*", "subagents", "*.jsonl")}},
		{agent: "claude-code", parser: "config", globs: []string{
			filepath.Join(h, ".claude", "settings.json"), filepath.Join(h, ".claude.json"),
			filepath.Join(h, ".claude", "CLAUDE.md")}},
		// OpenAI Codex CLI / IDE extension
		{agent: "codex", parser: "codex", globs: []string{
			filepath.Join(h, ".codex", "sessions", "**", "*.jsonl"),
			filepath.Join(h, ".codex", "archived_sessions", "*.jsonl")}},
		{agent: "codex", parser: "config", globs: []string{
			filepath.Join(h, ".codex", "config.toml"), filepath.Join(h, ".codex", "hooks.json"),
			filepath.Join(h, ".codex", "AGENTS.md")}},
		// Google Gemini CLI
		{agent: "gemini-cli", parser: "gemini", globs: []string{
			filepath.Join(h, ".gemini", "tmp", "*", "chats", "*.json"),
			filepath.Join(h, ".gemini", "tmp", "*", "logs.json"),
			filepath.Join(h, ".gemini", "tmp", "*", "checkpoint-*.json")}},
		{agent: "gemini-cli", parser: "config", globs: []string{
			filepath.Join(h, ".gemini", "settings.json"), filepath.Join(h, ".gemini", "GEMINI.md")}},
		// OpenCode (SQLite in current releases, JSON storage in older ones)
		{agent: "opencode", parser: "opencode-db", globs: []string{
			filepath.Join(h, ".local", "share", "opencode", "opencode.db"),
			filepath.Join(h, ".local", "share", "opencode", "*.db"),
			filepath.Join(r.LocalAppData, "opencode", "*.db"),
			filepath.Join(h, ".opencode", "opencode.db")}},
		{agent: "opencode", parser: "opencode-storage", isDir: true, globs: []string{
			filepath.Join(h, ".local", "share", "opencode", "storage"),
			filepath.Join(r.LocalAppData, "opencode", "storage")}},
		{agent: "opencode", parser: "config", globs: []string{
			filepath.Join(h, ".config", "opencode", "opencode.json"),
			filepath.Join(h, ".config", "opencode", "opencode.jsonc"),
			filepath.Join(h, ".config", "opencode", "plugin", "*"),
			filepath.Join(h, ".config", "opencode", "plugins", "*")}},
		// Cursor (IDE chat/composer and cursor-agent CLI)
		{agent: "cursor", parser: "cursor-db", globs: append(j(cur,
			filepath.Join("globalStorage", "state.vscdb"),
			filepath.Join("workspaceStorage", "*", "state.vscdb")),
			filepath.Join(h, ".cursor", "chats", "**", "*.db"))},
		{agent: "cursor", parser: "config", globs: []string{
			filepath.Join(h, ".cursor", "hooks.json"), filepath.Join(h, ".cursor", "mcp.json")}},
		// Cline and Roo Code (VS Code extensions that call any model provider)
		{agent: "cline", parser: "cline", globs: j(all,
			filepath.Join("globalStorage", "saoudrizwan.claude-dev", "tasks", "*", "ui_messages.json"),
			filepath.Join("globalStorage", "rooveterinaryinc.roo-cline", "tasks", "*", "ui_messages.json"))},
	}
}

// Discover finds every artifact for the selected agents ("all" or a list).
func Discover(r Roots, agents map[string]bool) []Source {
	seen := map[string]bool{}
	var out []Source
	for _, sp := range specs(r) {
		if len(agents) > 0 && !agents["all"] && !agents[sp.agent] {
			continue
		}
		for _, g := range sp.globs {
			for _, p := range globAny(g) {
				st, err := os.Stat(p)
				if err != nil || st.IsDir() != sp.isDir {
					continue
				}
				key := sp.parser + "|" + p
				if seen[key] {
					continue
				}
				seen[key] = true
				out = append(out, Source{Agent: sp.agent, Parser: sp.parser, Path: p,
					Size: st.Size(), ModTime: st.ModTime().UTC().Format(time.RFC3339)})
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out
}

// AgentNames lists the agents the collector knows about.
func AgentNames() []string {
	set := map[string]bool{}
	for _, s := range specs(Roots{}) {
		set[s.agent] = true
	}
	var n []string
	for k := range set {
		n = append(n, k)
	}
	sort.Strings(n)
	return n
}

// globAny supports a single "**" segment meaning any depth.
func globAny(pattern string) []string {
	if !strings.Contains(pattern, "**") {
		m, _ := filepath.Glob(pattern)
		return m
	}
	idx := strings.Index(pattern, "**")
	base := strings.TrimRight(pattern[:idx], `/\`)
	rest := strings.TrimLeft(pattern[idx+2:], `/\`)
	if _, err := os.Stat(base); err != nil {
		return nil
	}
	var out []string
	_ = filepath.WalkDir(base, func(p string, d fs.DirEntry, err error) error {
		if err != nil || !d.IsDir() {
			return nil
		}
		m, _ := filepath.Glob(filepath.Join(p, rest))
		out = append(out, m...)
		return nil
	})
	return out
}

// instructionFiles are loaded into agent context silently. They are the usual
// hiding place for prompt injection, so the collector hashes and captures them
// for every working directory it sees in the sessions.
var instructionFiles = []string{
	"AGENTS.md", "CLAUDE.md", "GEMINI.md", "CODEX.md", "Copilot.md", ".cursorrules", ".windsurfrules", ".clinerules",
	filepath.Join(".github", "copilot-instructions.md"),
	filepath.Join(".github", "instructions"),
	filepath.Join(".github", "prompts"),
	filepath.Join(".github", "hooks"),
	filepath.Join(".github", "copilot", "settings.json"),
	filepath.Join(".claude", "settings.json"), filepath.Join(".claude", "settings.local.json"),
	filepath.Join(".codex", "hooks.json"), filepath.Join(".codex", "config.toml"),
	filepath.Join(".cursor", "rules"), filepath.Join(".cursor", "hooks.json"), filepath.Join(".cursor", "mcp.json"),
	filepath.Join(".vscode", "mcp.json"), filepath.Join(".vscode", "settings.json"),
	filepath.Join(".gemini", "settings.json"), "opencode.json", filepath.Join(".opencode", "plugin"),
}

// WorkspaceArtifacts returns instruction/config files under a workspace folder.
func WorkspaceArtifacts(ws string) []string {
	var out []string
	for _, rel := range instructionFiles {
		p := filepath.Join(ws, rel)
		st, err := os.Stat(p)
		if err != nil {
			continue
		}
		if !st.IsDir() {
			out = append(out, p)
			continue
		}
		_ = filepath.WalkDir(p, func(q string, d fs.DirEntry, err error) error {
			if err == nil && !d.IsDir() {
				if info, e := d.Info(); e == nil && info.Size() < 2<<20 {
					out = append(out, q)
				}
			}
			return nil
		})
	}
	return out
}
