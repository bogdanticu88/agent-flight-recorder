package core

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
)

// Planned is one file the installer would write.
type Planned struct {
	Agent   string
	Path    string
	Content []byte
	Merge   bool   // merged into an existing settings file
	Note    string // manual follow-up the admin must do
}

type InstallOptions struct {
	Roots  Roots
	Agents map[string]bool
	Scope  string // user | machine
	Bin    string // absolute path of afr binary as it will exist on endpoints
	OS     string // target OS for machine paths (default: current)
}

func (o InstallOptions) want(a string) bool {
	return len(o.Agents) == 0 || o.Agents["all"] || o.Agents[a]
}

func (o InstallOptions) targetOS() string {
	if o.OS != "" {
		return o.OS
	}
	return runtime.GOOS
}

func (o InstallOptions) cmd(agent, event string) string {
	if o.targetOS() == "windows" {
		return fmt.Sprintf(`"%s" hook --agent %s --event %s`, o.Bin, agent, event)
	}
	return fmt.Sprintf(`'%s' hook --agent %s --event %s`, o.Bin, agent, event)
}

func machinePath(osName string, win, mac, linux string) string {
	switch osName {
	case "windows":
		return win
	case "darwin":
		return mac
	}
	return linux
}

// claudeStyle builds the {"hooks":{Event:[{matcher, hooks:[{type,command}]}]}} shape
// shared by Claude Code, Codex and Gemini CLI.
func (o InstallOptions) claudeStyle(agent string, events []string, matcherEvents map[string]bool, extra map[string]any) map[string]any {
	hooks := map[string]any{}
	for _, ev := range events {
		h := map[string]any{"type": "command", "command": o.cmd(agent, ev)}
		for k, v := range extra {
			h[k] = v
		}
		entry := map[string]any{"hooks": []any{h}}
		if matcherEvents[ev] {
			entry["matcher"] = "*"
		}
		hooks[ev] = []any{entry}
	}
	return hooks
}

// Plan works out every file to write for the selected agents and scope.
func Plan(o InstallOptions) ([]Planned, error) {
	if o.Bin == "" {
		return nil, fmt.Errorf("--bin is required (path of afr on the endpoint)")
	}
	h := o.Roots.Home
	osn := o.targetOS()
	machine := o.Scope == "machine"
	var out []Planned
	j := func(v any) []byte {
		var buf strings.Builder
		enc := json.NewEncoder(&buf)
		enc.SetEscapeHTML(false)
		enc.SetIndent("", "  ")
		_ = enc.Encode(v)
		return []byte(buf.String())
	}

	if o.want("copilot") { // VS Code agent mode + Copilot CLI share the Copilot hook runtime
		evs := []string{"sessionStart", "userPromptSubmitted", "preToolUse", "postToolUse", "subagentStart", "subagentStop", "agentStop", "sessionEnd"}
		hooks := map[string]any{}
		for _, ev := range evs {
			c := map[string]any{"type": "command", "timeoutSec": 10}
			if osn == "windows" {
				c["powershell"] = "& " + o.cmd("copilot", ev)
			} else {
				c["bash"] = o.cmd("copilot", ev)
			}
			hooks[ev] = []any{c}
		}
		p := filepath.Join(h, ".copilot", "hooks", "afr.json")
		note := "Covers Copilot CLI and VS Code agent sessions on the Copilot harness. VS Code hooks are in preview: make sure enterprise policy allows them. Local-harness VS Code sessions read .github/hooks or chat.hookFilesLocations instead."
		if machine {
			p = machinePath(osn, `C:\ProgramData\GitHub\Copilot\policy.d\afr.json`, "/etc/github-copilot/policy.d/afr.json", "/etc/github-copilot/policy.d/afr.json")
			note = "Policy hooks load before all others and cannot be disabled by the user (disableAllHooks). On POSIX the file must be root-owned and not group/world-writable. Documented for Copilot CLI; deploy the user-scope file too for VS Code until VS Code honours policy.d."
		}
		out = append(out, Planned{Agent: "copilot", Path: p, Content: j(map[string]any{"version": 1, "hooks": hooks}), Note: note})
	}

	if o.want("claude-code") {
		evs := []string{"SessionStart", "UserPromptSubmit", "PreToolUse", "PostToolUse", "PostToolUseFailure", "SubagentStop", "Stop", "SessionEnd", "PreCompact"}
		cfg := map[string]any{"hooks": o.claudeStyle("claude-code", evs, map[string]bool{"PreToolUse": true, "PostToolUse": true, "PostToolUseFailure": true}, map[string]any{"timeout": 10})}
		p := filepath.Join(h, ".claude", "settings.json")
		note := ""
		if machine {
			p = machinePath(osn, `C:\ProgramData\ClaudeCode\managed-settings.json`, "/Library/Application Support/ClaudeCode/managed-settings.json", "/etc/claude-code/managed-settings.json")
			note = "Managed settings override user settings. Consider \"allowManagedHooksOnly\": true so users cannot add hooks that undercut yours. Check the managed-settings path for your Claude Code version."
		}
		out = append(out, Planned{Agent: "claude-code", Path: p, Content: j(cfg), Merge: true, Note: note})
	}

	if o.want("codex") {
		evs := []string{"SessionStart", "UserPromptSubmit", "PreToolUse", "PostToolUse", "Stop"}
		cfg := map[string]any{"hooks": o.claudeStyle("codex", evs, map[string]bool{"PreToolUse": true, "PostToolUse": true}, map[string]any{"timeout": 10})}
		p := filepath.Join(h, ".codex", "hooks.json")
		note := "Hooks are on by default in current Codex releases. Non-managed hooks must be reviewed and trusted by the user (/hooks) before they run, and trust is tied to the hook's hash."
		if machine {
			note += " This installer only writes the user file. For enforced hooks use Codex managed hooks ([hooks] in requirements.toml with managed_dir / windows_managed_dir, allow_managed_hooks_only = true)."
		}
		out = append(out, Planned{Agent: "codex", Path: p, Content: j(cfg), Merge: true, Note: note})
	}

	if o.want("cursor") {
		evs := []string{"sessionStart", "beforeSubmitPrompt", "preToolUse", "postToolUse", "postToolUseFailure", "beforeReadFile", "beforeShellExecution", "beforeMCPExecution", "afterAgentThought", "afterAgentResponse", "stop", "sessionEnd"}
		hooks := map[string]any{}
		for _, ev := range evs {
			hooks[ev] = []any{map[string]any{"command": o.cmd("cursor", ev), "timeout": 10}}
		}
		p := filepath.Join(h, ".cursor", "hooks.json")
		if machine {
			p = machinePath(osn, `C:\ProgramData\Cursor\hooks.json`, "/Library/Application Support/Cursor/hooks.json", "/etc/cursor/hooks.json")
		}
		out = append(out, Planned{Agent: "cursor", Path: p, Content: j(map[string]any{"version": 1, "hooks": hooks}), Merge: true,
			Note: "Enterprise plans can also push hooks from the Cursor admin dashboard."})
	}

	if o.want("gemini-cli") {
		evs := []string{"SessionStart", "BeforeAgent", "BeforeTool", "AfterTool", "AfterAgent", "SessionEnd"}
		hooks := o.claudeStyle("gemini-cli", evs, map[string]bool{"BeforeTool": true, "AfterTool": true}, map[string]any{"name": "afr", "timeout": 10000})
		p := filepath.Join(h, ".gemini", "settings.json")
		if machine {
			p = machinePath(osn, `C:\ProgramData\gemini-cli\settings.json`, "/Library/Application Support/GeminiCli/settings.json", "/etc/gemini-cli/settings.json")
		}
		out = append(out, Planned{Agent: "gemini-cli", Path: p, Content: j(map[string]any{"hooks": hooks}), Merge: true,
			Note: "Hook timeouts are in milliseconds. Some Gemini CLI versions shipped hooks behind an experimental setting; check /hooks after installing."})
	}

	if o.want("opencode") {
		p := filepath.Join(h, ".config", "opencode", "plugin", "afr.js")
		out = append(out, Planned{Agent: "opencode", Path: p, Content: []byte(openCodePlugin(o.Bin)),
			Note: "OpenCode has no machine-wide plugin directory; deploy per user. Some versions use plugins/ instead of plugin/, or need the file listed under \"plugin\" in opencode.json."})
	}
	return out, nil
}

// Apply writes planned files. Settings files shared with the user are merged:
// only handlers recognised as afr's own are replaced, everything else is kept,
// and the previous file is backed up. Writes go through a temp file + rename.
func Apply(plans []Planned, bin string) ([]string, error) {
	var done []string
	for _, p := range plans {
		if err := os.MkdirAll(filepath.Dir(p.Path), 0o755); err != nil {
			return done, err
		}
		content := p.Content
		if p.Merge {
			if old, err := os.ReadFile(p.Path); err == nil && len(strings.TrimSpace(string(old))) > 0 {
				merged, err := mergeHooks(old, p.Content, bin)
				if err != nil {
					return done, fmt.Errorf("%s: %w (fix or remove the file, then rerun)", p.Path, err)
				}
				if err := os.WriteFile(p.Path+".afr-bak", old, 0o600); err != nil {
					return done, fmt.Errorf("%s: could not write backup: %w", p.Path, err)
				}
				content = merged
			} else if err != nil && !os.IsNotExist(err) {
				return done, fmt.Errorf("%s: %w", p.Path, err)
			}
		}
		if strings.HasSuffix(p.Path, ".json") {
			var probe any
			if err := json.Unmarshal(content, &probe); err != nil {
				return done, fmt.Errorf("%s: generated content is not valid JSON: %w", p.Path, err)
			}
		}
		tmp := p.Path + ".afr-tmp"
		if err := os.WriteFile(tmp, content, 0o644); err != nil {
			return done, err
		}
		if err := os.Rename(tmp, p.Path); err != nil {
			os.Remove(tmp)
			return done, err
		}
		done = append(done, p.Path)
	}
	return done, nil
}

// ourCommand matches a hook command line that afr's installer generated:
// an executable named afr / afr.exe (or the configured binary), quoted or
// not, optionally preceded by PowerShell's call operator, followed by exactly
// "hook --agent NAME [--event NAME]". A command that merely mentions afr, or
// runs something else afterwards, does not match and is left alone.
func ourCommand(cmd, bin string) bool {
	names := []string{regexp.QuoteMeta("afr"), regexp.QuoteMeta("afr.exe")}
	if b := filepath.Base(strings.ReplaceAll(bin, `\`, "/")); b != "" && b != "." {
		names = append(names, regexp.QuoteMeta(b))
	}
	name := `(?:` + strings.Join(names, "|") + `)`
	exe := `(?:"(?:[^"]*[\\/])?` + name + `"|'(?:[^']*[\\/])?` + name + `'|(?:[^"'\s]*[\\/])?` + name + `)`
	re := regexp.MustCompile(`^\s*(?:&\s*)?` + exe + `\s+hook\s+--agent\s+[a-z][a-z-]*(?:\s+--event\s+[A-Za-z.]+)?\s*$`)
	return re.MatchString(cmd)
}

// handlerIsOurs reports whether a single hook handler object was written by afr.
func handlerIsOurs(h any, bin string) bool {
	m, ok := h.(map[string]any)
	if !ok {
		return false
	}
	found := false
	for _, k := range []string{"command", "bash", "powershell", "commandWindows"} {
		if c, ok := m[k].(string); ok {
			if !ourCommand(c, bin) {
				return false
			}
			found = true
		}
	}
	return found
}

// mergeHooks adds our hook entries without touching anything else. Within a
// matcher group ({matcher, hooks:[...]}) only afr's own handlers are removed,
// so a group the user shares with afr keeps the user's handlers.
func mergeHooks(oldB, addB []byte, bin string) ([]byte, error) {
	var old, add map[string]any
	if err := json.Unmarshal(oldB, &old); err != nil || old == nil {
		return nil, fmt.Errorf("existing file is not a plain JSON object")
	}
	if err := json.Unmarshal(addB, &add); err != nil {
		return nil, err
	}
	for k, v := range add {
		if k != "hooks" {
			if _, exists := old[k]; !exists {
				old[k] = v
			}
			continue
		}
		oh, isMap := old["hooks"].(map[string]any)
		if old["hooks"] != nil && !isMap {
			return nil, fmt.Errorf(`"hooks" is not an object`)
		}
		if oh == nil {
			oh = map[string]any{}
		}
		for ev, entries := range v.(map[string]any) {
			var kept []any
			for _, e := range asSlice(oh[ev]) {
				em, _ := e.(map[string]any)
				if inner, ok := em["hooks"].([]any); ok { // matcher group
					var keepInner []any
					for _, h := range inner {
						if !handlerIsOurs(h, bin) {
							keepInner = append(keepInner, h)
						}
					}
					if len(keepInner) == 0 {
						continue
					}
					cp := map[string]any{}
					for kk, vv := range em {
						cp[kk] = vv
					}
					cp["hooks"] = keepInner
					kept = append(kept, cp)
					continue
				}
				if !handlerIsOurs(e, bin) {
					kept = append(kept, e)
				}
			}
			oh[ev] = append(kept, asSlice(entries)...)
		}
		old["hooks"] = oh
	}
	var buf strings.Builder
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	err := enc.Encode(old)
	return []byte(buf.String()), err
}

// Emit writes all planned files into a folder tree for packaging (Intune, GPO, MDM).
func Emit(plans []Planned, dir string) ([]string, error) {
	var out []string
	for _, p := range plans {
		dst := filepath.Join(dir, p.Agent, filepath.Base(p.Path))
		if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
			return out, err
		}
		if err := os.WriteFile(dst, p.Content, 0o644); err != nil {
			return out, err
		}
		out = append(out, dst)
		vs := VendorFor(p.Agent)
		info := fmt.Sprintf("target: %s\nmerge into existing: %v\n%s\n\nvendor support: %s\nchecked against: %s (%s)\n%s\n", p.Path, p.Merge, p.Note, vs.Status, vs.Docs, vs.Checked, vs.Notes)
		if err := os.WriteFile(dst+".target.txt", []byte(info), 0o644); err != nil {
			return out, err
		}
	}
	sort.Strings(out)
	return out, nil
}

func openCodePlugin(bin string) string {
	b, _ := json.Marshal(bin)
	return `// Agent Flight Recorder plugin for OpenCode.
// Forwards prompts and tool calls to the afr hook recorder. If afr's policy
// denies a tool call (exit code 2) the plugin throws, which blocks the tool.
const AFR_BIN = ` + string(b) + `;

export const AgentFlightRecorder = async ({ directory }) => {
  const run = async (event, payload) => {
    let proc;
    try {
      proc = Bun.spawn([AFR_BIN, "hook", "--agent", "opencode", "--event", event], {
        stdin: "pipe", stdout: "pipe", stderr: "pipe",
      });
      proc.stdin.write(JSON.stringify({ cwd: directory, ...payload }));
      proc.stdin.end();
    } catch (e) {
      return; // recorder missing: never break the agent
    }
    const code = await proc.exited;
    if (code === 2) {
      const reason = (await new Response(proc.stderr).text()).trim();
      throw new Error(reason || "Blocked by security policy");
    }
  };
  const text = (parts) => (parts || []).map((p) => p.text || "").filter(Boolean).join("\n");
  return {
    "chat.message": async (input, output) =>
      run("prompt", { session_id: input.sessionID, prompt: text(output.parts), model: input.model?.modelID }),
    "tool.execute.before": async (input, output) =>
      run("PreToolUse", { session_id: input.sessionID, call_id: input.callID, tool_name: input.tool, tool_input: output.args }),
    "tool.execute.after": async (input, output) =>
      run("PostToolUse", { session_id: input.sessionID, call_id: input.callID, tool_name: input.tool,
        tool_response: typeof output.output === "string" ? output.output : JSON.stringify(output.output ?? output) }),
    event: async ({ event }) => {
      if (event.type === "session.created" || event.type === "session.idle") {
        await run(event.type, { session_id: event.properties?.sessionID ?? event.properties?.info?.id });
      }
    },
  };
};
`
}

// VendorSupport records what each integration was checked against. None has
// been exercised against a real agent by this project's tests: payloads are
// synthetic. "documented" means the config shape and deny protocol match the
// vendor's published documentation on the date given.
type VendorSupport struct {
	Agent, Status, Docs, Checked, Notes string
}

var VendorSupportTable = []VendorSupport{
	{"claude-code", "documented, unverified against a real install", "https://code.claude.com/docs/en/hooks", "2026-10-31",
		"settings.json hooks; matcher groups; timeout in seconds; PreToolUse deny via hookSpecificOutput.permissionDecision; PostToolUse fires after success, PostToolUseFailure after failure; managed settings support allowManagedHooksOnly."},
	{"codex", "documented, unverified against a real install", "https://learn.chatgpt.com/docs/hooks (redirect target of developers.openai.com/codex/hooks)", "2026-10-31",
		"hooks.json; timeout in seconds; PreToolUse deny via hookSpecificOutput.permissionDecision (exit 2 also blocks); non-managed hooks require user trust; managed hooks via requirements.toml."},
	{"copilot", "experimental", "https://docs.github.com/en/copilot/reference/hooks-reference ; https://code.visualstudio.com/docs/agent-customization/hooks", "2026-10-30",
		"hook file version 1 with bash/powershell and timeoutSec; deny via permissionDecision. VS Code agent hooks are in preview and their full payload schema was not confirmed; policy.d is documented for Copilot CLI."},
	{"cursor", "experimental", "https://cursor.com/docs/hooks", "2026-10-30",
		"hooks.json version 1; exit code 2 denies; permission field. Enterprise file locations not confirmed."},
	{"gemini-cli", "experimental", "https://geminicli.com/docs/hooks/", "2026-10-31",
		"settings.json hooks with matcher groups; timeout in milliseconds; exit 2 blocks with stderr as reason. Stdin field names were not listed in the documentation read."},
	{"opencode", "experimental", "OpenCode plugin documentation and community references", "2026-10-30",
		"JS plugin; throwing from tool.execute.before blocks the tool. Plugin directory name differs between versions."},
}

// VendorFor returns the support record for an agent.
func VendorFor(agent string) VendorSupport {
	for _, v := range VendorSupportTable {
		if v.Agent == agent {
			return v
		}
	}
	return VendorSupport{Agent: agent, Status: "unknown"}
}
