package core

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
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
		evs := []string{"SessionStart", "UserPromptSubmit", "PreToolUse", "PostToolUse", "SubagentStop", "Stop", "SessionEnd", "PreCompact"}
		cfg := map[string]any{"hooks": o.claudeStyle("claude-code", evs, map[string]bool{"PreToolUse": true, "PostToolUse": true}, map[string]any{"timeout": 10})}
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
		note := "Hooks may need enabling in ~/.codex/config.toml ([features] codex_hooks = true) depending on Codex version. Check Windows support for your version. Non-managed hooks must be trusted once by the user."
		if machine {
			note += " For machine scope use Codex managed configuration (requirements/managed config) to enforce these hooks."
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
			Note: "Hooks are experimental in some Gemini CLI versions and may need an enable flag in settings.json."})
	}

	if o.want("opencode") {
		p := filepath.Join(h, ".config", "opencode", "plugin", "afr.js")
		out = append(out, Planned{Agent: "opencode", Path: p, Content: []byte(openCodePlugin(o.Bin)),
			Note: "OpenCode has no machine-wide plugin directory; deploy per user. Some versions use plugins/ instead of plugin/, or need the file listed under \"plugin\" in opencode.json."})
	}
	return out, nil
}

// Apply writes planned files, merging into existing JSON settings and keeping a backup.
func Apply(plans []Planned) ([]string, error) {
	var done []string
	for _, p := range plans {
		if err := os.MkdirAll(filepath.Dir(p.Path), 0o755); err != nil {
			return done, err
		}
		content := p.Content
		if p.Merge {
			if old, err := os.ReadFile(p.Path); err == nil && len(strings.TrimSpace(string(old))) > 0 {
				merged, err := mergeHooks(old, p.Content)
				if err != nil {
					return done, fmt.Errorf("%s: %w (fix or remove the file, then rerun)", p.Path, err)
				}
				_ = os.WriteFile(p.Path+".afr-bak", old, 0o600)
				content = merged
			}
		}
		if err := os.WriteFile(p.Path, content, 0o644); err != nil {
			return done, err
		}
		done = append(done, p.Path)
	}
	return done, nil
}

// mergeHooks adds our hook entries without touching anything else, and
// replaces previous afr entries so reinstalling is idempotent.
func mergeHooks(oldB, addB []byte) ([]byte, error) {
	var old, add map[string]any
	if err := json.Unmarshal(oldB, &old); err != nil {
		return nil, fmt.Errorf("existing file is not plain JSON")
	}
	_ = json.Unmarshal(addB, &add)
	for k, v := range add {
		if k != "hooks" {
			if _, exists := old[k]; !exists {
				old[k] = v
			}
			continue
		}
		oh, _ := old["hooks"].(map[string]any)
		if oh == nil {
			oh = map[string]any{}
		}
		for ev, entries := range v.(map[string]any) {
			var kept []any
			for _, e := range asSlice(oh[ev]) {
				b, _ := json.Marshal(e)
				if !strings.Contains(string(b), " hook --agent ") {
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
		_ = os.WriteFile(dst+".target.txt", []byte(fmt.Sprintf("target: %s\nmerge into existing: %v\n%s\n", p.Path, p.Merge, p.Note)), 0o644)
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
