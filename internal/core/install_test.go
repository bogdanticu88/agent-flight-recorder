package core

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestOurCommandRecognition(t *testing.T) {
	bin := "/usr/local/bin/afr"
	for cmd, want := range map[string]bool{
		`"C:\Program Files\AgentFlightRecorder\afr.exe" hook --agent copilot --event preToolUse`:   true,
		`& "C:\Program Files\AgentFlightRecorder\afr.exe" hook --agent copilot --event preToolUse`: true,
		`'/usr/local/bin/afr' hook --agent claude-code --event PreToolUse`:                         true,
		`/opt/x/afr hook --agent codex`:                                           true,
		`"C:\tools\safr.exe" hook --agent x`:                                      false,
		`my-guard.sh hook --agent x`:                                              false,
		`'/usr/local/bin/afr' hook --agent codex --event PreToolUse && curl evil`: false,
		`python3 check.py # afr hook --agent claude-code`:                         false,
	} {
		if got := ourCommand(cmd, bin); got != want {
			t.Errorf("%q: got %v want %v", cmd, got, want)
		}
	}
}

func TestInstallMergeKeepsUserHooksAndIsIdempotent(t *testing.T) {
	home := t.TempDir()
	settings := filepath.Join(home, ".claude", "settings.json")
	writeFile(t, settings, `{"model":"opus","hooks":{"PreToolUse":[
	  {"matcher":"Bash","hooks":[{"type":"command","command":"my-guard.sh"},{"type":"command","command":"echo afr hook --agent claude-code"}]}
	]}}`)
	o := InstallOptions{Roots: RootsFor(home), Agents: map[string]bool{"claude-code": true}, Scope: "user", Bin: "/usr/local/bin/afr", OS: "linux"}
	for i := 0; i < 2; i++ {
		plans, err := Plan(o)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := Apply(plans, o.Bin); err != nil {
			t.Fatal(err)
		}
	}
	b, _ := os.ReadFile(settings)
	var cfg map[string]any
	if err := json.Unmarshal(b, &cfg); err != nil {
		t.Fatal(err)
	}
	if cfg["model"] != "opus" {
		t.Fatal("unrelated setting lost")
	}
	s := string(b)
	mustContain(t, s, "my-guard.sh")
	mustContain(t, s, "echo afr hook --agent claude-code") // looks similar, is not ours
	if n := strings.Count(s, "'/usr/local/bin/afr' hook --agent claude-code --event PreToolUse"); n != 1 {
		t.Fatalf("our PreToolUse handler appears %d times after two installs", n)
	}
	if _, err := os.Stat(settings + ".afr-bak"); err != nil {
		t.Fatal("no backup written")
	}
}

func TestInstallRefusesNonObjectSettings(t *testing.T) {
	home := t.TempDir()
	settings := filepath.Join(home, ".claude", "settings.json")
	writeFile(t, settings, `[1,2,3]`)
	o := InstallOptions{Roots: RootsFor(home), Agents: map[string]bool{"claude-code": true}, Scope: "user", Bin: "/usr/local/bin/afr", OS: "linux"}
	plans, _ := Plan(o)
	if _, err := Apply(plans, o.Bin); err == nil {
		t.Fatal("overwrote a settings file it could not parse")
	}
	b, _ := os.ReadFile(settings)
	if string(b) != "[1,2,3]" {
		t.Fatal("original file modified")
	}
}

func TestEveryAgentHasASupportRecord(t *testing.T) {
	for a := range HookAgents {
		if v := VendorFor(a); v.Status == "unknown" || v.Docs == "" || v.Checked == "" {
			t.Errorf("%s has no vendor support record", a)
		}
	}
}
