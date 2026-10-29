package core

import (
	"regexp"
	"strings"
)

// Secrets are scrubbed on the device, before anything is written to a bundle
// or a live log. Agent transcripts routinely contain the exact credentials the
// agent was handling (tokens printed by a tool, .npmrc contents, env dumps).

type redactRule struct {
	name string
	re   *regexp.Regexp
	keep int // capture group to keep (0 = replace whole match)
}

var redactRules = []redactRule{
	{"private-key", regexp.MustCompile(`-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----`), 0},
	{"jwt", regexp.MustCompile(`eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}`), 0},
	{"github-token", regexp.MustCompile(`\b(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{40,})\b`), 0},
	{"artifactory", regexp.MustCompile(`\b(?:AKC[a-zA-Z0-9]{60,}|cmVmd[A-Za-z0-9]{50,})\b`), 0},
	{"aws-access-key", regexp.MustCompile(`\b(?:AKIA|ASIA)[A-Z0-9]{16}\b`), 0},
	{"azure-storage-key", regexp.MustCompile(`(?i)AccountKey=[A-Za-z0-9+/=]{40,}`), 0},
	{"azure-sas", regexp.MustCompile(`(?i)\bsig=[A-Za-z0-9%+/=]{20,}`), 0},
	{"slack", regexp.MustCompile(`\bxox[abprs]-[A-Za-z0-9-]{10,}\b`), 0},
	{"openai", regexp.MustCompile(`\bsk-(?:proj-|ant-)?[A-Za-z0-9_-]{20,}\b`), 0},
	{"google-api", regexp.MustCompile(`\bAIza[0-9A-Za-z_-]{35}\b`), 0},
	{"npm-token", regexp.MustCompile(`\bnpm_[A-Za-z0-9]{36}\b`), 0},
	{"bearer", regexp.MustCompile(`(?i)(\bbearer\s+)[A-Za-z0-9._~+/=-]{16,}`), 1},
	{"basic-auth-url", regexp.MustCompile(`(?i)(\b[a-z][a-z0-9+.-]*://[^\s:/@]+:)[^\s@/]{3,}(@)`), -1},
	// key = value / "key": "value" for anything that looks like a credential name
	{"kv-secret", regexp.MustCompile(`(?i)((?:password|passwd|pwd|secret|token|api[_-]?key|apikey|access[_-]?key|client[_-]?secret|auth|_auth|_authToken|identity[_-]?token|connection[_-]?string)["']?\s*[:=]\s*["']?)([^\s"',;\[<][^\s"',;]{5,})`), 1},
}

// Redact replaces secrets in s and reports how many were removed.
func Redact(s string) (string, int) {
	if s == "" {
		return s, 0
	}
	n := 0
	for _, r := range redactRules {
		s = r.re.ReplaceAllStringFunc(s, func(m string) string {
			n++
			tag := "[REDACTED:" + r.name + "]"
			switch r.keep {
			case 1:
				sub := r.re.FindStringSubmatch(m)
				if len(sub) > 1 {
					return sub[1] + tag
				}
			case -1:
				sub := r.re.FindStringSubmatch(m)
				if len(sub) > 2 {
					return sub[1] + tag + sub[2]
				}
			}
			return tag
		})
	}
	return s, n
}

// RedactEvent scrubs every free-text field of an event in place.
func RedactEvent(e *Event) int {
	total := 0
	for _, f := range []*string{&e.Text, &e.Input, &e.Command, &e.Reason} {
		var n int
		*f, n = Redact(*f)
		total += n
	}
	for i, p := range e.Paths {
		if strings.Contains(p, "REDACTED") {
			continue
		}
		e.Paths[i], _ = Redact(p)
	}
	return total
}
