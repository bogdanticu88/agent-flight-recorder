package core

import (
	"encoding/json"
	"regexp"
	"strings"
)

// Secrets are scrubbed on the device before anything is written to a bundle
// or a live log. Agent transcripts routinely contain the exact credentials the
// agent was handling (tokens printed by a tool, .npmrc contents, env dumps).
//
// Order matters: always redact the complete value, then truncate. A cut taken
// first can split a secret so that none of these patterns match any more.

type redactRule struct {
	name string
	re   *regexp.Regexp
	keep int // 1: keep capture group 1 as prefix; -1: keep groups 1 and 2 around the tag
}

const valueClass = `[^\s"'\\,;\[<]`

var redactRules = []redactRule{
	{"private-key", regexp.MustCompile(`-----BEGIN [A-Z0-9 ]*PRIVATE KEY[A-Z ]*-----[\s\S]*?-----END [A-Z0-9 ]*PRIVATE KEY[A-Z ]*-----`), 0},
	// An opening marker without its closing marker (cut off, or the closing
	// line was never captured): everything from the marker on is treated as key material.
	{"private-key-partial", regexp.MustCompile(`-----BEGIN [A-Z0-9 ]*PRIVATE KEY[A-Z ]*-----[\s\S]*`), 0},
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
	// key = value, "key": "value" and the same with escaped quotes (\"key\": \"value\")
	// for anything that looks like a credential name
	{"kv-secret", regexp.MustCompile(`(?i)((?:password|passwd|pwd|secret|token|api[_-]?key|apikey|access[_-]?key|client[_-]?secret|_auth|_authToken|identity[_-]?token|connection[_-]?string)(?:\\?["'])?\s*[:=]\s*(?:\\?["'])?)(` + valueClass + `[^\s"'\\,;]{5,})`), 1},
}

// secretKeyRe matches JSON object keys whose string values are secrets
// whatever they look like.
var secretKeyRe = regexp.MustCompile(`(?i)(password|passwd|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|authorization|credential|connection[_-]?string)`)

// nonSecretKeys are key names that match secretKeyRe but hold counts or labels.
var nonSecretKeys = map[string]bool{
	"max_tokens": true, "input_tokens": true, "output_tokens": true, "tokens": true, "token_count": true,
	"token_type": true, "max_output_tokens": true, "cache_read_input_tokens": true, "cache_creation_input_tokens": true,
}

// Redact replaces secrets in free text and reports how many were removed.
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
				if sub := r.re.FindStringSubmatch(m); len(sub) > 1 {
					return sub[1] + tag
				}
			case -1:
				if sub := r.re.FindStringSubmatch(m); len(sub) > 2 {
					return sub[1] + tag + sub[2]
				}
			}
			return tag
		})
	}
	return s, n
}

// RedactValue redacts a string that may hold JSON. JSON is decoded and every
// string value redacted in place (values under credential-like keys entirely),
// then re-encoded, so a secret cut short by an escaped quote is still caught
// and the result stays valid JSON. Text that is not JSON gets plain Redact.
func RedactValue(s string) (string, int) {
	t := strings.TrimSpace(s)
	if len(t) > 1 && (t[0] == '{' || t[0] == '[') {
		var v any
		dec := json.NewDecoder(strings.NewReader(t))
		dec.UseNumber()
		if dec.Decode(&v) == nil && !dec.More() {
			n := 0
			v = redactTree(v, "", &n, 0)
			if n == 0 {
				return s, 0
			}
			var b strings.Builder
			enc := json.NewEncoder(&b)
			enc.SetEscapeHTML(false)
			if enc.Encode(v) == nil {
				return strings.TrimSuffix(b.String(), "\n"), n
			}
		}
	}
	return Redact(s)
}

func redactTree(v any, key string, n *int, depth int) any {
	if depth > maxWalkDepth {
		*n++
		return "[REDACTED:too-deep]"
	}
	switch t := v.(type) {
	case map[string]any:
		for k, vv := range t {
			t[k] = redactTree(vv, k, n, depth+1)
		}
		return t
	case []any:
		for i := range t {
			t[i] = redactTree(t[i], key, n, depth+1)
		}
		return t
	case string:
		if key != "" && secretKeyRe.MatchString(key) && !nonSecretKeys[strings.ToLower(key)] && len(t) >= 4 && !strings.HasPrefix(t, "[REDACTED") {
			*n++
			return "[REDACTED:kv-secret]"
		}
		if strings.HasPrefix(strings.TrimSpace(t), "{") || strings.HasPrefix(strings.TrimSpace(t), "[") {
			r, c := RedactValue(t)
			*n += c
			return r
		}
		r, c := Redact(t)
		*n += c
		return r
	}
	return v
}

// RedactEvent scrubs every persisted free-text field of an event in place and
// returns the number of replacements.
func RedactEvent(e *Event) int {
	total := 0
	for _, f := range []*string{&e.Text, &e.Input, &e.Command, &e.Reason, &e.Error, &e.Cwd, &e.SourceRef} {
		var n int
		*f, n = RedactValue(*f)
		total += n
	}
	for i, p := range e.Paths {
		var n int
		e.Paths[i], n = Redact(p)
		total += n
	}
	return total
}

// TruncateEvent caps the large free-text fields. Call it after RedactEvent.
func TruncateEvent(e *Event, max int) {
	for _, f := range []*string{&e.Text, &e.Input, &e.Command, &e.Reason, &e.Error} {
		*f = Truncate(*f, max)
	}
}
