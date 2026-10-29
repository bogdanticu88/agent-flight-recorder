package core

import (
	"regexp"
	"strings"
)

// globToRegex: ** = any chars incl. '/', * = any chars except '/', ? = one char.
// Patterns not starting with '/' or a drive may match anywhere in the path.
func globToRegex(p string) *regexp.Regexp {
	var b strings.Builder
	anchored := strings.HasPrefix(p, "/") || (len(p) > 1 && p[1] == ':')
	if anchored {
		b.WriteString("^")
	} else {
		b.WriteString("(^|/)")
	}
	for i := 0; i < len(p); i++ {
		c := p[i]
		switch c {
		case '*':
			if i+1 < len(p) && p[i+1] == '*' {
				b.WriteString(".*")
				i++
				if i+1 < len(p) && p[i+1] == '/' {
					i++
					b.WriteString("/?")
				}
			} else {
				b.WriteString("[^/]*")
			}
		case '?':
			b.WriteString("[^/]")
		default:
			b.WriteString(regexp.QuoteMeta(string(c)))
		}
	}
	b.WriteString("($|/|[\\s\"'])")
	re, err := regexp.Compile(b.String())
	if err != nil {
		return regexp.MustCompile(regexp.QuoteMeta(p))
	}
	return re
}
