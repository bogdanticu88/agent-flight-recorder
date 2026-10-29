package core

import "testing"

func TestMatch(t *testing.T) {
	for _, c := range []struct {
		p, s string
		want bool
	}{
		{"**/.ssh/**", "/home/dev/.ssh/id_ed25519", true},
		{"**/artifactory_credentials_backup.txt", "/tmp/x/secrets/artifactory_credentials_backup.txt", true},
		{"**/.ssh/**", `C:\Users\bob\.ssh\id_rsa`, true},
		{"**/.ssh/**", "/home/dev/ssh-notes.txt", false},
	} {
		if got := MatchPattern(c.p, c.s); got != c.want {
			t.Errorf("%s vs %s = %v (re %s)", c.p, c.s, got, globToRegex(c.p).String())
		}
	}
}
