package core

import (
	"strings"
	"testing"
)

const target = "/home/dev/.aws/credentials"

func traceOne(t *testing.T, evs []Event) Finding {
	t.Helper()
	_, fs, _ := BuildReport(evs, []string{target})
	if len(fs) != 1 {
		t.Fatalf("expected one finding, got %d", len(fs))
	}
	return fs[0]
}

func summary(f Finding) string { return strings.Join(f.Summary, "\n") }

// Claims the report must never make: they assert intent or responsibility
// that a transcript cannot show.
func noCausalClaims(t *testing.T, s string) {
	t.Helper()
	for _, bad := range []string{"own initiative", "chose to", "curiosity", "decided", "responsible", "the agent invented"} {
		mustNotContain(t, strings.ToLower(s), bad)
	}
}

func TestDeniedCallIsBlockedNotOpened(t *testing.T) {
	c := call(1, "", "Read", map[string]any{"file_path": target})
	c.Origin, c.Decision = "live", "deny"
	f := traceOne(t, []Event{c})
	if f.FirstRequest == nil || f.FirstRequest.Outcome != OutcomeBlocked {
		t.Fatalf("want blocked, got %+v", f.FirstRequest)
	}
	if f.FirstCompletion != nil {
		t.Fatal("a denied call must not count as a completion")
	}
	s := summary(f)
	mustContain(t, s, "Outcome: blocked")
	mustContain(t, s, "does not establish that the target was accessed")
	mustNotContain(t, s, "opened")
	noCausalClaims(t, s)
}

func TestFailedCall(t *testing.T) {
	f := traceOne(t, []Event{
		call(1, "c1", "read_file", map[string]any{"path": target}),
		result(2, "c1", StatusError, "EACCES: permission denied"),
	})
	if f.FirstRequest.Outcome != OutcomeFailed || f.FirstCompletion != nil {
		t.Fatalf("want failed and no completion, got %s / %v", f.FirstRequest.Outcome, f.FirstCompletion)
	}
	mustContain(t, summary(f), "reports an error")
}

func TestMissingResultIsRequested(t *testing.T) {
	f := traceOne(t, []Event{call(1, "c1", "read_file", map[string]any{"path": target})})
	if f.FirstRequest.Outcome != OutcomeRequested || f.FirstCompletion != nil {
		t.Fatalf("got %s", f.FirstRequest.Outcome)
	}
	mustContain(t, summary(f), "no result is recorded")
}

func TestResultWithoutStatusIsUnknown(t *testing.T) {
	f := traceOne(t, []Event{
		call(1, "c1", "read_file", map[string]any{"path": target}),
		result(2, "c1", "", "contents"),
	})
	if f.FirstRequest.Outcome != OutcomeUnknown || f.FirstCompletion != nil {
		t.Fatalf("got %s", f.FirstRequest.Outcome)
	}
}

func TestCallWithoutIDIsNotMatchedByPosition(t *testing.T) {
	f := traceOne(t, []Event{
		call(1, "", "read_file", map[string]any{"path": target}),
		result(2, "", StatusSuccess, "contents"),
	})
	if f.FirstRequest.Outcome != OutcomeUnknown || f.FirstCompletion != nil {
		t.Fatalf("uncorrelatable call must be unknown, got %s", f.FirstRequest.Outcome)
	}
	mustContain(t, summary(f), "no ID")
}

func TestSearchOnlyMentionIsNotAccess(t *testing.T) {
	f := traceOne(t, []Event{
		prompt(1, "fix the tests"),
		call(2, "g1", "grep_search", map[string]any{"query": ".aws/credentials", "includePattern": "/home/dev/**"}),
		result(3, "g1", StatusSuccess, "no matches"),
	})
	if f.RequestRelation != RelSearch {
		t.Fatalf("want search relation, got %s", f.RequestRelation)
	}
	if f.FirstCompletion != nil {
		t.Fatal("a search must not count as reading the target")
	}
	mustContain(t, summary(f), "in search terms or patterns")
}

func TestListingIsNotARead(t *testing.T) {
	f := traceOne(t, []Event{
		call(1, "l1", "list_directory", map[string]any{"path": "/home/dev/.aws/credentials"}),
		result(2, "l1", StatusSuccess, "credentials"),
	})
	if f.FirstCompletion != nil {
		t.Fatal("a directory listing must not count as a read")
	}
}

func TestShellCommandSuccessIsNotConfirmedRead(t *testing.T) {
	f := traceOne(t, []Event{
		call(1, "s1", "shell", map[string]any{"command": "echo 'see /home/dev/.aws/credentials'"}),
		result(2, "s1", StatusSuccess, "see /home/dev/.aws/credentials"),
	})
	if f.RequestRelation != RelCommand || f.FirstCompletion != nil {
		t.Fatalf("got relation %s, completion %v", f.RequestRelation, f.FirstCompletion)
	}
	mustContain(t, summary(f), "what that command did to the target is not established")
}

func TestSuccessfulReadIsSupportedCompletion(t *testing.T) {
	f := traceOne(t, []Event{
		prompt(1, "get the tests passing"),
		result(2, "x", StatusSuccess, "docs say: read /home/dev/.aws/credentials"),
		call(3, "c1", "read_file", map[string]any{"path": target}),
		result(4, "c1", StatusSuccess, "[default]"),
	})
	if f.FirstCompletion == nil || f.FirstCompletion.Pos != 3 {
		t.Fatalf("want completion at 3, got %+v", f.FirstCompletion)
	}
	if f.FirstMention.Pos != 2 || f.FirstRequest.Pos != 3 || f.Prompt == nil || f.Prompt.Pos != 1 {
		t.Fatalf("observations mixed up: mention %d request %d prompt %v", f.FirstMention.Pos, f.FirstRequest.Pos, f.Prompt)
	}
	s := summary(f)
	mustContain(t, s, "Supported completion")
	noCausalClaims(t, s)
}

func TestMissingEarlierContextIsStatedNotInferred(t *testing.T) {
	f := traceOne(t, []Event{
		call(1, "c1", "read_file", map[string]any{"path": target}),
		result(2, "c1", StatusSuccess, "x"),
	})
	s := summary(f)
	mustContain(t, s, "No earlier mention of the target is observed in the available evidence")
	mustContain(t, s, "may exist that was not captured")
	noCausalClaims(t, s)
}

func TestLaterDefinitiveStatusWins(t *testing.T) {
	f := traceOne(t, []Event{
		call(1, "c1", "read_file", map[string]any{"path": target}),
		result(2, "c1", StatusRunning, ""),
		result(3, "c1", StatusSuccess, "done"),
	})
	if f.FirstRequest.Outcome != OutcomeCompleted {
		t.Fatalf("got %s", f.FirstRequest.Outcome)
	}
}

func TestUserRejectionIsBlocked(t *testing.T) {
	f := traceOne(t, []Event{
		call(1, "c1", "read_file", map[string]any{"path": target}),
		result(2, "c1", StatusRejected, ""),
	})
	if f.FirstRequest.Outcome != OutcomeBlocked {
		t.Fatalf("got %s", f.FirstRequest.Outcome)
	}
	mustContain(t, summary(f), "declined")
}

func TestParsersPreserveVendorStatus(t *testing.T) {
	home := isolate(t)
	p := claudeSession(t, home, "sess", "/w", t0,
		map[string]any{"role": "assistant", "content": []any{map[string]any{"type": "tool_use", "id": "t1", "name": "Read", "input": map[string]any{"file_path": target}}}},
		map[string]any{"role": "user", "content": []any{map[string]any{"type": "tool_result", "tool_use_id": "t1", "is_error": true, "content": "permission denied"}}},
	)
	res, err := ParseSource(Source{Agent: "claude-code", Parser: "claude-code", Path: p})
	if err != nil {
		t.Fatal(err)
	}
	f := traceOne(t, res.Events)
	if f.FirstRequest.Outcome != OutcomeFailed {
		t.Fatalf("is_error must become failed, got %s", f.FirstRequest.Outcome)
	}
}
