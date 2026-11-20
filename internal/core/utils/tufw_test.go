package utils

import "testing"

func TestShellQuote(t *testing.T) {
	if got := ShellQuote("it's"); got != `'it'\''s'` {
		t.Errorf("got %s", got)
	}
}
