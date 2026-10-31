package utils

import "testing"

func TestParseInterfaceIndex(t *testing.T) {
	interfaces := []string{"", "lo", "eth0"}
	if i := ParseInterfaceIndex("eth0", interfaces); i != 2 {
		t.Errorf("got %d, want 2", i)
	}
	if i := ParseInterfaceIndex("wlan0", interfaces); i != 0 {
		t.Errorf("unknown interface: got %d, want 0", i)
	}
}

func TestShellQuote(t *testing.T) {
	if got := ShellQuote("it's"); got != `'it'\''s'` {
		t.Errorf("got %s", got)
	}
}
