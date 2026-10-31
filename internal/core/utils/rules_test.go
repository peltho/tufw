package utils

import (
	"encoding/hex"
	"reflect"
	"testing"

	"github.com/peltho/tufw/internal/core/domain"
)

func hexComment(s string) string { return hex.EncodeToString([]byte(s)) }

// Layout as written by ufw's UFWBackendIptables._write_rules.
var userRules = `*filter
:ufw-user-input - [0:0]
:ufw-user-output - [0:0]
:ufw-user-forward - [0:0]
### RULES ###

### tuple ### allow tcp 22 0.0.0.0/0 any 192.168.1.0/24 in comment=` + hexComment("SSH admin's") + `
-A ufw-user-input -p tcp --dport 22 -s 192.168.1.0/24 -j ACCEPT

### tuple ### limit_log tcp 2222 0.0.0.0/0 any 0.0.0.0/0 in
-A ufw-user-input -p tcp --dport 2222 -j ufw-user-limit-accept

### tuple ### deny udp 53 8.8.8.8 any 0.0.0.0/0 out_eth0
-A ufw-user-output -o eth0 -p udp -d 8.8.8.8 --dport 53 -j DROP

### tuple ### route:allow tcp 443 172.16.0.5 any 10.0.0.0/8 in_eth1!out_eth2
-A ufw-user-forward -i eth1 -o eth2 -p tcp -d 172.16.0.5 --dport 443 -s 10.0.0.0/8 -j ACCEPT

### tuple ### allow udp 137,138 0.0.0.0/0 any 0.0.0.0/0 Samba - in
-A ufw-user-input -p udp -m multiport --dports 137,138 -j ACCEPT -m comment --comment 'dapp_Samba'
### tuple ### allow tcp 139,445 0.0.0.0/0 any 0.0.0.0/0 Samba - in
-A ufw-user-input -p tcp -m multiport --dports 139,445 -j ACCEPT -m comment --comment 'dapp_Samba'

### tuple ### allow tcp 80,443 10.0.0.5 any 0.0.0.0/0 Apache%20Full - in_eth0
-A ufw-user-input -i eth0 -p tcp -d 10.0.0.5 -m multiport --dports 80,443 -j ACCEPT

### tuple ### allow tcp any 0.0.0.0/0 22 10.0.0.1 - OpenSSH in

### tuple ### this is not a valid tuple at all because it is way too long

### END RULES ###
`

var userRules6 = `### RULES ###

### tuple ### allow tcp 22 ::/0 any ::/0 in
-A ufw6-user-input -p tcp --dport 22 -j ACCEPT

### tuple ### allow udp 137,138 ::/0 any ::/0 Samba - in
### tuple ### allow tcp 139,445 ::/0 any ::/0 Samba - in

### END RULES ###
`

func TestParseRulesFile(t *testing.T) {
	got := ParseRulesFile(userRules, false)

	want := []domain.Rule{
		{Action: "allow", Direction: "in", Protocol: "tcp", DPort: "22", Dst: "0.0.0.0/0", SPort: "any", Src: "192.168.1.0/24", Comment: "SSH admin's"},
		{Action: "limit", LogType: "log", Direction: "in", Protocol: "tcp", DPort: "2222", Dst: "0.0.0.0/0", SPort: "any", Src: "0.0.0.0/0"},
		{Action: "deny", Direction: "out", Protocol: "udp", DPort: "53", Dst: "8.8.8.8", SPort: "any", Src: "0.0.0.0/0", IfaceOut: "eth0"},
		{Action: "allow", Forward: true, Direction: "in", Protocol: "tcp", DPort: "443", Dst: "172.16.0.5", SPort: "any", Src: "10.0.0.0/8", IfaceIn: "eth1", IfaceOut: "eth2"},
		{Action: "allow", Direction: "in", Protocol: "udp", DPort: "137,138", Dst: "0.0.0.0/0", SPort: "any", Src: "0.0.0.0/0", DApp: "Samba"},
		{Action: "allow", Direction: "in", Protocol: "tcp", DPort: "139,445", Dst: "0.0.0.0/0", SPort: "any", Src: "0.0.0.0/0", DApp: "Samba"},
		{Action: "allow", Direction: "in", Protocol: "tcp", DPort: "80,443", Dst: "10.0.0.5", SPort: "any", Src: "0.0.0.0/0", DApp: "Apache Full", IfaceIn: "eth0"},
		{Action: "allow", Direction: "in", Protocol: "tcp", DPort: "any", Dst: "0.0.0.0/0", SPort: "22", Src: "10.0.0.1", SApp: "OpenSSH"},
	}

	if len(got) != len(want) {
		t.Fatalf("got %d rules, want %d: %+v", len(got), len(want), got)
	}
	for i := range want {
		if !reflect.DeepEqual(got[i], want[i]) {
			t.Errorf("rule %d:\n got %+v\nwant %+v", i, got[i], want[i])
		}
	}
}

func TestParseRulesFile_LegacyFormats(t *testing.T) {
	// 6 and 8 field tuples (no direction) come from old ufw versions
	got := ParseRulesFile("### tuple ### deny any any 0.0.0.0/0 any 1.2.3.4\n### tuple ### allow tcp 22 0.0.0.0/0 any 0.0.0.0/0 OpenSSH -\n", true)
	if len(got) != 2 {
		t.Fatalf("got %d rules, want 2", len(got))
	}
	if got[0].Direction != "in" || got[0].Src != "1.2.3.4" || !got[0].V6 {
		t.Errorf("unexpected legacy rule: %+v", got[0])
	}
	if got[1].DApp != "OpenSSH" || got[1].Direction != "in" {
		t.Errorf("unexpected legacy app rule: %+v", got[1])
	}
}

func TestNumberRules(t *testing.T) {
	rules := NumberRules(ParseRulesFile(userRules, false), ParseRulesFile(userRules6, true))

	// 8 v4 tuples - 1 duplicate Samba + 3 v6 tuples - 1 duplicate Samba
	if len(rules) != 9 {
		t.Fatalf("got %d numbered rules, want 9", len(rules))
	}
	for i, r := range rules {
		if r.Number != i+1 {
			t.Errorf("rule at %d has number %d", i, r.Number)
		}
	}
	if rules[4].DApp != "Samba" || rules[5].DApp != "Apache Full" {
		t.Errorf("Samba tuples not collapsed: %+v / %+v", rules[4], rules[5])
	}
	if !rules[7].V6 || rules[7].DPort != "22" || rules[8].DApp != "Samba" || !rules[8].V6 {
		t.Errorf("v6 rules should follow v4 rules: %+v / %+v", rules[7], rules[8])
	}
}

func TestRuleCells(t *testing.T) {
	rules := NumberRules(ParseRulesFile(userRules, false), ParseRulesFile(userRules6, true))

	want := []domain.CellValues{
		{Index: "[1]", To: "Anywhere", Port: "22", Proto: "tcp", Action: "ALLOW-IN", From: "192.168.1.0/24", Comment: "SSH admin's"},
		{Index: "[2]", To: "Anywhere", Port: "2222", Proto: "tcp", Action: "LIMIT-IN (log)", From: "Anywhere"},
		{Index: "[3]", To: "8.8.8.8", Port: "53", Proto: "udp", Action: "DENY-OUT", From: "Anywhere on eth0"},
		{Index: "[4]", To: "172.16.0.5 on eth2", Port: "443", Proto: "tcp", Action: "ALLOW-FWD", From: "10.0.0.0/8 on eth1"},
		{Index: "[5]", To: "Anywhere", Port: "Samba", Proto: "-", Action: "ALLOW-IN", From: "Anywhere"},
		{Index: "[6]", To: "10.0.0.5 on eth0", Port: "Apache Full", Proto: "-", Action: "ALLOW-IN", From: "Anywhere"},
		{Index: "[7]", To: "Anywhere", Port: "-", Proto: "-", Action: "ALLOW-IN", From: "10.0.0.1 (OpenSSH)"},
		{Index: "[8]", To: "Anywhere (v6)", Port: "22", Proto: "tcp", Action: "ALLOW-IN", From: "Anywhere (v6)"},
		{Index: "[9]", To: "Anywhere (v6)", Port: "Samba", Proto: "-", Action: "ALLOW-IN", From: "Anywhere (v6)"},
	}

	for i, w := range want {
		if got := RuleCells(rules[i]); !reflect.DeepEqual(got, w) {
			t.Errorf("rule %d:\n got %+v\nwant %+v", i+1, got, w)
		}
	}
}

func TestCountNumberedRules(t *testing.T) {
	out := `Status: active

     To                         Action      From
     --                         ------      ----
[ 1] 22/tcp                     ALLOW IN    192.168.1.0/24             # SSH admin's
[ 2] Samba                      ALLOW IN    Anywhere
[10] 22/tcp (v6)                ALLOW IN    Anywhere (v6)
`
	if n := CountNumberedRules(out); n != 3 {
		t.Errorf("got %d, want 3", n)
	}
	if n := CountNumberedRules("Status: inactive\n"); n != 0 {
		t.Errorf("got %d, want 0", n)
	}
}

func TestIPv6Enabled(t *testing.T) {
	tests := map[string]bool{
		"":                                      true,
		"IPV6=yes\n":                            true,
		"# comment\nIPV6=no\nDEFAULT_INPUT=x\n": false,
		`IPV6="no"`:                             false,
	}
	for in, want := range tests {
		if got := IPv6Enabled(in); got != want {
			t.Errorf("IPv6Enabled(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestShellArg(t *testing.T) {
	tests := map[string]string{
		"192.168.1.0/24": "192.168.1.0/24",
		"80,443":         "80,443",
		"fe80::1":        "fe80::1",
		"Apache Full":    "'Apache Full'",
		"a; rm -rf /":    "'a; rm -rf /'",
		"it's":           `'it'\''s'`,
	}
	for in, want := range tests {
		if got := ShellArg(in); got != want {
			t.Errorf("ShellArg(%q) = %q, want %q", in, got, want)
		}
	}
}
