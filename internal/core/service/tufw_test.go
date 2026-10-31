package service

import (
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"strings"
	"testing"

	"github.com/peltho/tufw/internal/core/domain"
)

var fixtureUserRules = `### RULES ###

### tuple ### allow tcp 22 192.168.0.1 any 0.0.0.0/0 in comment=` + hex.EncodeToString([]byte("SSH rule")) + `
-A ufw-user-input -p tcp -d 192.168.0.1 --dport 22 -j ACCEPT

### tuple ### route:deny any any 3.3.3.3 any 0.0.0.0/0 in_enp0s1!out_lo

### tuple ### allow tcp 80,443 0.0.0.0/0 any 0.0.0.0/0 Apache%20Full - in

### tuple ### deny udp 53 8.8.8.8 any 0.0.0.0/0 out_eth0

### END RULES ###
`

var fixtureUserRules6 = `### RULES ###

### tuple ### allow tcp 80,443 ::/0 any ::/0 Apache%20Full - in

### END RULES ###
`

// mockFiles makes readFile serve the given files (missing ones fail).
func mockFiles(t *testing.T, files map[string]string) {
	t.Helper()
	orig := readFile
	t.Cleanup(func() { readFile = orig })
	readFile = func(name string) ([]byte, error) {
		if content, ok := files[name]; ok {
			return []byte(content), nil
		}
		return nil, fs.ErrNotExist
	}
}

func defaultFiles() map[string]string {
	return map[string]string{
		"/etc/ufw/user.rules":  fixtureUserRules,
		"/etc/ufw/user6.rules": fixtureUserRules6,
		"/etc/default/ufw":     "IPV6=yes\n",
	}
}

func statusNumbered(n int) string {
	var b strings.Builder
	b.WriteString("Status: active\n\n     To    Action    From\n     --    ------    ----\n")
	for i := 1; i <= n; i++ {
		fmt.Fprintf(&b, "[%2d] something ALLOW IN Anywhere\n", i)
	}
	return b.String()
}

// mockShell records commands; `ufw status numbered` reports statusRules
// rules and dry-runs fail with dryRunErr if set.
func mockShell(t *testing.T, statusRules int, dryRunErr string) *[]string {
	t.Helper()
	orig := shellout
	t.Cleanup(func() { shellout = orig })
	var commands []string
	shellout = func(cmd string) (string, string, error) {
		commands = append(commands, cmd)
		switch {
		case cmd == "ufw status numbered":
			return statusNumbered(statusRules), "", nil
		case dryRunErr != "" && strings.HasPrefix(cmd, "ufw --dry-run"):
			return "", dryRunErr, errors.New("exit status 1")
		}
		return "", "", nil
	}
	return &commands
}

func loadedRules(t *testing.T) []domain.Rule {
	t.Helper()
	rules, err := New().LoadRules()
	if err != nil {
		t.Fatal(err)
	}
	return rules
}

func TestLoadRules(t *testing.T) {
	mockFiles(t, defaultFiles())
	rules := loadedRules(t)

	// 4 v4 rules + 1 v6 app rule
	if len(rules) != 5 {
		t.Fatalf("got %d rules, want 5", len(rules))
	}
	if rules[0].Comment != "SSH rule" || rules[2].DApp != "Apache Full" || !rules[4].V6 {
		t.Errorf("unexpected rules: %+v", rules)
	}
}

func TestLoadRules_IPv6DisabledAndLegacyPath(t *testing.T) {
	mockFiles(t, map[string]string{
		"/lib/ufw/user.rules": fixtureUserRules,
		"/etc/default/ufw":    "IPV6=no\n",
	})
	if rules := loadedRules(t); len(rules) != 4 {
		t.Errorf("got %d rules, want 4", len(rules))
	}
}

func TestLoadRules_MissingFiles(t *testing.T) {
	mockFiles(t, map[string]string{})
	if _, err := New().LoadRules(); err == nil {
		t.Error("expected an error when no rules file exists")
	}
}

func TestFilterRules(t *testing.T) {
	mockFiles(t, defaultFiles())
	rules := loadedRules(t)

	matches := FilterRules(rules, "apache")
	if len(matches) != 2 || matches[0].Number != 3 || matches[1].Number != 5 {
		t.Errorf("unexpected matches: %+v", matches)
	}
	if got := FilterRules(rules, ""); len(got) != 5 {
		t.Errorf("empty filter should keep everything, got %d", len(got))
	}
	// invalid regex falls back to a literal match
	if got := FilterRules(rules, "[1"); len(got) != 1 || got[0].Number != 1 {
		t.Errorf("literal fallback: got %+v", got)
	}
	if got := FilterRules(rules, "nothing-matches"); got == nil || len(got) != 0 {
		t.Errorf("expected an empty, non-nil slice, got %#v", got)
	}
}

func TestInterfaces(t *testing.T) {
	orig := interfaces
	t.Cleanup(func() { interfaces = orig })
	interfaces = func() ([]net.Interface, error) {
		return []net.Interface{{Name: "lo"}, {Name: "eth0"}}, nil
	}
	if got := New().Interfaces(); strings.Join(got, ",") != "lo,eth0" {
		t.Errorf("got %v", got)
	}
}

func TestIsActive(t *testing.T) {
	orig := shellout
	t.Cleanup(func() { shellout = orig })
	shellout = func(string) (string, string, error) { return "Status: inactive\n", "", nil }
	if active, err := New().IsActive(); active || err != nil {
		t.Errorf("got %v, %v", active, err)
	}
	shellout = func(string) (string, string, error) { return "Status: active\n", "", nil }
	if active, err := New().IsActive(); !active || err != nil {
		t.Errorf("got %v, %v", active, err)
	}
}

func TestCreate_BuildsCorrectCommands(t *testing.T) {
	tests := []struct {
		name        string
		values      domain.FormValues
		expectedCmd string
	}{
		{
			name:        "simple TCP rule",
			values:      domain.FormValues{To: "192.168.0.1", Port: "22", Protocol: "tcp", Action: "ALLOW IN", Comment: "SSH rule"},
			expectedCmd: "ufw allow in from any to 192.168.0.1 proto tcp port 22 comment 'SSH rule'",
		},
		{
			name:        "no proto",
			values:      domain.FormValues{To: "192.168.0.1", Port: "80", Action: "ALLOW IN"},
			expectedCmd: "ufw allow in from any to 192.168.0.1 port 80",
		},
		{
			name:        "forward rule",
			values:      domain.FormValues{To: "192.168.1.100", Port: "80", Interface: "eth0", InterfaceOut: "eth1", Protocol: "tcp", Action: "DENY FWD"},
			expectedCmd: "ufw route deny in on eth0 out on eth1 from any to 192.168.1.100 proto tcp port 80",
		},
		{
			name:        "forward rule without interfaces",
			values:      domain.FormValues{To: "1.2.3.4", Action: "ALLOW FWD"},
			expectedCmd: "ufw route allow from any to 1.2.3.4",
		},
		{
			name:        "interface out ignored for non-route rules",
			values:      domain.FormValues{To: "1.2.3.4", InterfaceOut: "eth1", Action: "ALLOW IN"},
			expectedCmd: "ufw allow in from any to 1.2.3.4",
		},
		{
			name:        "deny udp to subnet",
			values:      domain.FormValues{To: "10.0.0.0/24", Action: "DENY IN", Protocol: "udp"},
			expectedCmd: "ufw deny in from any to 10.0.0.0/24 proto udp",
		},
		{
			name:        "allow udp from subnet",
			values:      domain.FormValues{Action: "ALLOW IN", Protocol: "udp", From: "10.0.0.0/24"},
			expectedCmd: "ufw allow in from 10.0.0.0/24 to any proto udp",
		},
		{
			name:        "route with comment",
			values:      domain.FormValues{To: "172.16.0.5", Port: "443", Interface: "eth1", InterfaceOut: "eth2", Protocol: "tcp", Action: "ALLOW FWD", From: "10.0.0.0/8", Comment: "HTTPS route"},
			expectedCmd: "ufw route allow in on eth1 out on eth2 from 10.0.0.0/8 to 172.16.0.5 proto tcp port 443 comment 'HTTPS route'",
		},
		{
			name:        "deny outbound DNS",
			values:      domain.FormValues{To: "8.8.8.8", Port: "53", Protocol: "udp", Action: "DENY OUT", Comment: "Block Google DNS"},
			expectedCmd: "ufw deny out from any to 8.8.8.8 proto udp port 53 comment 'Block Google DNS'",
		},
		{
			name:        "IPv6 address",
			values:      domain.FormValues{To: "::1", Port: "22", Protocol: "tcp", Action: "ALLOW IN", Comment: "SSH v6"},
			expectedCmd: "ufw allow in from any to ::1 proto tcp port 22 comment 'SSH v6'",
		},
		{
			name:        "interface",
			values:      domain.FormValues{Port: "22", Interface: "eth0", Protocol: "tcp", Action: "ALLOW IN"},
			expectedCmd: "ufw allow in on eth0 from any to any proto tcp port 22",
		},
		{
			name:        "comment with quote is shell-safe",
			values:      domain.FormValues{Port: "22", Action: "ALLOW IN", Comment: "admin's box"},
			expectedCmd: `ufw allow in from any to any port 22 comment 'admin'\''s box'`,
		},
		{
			name:        "odd input is quoted",
			values:      domain.FormValues{To: "1.2.3.4; reboot", Action: "ALLOW IN"},
			expectedCmd: "ufw allow in from any to '1.2.3.4; reboot'",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			commands := mockShell(t, 5, "")

			got, err := New().Create(tt.values)
			if err != nil {
				t.Fatal(err)
			}

			want := []string{strings.Replace(tt.expectedCmd, "ufw ", "ufw --dry-run ", 1), tt.expectedCmd}
			if strings.Join(*commands, "\n") != strings.Join(want, "\n") {
				t.Errorf("expected:\n%s\ngot:\n%s", strings.Join(want, "\n"), strings.Join(*commands, "\n"))
			}
			if got != tt.expectedCmd {
				t.Errorf("returned %q", got)
			}
		})
	}
}

func TestCreate_EmptyRule(t *testing.T) {
	commands := mockShell(t, 5, "")
	if _, err := New().Create(domain.FormValues{Action: "ALLOW IN"}); !errors.Is(err, ErrEmptyRule) {
		t.Errorf("got %v", err)
	}
	if len(*commands) != 0 {
		t.Errorf("expected no command, got %q", *commands)
	}
}

func TestCreate_InvalidRule(t *testing.T) {
	commands := mockShell(t, 5, "ERROR: Bad port\n")
	_, err := New().Create(domain.FormValues{Port: "99999", Action: "ALLOW IN"})
	if !errors.Is(err, ErrInvalidRule) || !strings.HasSuffix(err.Error(), ": Bad port") {
		t.Errorf("got %v", err)
	}
	if len(*commands) != 1 {
		t.Errorf("only the dry-run should run, got %q", *commands)
	}
}

func TestEdit(t *testing.T) {
	tests := []struct {
		name     string
		number   int
		values   domain.FormValues
		expected []string
	}{
		{
			name:   "edit keeps the position",
			number: 1,
			values: domain.FormValues{To: "192.168.0.1", Port: "2222", Protocol: "tcp", Action: "ALLOW IN", Comment: "SSH rule"},
			expected: []string{
				"ufw status numbered",
				"ufw --dry-run insert 1 allow in from any to 192.168.0.1 proto tcp port 2222 comment 'SSH rule'",
				"ufw --force delete 1",
				"ufw insert 1 allow in from any to 192.168.0.1 proto tcp port 2222 comment 'SSH rule'",
			},
		},
		{
			name:   "edit route rule",
			number: 2,
			values: domain.FormValues{To: "3.3.3.3", Interface: "enp0s1", InterfaceOut: "eth1", Action: "DENY FWD"},
			expected: []string{
				"ufw status numbered",
				"ufw --dry-run route insert 2 deny in on enp0s1 out on eth1 from any to 3.3.3.3",
				"ufw --force delete 2",
				"ufw route insert 2 deny in on enp0s1 out on eth1 from any to 3.3.3.3",
			},
		},
		{
			name:   "edit last rule appends",
			number: 5,
			values: domain.FormValues{Port: "8080", Action: "ALLOW IN"},
			expected: []string{
				"ufw status numbered",
				"ufw --dry-run allow in from any to any port 8080",
				"ufw --force delete 5",
				"ufw allow in from any to any port 8080",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockFiles(t, defaultFiles())
			rules := loadedRules(t)
			commands := mockShell(t, 5, "")

			got, err := New().Edit(rules[tt.number-1], tt.values)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Join(*commands, "\n") != strings.Join(tt.expected, "\n") {
				t.Errorf("expected commands:\n%s\ngot:\n%s", strings.Join(tt.expected, "\n"), strings.Join(*commands, "\n"))
			}
			if got != tt.expected[3] {
				t.Errorf("returned %q", got)
			}
		})
	}
}

func assertNoModification(t *testing.T, commands []string) {
	t.Helper()
	for _, c := range commands {
		if strings.Contains(c, "delete") || (strings.Contains(c, "insert") && !strings.Contains(c, "--dry-run")) {
			t.Errorf("no rule should be modified, ran %q", c)
		}
	}
}

func TestEdit_RefusesOnNumberingMismatch(t *testing.T) {
	mockFiles(t, defaultFiles())
	rules := loadedRules(t)
	commands := mockShell(t, 4, "") // ufw disagrees with our 5 rules

	if _, err := New().Edit(rules[0], domain.FormValues{Port: "1", Action: "ALLOW IN"}); err == nil {
		t.Error("expected an error")
	}
	assertNoModification(t, *commands)
}

func TestEdit_InvalidRuleKeepsOriginal(t *testing.T) {
	mockFiles(t, defaultFiles())
	rules := loadedRules(t)
	commands := mockShell(t, 5, "ERROR: Bad port\n")

	if _, err := New().Edit(rules[0], domain.FormValues{Port: "99999", Action: "ALLOW IN"}); !errors.Is(err, ErrInvalidRule) {
		t.Errorf("got %v", err)
	}
	assertNoModification(t, *commands)
}

func TestDelete(t *testing.T) {
	mockFiles(t, defaultFiles())
	rules := loadedRules(t)
	commands := mockShell(t, 5, "")

	if err := New().Delete(rules[2]); err != nil {
		t.Fatal(err)
	}
	if last := (*commands)[len(*commands)-1]; last != "ufw --force delete 3" {
		t.Errorf("got %q", last)
	}
}

func TestDelete_RefusesWhenRuleChanged(t *testing.T) {
	files := defaultFiles()
	mockFiles(t, files)
	selected := loadedRules(t)[0]

	// Someone changes rule 1 behind our back
	files["/etc/ufw/user.rules"] = strings.Replace(fixtureUserRules, "allow tcp 22 192.168.0.1", "allow tcp 23 192.168.0.1", 1)
	commands := mockShell(t, 5, "")

	if err := New().Delete(selected); err == nil {
		t.Error("expected an error")
	}
	assertNoModification(t, *commands)
}

func TestDelete_RefusesWhenInactive(t *testing.T) {
	mockFiles(t, defaultFiles())
	rules := loadedRules(t)
	orig := shellout
	t.Cleanup(func() { shellout = orig })
	var commands []string
	shellout = func(cmd string) (string, string, error) {
		commands = append(commands, cmd)
		return "Status: inactive\n", "", nil
	}

	if err := New().Delete(rules[0]); err == nil {
		t.Error("expected an error")
	}
	assertNoModification(t, commands)
}

func TestRuleToFormValues(t *testing.T) {
	mockFiles(t, defaultFiles())
	rules := loadedRules(t)

	tests := []struct {
		number int
		cmd    string // rebuilt command, "" if the rule must not be editable
	}{
		{1, "allow in from any to 192.168.0.1 proto tcp port 22 comment 'SSH rule'"},
		{2, "route deny in on enp0s1 out on lo from any to 3.3.3.3"},
		{3, ""}, // app profile
		{4, "deny out on eth0 from any to 8.8.8.8 proto udp port 53"},
		{5, ""}, // app profile (v6)
	}

	for _, tt := range tests {
		fv, err := RuleToFormValues(rules[tt.number-1])
		if tt.cmd == "" {
			if err == nil {
				t.Errorf("rule %d: expected editing to be refused", tt.number)
			}
			continue
		}
		if err != nil {
			t.Errorf("rule %d: %v", tt.number, err)
			continue
		}
		got, err := buildRuleArgs(fv, 0)
		if err != nil || got != tt.cmd {
			t.Errorf("rule %d: rebuilt %q (err %v), want %q", tt.number, got, err, tt.cmd)
		}
	}
}
