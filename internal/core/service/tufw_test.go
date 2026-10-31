package service

import (
	"encoding/hex"
	"fmt"
	"io/fs"
	"strings"
	"testing"

	"github.com/gdamore/tcell/v2"
	"github.com/peltho/tufw/internal/core/domain"
	"github.com/rivo/tview"
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

// mockShell records commands; `ufw status numbered` reports statusRules rules.
func mockShell(t *testing.T, statusRules int) *[]string {
	t.Helper()
	orig := shellout
	t.Cleanup(func() { shellout = orig })
	var commands []string
	shellout = func(cmd string) (string, string, error) {
		commands = append(commands, cmd)
		if cmd == "ufw status numbered" {
			return statusNumbered(statusRules), "", nil
		}
		return "", "", nil
	}
	return &commands
}

func newLoadedTui(t *testing.T) *Tui {
	t.Helper()
	tui := CreateApplication(tcell.ColorBlue)
	tui.Init()
	tui.ReloadTable()
	return tui
}

func populateForm(f *tview.Form, v domain.FormValues) {
	f.Clear(true)
	f.AddInputField("To", v.To, 10, nil, nil)
	f.AddInputField("Port", v.Port, 10, nil, nil)
	f.AddDropDown("Interface", []string{v.Interface}, 0, nil)
	f.AddDropDown("Interface out", []string{v.InterfaceOut}, 0, nil)
	f.AddDropDown("Protocol", []string{v.Protocol}, 0, nil)
	f.AddDropDown("Action *", []string{v.Action}, 0, nil)
	f.AddInputField("From", v.From, 10, nil, nil)
	f.AddInputField("Comment", v.Comment, 10, nil, nil)
}

func TestLoadRules(t *testing.T) {
	mockFiles(t, defaultFiles())
	tui := newLoadedTui(t)

	// 4 v4 rules + 1 v6 app rule
	if len(tui.rules) != 5 {
		t.Fatalf("got %d rules, want 5", len(tui.rules))
	}
	if tui.table.GetRowCount() != 6 {
		t.Errorf("got %d table rows, want 6 (header + 5)", tui.table.GetRowCount())
	}

	want := []string{"[1]", "192.168.0.1", "22", "tcp", "ALLOW-IN", "Anywhere", "SSH rule"}
	for c, w := range want {
		if got := tui.table.GetCell(1, c).Text; got != w {
			t.Errorf("row 1 col %d: got %q, want %q", c, got, w)
		}
	}
	if got := tui.table.GetCell(3, 2).Text; got != "Apache Full" {
		t.Errorf("app rule port cell: got %q", got)
	}
}

func TestLoadRules_IPv6DisabledAndLegacyPath(t *testing.T) {
	mockFiles(t, map[string]string{
		"/lib/ufw/user.rules": fixtureUserRules,
		"/etc/default/ufw":    "IPV6=no\n",
	})
	tui := CreateApplication(tcell.ColorBlue)
	rules, err := tui.LoadRules()
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 4 {
		t.Errorf("got %d rules, want 4", len(rules))
	}
}

func TestLoadRules_MissingFiles(t *testing.T) {
	mockFiles(t, map[string]string{})
	tui := CreateApplication(tcell.ColorBlue)
	if _, err := tui.LoadRules(); err == nil {
		t.Error("expected an error when no rules file exists")
	}
}

func TestSearch(t *testing.T) {
	mockFiles(t, defaultFiles())
	tui := newLoadedTui(t)

	matches, err := tui.LoadSearchData("apache")
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != 2 || matches[0].Number != 3 || matches[1].Number != 5 {
		t.Errorf("unexpected matches: %+v", matches)
	}
}

func TestCreateRule_BuildsCorrectCommands(t *testing.T) {
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
			mockFiles(t, defaultFiles())
			commands := mockShell(t, 5)

			tui := CreateApplication(tcell.ColorBlue)
			tui.Init()
			populateForm(tui.form, tt.values)

			got := tui.CreateRule()

			if len(*commands) != 2 {
				t.Fatalf("expected dry-run + apply, got %q", *commands)
			}
			if (*commands)[0] != strings.Replace(tt.expectedCmd, "ufw ", "ufw --dry-run ", 1) {
				t.Errorf("unexpected dry-run: %s", (*commands)[0])
			}
			if (*commands)[1] != tt.expectedCmd || got == nil || *got != tt.expectedCmd {
				t.Errorf("expected:\n%s\ngot:\n%s", tt.expectedCmd, (*commands)[1])
			}
		})
	}
}

func TestCreateRule_EmptyFormDoesNothing(t *testing.T) {
	mockFiles(t, defaultFiles())
	commands := mockShell(t, 5)
	tui := CreateApplication(tcell.ColorBlue)
	tui.Init()
	populateForm(tui.form, domain.FormValues{Action: "ALLOW IN"})

	if tui.CreateRule() != nil || len(*commands) != 0 {
		t.Errorf("expected no command, got %q", *commands)
	}
}

func TestEditRule(t *testing.T) {
	tests := []struct {
		name     string
		number   int
		values   domain.FormValues
		expected []string
	}{
		{
			name:   "edit keeps the position",
			number: 1,
			values: domain.FormValues{To: "192.168.0.1", Port: "2222", Protocol: "tcp", Action: "allow-in", Comment: "SSH rule"},
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
			values: domain.FormValues{To: "3.3.3.3", Interface: "enp0s1", InterfaceOut: "eth1", Action: "deny-fwd"},
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
			tui := newLoadedTui(t)
			commands := mockShell(t, 5)

			got := tui.EditRule(tui.rules[tt.number-1], tt.values)

			if strings.Join(*commands, "\n") != strings.Join(tt.expected, "\n") {
				t.Errorf("expected commands:\n%s\ngot:\n%s", strings.Join(tt.expected, "\n"), strings.Join(*commands, "\n"))
			}
			if got == nil || *got != tt.expected[3] {
				t.Errorf("unexpected return value %v", got)
			}
		})
	}
}

func TestEditRule_RefusesOnNumberingMismatch(t *testing.T) {
	mockFiles(t, defaultFiles())
	tui := newLoadedTui(t)
	commands := mockShell(t, 4) // ufw disagrees with our 5 rules

	if got := tui.EditRule(tui.rules[0], domain.FormValues{Port: "1", Action: "ALLOW IN"}); got != nil {
		t.Errorf("expected refusal, got %s", *got)
	}
	for _, c := range *commands {
		if strings.Contains(c, "delete") || strings.Contains(c, "insert") {
			t.Errorf("no rule should be modified, ran %q", c)
		}
	}
}

func TestDeleteRule(t *testing.T) {
	mockFiles(t, defaultFiles())
	tui := newLoadedTui(t)
	commands := mockShell(t, 5)

	if err := tui.DeleteRule(tui.rules[2]); err != nil {
		t.Fatal(err)
	}
	if last := (*commands)[len(*commands)-1]; last != "ufw --force delete 3" {
		t.Errorf("got %q", last)
	}
}

func TestDeleteRule_RefusesWhenRuleChanged(t *testing.T) {
	files := defaultFiles()
	mockFiles(t, files)
	tui := newLoadedTui(t)
	selected := tui.rules[0]

	// Someone changes rule 1 behind our back
	files["/etc/ufw/user.rules"] = strings.Replace(fixtureUserRules, "allow tcp 22 192.168.0.1", "allow tcp 23 192.168.0.1", 1)
	commands := mockShell(t, 5)

	if err := tui.DeleteRule(selected); err == nil {
		t.Error("expected an error")
	}
	for _, c := range *commands {
		if strings.Contains(c, "delete") {
			t.Errorf("no rule should be deleted, ran %q", c)
		}
	}
}

func TestDeleteRule_RefusesWhenInactive(t *testing.T) {
	mockFiles(t, defaultFiles())
	tui := newLoadedTui(t)
	orig := shellout
	t.Cleanup(func() { shellout = orig })
	shellout = func(cmd string) (string, string, error) {
		if strings.Contains(cmd, "delete") {
			t.Errorf("no rule should be deleted, ran %q", cmd)
		}
		return "Status: inactive\n", "", nil
	}

	if err := tui.DeleteRule(tui.rules[0]); err == nil {
		t.Error("expected an error")
	}
}

func TestRuleToFormValues(t *testing.T) {
	mockFiles(t, defaultFiles())
	tui := newLoadedTui(t)

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
		fv, err := ruleToFormValues(tui.rules[tt.number-1])
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
