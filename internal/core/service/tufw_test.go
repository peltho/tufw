package service

import (
	"slices"
	"strings"
	"testing"

	"github.com/gdamore/tcell/v2"
	"github.com/peltho/tufw/internal/core/domain"
	"github.com/peltho/tufw/internal/core/utils"
	"github.com/rivo/tview"
	"gitlab.com/rythme/gommon/pointer"
)

var tests = []struct {
	name         string
	values       domain.FormValues
	expectedCmd  string
	row          string
	formattedRow string
}{
	{
		name: "simple TCP rule",
		values: domain.FormValues{
			To:        pointer.Of("192.168.0.1"),
			Port:      pointer.Of("22"),
			Interface: pointer.Of(""),
			Protocol:  pointer.Of("tcp"),
			Action:    "ALLOW IN",
			From:      pointer.Of(""),
			Comment:   pointer.Of("SSH rule"),
		},
		row:          "[ 1] 192.168.0.1 22/tcp         ALLOW IN    Anywhere # SSH rule",
		formattedRow: "[1] 192.168.0.1/tcp 22 ALLOW-IN Anywhere # SSH rule",
		expectedCmd:  "ufw allow in from any to 192.168.0.1 proto tcp port 22 comment 'SSH rule'",
	},
	{
		name: "no proto",
		values: domain.FormValues{
			To:        pointer.Of("192.168.0.1"),
			Port:      pointer.Of("80"),
			Interface: pointer.Of(""),
			Protocol:  pointer.Of(""),
			Action:    "ALLOW IN",
			From:      pointer.Of(""),
			Comment:   pointer.Of(""),
		},
		row:          "[ 1] 192.168.0.1 80         ALLOW IN    Anywhere",
		formattedRow: "[1] 192.168.0.1 80 ALLOW-IN Anywhere",
		expectedCmd:  "ufw allow in from any to 192.168.0.1 port 80",
	},
	{
		name: "forward rule",
		values: domain.FormValues{
			To:           pointer.Of("192.168.1.100"),
			Port:         pointer.Of("80"),
			Interface:    pointer.Of("eth0"),
			InterfaceOut: pointer.Of("eth1"),
			Protocol:     pointer.Of("tcp"),
			Action:       "DENY FWD",
			From:         pointer.Of(""),
			Comment:      pointer.Of(""),
		},
		row:          "[ 1] 192.168.1.100 80/tcp DENY FWD Anywhere on eth0 out on eth1",
		formattedRow: "[1] 192.168.1.100/tcp_on_eth1 80 DENY-FWD Anywhere_on_eth0",
		expectedCmd:  "ufw route deny in on eth0 out on eth1 from any to 192.168.1.100 proto tcp port 80",
	},
	{
		name: "HTTP allow",
		values: domain.FormValues{
			To:        pointer.Of("192.168.0.2"),
			Port:      pointer.Of("80"),
			Interface: pointer.Of(""),
			Protocol:  pointer.Of(""),
			Action:    "ALLOW IN",
			From:      pointer.Of(""),
			Comment:   pointer.Of("Web"),
		},
		row:          "[ 1] 192.168.0.2 80 ALLOW IN Anywhere                       # Web",
		formattedRow: "[1] 192.168.0.2 80 ALLOW-IN Anywhere # Web",
		expectedCmd:  "ufw allow in from any to 192.168.0.2 port 80 comment 'Web'",
	},
	{
		name: "Deny udp to",
		values: domain.FormValues{
			To:        pointer.Of("10.0.0.0/24"),
			Port:      pointer.Of(""),
			Interface: pointer.Of(""),
			Action:    "DENY IN",
			Protocol:  pointer.Of("udp"),
			From:      pointer.Of(""),
		},
		row:          "[ 1] 10.0.0.0/24 - udp DENY IN Anywhere",
		formattedRow: "[1] 10.0.0.0/24/udp - DENY-IN Anywhere",
		expectedCmd:  "ufw deny in from any to 10.0.0.0/24 proto udp",
	},
	{
		name: "Allow udp from anywhere",
		values: domain.FormValues{
			To:        pointer.Of(""),
			Port:      pointer.Of(""),
			Interface: pointer.Of(""),
			Action:    "ALLOW IN",
			Protocol:  pointer.Of("udp"),
			From:      pointer.Of("10.0.0.0/24"),
		},
		row:          "[ 1] Anywhere - udp ALLOW IN 10.0.0.0/24",
		formattedRow: "[1] Anywhere/udp - ALLOW-IN 10.0.0.0/24",
		expectedCmd:  "ufw allow in from 10.0.0.0/24 to any proto udp",
	},
	{
		name: "Allow route forwarding with comment",
		values: domain.FormValues{
			To:           pointer.Of("172.16.0.5"),
			Port:         pointer.Of("443"),
			Interface:    pointer.Of("eth1"),
			InterfaceOut: pointer.Of("eth2"),
			Protocol:     pointer.Of("tcp"),
			Action:       "ALLOW FWD",
			From:         pointer.Of("10.0.0.0/8"),
			Comment:      pointer.Of("HTTPS route"),
		},
		row:          "[ 1] 172.16.0.5 443/tcp ALLOW FWD 10.0.0.0/8 on eth1 out on eth2 # HTTPS route",
		formattedRow: "[1] 172.16.0.5/tcp_on_eth2 443 ALLOW-FWD 10.0.0.0/8_on_eth1 # HTTPS route",
		expectedCmd:  "ufw route allow in on eth1 out on eth2 from 10.0.0.0/8 to 172.16.0.5 proto tcp port 443 comment 'HTTPS route'",
	},
	{
		name: "Allow route with no port",
		values: domain.FormValues{
			To:           pointer.Of("192.168.50.10"),
			Port:         pointer.Of(""),
			Interface:    pointer.Of("eth0"),
			InterfaceOut: pointer.Of("eth1"),
			Protocol:     pointer.Of(""),
			Action:       "ALLOW FWD",
			From:         pointer.Of("10.0.0.0/8"),
			Comment:      pointer.Of("No port route"),
		},
		row:          "[ 1] 192.168.50.10 ALLOW FWD 10.0.0.0/8 on eth0 out on eth1 # No port route",
		formattedRow: "[1] 192.168.50.10_on_eth1 - ALLOW-FWD 10.0.0.0/8_on_eth0 # No port route",
		expectedCmd:  "ufw route allow in on eth0 out on eth1 from 10.0.0.0/8 to 192.168.50.10 comment 'No port route'",
	},
	{
		name: "Allow SSH from specific host",
		values: domain.FormValues{
			To:        pointer.Of("192.168.1.1"),
			Port:      pointer.Of("22"),
			Interface: pointer.Of(""),
			Protocol:  pointer.Of("tcp"),
			Action:    "ALLOW IN",
			From:      pointer.Of("192.168.1.50"),
			Comment:   pointer.Of("Admin host"),
		},
		row:          "[ 1] 192.168.1.1 22/tcp ALLOW IN 192.168.1.50 # Admin host",
		formattedRow: "[1] 192.168.1.1/tcp 22 ALLOW-IN 192.168.1.50 # Admin host",
		expectedCmd:  "ufw allow in from 192.168.1.50 to 192.168.1.1 proto tcp port 22 comment 'Admin host'",
	},
	{
		name: "Allow from subnet to any port 25 (SMTP)",
		values: domain.FormValues{
			To:        pointer.Of(""),
			Port:      pointer.Of("25"),
			Interface: pointer.Of(""),
			Protocol:  pointer.Of("tcp"),
			Action:    "ALLOW IN",
			From:      pointer.Of("192.168.10.0/24"),
			Comment:   pointer.Of("SMTP inbound"),
		},
		row:          "[ 1] Anywhere 25/tcp ALLOW IN 192.168.10.0/24 # SMTP inbound",
		formattedRow: "[1] Anywhere/tcp 25 ALLOW-IN 192.168.10.0/24 # SMTP inbound",
		expectedCmd:  "ufw allow in from 192.168.10.0/24 to any proto tcp port 25 comment 'SMTP inbound'",
	},
	{
		name: "Deny outbound DNS",
		values: domain.FormValues{
			To:        pointer.Of("8.8.8.8"),
			Port:      pointer.Of("53"),
			Interface: pointer.Of(""),
			Protocol:  pointer.Of("udp"),
			Action:    "DENY OUT",
			From:      pointer.Of(""),
			Comment:   pointer.Of("Block Google DNS"),
		},
		row:          "[ 1] 8.8.8.8 53/udp DENY OUT Anywhere # Block Google DNS",
		formattedRow: "[1] 8.8.8.8/udp 53 DENY-OUT Anywhere # Block Google DNS",
		expectedCmd:  "ufw deny out from any to 8.8.8.8 proto udp port 53 comment 'Block Google DNS'",
	},
	{
		name: "Allow IPv6 SSH inbound",
		values: domain.FormValues{
			To:        pointer.Of("::1"),
			Port:      pointer.Of("22"),
			Interface: pointer.Of(""),
			Protocol:  pointer.Of("tcp"),
			Action:    "ALLOW IN",
			From:      pointer.Of(""),
			Comment:   pointer.Of("SSH v6"),
		},
		row:          "[ 1] ::1 22/tcp ALLOW IN Anywhere (v6) # SSH v6",
		formattedRow: "[1] ::1/tcp 22 ALLOW-IN Anywhere # SSH v6",
		expectedCmd:  "ufw allow in from any to ::1 proto tcp port 22 comment 'SSH v6'",
	},
	{
		name: "open eth0",
		values: domain.FormValues{
			To:        pointer.Of(""),
			Port:      pointer.Of("22"),
			Interface: pointer.Of("eth0"),
			Protocol:  pointer.Of("tcp"),
			Action:    "ALLOW IN",
			From:      pointer.Of(""),
			Comment:   pointer.Of(""),
		},
		row:          "[ 1] Anywhere 22/tcp ALLOW IN Anywhere on eth0",
		formattedRow: "[1] Anywhere/tcp 22 ALLOW-IN Anywhere on eth0",
		expectedCmd:  "ufw allow in on eth0 from any to any proto tcp port 22",
	},
	{
		name: "ssh everywhere",
		values: domain.FormValues{
			To:        pointer.Of(""),
			Port:      pointer.Of("22"),
			Interface: pointer.Of(""),
			Protocol:  pointer.Of(""),
			Action:    "ALLOW IN",
			From:      pointer.Of(""),
			Comment:   pointer.Of(""),
		},
		row:          "[ 1] 22                         ALLOW IN    Anywhere",
		formattedRow: "[1] 22 ALLOW-IN Anywhere",
		expectedCmd:  "ufw allow in from any to any port 22",
	},
}

func populateForm(f *tview.Form, v domain.FormValues) {
	f.Clear(true) // remove previous fields if any

	f.AddInputField("To", *v.To, 10, nil, nil)

	f.AddInputField("Port", *v.Port, 10, nil, nil)

	if v.Interface != nil {
		f.AddDropDown("Interface", []string{*v.Interface}, 0, nil)
	} else {
		f.AddDropDown("Interface", []string{""}, 0, nil)
	}

	if v.InterfaceOut != nil {
		f.AddDropDown("Interface out", []string{*v.InterfaceOut}, 0, nil)
	}

	f.AddDropDown("Protocol", []string{*v.Protocol}, 0, nil)

	f.AddDropDown("Action *", []string{v.Action}, 0, nil)

	f.AddInputField("From", *v.From, 10, nil, nil)

	comment := ""
	if v.Comment != nil {
		comment = *v.Comment
	}
	f.AddInputField("Comment", comment, 10, nil, nil)
}

func TestCreateRule_BuildsCorrectCommands(t *testing.T) {
	// Save original
	origShellout := shellout
	defer func() { shellout = origShellout }()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var commands []string

			// Mock per test
			shellout = func(cmd string) (string, string, error) {
				commands = append(commands, cmd)
				return tt.row, "", nil
			}

			// Setup UI
			tui := CreateApplication(tcell.ColorBlue)
			tui.Init()
			populateForm(tui.form, tt.values)

			tui.CreateRule()

			if len(commands) < 2 {
				t.Fatalf("expected at least 2 commands, got %d", len(commands))
			}

			execCmd := commands[1]

			if execCmd != tt.expectedCmd {
				t.Errorf("expected exec cmd:\n%s\nbut got:\n%s", tt.expectedCmd, execCmd)
			}

			loadedRow := utils.FormatUfwRule(tt.row)
			if loadedRow != tt.formattedRow {
				t.Errorf("expected formatted row to be: %q, got %q", tt.formattedRow, loadedRow)
			}

			tui.CreateTable([]string{tt.row})

			cell := tui.table.GetCell(1, 0)
			expected := "[1]"
			if cell.Text != expected {
				t.Errorf("expected value for cell #: %q, got %q", expected, cell.Text)
			}

			cell = tui.table.GetCell(1, 1)
			if tt.values.To != nil {
				expected = *tt.values.To
				if tt.values.Protocol != nil && *tt.values.Protocol != "" {
					expected = expected + "/" + *tt.values.Protocol
				}
				if *tt.values.To == "" {
					expected = "Anywhere" + expected
				}
				if (tt.values.Action == "ALLOW FWD" || tt.values.Action == "DENY FWD") && tt.values.InterfaceOut != nil {
					expected = expected + "_on_" + *tt.values.InterfaceOut
				}
				if cell.Text != expected {
					t.Errorf("expected value for cell To: %q, got %q", expected, cell.Text)
				}
			}

			cell = tui.table.GetCell(1, 2)
			if tt.values.Port != nil {
				expected = *tt.values.Port
				if *tt.values.Port == "" {
					expected = "-"
				}

				if cell.Text != expected {
					t.Errorf("expected value for cell Port: %q, got %q", expected, cell.Text)
				}
			}

			cell = tui.table.GetCell(1, 3)
			expected = strings.ReplaceAll(tt.values.Action, " ", "-")
			if cell.Text != expected {
				t.Errorf("expected value for cell Action: %q, got %q", expected, cell.Text)
			}

			cell = tui.table.GetCell(1, 4)
			if tt.values.From == nil || *tt.values.From == "" || *tt.values.From == "Anywhere" || *tt.values.From == "any" {
				expected = "Anywhere"
			} else {
				expected = *tt.values.From
			}
			if tt.values.Interface != nil && *tt.values.Interface != "" && slices.Contains([]string{"ALLOW FWD", "DENY FWD"}, tt.values.Action) {
				expected = expected + "_on_" + *tt.values.Interface
			}

			if cell.Text != expected {
				t.Errorf("expected value for cell From: %q, got %q", expected, cell.Text)
			}

			cell = tui.table.GetCell(1, 5)
			if tt.values.Comment != nil {
				expected = *tt.values.Comment
				if cell.Text != expected {
					t.Errorf("expected value for cell Comment: %q, got %q", expected, cell.Text)
				}
			}
		})
	}
}

func TestEditRule(t *testing.T) {
	var tests = []struct {
		name        string
		values      domain.FormValues
		expectedCmd string
	}{
		{
			name: "edit simple TCP rule",
			values: domain.FormValues{
				To:        pointer.Of("192.168.0.1"),
				Port:      pointer.Of("22"),
				Interface: pointer.Of(""),
				Protocol:  pointer.Of("tcp"),
				Action:    "ALLOW IN",
				From:      pointer.Of(""),
				Comment:   pointer.Of("SSH rule"),
			},
			expectedCmd: "ufw insert 1 allow in from any to 192.168.0.1 proto tcp port 22 comment 'SSH rule'",
		},
		{
			name: "Allow fwd route with interface out",
			values: domain.FormValues{
				To:           pointer.Of("192.168.50.10"),
				Port:         pointer.Of(""),
				Interface:    pointer.Of("eth0"),
				InterfaceOut: pointer.Of("eth1"),
				Protocol:     pointer.Of(""),
				Action:       "ALLOW FWD",
				From:         pointer.Of("10.0.0.0/8"),
				Comment:      pointer.Of("No port route"),
			},
			expectedCmd: "ufw route insert 1 allow in on eth0 out on eth1 from 10.0.0.0/8 to 192.168.50.10 comment 'No port route'",
		},
		{
			name: "Allow fwd route without interface out",
			values: domain.FormValues{
				To:           pointer.Of("192.168.50.10"),
				Port:         pointer.Of(""),
				Interface:    pointer.Of("eth0"),
				InterfaceOut: pointer.Of(""),
				Protocol:     pointer.Of(""),
				Action:       "ALLOW FWD",
				From:         pointer.Of("10.0.0.0/8"),
				Comment:      pointer.Of(""),
			},
			expectedCmd: "ufw route insert 1 allow in on eth0 from 10.0.0.0/8 to 192.168.50.10",
		},
	}

	tui := CreateApplication(tcell.ColorBlue)
	tui.Init()

	shellout = func(cmd string) (string, string, error) {
		return "", "", nil
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := tui.EditRule(1, tt.values)
			if *v != tt.expectedCmd {
				t.Errorf("expected command: %q, got %q", tt.expectedCmd, *v)
			}
		})
	}
}
