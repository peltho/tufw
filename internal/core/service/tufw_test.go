package service

import (
	"fmt"
	"strings"
	"testing"

	"github.com/gdamore/tcell/v2"
	"github.com/peltho/tufw/internal/core/utils"
	"github.com/rivo/tview"
	"gitlab.com/rythme/gommon/pointer"
)

type formValues struct {
	To           *string
	Port         *string
	Interface    *string
	InterfaceOut *string
	Protocol     *string
	Action       string
	From         *string
	Comment      *string
}

func populateForm(f *tview.Form, v formValues) {
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

	tests := []struct {
		name        string
		values      formValues
		expectedCmd string
		row         string
	}{
		{
			name: "simple TCP rule",
			values: formValues{
				To:        pointer.Of("192.168.0.1"),
				Port:      pointer.Of("22"),
				Interface: pointer.Of(""),
				Protocol:  pointer.Of("tcp"),
				Action:    "ALLOW IN",
				From:      pointer.Of(""),
				Comment:   pointer.Of("SSH rule"),
			},
			row:         "[ 1] 192.168.0.1 22/tcp         ALLOW IN    Anywhere # SSH rule",
			expectedCmd: "ufw allow in from any to 192.168.0.1 proto tcp port 22 comment 'SSH rule'",
		},
		{
			name: "no proto",
			values: formValues{
				To:        pointer.Of("192.168.0.1"),
				Port:      pointer.Of("80"),
				Interface: pointer.Of(""),
				Protocol:  pointer.Of(""),
				Action:    "ALLOW IN",
				From:      pointer.Of(""),
				Comment:   pointer.Of(""),
			},
			row:         "[ 1] 192.168.0.1 80         ALLOW IN    Anywhere",
			expectedCmd: "ufw allow in from any to 192.168.0.1 port 80",
		},
		{
			name: "forward rule",
			values: formValues{
				To:           pointer.Of("192.168.1.100"),
				Port:         pointer.Of("80"),
				Interface:    pointer.Of("eth0"),
				InterfaceOut: pointer.Of("eth1"),
				Protocol:     pointer.Of("tcp"),
				Action:       "DENY FWD",
				From:         pointer.Of(""),
				Comment:      pointer.Of(""),
			},
			row:         "[ 1] 192.168.1.100 80/tcp DENY FWD Anywhere on eth0 out on eth1",
			expectedCmd: "ufw route deny in on eth0 out on eth1 from any to 192.168.1.100 proto tcp port 80",
		},
		{
			name: "HTTP allow",
			values: formValues{
				To:        pointer.Of("192.168.0.2"),
				Port:      pointer.Of("80"),
				Interface: pointer.Of(""),
				Protocol:  pointer.Of(""),
				Action:    "ALLOW IN",
				From:      pointer.Of(""),
				Comment:   pointer.Of("Web"),
			},
			row:         "[ 1] 192.168.0.2 80 ALLOW IN Anywhere                       # Web",
			expectedCmd: "ufw allow in from any to 192.168.0.2 port 80 comment 'Web'",
		},
		{
			name: "Deny udp to",
			values: formValues{
				To:        pointer.Of("10.0.0.0/24"),
				Port:      pointer.Of(""),
				Interface: pointer.Of(""),
				Action:    "DENY IN",
				Protocol:  pointer.Of("udp"),
				From:      pointer.Of(""),
			},
			row:         "[ 1] 10.0.0.0/24 - udp DENY IN Anywhere",
			expectedCmd: "ufw deny in from any to 10.0.0.0/24 proto udp",
		},
		{
			name: "Allow udp from anywhere",
			values: formValues{
				To:        pointer.Of(""),
				Port:      pointer.Of(""),
				Interface: pointer.Of(""),
				Action:    "ALLOW IN",
				Protocol:  pointer.Of("udp"),
				From:      pointer.Of("10.0.0.0/24"),
			},
			row:         "[ 1] Anywhere - udp ALLOW IN 10.0.0.0/24",
			expectedCmd: "ufw allow in from 10.0.0.0/24 to any proto udp",
		},
		{
			name: "Allow route forwarding with comment",
			values: formValues{
				To:           pointer.Of("172.16.0.5"),
				Port:         pointer.Of("443"),
				Interface:    pointer.Of("eth1"),
				InterfaceOut: pointer.Of("eth2"),
				Protocol:     pointer.Of("tcp"),
				Action:       "ALLOW FWD",
				From:         pointer.Of("10.0.0.0/8"),
				Comment:      pointer.Of("HTTPS route"),
			},
			row:         "[ 1] 172.16.0.5 443/tcp ALLOW FWD 10.0.0.0/8 on eth1 out on eth2 # HTTPS route",
			expectedCmd: "ufw route allow in on eth1 out on eth2 from 10.0.0.0/8 to 172.16.0.5 proto tcp port 443 comment 'HTTPS route'",
		},
		{
			name: "Allow route with no port",
			values: formValues{
				To:           pointer.Of("192.168.50.10"),
				Port:         pointer.Of(""),
				Interface:    pointer.Of("eth0"),
				InterfaceOut: pointer.Of("eth1"),
				Protocol:     pointer.Of(""),
				Action:       "ALLOW FWD",
				From:         pointer.Of("10.0.0.0/8"),
				Comment:      pointer.Of("No port route"),
			},
			row:         "[ 1] 192.168.50.10 ALLOW FWD 10.0.0.0/8 on eth0 out on eth1 # No port route",
			expectedCmd: "ufw route allow in on eth0 out on eth1 from 10.0.0.0/8 to 192.168.50.10 comment 'No port route'",
		},
		{
			name: "Allow SSH from specific host",
			values: formValues{
				To:        pointer.Of("192.168.1.1"),
				Port:      pointer.Of("22"),
				Interface: pointer.Of(""),
				Protocol:  pointer.Of("tcp"),
				Action:    "ALLOW IN",
				From:      pointer.Of("192.168.1.50"),
				Comment:   pointer.Of("Admin host"),
			},
			row:         "[ 1] 192.168.1.1 22/tcp ALLOW IN 192.168.1.50 # Admin host",
			expectedCmd: "ufw allow in from 192.168.1.50 to 192.168.1.1 proto tcp port 22 comment 'Admin host'",
		},
		{
			name: "Allow from subnet to any port 25 (SMTP)",
			values: formValues{
				To:        pointer.Of(""),
				Port:      pointer.Of("25"),
				Interface: pointer.Of(""),
				Protocol:  pointer.Of("tcp"),
				Action:    "ALLOW IN",
				From:      pointer.Of("192.168.10.0/24"),
				Comment:   pointer.Of("SMTP inbound"),
			},
			row:         "[ 1] Anywhere 25/tcp ALLOW IN 192.168.10.0/24 # SMTP inbound",
			expectedCmd: "ufw allow in from 192.168.10.0/24 to any proto tcp port 25 comment 'SMTP inbound'",
		},
		{
			name: "Deny outbound DNS",
			values: formValues{
				To:        pointer.Of("8.8.8.8"),
				Port:      pointer.Of("53"),
				Interface: pointer.Of(""),
				Protocol:  pointer.Of("udp"),
				Action:    "DENY OUT",
				From:      pointer.Of(""),
				Comment:   pointer.Of("Block Google DNS"),
			},
			row:         "[ 1] 8.8.8.8 53/udp DENY OUT Anywhere # Block Google DNS",
			expectedCmd: "ufw deny out from any to 8.8.8.8 proto udp port 53 comment 'Block Google DNS'",
		},
		{
			name: "Allow IPv6 SSH inbound",
			values: formValues{
				To:        pointer.Of("::1"),
				Port:      pointer.Of("22"),
				Interface: pointer.Of(""),
				Protocol:  pointer.Of("tcp"),
				Action:    "ALLOW IN",
				From:      pointer.Of(""),
				Comment:   pointer.Of("SSH v6"),
			},
			row:         "[ 1] ::1 22/tcp ALLOW IN Anywhere (v6) # SSH v6",
			expectedCmd: "ufw allow in from any to ::1 proto tcp port 22 comment 'SSH v6'",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var commands []string

			fmt.Println(tt.values.Protocol)

			// Mock per test
			shellout = func(cmd string) (error, string, string) {
				commands = append(commands, cmd)
				return nil, tt.row, ""
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

			tui.CreateTable([]string{loadedRow})

			cell := tui.table.GetCell(1, 0)
			expected := "[1]"
			if cell.Text != expected {
				t.Errorf("expected value for cell #: %q, got %q", expected, cell.Text)
			}

			cell = tui.table.GetCell(1, 1)
			if tt.values.To != nil {
				expected = *tt.values.To
				if tt.values.Protocol != nil && *tt.values.Protocol != "" {
					expected = *tt.values.To + "/" + *tt.values.Protocol
				}
				if *tt.values.To == "" {
					expected = "Anywhere" + expected
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
			if (tt.values.Action == "ALLOW FWD" || tt.values.Action == "DENY FWD") && tt.values.InterfaceOut != nil {
				expected = expected + " (" + *tt.values.InterfaceOut + ")"
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
