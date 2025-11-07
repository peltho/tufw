package service

import (
	"testing"

	"github.com/gdamore/tcell/v2"
	"github.com/peltho/tufw/internal/core/domain"
	"github.com/peltho/tufw/internal/core/utils"
	"github.com/rivo/tview"
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
			To:        "192.168.0.1",
			Port:      "22",
			Interface: "",
			Protocol:  "tcp",
			Action:    "ALLOW IN",
			From:      "",
			Comment:   "SSH rule",
		},
		row:          "[ 1] 192.168.0.1 22/tcp         ALLOW IN    Anywhere # SSH rule",
		formattedRow: "[1] 192.168.0.1/tcp 22 ALLOW-IN Anywhere # SSH rule",
		expectedCmd:  "ufw allow in from any to 192.168.0.1 proto tcp port 22 comment 'SSH rule'",
	},
	{
		name: "no proto",
		values: domain.FormValues{
			To:        "192.168.0.1",
			Port:      "80",
			Interface: "",
			Protocol:  "",
			Action:    "ALLOW IN",
			From:      "",
			Comment:   "",
		},
		row:          "[ 1] 192.168.0.1 80         ALLOW IN    Anywhere",
		formattedRow: "[1] 192.168.0.1 80 ALLOW-IN Anywhere",
		expectedCmd:  "ufw allow in from any to 192.168.0.1 port 80",
	},
	{
		name: "forward rule",
		values: domain.FormValues{
			To:           "192.168.1.100",
			Port:         "80",
			Interface:    "eth0",
			InterfaceOut: "eth1",
			Protocol:     "tcp",
			Action:       "DENY FWD",
			From:         "",
			Comment:      "",
		},
		row:          "[ 1] 192.168.1.100 80/tcp DENY FWD Anywhere on eth0 out on eth1",
		formattedRow: "[1] 192.168.1.100/tcp_on_eth1 80 DENY-FWD Anywhere_on_eth0",
		expectedCmd:  "ufw route deny in on eth0 out on eth1 from any to 192.168.1.100 proto tcp port 80",
	},
	{
		name: "HTTP allow",
		values: domain.FormValues{
			To:        "192.168.0.2",
			Port:      "80",
			Interface: "",
			Protocol:  "",
			Action:    "ALLOW IN",
			From:      "",
			Comment:   "Web",
		},
		row:          "[ 1] 192.168.0.2 80 ALLOW IN Anywhere                       # Web",
		formattedRow: "[1] 192.168.0.2 80 ALLOW-IN Anywhere # Web",
		expectedCmd:  "ufw allow in from any to 192.168.0.2 port 80 comment 'Web'",
	},
	{
		name: "Deny udp to",
		values: domain.FormValues{
			To:        "10.0.0.0/24",
			Port:      "",
			Interface: "",
			Action:    "DENY IN",
			Protocol:  "udp",
			From:      "",
		},
		row:          "[ 1] 10.0.0.0/24 - udp DENY IN Anywhere",
		formattedRow: "[1] 10.0.0.0/24/udp - DENY-IN Anywhere",
		expectedCmd:  "ufw deny in from any to 10.0.0.0/24 proto udp",
	},
	{
		name: "Allow udp from anywhere",
		values: domain.FormValues{
			To:        "",
			Port:      "",
			Interface: "",
			Action:    "ALLOW IN",
			Protocol:  "udp",
			From:      "10.0.0.0/24",
		},
		row:          "[ 1] Anywhere - udp ALLOW IN 10.0.0.0/24",
		formattedRow: "[1] Anywhere/udp - ALLOW-IN 10.0.0.0/24",
		expectedCmd:  "ufw allow in from 10.0.0.0/24 to any proto udp",
	},
	{
		name: "Allow route forwarding with comment",
		values: domain.FormValues{
			To:           "172.16.0.5",
			Port:         "443",
			Interface:    "eth1",
			InterfaceOut: "eth2",
			Protocol:     "tcp",
			Action:       "ALLOW FWD",
			From:         "10.0.0.0/8",
			Comment:      "HTTPS route",
		},
		row:          "[ 1] 172.16.0.5 443/tcp ALLOW FWD 10.0.0.0/8 on eth1 out on eth2 # HTTPS route",
		formattedRow: "[1] 172.16.0.5/tcp_on_eth2 443 ALLOW-FWD 10.0.0.0/8_on_eth1 # HTTPS route",
		expectedCmd:  "ufw route allow in on eth1 out on eth2 from 10.0.0.0/8 to 172.16.0.5 proto tcp port 443 comment 'HTTPS route'",
	},
	{
		name: "Allow route with no port",
		values: domain.FormValues{
			To:           "192.168.50.10",
			Port:         "",
			Interface:    "eth0",
			InterfaceOut: "eth1",
			Protocol:     "",
			Action:       "ALLOW FWD",
			From:         "10.0.0.0/8",
			Comment:      "No port route",
		},
		row:          "[ 1] 192.168.50.10 ALLOW FWD 10.0.0.0/8 on eth0 out on eth1 # No port route",
		formattedRow: "[1] 192.168.50.10_on_eth1 - ALLOW-FWD 10.0.0.0/8_on_eth0 # No port route",
		expectedCmd:  "ufw route allow in on eth0 out on eth1 from 10.0.0.0/8 to 192.168.50.10 comment 'No port route'",
	},
	{
		name: "Allow SSH from specific host",
		values: domain.FormValues{
			To:        "192.168.1.1",
			Port:      "22",
			Interface: "",
			Protocol:  "tcp",
			Action:    "ALLOW IN",
			From:      "192.168.1.50",
			Comment:   "Admin host",
		},
		row:          "[ 1] 192.168.1.1 22/tcp ALLOW IN 192.168.1.50 # Admin host",
		formattedRow: "[1] 192.168.1.1/tcp 22 ALLOW-IN 192.168.1.50 # Admin host",
		expectedCmd:  "ufw allow in from 192.168.1.50 to 192.168.1.1 proto tcp port 22 comment 'Admin host'",
	},
	{
		name: "Allow from subnet to any port 25 (SMTP)",
		values: domain.FormValues{
			To:        "",
			Port:      "25",
			Interface: "",
			Protocol:  "tcp",
			Action:    "ALLOW IN",
			From:      "192.168.10.0/24",
			Comment:   "SMTP inbound",
		},
		row:          "[ 1] Anywhere 25/tcp ALLOW IN 192.168.10.0/24 # SMTP inbound",
		formattedRow: "[1] Anywhere/tcp 25 ALLOW-IN 192.168.10.0/24 # SMTP inbound",
		expectedCmd:  "ufw allow in from 192.168.10.0/24 to any proto tcp port 25 comment 'SMTP inbound'",
	},
	{
		name: "Deny outbound DNS",
		values: domain.FormValues{
			To:        "8.8.8.8",
			Port:      "53",
			Interface: "",
			Protocol:  "udp",
			Action:    "DENY OUT",
			From:      "",
			Comment:   "Block Google DNS",
		},
		row:          "[ 1] 8.8.8.8 53/udp DENY OUT Anywhere # Block Google DNS",
		formattedRow: "[1] 8.8.8.8/udp 53 DENY-OUT Anywhere # Block Google DNS",
		expectedCmd:  "ufw deny out from any to 8.8.8.8 proto udp port 53 comment 'Block Google DNS'",
	},
	{
		name: "Allow IPv6 SSH inbound",
		values: domain.FormValues{
			To:        "::1",
			Port:      "22",
			Interface: "",
			Protocol:  "tcp",
			Action:    "ALLOW IN",
			From:      "",
			Comment:   "SSH v6",
		},
		row:          "[ 1] ::1 22/tcp ALLOW IN Anywhere (v6) # SSH v6",
		formattedRow: "[1] ::1/tcp 22 ALLOW-IN Anywhere # SSH v6",
		expectedCmd:  "ufw allow in from any to ::1 proto tcp port 22 comment 'SSH v6'",
	},
	{
		name: "foo",
		values: domain.FormValues{
			To:           "3.3.3.3",
			Port:         "",
			Interface:    "enp0s1",
			InterfaceOut: "lo",
			Protocol:     "",
			Action:       "DENY FWD",
			From:         "",
			Comment:      "",
		},
		row:          "[ 1] 3.3.3.3 on lo DENY FWD Anywhere on enp0s1",
		formattedRow: "[1] 3.3.3.3_on_lo - DENY-FWD Anywhere_on_enp0s1",
		expectedCmd:  "ufw route deny in on enp0s1 out on lo from any to 3.3.3.3",
	},
	{
		name: "open eth0",
		values: domain.FormValues{
			To:        "",
			Port:      "22",
			Interface: "eth0",
			Protocol:  "tcp",
			Action:    "ALLOW IN",
			From:      "",
			Comment:   "",
		},
		row:          "[ 1] Anywhere 22/tcp ALLOW IN Anywhere on eth0",
		formattedRow: "[1] Anywhere/tcp 22 ALLOW-IN Anywhere_on_eth0",
		expectedCmd:  "ufw allow in on eth0 from any to any proto tcp port 22",
	},
	{
		name: "ssh everywhere without To",
		values: domain.FormValues{
			To:        "",
			Port:      "22",
			Interface: "",
			Protocol:  "",
			Action:    "ALLOW IN",
			From:      "",
			Comment:   "",
		},
		row:          "[ 1] 22                         ALLOW IN    Anywhere",
		formattedRow: "[1] 22 ALLOW-IN Anywhere",
		expectedCmd:  "ufw allow in from any to any port 22",
	},
}

func populateForm(f *tview.Form, v domain.FormValues) {
	f.Clear(true) // remove previous fields if any

	f.AddInputField("To", v.To, 10, nil, nil)

	f.AddInputField("Port", v.Port, 10, nil, nil)

	f.AddDropDown("Interface", []string{v.Interface}, 0, nil)

	f.AddDropDown("Interface out", []string{v.InterfaceOut}, 0, nil)

	f.AddDropDown("Protocol", []string{v.Protocol}, 0, nil)

	f.AddDropDown("Action *", []string{v.Action}, 0, nil)

	f.AddInputField("From", v.From, 10, nil, nil)

	f.AddInputField("Comment", v.Comment, 10, nil, nil)
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

			cellValues := utils.FillCell(loadedRow)

			cell := tui.table.GetCell(1, 0)
			if cell.Text != cellValues.Index {
				t.Errorf("expected value for cell #: %q, got %q", cellValues.Index, cell.Text)
			}

			cell = tui.table.GetCell(1, 1)
			if cell.Text != cellValues.To {
				t.Errorf("expected value for cell To: %q, got %q", cellValues.To, cell.Text)
			}

			cell = tui.table.GetCell(1, 2)
			if cell.Text != cellValues.Port {
				t.Errorf("expected value for cell Port: %q, got %q", cellValues.Port, cell.Text)
			}

			cell = tui.table.GetCell(1, 3)
			if cell.Text != cellValues.Action {
				t.Errorf("expected value for cell Action: %q, got %q", cellValues.Action, cell.Text)
			}

			cell = tui.table.GetCell(1, 4)
			if cell.Text != cellValues.From {
				t.Errorf("expected value for cell From: %q, got %q", cellValues.From, cell.Text)
			}

			cell = tui.table.GetCell(1, 5)
			if cell.Text != cellValues.Comment {
				t.Errorf("expected value for cell Comment: %q, got %q", cellValues.Comment, cell.Text)
			}
		})
	}
}

func TestEditRule(t *testing.T) {
	var tests = []struct {
		name        string
		position    int
		values      domain.FormValues
		expectedCmd string
	}{
		{
			name:     "edit simple TCP rule",
			position: 3,
			values: domain.FormValues{
				To:        "192.168.0.1",
				Port:      "22",
				Interface: "",
				Protocol:  "tcp",
				Action:    "ALLOW-IN",
				From:      "",
				Comment:   "SSH rule",
			},
			expectedCmd: "ufw insert 2 allow in from any to 192.168.0.1 proto tcp port 22 comment 'SSH rule'",
		},
		{
			name:     "Allow fwd route with interface out",
			position: 3,
			values: domain.FormValues{
				To:           "192.168.50.10",
				Port:         "",
				Interface:    "eth0",
				InterfaceOut: "eth1",
				Protocol:     "",
				Action:       "ALLOW-FWD",
				From:         "10.0.0.0/8",
				Comment:      "No port route",
			},
			expectedCmd: "ufw route insert 2 allow in on eth0 out on eth1 from 10.0.0.0/8 to 192.168.50.10 comment 'No port route'",
		},
		{
			name:     "Allow fwd route without interface out",
			position: 3,
			values: domain.FormValues{
				To:           "192.168.50.10",
				Port:         "",
				Interface:    "eth0",
				InterfaceOut: "",
				Protocol:     "",
				Action:       "ALLOW-FWD",
				From:         "10.0.0.0/8",
				Comment:      "",
			},
			expectedCmd: "ufw route insert 2 allow in on eth0 from 10.0.0.0/8 to 192.168.50.10",
		},
	}

	tui := CreateApplication(tcell.ColorBlue)
	tui.Init()

	shellout = func(cmd string) (string, string, error) {
		return "", "", nil
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := tui.EditRule(tt.position, tt.values)
			if *v != tt.expectedCmd {
				t.Errorf("expected command: %q, got %q", tt.expectedCmd, *v)
			}
		})
	}
}
