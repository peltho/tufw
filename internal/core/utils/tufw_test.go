package utils

import (
	"reflect"
	"testing"

	"github.com/peltho/tufw/internal/core/domain"
)

func TestParseProtocol(t *testing.T) {
	tests := []struct {
		name     string
		toCell   string
		fromCell string
		expected string
	}{
		{
			name:     "basic",
			toCell:   "192.168.1.34/tcp",
			fromCell: "Anywhere",
			expected: "tcp",
		},
		{
			name:     "basic",
			toCell:   "192.168.1.34",
			fromCell: "Anywhere",
			expected: "",
		},
		{
			name:     "basic",
			toCell:   "192.168.1.34",
			fromCell: "8.8.8.8/udp",
			expected: "udp",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			value := ParseProtocol(tt.toCell, tt.fromCell)
			if value != tt.expected {
				t.Errorf("got %v, want %v", value, tt.expected)
			}
		})
	}
}

func TestParseFromOrTo(t *testing.T) {
	tests := []struct {
		input   string
		address string
		proto   string
		iface   string
	}{
		{
			input:   "192.168.50.10_on_eth1",
			address: "192.168.50.10",
			proto:   "",
			iface:   "eth1",
		},
		{
			input:   "::1",
			address: "::1",
			proto:   "",
			iface:   "",
		},
		{
			input:   "192.168.50.10/tcp",
			address: "192.168.50.10",
			proto:   "tcp",
			iface:   "",
		},
		{
			input:   "192.168.50.10/24/tcp_on_eth1",
			address: "192.168.50.10/24",
			proto:   "tcp",
			iface:   "eth1",
		},
		{
			input:   "192.168.50.10/24_on_eth1",
			address: "192.168.50.10/24",
			proto:   "",
			iface:   "eth1",
		},
		{
			input:   "::1/udp",
			address: "::1",
			proto:   "udp",
			iface:   "",
		},
		{
			input:   "::1/udp_on_lo",
			address: "::1",
			proto:   "udp",
			iface:   "lo",
		},
		{
			input:   "Anywhere_on_eth0",
			address: "Anywhere",
			proto:   "",
			iface:   "eth0",
		},
		{
			input:   "Anywhere on eth0",
			address: "Anywhere",
			proto:   "",
			iface:   "eth0",
		},
	}

	for _, tt := range tests {
		t.Run("", func(t *testing.T) {
			address, proto, iface := ParseFromOrTo(tt.input)
			if address != tt.address {
				t.Errorf("address: got %v, want %v", address, tt.address)
			}
			if proto != tt.proto {
				t.Errorf("proto: got %v, want %v", proto, tt.proto)
			}
			if iface != tt.iface {
				t.Errorf("iface: got %v, want %v", iface, tt.iface)
			}
		})
	}
}

func TestParseInterfaceIndex(t *testing.T) {

	tests := []struct {
		name       string
		input      string
		interfaces []string
		expected   int
	}{
		{
			name:       "match in middle",
			input:      "Anywhere_on_eth1",
			interfaces: []string{"eth0", "eth1", "eth2"},
			expected:   1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ParseInterfaceIndex(tt.input, tt.interfaces)
			if result != tt.expected {
				t.Errorf("got %d, want %d", result, tt.expected)
			}
		})
	}
}

func TestFillCell(t *testing.T) {
	tests := []struct {
		input    string
		expected domain.CellValues
	}{
		{
			input: "[1] 192.168.50.10_on_eth1 - ALLOW-FWD 10.0.0.0/8_on_eth0 # No port route",
			expected: domain.CellValues{
				Index:   "[1]",
				To:      "192.168.50.10_on_eth1",
				Port:    "-",
				Action:  "ALLOW-FWD",
				From:    "10.0.0.0/8_on_eth0",
				Comment: "No port route",
			},
		},
		{
			input: "[1] 172.16.0.5/tcp_on_eth2 443 ALLOW-FWD 10.0.0.0/8_on_eth1 # HTTPS route",
			expected: domain.CellValues{
				Index:   "[1]",
				To:      "172.16.0.5/tcp_on_eth2",
				Port:    "443",
				Action:  "ALLOW-FWD",
				From:    "10.0.0.0/8_on_eth1",
				Comment: "HTTPS route",
			},
		},
		{
			input: "[1] 192.168.0.1/tcp 22 ALLOW-IN Anywhere # SSH rule",
			expected: domain.CellValues{
				Index:   "[1]",
				To:      "192.168.0.1/tcp",
				Port:    "22",
				Action:  "ALLOW-IN",
				From:    "Anywhere",
				Comment: "SSH rule",
			},
		},
		{
			input: "[1] 5.5.5.5_on_eth1 - ALLOW-FWD Anywhere_on_eth0",
			expected: domain.CellValues{
				Index:   "[1]",
				To:      "5.5.5.5_on_eth1",
				Port:    "-",
				Action:  "ALLOW-FWD",
				From:    "Anywhere_on_eth0",
				Comment: "",
			},
		},
	}

	for _, tt := range tests {
		t.Run("", func(t *testing.T) {
			result := FillCell(tt.input)
			if result == nil {
				t.Fatalf("FillCell returned nil for input %q", tt.input)
			}
			if !reflect.DeepEqual(*result, tt.expected) {
				t.Errorf("got %+v, want %+v", *result, tt.expected)
			}
		})
	}
}
