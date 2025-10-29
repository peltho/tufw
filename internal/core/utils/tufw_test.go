package utils

import (
	"testing"
)

func TestSplitValueWithIface(t *testing.T) {
	tests := []struct {
		name  string
		input string
		iface string
		val   string
	}{
		{
			name:  "get eth1 interface",
			input: "Anywhere (eth1)",
			iface: "eth1",
			val:   "Anywhere",
		},
		{
			name:  "get no interface",
			input: "Anywhere",
			iface: "",
			val:   "Anywhere",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			val, iface := SplitValueWithIface(tt.input)
			if val != tt.val {
				t.Errorf("got %v, want %v", val, tt.val)
			}

			if iface != tt.iface {
				t.Errorf("got %v, want %v", iface, tt.iface)
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
