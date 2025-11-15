package alert

import (
	"testing"
)

func TestSelectAlertingNode(t *testing.T) {
	tests := []struct {
		name     string
		nodes    []string
		expected string
	}{
		{"single node", []string{"node1"}, "node1"},
		{"three node alphabetical", []string{"node1", "node2", "node3"}, "node1"},
		{"three node out of order", []string{"node2", "node3", "node1"}, "node1"},
		{"empty list", []string{""}, ""},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := SelectAlertingNode(test.nodes)
			if result != test.expected {
				t.Errorf("Expected %s, got %s", test.expected, result)
			}
		})
	}
}
