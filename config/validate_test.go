package config

import (
	"fmt"
	"strings"
	"testing"
)

type mockConfig struct {
	mockErr error
}

func (m *mockConfig) validateMonitorConfig() error {
	return m.mockErr
}

func TestValidateConfig(t *testing.T) {
	tests := []struct {
		name      string
		config    Validator
		expectErr bool
	}{
		{"success", &mockConfig{mockErr: nil}, false},
		{"error", &mockConfig{mockErr: fmt.Errorf("validation failed")}, true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := validateConfig(test.config)
			if (result != nil) != test.expectErr {
				t.Errorf("Expected error: %v, got: %v", test.expectErr, result)
			}
		})
	}
}

func TestValidateMonitorConfig(t *testing.T) {
	tests := []struct {
		name     string
		config   *Config
		expected string
	}{
		{"default config", &Config{Monitor: MonitorConfig{PollingInterval: "30s", Timeout: "5s", AlertSelection: "alphabetical"}}, ""},
		{"empty config", nil, fmt.Sprintf(fmtErrEmptyConfig, "config")},
		{"empty polling interval", &Config{Monitor: MonitorConfig{PollingInterval: "", Timeout: "5s", AlertSelection: "alphabetical"}}, fmt.Sprintf(fmtErrEmptyConfigOption, "monitor.polling_interval")},
		{"empty timeout", &Config{Monitor: MonitorConfig{PollingInterval: "30s", Timeout: "", AlertSelection: "alphabetical"}}, fmt.Sprintf(fmtErrEmptyConfigOption, "monitor.timeout")},
		{"empty alert selection", &Config{Monitor: MonitorConfig{PollingInterval: "30s", Timeout: "5s", AlertSelection: ""}}, fmt.Sprintf(fmtErrEmptyConfigOption, "monitor.alert_selection")},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := test.config.validateMonitorConfig()
			if test.expected == "" {
				if result != nil {
					t.Errorf("Expected no error, got '%v'", result)
				}
			} else {
				if result == nil {
					t.Errorf("Expected error containing %q, got nil", test.expected)
				} else if !strings.Contains(result.Error(), test.expected) {
					t.Errorf("Expected error containing %q, got %v", test.expected, result)
				}
			}
		})
	}
}
