package config

import (
	"errors"
	"fmt"
)

type Validator interface {
	validateMonitorConfig() error
}

func validateConfig(config Validator) error {
	err := config.validateMonitorConfig()
	if err != nil {
		return err
	}

	return nil
}

func (c *Config) validateMonitorConfig() error {
	if c == nil {
		return fmt.Errorf(fmtErrEmptyConfig, "config")
	}

	if c.Monitor.PollingInterval == "" {
		return fmt.Errorf(fmtErrEmptyConfigOption, "monitor.polling_interval")
	}

	if c.Monitor.Timeout == "" {
		return fmt.Errorf(fmtErrEmptyConfigOption, "monitor.timeout")
	}

	if c.Monitor.AlertSelection == "" {
		return fmt.Errorf(fmtErrEmptyConfigOption, "monitor.alert_selection")
	}

	return nil
}

func (c *Config) validateMeshConfig() error {
	if c == nil {
		return fmt.Errorf(fmtErrEmptyConfig, "config")
	}

	if c.Mesh.Port <= 0 || c.Mesh.Port > 65535 {
		return errors.New("monitor.polling_interval must be in the range 1-65535")
	}

	return nil
}
