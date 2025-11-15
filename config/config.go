package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

func LoadConfig(path string) (*Config, error) {
	if path == "" {
		return nil, fmt.Errorf("config file path is required (use -config or -c)")
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	var config Config
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to parse config: %w", err)
	}

	if err := validateConfig(&config); err != nil {
		return nil, fmt.Errorf("config validation failed: %w", err)
	}

	return &config, nil
}

func (c *Config) UnmarshalYAML(unmarshall func(interface{}) error) error {
	type raw Config
	r := raw{
		Monitor: DefaultMonitorConfig,
		Mesh:    DefaultMeshConfig,
		Cluster: DefaultClusterConfig,
		Alert:   DefaultAlertConfig,
	}

	if err := unmarshall(&r); err != nil {
		return err
	}

	*c = Config(r)

	return nil
}
