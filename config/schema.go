package config

type Config struct {
	Monitor MonitorConfig `yaml:"monitor"`
	Mesh    MeshConfig    `yaml:"mesh"`
	Cluster ClusterConfig `yaml:"cluster"`
	Alert   AlertConfig   `yaml:"alert"`
	Logging LoggingConfig `yaml:"logging"`
}

type MonitorConfig struct {
	PollingInterval string `yaml:"polling_interval"`
	Timeout         string `yaml:"timeout"`
	AlertSelection  string `yaml:"alert_selection"`
}

var DefaultMonitorConfig = MonitorConfig{
	PollingInterval: `30s`,
	Timeout:         `5s`,
	AlertSelection:  "alphabetical",
}

type MeshConfig struct {
	Port        int  `yaml:"port"`
	TLSEnabled  bool `yaml:"tls_enabled"`
	JoinEnabled bool `yaml:"join_enabled"`
}

var DefaultMeshConfig = MeshConfig{
	Port:        8443,
	TLSEnabled:  false,
	JoinEnabled: false,
}

type ClusterConfig struct {
	CertDir              string `yaml:"cert_dir"`
	CertValidityDays     int    `yaml:"cert_validity_days"`
	RenewalThresholdDays int    `yaml:"renewal_threshold_days"`
}

var DefaultClusterConfig = ClusterConfig{
	CertDir:              "/etc/proxmox-node-monitor/certs",
	CertValidityDays:     365,
	RenewalThresholdDays: 292,
}

type AlertConfig struct {
	Enabled    bool                 `yaml:"enabled"`
	Thresholds AlertThresholdConfig `yaml:"thresholds"`
	Email      EmailAlertConfig     `yaml:"email"`
}

var DefaultAlertConfig = AlertConfig{
	Enabled:    false,
	Thresholds: DefaultAlertThresholdConfig,
}

type AlertThresholdConfig struct {
	NodeDownDuration string `yaml:"node_down_duration"`
	AlertInterval    string `yaml:"alert_interval"`
}

var DefaultAlertThresholdConfig = AlertThresholdConfig{
	NodeDownDuration: "1m",
	AlertInterval:    "30m",
}

type EmailAlertConfig struct {
	Host     string `yaml:"host"`
	Port     int    `yaml:"port"`
	From     string `yaml:"from"`
	To       string `yaml:"to"`
	Username string `yaml:"username"`
	Password string `yaml:"password"`
}

type LoggingConfig struct {
	Path string `yaml:"path"`
}
