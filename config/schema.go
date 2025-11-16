package config

type Config struct {
	Monitor MonitorConfig `yaml:"monitor" json:"monitor"`
	Mesh    MeshConfig    `yaml:"mesh" json:"mesh"`
	Cluster ClusterConfig `yaml:"cluster" json:"cluster"`
	Alert   AlertConfig   `yaml:"alert" json:"alert"`
	Logging LoggingConfig `yaml:"logging" json:"logging"`
}

type MonitorConfig struct {
	PollingInterval string `yaml:"polling_interval" json:"polling_interval"`
	Timeout         string `yaml:"timeout" json:"timeout"`
	AlertSelection  string `yaml:"alert_selection" json:"alert_selection"`
}

var DefaultMonitorConfig = MonitorConfig{
	PollingInterval: `30s`,
	Timeout:         `5s`,
	AlertSelection:  "alphabetical",
}

type MeshConfig struct {
	Port        int  `yaml:"port" json:"port"`
	TLSEnabled  bool `yaml:"tls_enabled" json:"tls_enabled"`
	JoinEnabled bool `yaml:"join_enabled" json:"join_enabled"`
}

var DefaultMeshConfig = MeshConfig{
	Port:        8443,
	TLSEnabled:  false,
	JoinEnabled: false,
}

type ClusterConfig struct {
	CertDir              string   `yaml:"cert_dir" json:"cert_dir"`
	TrustedProxies       []string `yaml:"trusted_proxies" json:"trusted_proxies"`
	CertValidityDays     int      `yaml:"cert_validity_days" json:"cert_validity_days"`
	RenewalThresholdDays int      `yaml:"renewal_threshold_days" json:"renewal_threshold_days"`
}

var DefaultClusterConfig = ClusterConfig{
	CertDir:              "/etc/proxmox-node-monitor/certs",
	CertValidityDays:     365,
	RenewalThresholdDays: 292,
}

type AlertConfig struct {
	Enabled    bool                 `yaml:"enabled" json:"enabled"`
	Thresholds AlertThresholdConfig `yaml:"thresholds" json:"thresholds"`
	Email      EmailAlertConfig     `yaml:"email" json:"email"`
}

var DefaultAlertConfig = AlertConfig{
	Enabled:    false,
	Thresholds: DefaultAlertThresholdConfig,
}

type AlertThresholdConfig struct {
	NodeDownDuration string `yaml:"node_down_duration" json:"node_down_duration"`
	AlertInterval    string `yaml:"alert_interval" json:"alert_interval"`
}

var DefaultAlertThresholdConfig = AlertThresholdConfig{
	NodeDownDuration: "1m",
	AlertInterval:    "30m",
}

type EmailAlertConfig struct {
	Host     string `yaml:"host" json:"host"`
	Port     int    `yaml:"port" json:"port"`
	From     string `yaml:"from" json:"from"`
	To       string `yaml:"to" json:"to"`
	Username string `yaml:"username" json:"username"`
	Password string `yaml:"password" json:"password"`
}

type LoggingConfig struct {
	Path string `yaml:"path" json:"path"`
}
