package monitor

import (
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/Crowley723/proxmox-node-monitor/config"
	"github.com/Crowley723/proxmox-node-monitor/peers"
)

type HealthStatus struct {
	Hostname  string    `json:"hostname"`
	Status    string    `json:"status"`
	Timestamp time.Time `json:"timestamp"`
	Uptime    float64   `json:"uptime"`
	Healthy   bool
	LastCheck time.Time
	Error     string
}

type Monitor struct {
	config       *config.Config
	logger       *slog.Logger
	peerRegistry *peers.PeerRegistry
	client       *http.Client
	healthMap    map[string]*HealthStatus
	mu           sync.RWMutex
}
