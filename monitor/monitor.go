package monitor

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/Crowley723/proxmox-node-monitor/config"
	"github.com/Crowley723/proxmox-node-monitor/peers"
	"github.com/Crowley723/proxmox-node-monitor/utils"
)

func New(cfg *config.Config, logger *slog.Logger, registry *peers.PeerRegistry) (*Monitor, error) {
	client, err := createMTLSClient(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create mTLS client: %w", err)
	}

	return &Monitor{
		config:       cfg,
		logger:       logger,
		peerRegistry: registry,
		client:       client,
		healthMap:    make(map[string]*HealthStatus),
	}, nil
}

func createMTLSClient(cfg *config.Config) (*http.Client, error) {
	cert, err := tls.LoadX509KeyPair(
		cfg.Cluster.NodeCertPath(""),
		cfg.Cluster.NodeKeyPath(""),
	)
	if err != nil {
		return nil, err
	}

	caCert, err := os.ReadFile(cfg.Cluster.CACertPath(""))
	if err != nil {
		return nil, err
	}

	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      caCertPool,
	}

	timeout, err := time.ParseDuration(cfg.Monitor.Timeout)
	if err != nil {
		return nil, fmt.Errorf("failed to parse timeout: %w", err)
	}

	return &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
		},
		Timeout: timeout,
	}, nil
}

func (m *Monitor) Start(ctx context.Context) {
	pollingInterval, err := time.ParseDuration(m.config.Monitor.PollingInterval)
	if err != nil {
		m.logger.Error("Failed to start peer monitor: Failed to parse polling interval", "error", err)
		return
	}
	ticker := time.NewTicker(pollingInterval)
	defer ticker.Stop()

	m.logger.Info("starting monitor loop",
		"interval", m.config.Monitor.PollingInterval,
		"timeout", m.config.Monitor.Timeout)

	m.checkAllPeers(ctx)

	for {
		select {
		case <-ctx.Done():
			m.logger.Info("monitor loop stopped")
			return
		case <-ticker.C:
			m.checkAllPeers(ctx)
		}
	}
}

func (m *Monitor) checkAllPeers(ctx context.Context) {
	allPeers := m.peerRegistry.Peers

	m.logger.Debug("checking peer health", "peer_count", len(allPeers))

	for _, peer := range allPeers {
		if peer.Hostname == (utils.GetHostname()) {
			continue
		}

		go m.checkPeer(ctx, peer)
	}
}

func (m *Monitor) checkPeer(ctx context.Context, peer peers.Peer) {
	url := fmt.Sprintf("https://%s:%d/health", peer.Address, m.config.Mesh.Port)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		m.recordFailure(peer.Hostname, err)
		return
	}

	resp, err := m.client.Do(req)
	if err != nil {
		m.recordFailure(peer.Hostname, err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		m.recordFailure(peer.Hostname, fmt.Errorf("status %d", resp.StatusCode))
		return
	}

	var health HealthStatus
	if err := json.NewDecoder(resp.Body).Decode(&health); err != nil {
		m.recordFailure(peer.Hostname, err)
		return
	}

	m.recordSuccess(peer.Hostname, &health)
}

func (m *Monitor) recordSuccess(hostname string, health *HealthStatus) {
	m.mu.Lock()
	defer m.mu.Unlock()

	health.Healthy = true
	health.LastCheck = time.Now()
	m.healthMap[hostname] = health

	m.logger.Debug("peer health check succeeded",
		"peer", hostname,
		"status", health.Status,
		"uptime", health.Uptime)
}

func (m *Monitor) recordFailure(hostname string, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	status := &HealthStatus{
		Hostname:  hostname,
		Healthy:   false,
		LastCheck: time.Now(),
		Error:     err.Error(),
	}
	m.healthMap[hostname] = status

	m.logger.Warn("peer health check failed",
		"peer", hostname,
		"error", err)
}

func (m *Monitor) GetHealthStatus() map[string]*HealthStatus {
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := make(map[string]*HealthStatus)
	for k, v := range m.healthMap {
		result[k] = v
	}
	return result
}
