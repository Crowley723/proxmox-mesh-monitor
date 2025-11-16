package peers

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

var mu sync.RWMutex

func LoadRegistry(path string) (*PeerRegistry, error) {
	mu.RLock()
	defer mu.RUnlock()

	peersData, err := os.ReadFile(filepath.Join(path, ConstPeersFile))
	if err != nil {
		if os.IsNotExist(err) {
			return &PeerRegistry{Peers: []Peer{}}, nil
		}
		return nil, fmt.Errorf("failed to read peers file: %w", err)
	}

	var registry PeerRegistry
	if err := json.Unmarshal(peersData, &registry); err != nil {
		return nil, fmt.Errorf("failed to parse peers file: %w", err)
	}

	return &registry, nil
}

func AddPeer(path string, peer Peer) error {
	mu.Lock()
	defer mu.Unlock()

	data, err := os.ReadFile(filepath.Join(path, ConstPeersFile))
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to read peers file: %w", err)
	}

	var registry PeerRegistry
	if len(data) > 0 {
		if err := json.Unmarshal(data, &registry); err != nil {
			return fmt.Errorf("failed to parse peers file: %w", err)
		}
	}

	for _, p := range registry.Peers {
		if p.Hostname == peer.Hostname {
			return fmt.Errorf("peer %s already exists", peer.Hostname)
		}
	}

	registry.Peers = append(registry.Peers, peer)

	filePath := filepath.Join(path, ConstPeersFile)
	data, err = json.MarshalIndent(&registry, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal registry: %w", err)
	}

	if err := os.WriteFile(filePath, data, 0600); err != nil {
		return fmt.Errorf("failed to write peers file: %w", err)
	}

	return nil
}

func GetPeer(path string, hostname string) (*Peer, error) {
	mu.RLock()
	defer mu.RUnlock()

	reg, err := LoadRegistry(path)
	if err != nil {
		return nil, err
	}

	for i := range reg.Peers {
		if reg.Peers[i].Hostname == hostname {
			return &reg.Peers[i], nil
		}
	}
	return nil, fmt.Errorf("peer not found")
}

func GetKeymaster(path string) (*Peer, error) {
	mu.RLock()
	defer mu.RUnlock()

	reg, err := LoadRegistry(path)
	if err != nil {
		return nil, err
	}

	for _, peer := range reg.Peers {
		if peer.Role == RoleKeymaster {
			return &peer, nil
		}
	}

	return nil, fmt.Errorf("keymaster not found")
}

func SaveRegistry(path string, reg *PeerRegistry) error {
	mu.Lock()
	defer mu.Unlock()

	//Create Certs directory
	err := os.MkdirAll(path, 0700)
	if err != nil {
		return fmt.Errorf("unable to create certificate directory: %v", err)
	}

	filePath := filepath.Join(path, ConstPeersFile)
	data, err := json.MarshalIndent(reg, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal registry: %w", err)
	}

	if err := os.WriteFile(filePath, data, 0600); err != nil {
		return fmt.Errorf("failed to write peers file: %w", err)
	}

	return nil
}

func InitializeRegistry(path string, firstAddress string) error {
	hostname, err := os.Hostname()
	if err != nil {
		return fmt.Errorf("failed to get hostname: %w", err)
	}

	if firstAddress == "" {
		return fmt.Errorf("no address specified")
	}

	firstPeer := Peer{
		Hostname: hostname,
		Address:  firstAddress,
		Role:     RoleKeymaster,
	}

	registry := &PeerRegistry{
		Peers: []Peer{firstPeer},
	}

	return SaveRegistry(path, registry)
}
