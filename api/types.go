package api

import (
	"github.com/Crowley723/proxmox-node-monitor/config"
	"github.com/Crowley723/proxmox-node-monitor/peers"
)

type JoinResponse struct {
	Certificate string         `json:"certificate"`
	Peers       []peers.Peer   `json:"peers"`
	Config      ConfigResponse `json:"config"`
}

type ConfigResponse struct {
	Monitor config.MonitorConfig `json:"monitor"`
	Mesh    config.MeshConfig    `json:"mesh"`
	Cluster config.ClusterConfig `json:"cluster"`
	Alert   config.AlertConfig   `json:"alert"`
}
