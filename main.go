package main

import (
	"flag"
	"fmt"
	"log/slog"
	"os"

	"github.com/Crowley723/proxmox-node-monitor/api"
	"github.com/Crowley723/proxmox-node-monitor/config"
	"github.com/Crowley723/proxmox-node-monitor/mesh"
)

func main() {
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stdout, nil)))

	var (
		joinAddr      = flag.String("join", "", "join an existing cluster (address of keymaster node)")
		joinToken     = flag.String("join-token", "", "token for joining")
		configPath    = flag.String("config", "config.yaml", "config file path")
		certDir       = flag.String("cert-dir", "/etc/mesh-app/certs", "directory for cert/key files")
		bootstrapMode = flag.Bool("bootstrap", false, "bootstrap a new cluster (first node only)")
	)
	flag.Parse()

	// Bootstrap first node: generate CA, node cert, and keypair.
	if *bootstrapMode {
		cfg, err := config.LoadConfig(*configPath)
		if err != nil {
			slog.Error("failed to load config", "err", err)
		}

		if err := mesh.Bootstrap(cfg, *certDir); err != nil {
			slog.Error("bootstrap failed: %v", "err", err)
		}
		slog.Info(fmt.Sprintf("Bootstrap Complete. Config: %s, Certs: %s\n", *configPath, *certDir))
		return
	}

	// Join additional nodes: generate tls cert, get it signed, pull config from cluster.
	if *joinAddr != "" {
		if *joinToken == "" {
			slog.Error("join-token required when using -join")
		}
		//if err := mesh.Join(*joinAddr, *joinToken, *configPath, *certDir); err != nil {
		//	slog.Error("join failed: %v", err)
		//}
		slog.Info("Join complete. Restart in normal mode with: ./app -config config.yaml")
		return
	}

	// Normal mode: load config and run.
	cfg, err := config.LoadConfig(*configPath)
	if err != nil {
		slog.Error("failed to load config: %v", "err", err)
		os.Exit(1)
	}

	logFile, err := os.OpenFile(cfg.Logging.Path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		slog.Error("failed to open log file", "error", err)
		os.Exit(1)
	}
	defer func(logFile *os.File) {
		err := logFile.Close()
		if err != nil {
			os.Exit(1)
		}
	}(logFile)

	slog.SetDefault(slog.New(slog.NewJSONHandler(logFile, nil)))

	//TODO: add context and signal handling?
	err = api.StartServer(cfg)
	if err != nil {
		slog.Error("failed to start server: %v", "err", err)
		return
	}
}
