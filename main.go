package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/Crowley723/proxmox-node-monitor/api"
	"github.com/Crowley723/proxmox-node-monitor/config"
	"github.com/Crowley723/proxmox-node-monitor/mesh"
)

func main() {
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stdout, nil)))

	var (
		joinAddr          = flag.String("join", "", "join an existing cluster (address of keymaster node)")
		joinToken         = flag.String("join-token", "", "token for joining")
		configPath        = flag.String("config", "config.yaml", "config file path")
		certDir           = flag.String("cert-dir", "/etc/mesh-app/certs", "directory for cert/key files")
		bootstrapMode     = flag.Bool("bootstrap", false, "bootstrap a new cluster (first node only)")
		generateToken     = flag.Bool("generate-token", false, "generate a new join token (keymaster only)")
		tokenNodeHostname = flag.String("token-node-hostname", "", "hostname for the new node (used for host validation)")
		tokenExpiry       = flag.Duration("token-expiry", 24*time.Hour, "token expiry duration")
		verifyToken       = flag.Bool("verify-token", false, "verify the token")
		tokenValue        = flag.String("token", "", "token value")
	)
	flag.Parse()

	// validates join jwt tokens.
	if *verifyToken {
		validateJoinToken(configPath, tokenValue, tokenNodeHostname)
		return
	}

	// Generates a join jwt token for a specific hostname.
	if *generateToken {
		generateJoinToken(configPath, tokenNodeHostname, tokenExpiry)
		return
	}

	// Bootstrap first node: generate CA, node cert, and keypair.
	if *bootstrapMode {
		bootstrap(configPath, certDir)
		return
	}

	// Join additional nodes: generate tls cert, get it signed, pull config from cluster.
	if *joinAddr != "" {
		join(configPath, joinAddr, certDir, joinToken)
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

	logger := slog.New(slog.NewJSONHandler(logFile, nil))
	slog.SetDefault(logger)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigChan
		logger.Info("Received shutdown signal")
		cancel()
	}()

	err = api.StartServer(ctx, cfg, logger)
	if err != nil {
		logger.Error("failed to start server", "err", err)
		return
	}
}

func validateJoinToken(configPath *string, tokenValue *string, tokenNodeHostname *string) {
	if *tokenValue == "" {
		slog.Error("--token required with --verify-token")
		os.Exit(1)
	}

	if *tokenNodeHostname == "" {
		slog.Error("--token-node-hostname required with --verify-token")
		os.Exit(1)
	}

	cfg, err := config.LoadConfig(*configPath)
	if err != nil {
		slog.Error("failed to load config", "err", err)
		os.Exit(1)
	}

	_, err = mesh.ValidateJoinToken(cfg, *tokenNodeHostname, *tokenValue)
	if err != nil {
		slog.Error("failed to verify token", "err", err)
		os.Exit(1)
	}

	fmt.Println("Token is valid")
}

func generateJoinToken(configPath *string, tokenNodeHostname *string, tokenExpiry *time.Duration) {
	if *tokenNodeHostname == "" {
		slog.Error("--token-node-hostname required with --generate-token")
		os.Exit(1)
	}
	cfg, err := config.LoadConfig(*configPath)
	if err != nil {
		slog.Error("failed to load config", "err", err)
		os.Exit(1)
	}
	token, err := mesh.GenerateJoinToken(cfg, *tokenNodeHostname, *tokenExpiry)
	if err != nil {
		slog.Error("failed to generate token", "err", err)
		os.Exit(1)
	}
	fmt.Println(token)
}

func bootstrap(configPath *string, certDir *string) {
	cfg, err := config.LoadConfig(*configPath)
	if err != nil {
		slog.Error("failed to load config", "err", err)
	}

	if err := mesh.Bootstrap(cfg, *certDir); err != nil {
		slog.Error("bootstrap failed", "err", err)
		return
	}
	slog.Info("Bootstrap Complete", "config", *configPath, "certs", *certDir)
}

func join(configPath *string, joinAddr *string, certDir *string, joinToken *string) {
	if *joinToken == "" {
		slog.Error("join-token required when using -join")
	}
	//if err := mesh.Join(*joinAddr, *joinToken, *configPath, *certDir); err != nil {
	//	slog.Error("join failed: %v", err)
	//}
	slog.Info("Join complete. Restart in normal mode with: ./app -config config.yaml")
	return
}
