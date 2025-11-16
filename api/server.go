package api

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/Crowley723/proxmox-node-monitor/config"
)

func StartServer(ctx context.Context, cfg *config.Config, logger *slog.Logger) error {
	cert, err := tls.LoadX509KeyPair(cfg.Cluster.NodeCertPath(""), cfg.Cluster.NodeKeyPath(""))
	if err != nil {
		return err
	}

	caCert, err := os.ReadFile(cfg.Cluster.CACertPath(""))
	if err != nil {
		return err
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.RequestClientCert,
		ClientCAs:    caCertPool,
	}

	mux := http.NewServeMux()

	appCtx := NewAppContext(ctx, cfg, logger)

	mux.HandleFunc("GET /ca.crt", Wrap(handleCACertGET))
	mux.HandleFunc("GET /jwks.json", Wrap(handleJWKSPublicKeyGET))
	mux.HandleFunc("GET /crl", Wrap(handleCRLGET))
	mux.HandleFunc("POST /join", Wrap(handleJoinPOST))
	mux.HandleFunc("POST /sign-csr", RequireMTLS(caCertPool, handleSignCSR))
	mux.HandleFunc("GET /config", RequireMTLS(caCertPool, handleConfigGET))

	handler := AppContextMiddleware(appCtx)(mux)

	address := fmt.Sprintf(":%d", cfg.Mesh.Port)

	server := &http.Server{
		Addr:      address,
		TLSConfig: tlsConfig,
		Handler:   handler,
	}

	logger.Info("Listening on address", "addr", address)

	done := make(chan error, 1)

	go func() {
		if err := server.ListenAndServeTLS("", ""); err != nil && !errors.Is(err, http.ErrServerClosed) {
			done <- err
		}
		done <- nil
	}()

	<-ctx.Done()
	logger.Info("Shutting down server")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := server.Shutdown(shutdownCtx); err != nil {
		logger.Error("graceful shutdown failed", "err", err)
		return err
	}

	return <-done
}
