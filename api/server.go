package api

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/Crowley723/proxmox-node-monitor/providers"
)

func StartServer(ctx *providers.AppContext) error {
	cert, err := tls.LoadX509KeyPair(ctx.Config.Cluster.NodeCertPath(""), ctx.Config.Cluster.NodeKeyPath(""))
	if err != nil {
		return err
	}

	caCert, err := os.ReadFile(ctx.Config.Cluster.CACertPath(""))
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

	mux.HandleFunc("GET /ca.crt", providers.Wrap(handleCACertGET))
	mux.HandleFunc("GET /jwks.json", providers.Wrap(handleJWKSPublicKeyGET))
	mux.HandleFunc("GET /crl", providers.Wrap(handleCRLGET))
	mux.HandleFunc("POST /join", providers.Wrap(handleJoinPOST))
	mux.HandleFunc("GET /config", RequireMTLS(caCertPool, handleConfigGET))

	handler := providers.AppContextMiddleware(ctx)(mux)

	address := fmt.Sprintf(":%d", ctx.Config.Mesh.Port)

	server := &http.Server{
		Addr:      address,
		TLSConfig: tlsConfig,
		Handler:   handler,
	}

	ctx.Logger.Info("Listening on address", "addr", address)

	done := make(chan error, 1)

	go func() {
		if err := server.ListenAndServeTLS("", ""); err != nil && !errors.Is(err, http.ErrServerClosed) {
			done <- err
		}
		done <- nil
	}()

	<-ctx.Done()
	ctx.Logger.Info("Shutting down server")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := server.Shutdown(shutdownCtx); err != nil {
		ctx.Logger.Error("graceful shutdown failed", "err", err)
		return err
	}

	return <-done
}
