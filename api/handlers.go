package api

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"os"

	"github.com/Crowley723/proxmox-node-monitor/utils"
	"github.com/go-jose/go-jose/v4"
)

// handleCACertGET returns the CA certificate
func handleCACertGET(ctx *AppContext) {
	bytes, err := os.ReadFile(ctx.Config.Cluster.CACertPath(""))
	if err != nil {
		ctx.Logger.Error("failed to read CA cert", "err", err)
		ctx.SetJSONError(http.StatusInternalServerError, "Internal server error")
		return
	}

	ctx.WriteBytes(http.StatusOK, "application/x-pem-file", bytes)
}

// handleCACertGET returns the CA certificate
func handleJWKSPublicKeyGET(ctx *AppContext) {
	bytes, err := os.ReadFile(ctx.Config.Cluster.JWTSigningPublicKeyPath(""))
	if err != nil {
		ctx.Logger.Error("failed to read jwt public key", "err", err)
		ctx.SetJSONError(http.StatusInternalServerError, "Internal server error")
		return
	}

	block, _ := pem.Decode(bytes)
	if block == nil {
		ctx.Logger.Error("failed to decode jwt public key")
		ctx.SetJSONError(http.StatusInternalServerError, "Internal server error")
		return
	}

	var key interface{}
	switch block.Type {
	case "PRIVATE KEY", "EC PRIVATE KEY":
		ctx.Logger.Error("decoded private key, canceling request")
		ctx.SetJSONError(http.StatusInternalServerError, "Internal server error")
		return
	case "PUBLIC KEY":
		pubKey, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			ctx.Logger.Error("failed to parse jwt public key", "err", err)
			ctx.SetJSONError(http.StatusInternalServerError, "Internal server error")
			return
		}
		key = pubKey
	default:
		ctx.Logger.Error("unknown jwt public key type", "type", block.Type)
		ctx.SetJSONError(http.StatusInternalServerError, "Internal server error")
		return
	}

	keyID := utils.GenerateKeyID(key)

	jwk := jose.JSONWebKey{
		Key:       key,
		KeyID:     keyID,
		Algorithm: utils.GetAlgorithmFromKey(key),
		Use:       "sig",
	}

	jwks := jose.JSONWebKeySet{
		Keys: []jose.JSONWebKey{jwk},
	}

	ctx.Response.Header().Set("Cache-Control", "public, max-age=3600")
	ctx.WriteJSON(http.StatusOK, jwks)
}

// handleCRLGET returns the certificate revocation list
func handleCRLGET(ctx *AppContext) {
	ctx.WriteText(http.StatusOK, "CRL URL")
	//ctx.WriteBytes(http.StatusOK, "application/pkcs7-crl", bytes)
}

// handleJoinPOST handles node join requests
func handleJoinPOST(ctx *AppContext) {
	// Check if joining is enabled
	if !ctx.Config.Mesh.JoinEnabled {
		http.Error(ctx.Response, "Node joining is disabled", http.StatusForbidden)
		return
	}

	// TODO: Implement join logic
	// 1. Validate join token
	// 2. Generate node certificate
	// 3. Add node to cluster

	ctx.Response.Header().Set("Content-Type", "application/json")
	ctx.Response.WriteHeader(http.StatusOK)
	json.NewEncoder(ctx.Response).Encode(map[string]string{
		"status": "join request received",
	})
}

// handleSignCSR handles certificate signing requests
func handleSignCSR(ctx *AppContext) {
	// TODO: Implement CSR signing logic
	// 1. Parse CSR from request body
	// 2. Validate CSR
	// 3. Sign with CA key
	// 4. Return signed certificate

	_ = ctx.Config // Suppress unused variable warning until implementation is complete
	ctx.Response.Header().Set("Content-Type", "application/x-pem-file")
	ctx.Response.WriteHeader(http.StatusOK)
	ctx.Response.Write([]byte("Signed certificate placeholder"))
}

// handleConfig returns the cluster configuration (legacy handler for compatibility)
func handleConfigGET(ctx *AppContext) {
	ctx.Response.Header().Set("Content-Type", "application/json")
	// TODO: Return actual configuration
	ctx.Response.Write([]byte(`{"status": "config endpoint"}`))
}
