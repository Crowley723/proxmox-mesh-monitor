package api

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	"github.com/Crowley723/proxmox-node-monitor/mesh"
	"github.com/Crowley723/proxmox-node-monitor/peers"
	"github.com/Crowley723/proxmox-node-monitor/providers"
	"github.com/Crowley723/proxmox-node-monitor/utils"
	"github.com/go-jose/go-jose/v4"
)

// handleCACertGET returns the CA certificate
func handleCACertGET(ctx *providers.AppContext) {
	bytes, err := os.ReadFile(ctx.Config.Cluster.CACertPath(""))
	if err != nil {
		ctx.Logger.Error("failed to read CA cert", "err", err)
		ctx.SetJSONError(http.StatusInternalServerError, "Internal server error")
		return
	}

	ctx.WriteBytes(http.StatusOK, "application/x-pem-file", bytes)
}

// handleCACertGET returns the CA certificate
func handleJWKSPublicKeyGET(ctx *providers.AppContext) {
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
func handleCRLGET(ctx *providers.AppContext) {
	ctx.WriteText(http.StatusOK, "CRL URL")
	//ctx.WriteBytes(http.StatusOK, "application/pkcs7-crl", bytes)
}

// handleJoinPOST handles node join requests
func handleJoinPOST(ctx *providers.AppContext) {
	if !ctx.Config.Mesh.JoinEnabled {
		http.Error(ctx.Response, "Node joining is disabled", http.StatusForbidden)
		return
	}

	token := ctx.Request.Header.Get("Authorization")
	if token == "" {
		ctx.SetJSONError(http.StatusUnauthorized, "Unauthorized")
		return
	}

	ok, claims, err := mesh.ValidateJoinToken(ctx.Config, strings.TrimPrefix(token, "Bearer "))
	if err != nil {
		ctx.Logger.Error("failed to validate join token", "err", err)
		ctx.SetJSONError(http.StatusUnauthorized, "Unauthorized")
		return
	}

	if !ok {
		ctx.SetJSONError(http.StatusUnauthorized, "Unauthorized")
		return
	}

	csrBytes, err := io.ReadAll(ctx.Request.Body)
	if err != nil {
		ctx.Logger.Error("failed to read CSR", "err", err)
		ctx.SetJSONError(http.StatusBadRequest, "Bad Request")
		return
	}

	block, _ := pem.Decode(csrBytes)
	if block == nil {
		ctx.Logger.Error("failed to decode CSR")
		ctx.SetJSONError(http.StatusBadRequest, "Bad Request")
		return
	}

	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		ctx.Logger.Error("failed to parse CSR", "err", err)
		ctx.SetJSONError(http.StatusBadRequest, "Bad Request")
		return
	}

	tokenID := (claims)["node_id"].(string)

	if csr.Subject.CommonName != tokenID {
		ctx.Logger.Error("CSR hostname doesn't match token", "expected", tokenID, "got", csr.Subject.CommonName)
		ctx.SetJSONError(http.StatusForbidden, "Forbidden")
		return
	}

	clientIP := peers.GetClientIP(ctx.Request, ctx.Config.Cluster.TrustedProxies, ctx.Config.Cluster.CertDir)
	clientAddress := fmt.Sprintf("%s:%d", clientIP, ctx.Config.Mesh.Port)

	var certBytes []byte
	if ctx.IsKeymaster {
		certBytes, err = mesh.SignCSR(ctx, csr, clientIP)
		if err != nil {
			ctx.Logger.Error("failed to sign CSR", "err", err)
			ctx.SetJSONError(http.StatusBadRequest, "Bad Request")
			return
		}
	} else {
		master, err := peers.GetKeymaster(ctx.Config.Cluster.CertDir)
		if err != nil {
			ctx.Logger.Error("failed to load peer registry", "err", err)
			ctx.SetJSONError(http.StatusInternalServerError, "Internal server error")
			return
		}

		certBytes, err = mesh.ForwardJoinRequest(ctx, token, master.Address, csrBytes)
		if err != nil {
			ctx.Logger.Error("keymaster failed to sign CSR", "err", err)
			ctx.SetJSONError(http.StatusBadRequest, "Bad Request")
			return
		}
	}

	newPeer := &peers.Peer{
		Hostname: csr.Subject.CommonName,
		Address:  clientAddress,
		Role:     peers.RoleMember,
	}

	err = peers.AddPeer(ctx.Config.Cluster.CertDir, *newPeer)
	if err != nil {
		ctx.Logger.Error("failed to add peer to registry", "err", err)
		ctx.SetJSONError(http.StatusInternalServerError, "Internal server error")
		return
	}

	peerReg, _ := peers.LoadRegistry(ctx.Config.Cluster.CertDir)

	configResp := ConfigResponse{
		Monitor: ctx.Config.Monitor,
		Mesh:    ctx.Config.Mesh,
		Cluster: ctx.Config.Cluster,
		Alert:   ctx.Config.Alert,
	}

	response := JoinResponse{
		Certificate: base64.StdEncoding.EncodeToString(certBytes),
		Peers:       peerReg.Peers,
		Config:      configResp,
	}

	ctx.Response.Header().Set("Content-Type", "application/json")
	ctx.WriteJSON(http.StatusOK, response)

}

// handleConfig returns the cluster configuration (legacy handler for compatibility)
func handleConfigGET(ctx *providers.AppContext) {
	ctx.Response.Header().Set("Content-Type", "application/json")
	// TODO: Return actual configuration
	ctx.Response.Write([]byte(`{"status": "config endpoint"}`))
}
