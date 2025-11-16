package mesh

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/Crowley723/proxmox-node-monitor/config"
	"github.com/Crowley723/proxmox-node-monitor/utils"
	"github.com/golang-jwt/jwt/v5"
)

func GenerateJoinToken(cfg *config.Config, nodeID string, expiry time.Duration) (string, error) {
	signingKeyPath := filepath.Join(cfg.Cluster.JWTSigningKeyPath(""))
	signingKeyBytes, err := os.ReadFile(signingKeyPath)
	if err != nil {
		return "", fmt.Errorf("failed to read signing key: %w", err)
	}

	block, _ := pem.Decode(signingKeyBytes)
	if block == nil {
		return "", fmt.Errorf("failed to decode signing key PEM")
	}

	var key interface{}
	switch block.Type {
	case "PRIVATE KEY", "RSA PRIVATE KEY", "EC PRIVATE KEY":
		privateKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return "", fmt.Errorf("failed to parse private key: %w", err)
		}
		key = privateKey
	default:
		return "", fmt.Errorf("unknown key type: %s", block.Type)
	}

	if expiry.Seconds() == 0 {
		expiry = 30 * time.Minute
	}

	claims := jwt.MapClaims{
		"node_id": nodeID,
		"exp":     time.Now().Add(expiry).Unix(),
		"iat":     time.Now().Unix(),
	}

	signingMethod := utils.GetSigningMethodFromKey(key)
	token := jwt.NewWithClaims(signingMethod, claims)

	tokenString, err := token.SignedString(key)
	if err != nil {
		return "", fmt.Errorf("failed to sign token: %w", err)
	}

	return tokenString, nil
}

func ValidateJoinToken(cfg *config.Config, nodeID string, tokenString string) (valid bool, err error) {
	publicKeyPath := filepath.Join(cfg.Cluster.JWTSigningPublicKeyPath(""))
	publicKeyBytes, err := os.ReadFile(publicKeyPath)
	if err != nil {
		return false, fmt.Errorf("failed to read public key: %w", err)
	}

	block, _ := pem.Decode(publicKeyBytes)
	if block == nil {
		return false, fmt.Errorf("failed to decode public key PEM")
	}

	var key interface{}
	switch block.Type {
	case "PUBLIC KEY":
		publicKey, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return false, fmt.Errorf("failed to parse public key: %w", err)
		}
		key = publicKey
	default:
		return false, fmt.Errorf("unknown key type: %s", block.Type)
	}

	token, err := jwt.ParseWithClaims(tokenString, jwt.MapClaims{}, func(token *jwt.Token) (interface{}, error) {
		if utils.GetSigningMethodFromKey(key) != token.Method {
			return nil, fmt.Errorf("invalid signing method: expected %v, got %v", utils.GetSigningMethodFromKey(key), token.Method)
		}
		return key, nil
	})

	if err != nil {
		return false, fmt.Errorf("failed to parse token: %w", err)
	}

	if !token.Valid {
		return false, fmt.Errorf("invalid token")
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return false, fmt.Errorf("invalid token claims")
	}

	tokenNodeID, ok := (claims)["node_id"].(string)
	if !ok {
		return false, fmt.Errorf("invalid token or token node_id claim")
	}

	if tokenNodeID != nodeID {
		return false, fmt.Errorf("node_id mismatch: expected %s, got %s", nodeID, tokenNodeID)
	}

	return true, nil
}
