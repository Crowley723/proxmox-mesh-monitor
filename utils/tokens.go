package utils

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"

	"github.com/golang-jwt/jwt/v5"
)

func GetSigningMethodFromKey(key interface{}) jwt.SigningMethod {
	switch key.(type) {
	case *rsa.PrivateKey:
		return jwt.SigningMethodRS256
	case *ecdsa.PrivateKey:
		return jwt.SigningMethodES256
	case ed25519.PrivateKey:
		return jwt.SigningMethodEdDSA
	default:
		return jwt.SigningMethodES256
	}
}

func GenerateKeyID(pubKey interface{}) string {
	pubKeyBytes, _ := x509.MarshalPKIXPublicKey(pubKey)
	hash := sha256.Sum256(pubKeyBytes)
	return hex.EncodeToString(hash[:])[:16]
}

func GetAlgorithmFromKey(key interface{}) string {
	switch key.(type) {
	case *rsa.PublicKey:
		return "RS256"
	case *ecdsa.PublicKey:
		return "ES256"
	case ed25519.PublicKey:
		return "EdDSA"
	default:
		return "RS256"
	}
}
