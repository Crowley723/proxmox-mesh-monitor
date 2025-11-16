package mesh

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"log/slog"
	"math/big"
	"net"
	"os"
	"time"

	"github.com/Crowley723/proxmox-node-monitor/config"
	"github.com/Crowley723/proxmox-node-monitor/peers"
)

// Bootstrap initializes the PKI required to sign mTLS certificates for other nodes. It creates the root CA for the cluster as well as the certificate for the current keymaster node.
func Bootstrap(cfg *config.Config, certsDir string, address string) error {
	err := peers.InitializeRegistry(certsDir, address)
	if err != nil {
		return fmt.Errorf("error initializing registry %v", err)
	}

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("error generating CA key: %v", err)
	}

	caCertTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   "proxmox-monitor-mesh-ca",
			Organization: []string{"Homelab"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
	}

	caCertBytes, err := x509.CreateCertificate(rand.Reader, caCertTemplate, caCertTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		return fmt.Errorf("error creating CA certificate: %v", err)
	}

	nodeKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("error generating node key: %v", err)
	}

	caCert, err := x509.ParseCertificate(caCertBytes)

	nodeCertTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			CommonName: "keymaster",
		},
		NotBefore:          time.Now(),
		NotAfter:           time.Now().AddDate(10, 0, 0),
		KeyUsage:           x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:        []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		SignatureAlgorithm: x509.ECDSAWithSHA384,
		DNSNames:           []string{"localhost", "keymaster"},
		IPAddresses:        []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1"), net.ParseIP(address)},
	}

	nodeCertBytes, err := x509.CreateCertificate(rand.Reader, nodeCertTemplate, caCert, &nodeKey.PublicKey, caKey)

	caKeyBytes, err := x509.MarshalPKCS8PrivateKey(caKey)
	if err != nil {
		return fmt.Errorf("error marshalling CA key: %v", err)
	}

	//Create JWT Signing keypair
	jwtSigningKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("error generating jwt signing key: %v", err)
	}

	jwtSigningKeyBytes, err := x509.MarshalPKCS8PrivateKey(jwtSigningKey)
	if err != nil {
		return fmt.Errorf("error marshalling jwt private key: %v", err)
	}

	jwtSigningPublicKeyBytes, err := x509.MarshalPKIXPublicKey(&jwtSigningKey.PublicKey)
	if err != nil {
		return fmt.Errorf("error marshalling jwt public key: %v", err)
	}

	//Create Certs directory
	err = os.MkdirAll(certsDir, 0700)
	if err != nil {
		return fmt.Errorf("unable to create certificate directory: %v", err)
	}

	err = writePrivateKeyFile(cfg.Cluster.JWTSigningKeyPath(certsDir), jwtSigningKeyBytes)
	if err != nil {
		return fmt.Errorf("error writing jwt private key file: %v", err)
	}

	err = writePublicKeyFile(cfg.Cluster.JWTSigningPublicKeyPath(certsDir), jwtSigningPublicKeyBytes)
	if err != nil {
		return fmt.Errorf("error writing jwt public key file: %v", err)
	}

	// Write CA Key to disk
	err = writePrivateKeyFile(cfg.Cluster.CAKeyPath(certsDir), caKeyBytes)
	if err != nil {
		return fmt.Errorf("error writing CA key file: %v", err)
	}

	//Write CA Cert to disk
	err = writeCertificateFile(cfg.Cluster.CACertPath(certsDir), caCertBytes)
	if err != nil {
		return fmt.Errorf("error writing CA cert file: %v", err)
	}

	nodeKeyBytes, err := x509.MarshalPKCS8PrivateKey(nodeKey)
	if err != nil {
		return fmt.Errorf("error marshalling node key: %v", err)
	}

	//Write Node Key to disk
	err = writePrivateKeyFile(cfg.Cluster.NodeKeyPath(certsDir), nodeKeyBytes)
	if err != nil {
		return fmt.Errorf("error writing node key file: %v", err)
	}

	// Write Node Cert to disk
	err = writeCertificateFile(cfg.Cluster.NodeCertPath(certsDir), nodeCertBytes)
	if err != nil {
		return fmt.Errorf("error writing node cert file: %v", err)
	}

	return nil
}

// writeCertificateFile takes the bytes of a certificate and writes it to a file on disk at the specified path
func writeCertificateFile(filePath string, value []byte) error {
	f, err := os.OpenFile(filePath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("error opening file for writing: %v", err)
	}

	err = pem.Encode(f, &pem.Block{Type: constCertificateHeader, Bytes: value})
	if err != nil {
		return fmt.Errorf("error encoding data: %v", err)
	}

	err = f.Close()
	if err != nil {
		return fmt.Errorf("error closing file: %v", err)
	}

	return nil
}

// writePrivateKeyFile takes the bytes of a private key and writes it to a file on disk at the specified path.
func writePrivateKeyFile(filePath string, value []byte) error {
	f, err := os.OpenFile(filePath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("error opening file for writing: %v", err)
	}

	defer func(f *os.File) {
		err := f.Close()
		if err != nil {
			slog.Error("error closing node key file", "err", err)
		}
	}(f)

	err = pem.Encode(f, &pem.Block{Type: constPrivateKeyHeader, Bytes: value})
	if err != nil {
		return fmt.Errorf("error encoding key: %v", err)
	}

	return nil
}

// writePublicKeyFile takes the bytes of a public key and writes it to a file on disk at the specified path.
func writePublicKeyFile(filePath string, value []byte) error {
	f, err := os.OpenFile(filePath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("error opening file for writing: %v", err)
	}

	defer func(f *os.File) {
		err := f.Close()
		if err != nil {
			slog.Error("error closing node key file", "err", err)
		}
	}(f)

	err = pem.Encode(f, &pem.Block{Type: constPublicKeyHeader, Bytes: value})
	if err != nil {
		return fmt.Errorf("error encoding key: %v", err)
	}

	return nil
}
