package mesh

import (
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"time"

	"github.com/Crowley723/proxmox-node-monitor/providers"
)

func SignCSR(ctx *providers.AppContext, csr *x509.CertificateRequest, ipAddress string) ([]byte, error) {
	caKeyBytes, err := os.ReadFile(ctx.Config.Cluster.CAKeyPath(""))
	if err != nil {
		return nil, fmt.Errorf("failed to read CA key: %w", err)
	}

	block, _ := pem.Decode(caKeyBytes)
	if block == nil {
		return nil, fmt.Errorf("failed to decode CA key PEM")
	}

	caPrivateKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse CA private key: %w", err)
	}

	caCertBytes, err := os.ReadFile(ctx.Config.Cluster.CACertPath(""))
	if err != nil {
		return nil, fmt.Errorf("failed to read CA cert: %w", err)
	}

	block, _ = pem.Decode(caCertBytes)
	if block == nil {
		return nil, fmt.Errorf("failed to decode CA cert PEM")
	}

	caCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse CA cert: %w", err)
	}

	certTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      csr.Subject,
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(1, 0, 0),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		DNSNames:     csr.DNSNames,
		IPAddresses:  []net.IP{net.ParseIP(ipAddress)},
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, certTemplate, caCert, csr.PublicKey, caPrivateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create certificate: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	})

	return certPEM, nil
}
