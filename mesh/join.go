package mesh

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/Crowley723/proxmox-node-monitor/config"
	"github.com/Crowley723/proxmox-node-monitor/peers"
	"github.com/Crowley723/proxmox-node-monitor/providers"
	"github.com/Crowley723/proxmox-node-monitor/utils"
	"gopkg.in/yaml.v3"
)

func Join(ctx context.Context, joinAddr, joinToken, configFile, certsDir string) error {
	caCertBytes, err := fetchCACert(ctx, joinAddr)
	if err != nil {
		return fmt.Errorf("failed to fetch CA cert: %w", err)
	}

	//Create Certs directory
	err = os.MkdirAll(certsDir, 0700)
	if err != nil {
		return fmt.Errorf("unable to create certificate directory: %v", err)
	}

	err = writeCertificateFile(filepath.Join(certsDir, config.ConstCACertName), caCertBytes)
	if err != nil {
		return fmt.Errorf("failed to write CA cert: %w", err)
	}

	err = generateNodeKey(certsDir)
	if err != nil {
		return fmt.Errorf("error generating node key: %v", err)
	}

	csrBytes, err := generateCSR(certsDir)
	if err != nil {
		return fmt.Errorf("failed to generate CSR: %w", err)
	}

	response, err := sendJoinRequest(ctx, joinAddr, joinToken, csrBytes, caCertBytes)
	if err != nil {
		return fmt.Errorf("failed to join mesh: %w", err)
	}

	var joinResp struct {
		Certificate string        `json:"certificate"`
		Peers       interface{}   `json:"peers"`
		Config      config.Config `json:"config"`
	}

	if err := json.Unmarshal(response, &joinResp); err != nil {
		return fmt.Errorf("failed to decode join response: %w", err)
	}

	certBytes, err := base64.StdEncoding.DecodeString(joinResp.Certificate)
	if err != nil {
		return fmt.Errorf("failed to decode certificate: %w", err)
	}

	err = writeCertificate(certsDir, certBytes)
	if err != nil {
		return fmt.Errorf("failed to write certificate: %w", err)
	}

	finalConfig := joinResp.Config

	// Apply CLI overrides
	//if cliOverrides != nil {
	//	if cliOverrides.Monitor != config.DefaultMonitorConfig {
	//		finalConfig.Monitor = cliOverrides.Monitor
	//	}
	//	if cliOverrides.Mesh != config.DefaultMeshConfig {
	//		finalConfig.Mesh = cliOverrides.Mesh
	//	}
	//	if cliOverrides.Cluster.CertDir != "" {
	//		finalConfig.Cluster.CertDir = cliOverrides.Cluster.CertDir
	//	}
	//	if cliOverrides.Logging.Path != "" {
	//		finalConfig.Logging.Path = cliOverrides.Logging.Path
	//	}
	//}

	if finalConfig.Logging.Path == "" {
		finalConfig.Logging.Path = "app.log"
	}

	if err := writeConfigFile(configFile, &finalConfig); err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}

	return nil
}

func generateNodeKey(certsDir string) error {
	nodeKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("error generating node key: %v", err)
	}

	//Create Certs directory
	err = os.MkdirAll(certsDir, 0700)
	if err != nil {
		return fmt.Errorf("unable to create certificate directory: %v", err)
	}

	nodeKeyBytes, err := x509.MarshalPKCS8PrivateKey(nodeKey)
	if err != nil {
		return fmt.Errorf("error marshalling node key: %v", err)
	}

	//Write Node Key to disk
	err = writePrivateKeyFile(filepath.Join(certsDir, config.ConstNodeKeyName), nodeKeyBytes)
	if err != nil {
		return fmt.Errorf("error writing node key file: %v", err)
	}
	return nil
}

func generateCSR(certsDir string) (csr []byte, err error) {
	hostname := utils.GetHostname()

	nodeKeyPath := filepath.Join(certsDir, config.ConstNodeKeyName)
	nodeKeyBytes, err := os.ReadFile(nodeKeyPath)
	if err != nil {
		return nil, fmt.Errorf("unable to read node key: %s", err)
	}

	block, _ := pem.Decode(nodeKeyBytes)
	if block == nil {
		return nil, fmt.Errorf("failed to decode signing key PEM")
	}

	privateKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %w", err)
	}

	csrTemplate := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: hostname,
		},
		SignatureAlgorithm: x509.ECDSAWithSHA384,
	}

	csrBytes, err := x509.CreateCertificateRequest(rand.Reader, csrTemplate, privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create CSR: %w", err)
	}

	csrPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csrBytes,
	})

	return csrPEM, nil
}

func fetchCACert(ctx context.Context, joinAddr string) ([]byte, error) {
	if !strings.Contains(joinAddr, "://") {
		joinAddr = fmt.Sprintf("https://%s:8443", joinAddr)
	}

	baseURL := strings.TrimSuffix(joinAddr, "/join")
	caCertURL := fmt.Sprintf("%s/ca.crt", baseURL)

	insecureClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
	}

	req, err := http.NewRequestWithContext(ctx, "GET", caCertURL, nil)
	if err != nil {
		return nil, fmt.Errorf("error creating CA cert request: %w", err)
	}

	resp, err := insecureClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("error fetching CA cert: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to fetch CA cert: status %d", resp.StatusCode)
	}

	return io.ReadAll(resp.Body)
}

func sendJoinRequest(ctx context.Context, joinAddr string, joinToken string, csrBytes []byte, caCertBytes []byte) ([]byte, error) {
	if !strings.Contains(joinAddr, "/join") {
		joinAddr = fmt.Sprintf("%s://%s:%d/join", "https", joinAddr, 8443)
	}

	caCertPool := x509.NewCertPool()
	if !caCertPool.AppendCertsFromPEM(caCertBytes) {
		return nil, fmt.Errorf("failed to parse CA cert")
	}

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs: caCertPool,
			},
		},
	}

	request, err := http.NewRequestWithContext(ctx, "POST", joinAddr, bytes.NewReader(csrBytes))
	if err != nil {
		return nil, fmt.Errorf("error creating join request: %w", err)
	}

	request.Header.Set("Content-Type", "application/octet-stream")
	request.Header.Set("Authorization", fmt.Sprintf("Bearer %s", joinToken))

	resp, err := client.Do(request)
	if err != nil {
		return nil, fmt.Errorf("error sending join request: %w", err)
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			fmt.Printf("error closing response body: %v\n", err)
		}
	}(resp.Body)

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("join request failed with status %d: %s", resp.StatusCode, string(body))
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("error reading response body: %w", err)
	}

	return body, nil
}

func ForwardJoinRequest(ctx *providers.AppContext, joinAddr string, joinToken string, csrBytes []byte) ([]byte, error) {
	if !strings.Contains(joinAddr, "/join") {
		joinAddr = fmt.Sprintf("%s://%s/join", "https", joinAddr)
	}

	request, err := http.NewRequestWithContext(ctx, "POST", joinAddr, bytes.NewReader(csrBytes))
	if err != nil {
		return nil, fmt.Errorf("error creating join request: %w", err)
	}

	thisNodeHostname, _ := os.Hostname()
	thisPeer, _ := peers.GetPeer(ctx.Config.Cluster.CertDir, thisNodeHostname)

	request.Header.Set("Content-Type", "application/octet-stream")
	request.Header.Set("Authorization", fmt.Sprintf("Bearer %s", joinToken))

	thisNodeIP, _, err := net.SplitHostPort(thisPeer.Address)
	if err != nil {
		return nil, fmt.Errorf("error getting peer address: %v", err)
	}

	if existingXFF := request.Header.Get("X-Forwarded-For"); existingXFF != "" {
		request.Header.Set("X-Forwarded-For", fmt.Sprintf("%s, %s", existingXFF, thisNodeIP))
	} else {
		clientIP := peers.GetClientIP(ctx.Request, ctx.Config.Cluster.TrustedProxies, ctx.Config.Cluster.CertDir)
		request.Header.Set("X-Forwarded-For", fmt.Sprintf("%s, %s", clientIP, thisNodeIP))
	}

	resp, err := http.DefaultClient.Do(request)
	if err != nil {
		return nil, fmt.Errorf("error sending join request: %w", err)
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			fmt.Printf("error closing response body: %v\n", err)
		}
	}(resp.Body)

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("join request failed with status %d: %s", resp.StatusCode, string(body))
	}

	return io.ReadAll(resp.Body)
}

func writeCertificate(certsDir string, certBytes []byte) error {
	block, _ := pem.Decode(certBytes)
	if block == nil {
		return fmt.Errorf("failed to decode certificate PEM")
	}

	return writeCertificateFile(filepath.Join(certsDir, config.ConstNodeCertName), block.Bytes)
}

func writeConfigFile(filePath string, cfg *config.Config) error {
	data, err := yaml.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	err = os.WriteFile(filePath, data, 0600)
	if err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}

	return nil
}
