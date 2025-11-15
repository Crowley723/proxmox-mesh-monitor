package config

import (
	"path/filepath"
)

// CACertPath Returns the path for the CA public certificate
func (c *ClusterConfig) CACertPath(dir string) string {
	if dir == "" {
		return filepath.Join(c.CertDir, constCACertName)
	}
	return filepath.Join(dir, constCACertName)
}

// CAKeyPath returns the path for the CA private key use to sign certs for all nodes.
func (c *ClusterConfig) CAKeyPath(dir string) string {
	if dir == "" {
		return filepath.Join(c.CertDir, constCAKeyName)
	}
	return filepath.Join(dir, constCAKeyName)
}

// NodeCertPath returns the path for the current node's certificate
func (c *ClusterConfig) NodeCertPath(dir string) string {
	if dir == "" {
		return filepath.Join(c.CertDir, constNodeCertName)
	}
	return filepath.Join(dir, constNodeCertName)
}

// NodeKeyPath returns the path for the current node's private key
func (c *ClusterConfig) NodeKeyPath(dir string) string {
	if dir == "" {
		return filepath.Join(c.CertDir, constNodeKeyName)
	}
	return filepath.Join(dir, constNodeKeyName)
}

// JWTSigningKeyPath returns the path for the key used to sign join tokens.
func (c *ClusterConfig) JWTSigningKeyPath(dir string) string {
	if dir == "" {
		return filepath.Join(c.CertDir, constJWTSigningKeyName)
	}
	return filepath.Join(dir, constJWTSigningKeyName)
}
