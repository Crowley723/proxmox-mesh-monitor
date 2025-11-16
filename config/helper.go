package config

import (
	"path/filepath"
)

// CACertPath Returns the path for the CA public certificate
func (c *ClusterConfig) CACertPath(dir string) string {
	if dir == "" {
		return filepath.Join(c.CertDir, ConstCACertName)
	}
	return filepath.Join(dir, ConstCACertName)
}

// CAKeyPath returns the path for the CA private key use to sign certs for all nodes.
func (c *ClusterConfig) CAKeyPath(dir string) string {
	if dir == "" {
		return filepath.Join(c.CertDir, ConstCAKeyName)
	}
	return filepath.Join(dir, ConstCAKeyName)
}

// NodeCertPath returns the path for the current node's certificate
func (c *ClusterConfig) NodeCertPath(dir string) string {
	if dir == "" {
		return filepath.Join(c.CertDir, ConstNodeCertName)
	}
	return filepath.Join(dir, ConstNodeCertName)
}

// NodeKeyPath returns the path for the current node's private key
func (c *ClusterConfig) NodeKeyPath(dir string) string {
	if dir == "" {
		return filepath.Join(c.CertDir, ConstNodeKeyName)
	}
	return filepath.Join(dir, ConstNodeKeyName)
}

// JWTSigningKeyPath returns the path for the private key used to sign join tokens.
func (c *ClusterConfig) JWTSigningKeyPath(dir string) string {
	if dir == "" {
		return filepath.Join(c.CertDir, ConstJWTSigningKeyName)
	}
	return filepath.Join(dir, ConstJWTSigningKeyName)
}

// JWTSigningPublicKeyPath returns the path for the public key used to sign join tokens.
func (c *ClusterConfig) JWTSigningPublicKeyPath(dir string) string {
	if dir == "" {
		return filepath.Join(c.CertDir, ConstJWTSigningPublicKeyName)
	}
	return filepath.Join(dir, ConstJWTSigningPublicKeyName)
}
