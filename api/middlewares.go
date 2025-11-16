package api

import (
	"crypto/x509"
	"net/http"
	"time"

	"github.com/Crowley723/proxmox-node-monitor/providers"
)

// RequireMTLS wraps a handler requiring mutual TLS
func RequireMTLS(caCertPool *x509.CertPool, handler providers.AppHandler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		appCtx := providers.GetAppContext(r)
		if len(r.TLS.PeerCertificates) == 0 {
			http.Error(w, "Client certificate required", http.StatusUnauthorized)
			return
		}

		cert := r.TLS.PeerCertificates[0]

		if cert.NotAfter.Before(time.Now()) {
			http.Error(w, "Client certificate expired", http.StatusUnauthorized)
			return
		}

		if cert.NotBefore.After(time.Now()) {
			http.Error(w, "Client certificate not yet valid", http.StatusUnauthorized)
			return
		}

		if len(cert.ExtKeyUsage) == 0 {
			http.Error(w, "Client certificate missing extended key usage", http.StatusUnauthorized)
			return
		}

		//TODO: implement cert revocation validation.
		_, err := cert.Verify(x509.VerifyOptions{
			Roots: caCertPool,
		})
		if err != nil {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}

		handler(appCtx)
	}
}
