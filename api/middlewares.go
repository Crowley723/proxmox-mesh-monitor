package api

import (
	"crypto/x509"
	"net/http"
	"time"
)

func RequireMTLSMiddleware(caCertPool *x509.CertPool) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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

			next.ServeHTTP(w, r)
		})
	}
}
