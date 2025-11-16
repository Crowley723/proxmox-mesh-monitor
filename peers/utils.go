package peers

import (
	"net/http"
	"strings"
)

func GetClientIP(r *http.Request, trustedProxies []string, certPath string) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		clientIP := strings.Split(xff, ",")[0]
		clientIP = strings.TrimSpace(clientIP)

		remoteIP := strings.Split(r.RemoteAddr, ":")[0]
		if isTrusted(remoteIP, trustedProxies, certPath) {
			return clientIP
		}
	}

	return strings.Split(r.RemoteAddr, ":")[0]
}

func isTrusted(ip string, trustedProxies []string, certPath string) bool {
	for _, trusted := range trustedProxies {
		if ip == trusted {
			return true
		}
	}

	reg, err := LoadRegistry(certPath)
	if err != nil {
		return false
	}

	for _, peer := range reg.Peers {
		peerIP := strings.Split(peer.Address, ":")[0]
		if ip == peerIP {
			return true
		}
	}

	return false
}
