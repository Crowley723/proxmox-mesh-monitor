package utils

import (
	"log"
	"os"
)

func GetHostname() string {
	hostname := os.Getenv("HOSTNAME")
	if hostname == "" {
		osHostname, err := os.Hostname()
		if err != nil {
			log.Printf("Error getting hostname: %v", err)
			return "unknown"
		}
		hostname = osHostname
	}

	return hostname
}
