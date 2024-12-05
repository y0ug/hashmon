package webserver

import (
	"os"
	"strings"
)

// WebserverConfig holds the configuration for the webserver.
type WebserverConfig struct {
	ListenTo           string
	CorsAllowedOrigins []string
}

// NewWebserverConfig initializes the webserver configuration from environment variables.
func NewWebserverConfig() (*WebserverConfig, error) {
	config := &WebserverConfig{}

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	config.ListenTo = ":" + port

	corsAllowedOrigins := os.Getenv("CORS_ALLOWED_ORIGINS")
	if corsAllowedOrigins != "" {
		config.CorsAllowedOrigins = strings.Split(corsAllowedOrigins, ",")
	}

	return config, nil
}
