package notifications

import (
	"fmt"
	"os"
	"strings"
)

// NotificationConfig holds the notification-related configuration.
type NotificationConfig struct {
	ShoutrrrURLs []string
}

// LoadNotificationConfig loads notification configuration from environment variables.
func LoadNotificationConfig() (*NotificationConfig, error) {
	shoutrrrURLsStr := os.Getenv("SHOUTRRR_URLS")
	if shoutrrrURLsStr == "" {
		return nil, fmt.Errorf("SHOUTRRR_URLS environment variable is required for notifications")
	}

	shoutrrrURLs := parseShoutrrrURLs(shoutrrrURLsStr)

	return &NotificationConfig{
		ShoutrrrURLs: shoutrrrURLs,
	}, nil
}

// parseShoutrrrURLs parses a comma-separated list of Shoutrrr URLs.
func parseShoutrrrURLs(urls string) []string {
	var result []string
	for _, url := range strings.Split(urls, ",") {
		trimmed := strings.TrimSpace(url)
		if trimmed != "" {
			result = append(result, trimmed)
		}
	}
	return result
}
