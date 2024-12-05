package hashmon

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
	"golang.org/x/time/rate"
)

// Config holds the hashmon-specific configuration.
type Config struct {
	InputFilePath    string
	PollInterval     time.Duration
	CheckInterval    time.Duration
	VirusTotalAPIKey string
	CuckooBaseURL    string
	CuckooAPIKey     string
	RateLimits       []RateLimitConfig
}

// RateLimitConfig defines rate limiting settings per API.
type RateLimitConfig struct {
	APIName string
	Rate    rate.Limit // Requests per second
	Burst   int        // Maximum burst size
}

// LoadConfig loads hashmon-specific configuration from environment variables.
func LoadConfig() (*Config, error) {
	inputFilePath := os.Getenv("INPUT_FILE_PATH")
	if inputFilePath == "" {
		return nil, fmt.Errorf("INPUT_FILE_PATH environment variable is required")
	}

	pollIntervalStr := os.Getenv("POLL_INTERVAL_MINUTES")
	pollInterval, err := strconv.Atoi(pollIntervalStr)
	if err != nil || pollInterval <= 0 {
		pollInterval = 5 // Default to 5 minutes
		logrus.Infof("Invalid or missing POLL_INTERVAL_MINUTES. Defaulting to %d minutes.", pollInterval)
	}

	checkIntervalStr := os.Getenv("CHECK_INTERVAL_MINUTES")
	checkInterval, err := strconv.Atoi(checkIntervalStr)
	if err != nil || checkInterval <= 0 {
		checkInterval = 60 // Default to 60 minutes
		logrus.Infof("Invalid or missing CHECK_INTERVAL_MINUTES. Defaulting to %d minutes.", checkInterval)
	}

	rateLimitsStr := os.Getenv("RATE_LIMITS")
	rateLimits, err := parseRateLimits(rateLimitsStr)
	if err != nil {
		return nil, fmt.Errorf("failed to parse RATE_LIMITS: %v", err)
	}

	return &Config{
		InputFilePath:    inputFilePath,
		PollInterval:     time.Duration(pollInterval) * time.Minute,
		CheckInterval:    time.Duration(checkInterval) * time.Minute,
		VirusTotalAPIKey: os.Getenv("VT_API_KEY"),
		CuckooBaseURL:    os.Getenv("CUCKOO_BASE_URL"),
		CuckooAPIKey:     os.Getenv("CUCKOO_API_KEY"),
		RateLimits:       rateLimits,
	}, nil
}

// parseRateLimits parses rate limits from a comma-separated list of API:rate:burst.
func parseRateLimits(input string) ([]RateLimitConfig, error) {
	var rateLimits []RateLimitConfig
	if input == "" {
		return rateLimits, nil // No rate limits defined
	}
	entries := strings.Split(input, ",")
	for _, entry := range entries {
		parts := strings.Split(entry, ":")
		if len(parts) != 3 {
			return nil, fmt.Errorf("invalid rate limit entry: %s", entry)
		}
		apiName := strings.TrimSpace(parts[0])
		rateValue, err := strconv.ParseFloat(strings.TrimSpace(parts[1]), 64)
		if err != nil {
			return nil, fmt.Errorf("invalid rate value in entry '%s': %v", entry, err)
		}
		burstValue, err := strconv.Atoi(strings.TrimSpace(parts[2]))
		if err != nil {
			return nil, fmt.Errorf("invalid burst value in entry '%s': %v", entry, err)
		}
		rateLimits = append(rateLimits, RateLimitConfig{
			APIName: apiName,
			Rate:    rate.Limit(rateValue), // Requests per second
			Burst:   burstValue,
		})
	}
	return rateLimits, nil
}
