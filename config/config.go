package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/joho/godotenv"
	"github.com/sirupsen/logrus"
	"golang.org/x/time/rate"
)

// Config holds the application configuration.
type Config struct {
	InputFilePath    string
	PollInterval     time.Duration
	CheckInterval    time.Duration
	VirusTotalAPIKey string
	CuckooBaseURL    string
	CuckooAPIKey     string
	ShoutrrrURLs     []string
	RateLimits       []RateLimitConfig
	DatabaseType     string
	DatabasePath     string
}

type RateLimitConfig struct {
	APIName string
	Rate    rate.Limit // Requests per second
	Burst   int        // Maximum burst size
}

// LoadConfig loads configuration from environment variables and .env file.
func LoadConfig() (*Config, error) {
	// Load .env file if present
	err := godotenv.Load()
	if err != nil {
		logrus.Info("No .env file found or error loading it. Proceeding with environment variables.")
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
		logrus.Infof("Invalid or missing CHECK_INTERVAL_MINUTES. Defaulting to %d minutes.", pollInterval)
	}

	shoutrrrURLsStr := os.Getenv("SHOUTRRR_URLS")
	if shoutrrrURLsStr == "" {
		return nil, fmt.Errorf("SHOUTRRR_URLS environment variable is required")
	}
	shoutrrrURLs := parseShoutrrrURLs(shoutrrrURLsStr)

	// Parse Rate Limits
	rateLimitsStr := os.Getenv("RATE_LIMITS")
	rateLimits, err := parseRateLimits(rateLimitsStr)
	if err != nil {
		return nil, fmt.Errorf("failed to parse RATE_LIMITS: %v", err)
	}

	return &Config{
		InputFilePath:    os.Getenv("INPUT_FILE_PATH"),
		PollInterval:     time.Duration(pollInterval) * time.Minute,
		CheckInterval:    time.Duration(checkInterval) * time.Minute,
		VirusTotalAPIKey: os.Getenv("VT_API_KEY"),
		CuckooBaseURL:    os.Getenv("CUCKOO_BASE_URL"),
		CuckooAPIKey:     os.Getenv("CUCKOO_API_KEY"),
		ShoutrrrURLs:     shoutrrrURLs,
		RateLimits:       rateLimits,
		DatabaseType:     os.Getenv("DATABASE_TYPE"),
		DatabasePath:     os.Getenv("DATABASE_PATH"),
	}, nil
}

// parseShoutrrrURLs parses a comma-separated list of Shoutrrr URLs.
func parseShoutrrrURLs(urls string) []string {
	var result []string
	for _, url := range splitAndTrim(urls, ",") {
		if url != "" {
			result = append(result, url)
		}
	}
	return result
}

// splitAndTrim splits a string by sep and trims spaces.
func splitAndTrim(s, sep string) []string {
	var result []string
	for _, part := range strings.Split(s, sep) {
		trimmed := strings.TrimSpace(part)
		result = append(result, trimmed)
	}
	return result
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
