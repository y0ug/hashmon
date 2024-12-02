// apis/virustotal.go
package apis

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/sirupsen/logrus"
)

// VirusTotalClient implements the APIClient interface for VirusTotal.
type VirusTotalClient struct {
	APIKey      string
	Client      *http.Client
	RateLimiter *RateLimiter
}

// NewVirusTotalClient initializes a new VirusTotalClient.
func NewVirusTotalClient(apiKey string) *VirusTotalClient {
	return &VirusTotalClient{
		APIKey: apiKey,
		Client: &http.Client{Timeout: 10 * time.Second},
	}
}

// SetRateLimiter sets the rate limiter for the VirusTotalClient.
func (vt *VirusTotalClient) SetRateLimiter(limiter *RateLimiter) {
	vt.RateLimiter = limiter
}

// ProviderName returns the name of the API provider.
func (vt *VirusTotalClient) ProviderName() string {
	return "VirusTotal"
}

// CheckHash checks if the hash exists in VirusTotal's database.
func (vt *VirusTotalClient) CheckHash(ctx context.Context, hash string) (bool, error) {
	if vt.RateLimiter != nil {
		// Wait for permission to proceed based on rate limiter
		if err := vt.RateLimiter.Limiter.Wait(ctx); err != nil {
			return false, fmt.Errorf("rate limiter error: %v", err)
		}
	}

	url := fmt.Sprintf("https://www.virustotal.com/api/v3/files/%s", hash)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("x-apikey", vt.APIKey)

	resp, err := vt.Client.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	logrus.Info("VirusTotal API response status: ", resp.StatusCode)
	switch resp.StatusCode {
	case 200:
		return true, nil
	case 404:
		// Hash not found in VirusTotal
		return false, nil
	case 429:
		// Rate limit exceeded
		return false, fmt.Errorf("VirusTotal API rate limit exceeded")
	default:
		return false, fmt.Errorf("VirusTotal API returned status: %d", resp.StatusCode)
	}
}
