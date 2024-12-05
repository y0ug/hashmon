package apis

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// CuckooClient implements the APIClient interface for Cuckoo Sandbox.
type CuckooClient struct {
	BaseURL     string
	APIKey      string
	Client      *http.Client
	RateLimiter *RateLimiter
}

// CuckooResponse represents the structure of Cuckoo's API response.
type CuckooResponse struct {
	Status string `json:"status"`
	// Add other relevant fields if needed
}

// NewCuckooClient initializes a new CuckooClient.
func NewCuckooClient(baseURL, apiKey string) *CuckooClient {
	return &CuckooClient{
		BaseURL: baseURL,
		APIKey:  apiKey,
		Client:  &http.Client{Timeout: 10 * time.Second},
	}
}

// SetRateLimiter sets the rate limiter for the CuckooClient.
func (c *CuckooClient) SetRateLimiter(limiter *RateLimiter) {
	c.RateLimiter = limiter
}

// ProviderName returns the name of the API provider.
func (c *CuckooClient) ProviderName() string {
	return "Cuckoo Sandbox"
}

// CheckHash checks if the hash exists in Cuckoo Sandbox's database.
func (c *CuckooClient) CheckHash(ctx context.Context, hash string) (bool, error) {
	if c.RateLimiter != nil {
		// Wait for permission to proceed based on rate limiter
		if err := c.RateLimiter.Limiter.Wait(ctx); err != nil {
			return false, fmt.Errorf("rate limiter error: %v", err)
		}
	}

	url := fmt.Sprintf("%s/api/tasks/%s", c.BaseURL, hash)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", c.APIKey))

	resp, err := c.Client.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case 200:
		var cuckooResp CuckooResponse
		if err := json.NewDecoder(resp.Body).Decode(&cuckooResp); err != nil {
			return false, err
		}
		// If the status is not "not_found", consider the hash as existing
		return cuckooResp.Status != "not_found", nil
	case 404:
		// Hash not found in Cuckoo Sandbox
		return false, nil
	default:
		return false, fmt.Errorf("Cuckoo API returned status: %d", resp.StatusCode)
	}
}
