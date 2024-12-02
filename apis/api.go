package apis

import (
	"context"

	"golang.org/x/time/rate"
)

// APIClient defines the methods that any API client must implement.
type APIClient interface {
	// CheckHash returns true if the hash exists in the API's database, false otherwise.
	CheckHash(ctx context.Context, hash string) (bool, error)
	// SetRateLimiter sets the rate limiter for the API client.
	SetRateLimiter(limiter *RateLimiter)
	// ProviderName returns the name of the API provider.
	ProviderName() string
}

type RateLimiter struct {
	Limiter *rate.Limiter
	Burst   int
	Rate    rate.Limit // Requests per second
}
