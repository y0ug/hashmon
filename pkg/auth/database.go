package auth

import (
	"context"
	"time"
)

// Database defines the interface for database operations needed by the auth package.
type Database interface {
	// StoreRefreshToken stores a refresh token associated with a user.
	StoreRefreshToken(ctx context.Context, token, userID string, expiresAt time.Time) error

	// ValidateRefreshToken validates a refresh token and returns the associated user ID.
	ValidateRefreshToken(ctx context.Context, token string) (string, error)

	// AddBlacklistedToken adds a token to the blacklist until its expiration time.
	AddBlacklistedToken(ctx context.Context, token string, expiresAt int64) error

	// IsTokenBlacklisted checks if a token is blacklisted.
	IsTokenBlacklisted(ctx context.Context, token string) (bool, error)

	// RevokeRefreshToken revokes a refresh token, removing it from the store.
	RevokeRefreshToken(ctx context.Context, token string) error

	// StoreProviderTokens stores tokens from an OAuth2 provider for a user.
	StoreProviderTokens(ctx context.Context, userID, provider string, tokens ProviderTokens) error

	// GetProviderTokens retrieves tokens from an OAuth2 provider for a user.
	GetProviderTokens(ctx context.Context, userID, provider string) (ProviderTokens, error)

	// UpdateProviderTokens updates tokens from an OAuth2 provider for a user.
	UpdateProviderTokens(ctx context.Context, userID, provider string, tokens ProviderTokens) error
}
