package database

import (
	"context"
	"errors"
	"time"

	"github.com/y0ug/hashmon/internal/database/models"
	"github.com/y0ug/hashmon/pkg/auth"
)

// Database defines the methods required for hash storage and retrieval.
type Database interface {
	// Initialize sets up the necessary buckets or tables.
	Initialize(ctx context.Context) error

	Close(ctx context.Context) error

	// AddHash adds a new hash record.
	AddHash(ctx context.Context, record models.HashRecord) error

	// LoadHashes retrieves all hash records.
	LoadHashes(ctx context.Context) ([]models.HashRecord, error)

	// UpdateHash updates an existing hash record.
	UpdateHash(ctx context.Context, record models.HashRecord) error

	// DeleteHash removes a hash record.
	DeleteHash(ctx context.Context, sha256 string) error

	// GetHash retrieves a specific hash record.
	GetHash(ctx context.Context, sha256 string) (models.HashRecord, error)

	// MarkAsAlerted marks a hash as alerted for a specific provider.
	MarkAsAlerted(ctx context.Context, sha256, provider string) error

	// IsAlerted checks if a hash has been alerted for a specific provider.
	IsAlerted(ctx context.Context, sha256, provider string) (bool, error)

	// AddBlacklistedToken adds a token string to the blacklist with its expiration time.
	AddBlacklistedToken(ctx context.Context, tokenString string, exp int64) error

	// IsTokenBlacklisted checks if a token is in the blacklist.
	// If the token is expired, it removes it from the blacklist.
	IsTokenBlacklisted(ctx context.Context, tokenString string) (bool, error)

	// StoreRefreshToken saves a refresh token with associated user and expiration.
	StoreRefreshToken(ctx context.Context, token string, userID string, expiresAt time.Time) error

	// ValidateRefreshToken checks if a refresh token is valid and not expired.
	// Returns the associated userID if valid.
	ValidateRefreshToken(ctx context.Context, token string) (string, error)

	// RevokeRefreshToken removes a refresh token from the database.
	RevokeRefreshToken(ctx context.Context, token string) error

	StoreProviderTokens(ctx context.Context, userID string, provider string, tokens auth.ProviderTokens) error
	GetProviderTokens(ctx context.Context, userID string, provider string) (auth.ProviderTokens, error)
	UpdateProviderTokens(ctx context.Context, userID string, provider string, tokens auth.ProviderTokens) error
}

var ErrHashNotFound = errors.New("hash not found")
