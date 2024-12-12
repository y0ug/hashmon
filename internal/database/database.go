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
	// Initialize sets up the necessary tables.
	Initialize(ctx context.Context) error

	Close(ctx context.Context) error

	// AddHash adds a new hash record.
	AddHash(ctx context.Context, record models.HashRecord) error

	// UpdateHash updates an existing hash record.
	UpdateHash(ctx context.Context, hash string, record models.HashRecord) error

	// DeleteHash removes a hash record.
	DeleteHash(ctx context.Context, hash string) error

	// GetHash retrieves a specific hash record.
	GetHash(ctx context.Context, hash string) (models.HashStatus, error)

	LoadHashes(ctx context.Context) ([]models.HashStatus, error)
	// LoadHashesPaginated retrieves a specific page of hash records and the total count.
	// If filterFound is nil, no filtering is applied.
	// If filterFound is true, only hashes that have been found are retrieved.
	// If filterFound is false, only hashes that have not been found are retrieved.
	LoadHashesPaginated(ctx context.Context, page, perPage int, filterFound *bool) ([]models.HashStatus, int, error)

	// MarkAsAlerted marks a hash as alerted for a specific provider.
	MarkAsAlerted(ctx context.Context, hash, provider string) error

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

	// GetTotalHashes returns the total number of hashes in the database.
	GetTotalHashes(ctx context.Context) (int, error)

	// GetGlobalLastCheckAt returns the most recent LastCheckAt timestamp among all hashes.
	GetGlobalLastCheckAt(ctx context.Context) (time.Time, error)

	// GetTotalHashesFound returns the total number of hashes that have been found by any provider.
	GetTotalHashesFound(ctx context.Context) (int, error)

	// GetHashesFoundToday returns the number of hashes found within the last 24 hours.
	GetHashesFoundToday(ctx context.Context) (int, error)
}

var ErrHashNotFound = errors.New("hash not found")
