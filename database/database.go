package database

import (
	"errors"
	"time"

	"github.com/y0ug/hashmon/models"
)

// Database defines the methods required for hash storage and retrieval.
type Database interface {
	// Initialize sets up the necessary buckets or tables.
	Initialize() error

	Close() error

	// AddHash adds a new hash record.
	AddHash(record models.HashRecord) error

	// LoadHashes retrieves all hash records.
	LoadHashes() ([]models.HashRecord, error)

	// UpdateHash updates an existing hash record.
	UpdateHash(record models.HashRecord) error

	// DeleteHash removes a hash record.
	DeleteHash(sha256 string) error

	// GetHash retrieves a specific hash record.
	GetHash(sha256 string) (models.HashRecord, error)

	// MarkAsAlerted marks a hash as alerted for a specific provider.
	MarkAsAlerted(sha256, provider string) error

	// IsAlerted checks if a hash has been alerted for a specific provider.
	IsAlerted(sha256, provider string) (bool, error)

	// AddBlacklistedToken adds a token string to the blacklist with its expiration time.
	AddBlacklistedToken(tokenString string, exp int64) error

	// IsTokenBlacklisted checks if a token is in the blacklist.
	// If the token is expired, it removes it from the blacklist.
	IsTokenBlacklisted(tokenString string) (bool, error)

	// StoreRefreshToken saves a refresh token with associated user and expiration.
	StoreRefreshToken(token string, userID string, expiresAt time.Time) error

	// ValidateRefreshToken checks if a refresh token is valid and not expired.
	// Returns the associated userID if valid.
	ValidateRefreshToken(token string) (string, error)

	// RevokeRefreshToken removes a refresh token from the database.
	RevokeRefreshToken(token string) error
}

// Custom errors
var (
	ErrHashNotFound = errors.New("hash not found")
)
