package database

import (
	"errors"

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
}

// Custom errors
var (
	ErrHashNotFound = errors.New("hash not found")
)
