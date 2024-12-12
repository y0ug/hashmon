package models

import (
	"errors"
	"regexp"
	"time"
)

// HashRecord represents a hash entry in the database.
type HashRecord struct {
	Comment     string    `json:"comment"`
	Hash        string    `json:"hash"`
	LastCheckAt time.Time `json:"last_check_at"`
}

// HashStatus represents the alert status of a hash per provider.
type HashStatus struct {
	Hash        string          `json:"hash"`
	Comment     string          `json:"comment"`
	LastCheckAt time.Time       `json:"last_check_at"`
	Providers   map[string]bool `json:"providers"` // ProviderName -> Alerted (true/false)
	AlertedBy   []string        `json:"alerted_by,omitempty"`
}

// HashesResponse includes pagination metadata.
type HashesResponse struct {
	Hashes     []HashStatus `json:"hashes"`
	Page       int          `json:"page"`
	PerPage    int          `json:"per_page"`
	Total      int          `json:"total"`
	TotalPages int          `json:"total_pages"`
}

type HashDetailResponse struct {
	Hash HashStatus `json:"hash"`
}

// StatsResponse represents the structure of the /stats API response.
type StatsResponse struct {
	TotalHashes       int       `json:"total_hashes"`
	GlobalLastCheckAt time.Time `json:"global_last_check_at"`
	TotalHashesFound  int       `json:"total_hashes_found"`
	HashesFoundToday  int       `json:"hashes_found_today"`
}

// ToHashRecord converts HashStatus to HashRecord.
func (hs *HashStatus) ToHashRecord() HashRecord {
	return HashRecord{
		Hash:        hs.Hash,
		Comment:     hs.Comment,
		LastCheckAt: hs.LastCheckAt,
	}
}

// ValidateHash validates the hash length to ensure it's MD5, SHA1, SHA256, or SHA512.
func (hr *HashRecord) ValidateHash() error {
	hashLen := len(hr.Hash)
	valid := false
	switch hashLen {
	case 32, 40, 64, 128:
		valid = true
	default:
		valid = false
	}
	if !valid {
		return errors.New("invalid hash length; must be MD5, SHA1, SHA256, or SHA512")
	}

	// Optional: Validate hexadecimal characters
	match, _ := regexp.MatchString("^[a-fA-F0-9]+$", hr.Hash)
	if !match {
		return errors.New("hash must contain only hexadecimal characters")
	}

	return nil
}
