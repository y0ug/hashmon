// models.go
package models

import "time"

type HashRecord struct {
	FileName    string    `json:"filename"`
	SHA256      string    `json:"sha256"`
	BuildId     string    `json:"build_id"`
	LastCheckAt time.Time `json:"last_check_at"`
}

// HashStatus represents the alert status of a hash per provider.
type HashStatus struct {
	SHA256      string          `json:"sha256"`
	FileName    string          `json:"filename"`
	BuildId     string          `json:"build_id"`
	LastCheckAt time.Time       `json:"last_check_at"`
	Providers   map[string]bool `json:"providers"` // ProviderName -> Alerted (true/false)
	AlertedBy   []string        `json:"alerted_by,omitempty"`
}

// Response structures
type HashesResponse struct {
	Hashes []HashStatus `json:"hashes"`
}

type HashDetailResponse struct {
	Hash HashStatus `json:"hash"`
}
