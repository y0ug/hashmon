// models.go
package models

import "time"

type HashRecord struct {
	FileName string
	SHA256   string
	BuildId  string
}

// HashStatus represents the alert status of a hash per provider.
type HashStatus struct {
	SHA256      string          `json:"sha256"`
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
