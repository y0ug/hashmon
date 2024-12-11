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

func (hs *HashStatus) ToHashRecord() HashRecord {
	return HashRecord{
		SHA256:      hs.SHA256,
		FileName:    hs.FileName,
		BuildId:     hs.BuildId,
		LastCheckAt: hs.LastCheckAt,
	}
}
