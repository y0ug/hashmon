package auth

import "time"

type ProviderTokens struct {
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token,omitempty"` // Optional, as some providers may not issue refresh tokens
	ExpiresAt    time.Time `json:"expires_at"`
}
