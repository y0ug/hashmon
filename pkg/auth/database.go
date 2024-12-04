// auth/database.go
package auth

import (
	"time"
)

// Database defines the interface for database operations needed by the auth package.
type Database interface {
	StoreRefreshToken(token, userID string, expiresAt time.Time) error
	ValidateRefreshToken(token string) (userID string, err error)
	AddBlacklistedToken(token string, expiresAt int64) error
	IsTokenBlacklisted(token string) (bool, error)
	RevokeRefreshToken(token string) error

	StoreProviderTokens(userID string, tokens ProviderTokens) error
	GetProviderTokens(userID string) (ProviderTokens, error)
	UpdateProviderTokens(userID string, tokens ProviderTokens) error
}
