package auth

import "time"

// HttpResp represents the standard HTTP response structure.
// swagger:model
type HttpResp struct {
	Status  string      `json:"status" example:"success"`
	Data    interface{} `json:"data"`
	Message string      `json:"message" example:"Operation completed successfully"`
}

type ProviderTokens struct {
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token,omitempty"` // Optional, as some providers may not issue refresh tokens
	ExpiresAt    time.Time `json:"expires_at"`
}

type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"`
}

// UserInfo represents the authenticated user's information.
type UserInfo struct {
	Sub   string `json:"sub"`
	Name  string `json:"name"`
	Email string `json:"email"`
}

// StatusResponse defines the structure of the /status response.
type StatusResponse struct {
	Authenticated bool     `json:"authenticated"`
	User          UserInfo `json:"user,omitempty"`
	Message       string   `json:"message,omitempty"`
}
