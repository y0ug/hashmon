package providers

import "golang.org/x/oauth2"

type ProviderUserInfo struct {
	Sub        string `json:"sub"`                   // User's unique identifier
	Name       string `json:"name"`                  // User's name
	Email      string `json:"email"`                 // User's email
	Provider   string `json:"provider"`              // OAuth2 provider name
	ProfileURL string `json:"profile_url,omitempty"` // User's profile URL (optional)
	Picture    string `json:"picture,omitempty"`     // User's profile URL (optional)
	Scope      string `json:"scope,omitempty"`       // User's scope some provider can return less scope
}

// ProviderConfig holds the OAuth2 configuration for a single provider.
type ProviderConfig struct {
	Name             string            // Name of the provider (e.g., google, github)
	Type             string            // Provider type (e.g., google, github, generic)
	ClientID         string            // OAuth2 Client ID
	ClientSecret     string            // OAuth2 Client Secret
	RedirectURL      string            // OAuth2 Redirect URL
	AuthURL          string            // OAuth2 Authorization URL
	TokenURL         string            // OAuth2 Token URL
	UserInfoURL      string            // OAuth2 User Info URL
	WellKnownJwksURL string            // URL to fetch JWKs for ID token validation
	EndSessionURL    string            // OAuth2 End Session URL
	Scopes           []string          // OAuth2 Scopes
	AdditionalParams map[string]string // Additional OAuth2 parameters
	OAuth2Config     *oauth2.Config    // OAuth2 configuration
}
