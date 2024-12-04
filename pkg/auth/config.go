// auth/config.go
package auth

import (
	"fmt"
	"net/http"
	"os"
	"strconv"
	"time"

	"golang.org/x/oauth2"
)

// Config holds the authentication configuration.
type Config struct {
	AuthType               string
	OauthClientID          string
	OauthClientSecret      string
	OauthRedirectURL       string
	OauthLoginURL          string
	OauthTokenURL          string
	OauthWellknownJwks     string
	OauthUserInfoURL       string
	OauthEndSessionURL     string
	PostLogoutRedirectURI  string
	RedirectURL            string
	JwtSecret              []byte
	OAuth2Config           *oauth2.Config
	AccessTokenExpiration  time.Duration
	RefreshTokenExpiration time.Duration
	SecureCookie           bool
	CookieSameSite         http.SameSite
}

// NewConfig initializes the authentication configuration from environment variables.
func NewConfig() (*Config, error) {
	authConfig := &Config{}

	authConfig.AuthType = os.Getenv("AUTH_TYPE")
	if authConfig.AuthType == "" {
		authConfig.AuthType = "none"
	}

	if authConfig.AuthType == "oauth2" {
		authConfig.OauthClientID = os.Getenv("OAUTH_CLIENT_ID")
		authConfig.OauthClientSecret = os.Getenv("OAUTH_CLIENT_SECRET")
		authConfig.OauthRedirectURL = os.Getenv("OAUTH_REDIRECT_URL")
		authConfig.OauthLoginURL = os.Getenv("OAUTH_LOGIN_URL")
		authConfig.OauthTokenURL = os.Getenv("OAUTH_TOKEN_URL")
		authConfig.OauthWellknownJwks = os.Getenv("OAUTH_JWKS_URL")
		authConfig.JwtSecret = []byte(os.Getenv("JWT_SECRET"))
		authConfig.RedirectURL = os.Getenv("REDIRECT_URL")
		authConfig.OauthUserInfoURL = os.Getenv("OAUTH_USERINFO_URL")
		authConfig.OauthEndSessionURL = os.Getenv("OAUTH_END_SESSION_URL")

		authConfig.PostLogoutRedirectURI = os.Getenv("POST_LOGOUT_REDIRECT_URI")

		// Parse AccessTokenExpiration from environment variable
		accessExpStr := os.Getenv("ACCESS_TOKEN_EXPIRATION")
		if accessExpStr == "" {
			authConfig.AccessTokenExpiration = 15 * time.Minute // Default to 15 minutes
		} else {
			duration, err := parseDurationString(accessExpStr)
			if err != nil {
				return nil, fmt.Errorf("invalid ACCESS_TOKEN_EXPIRATION: %v", err)
			}
			authConfig.AccessTokenExpiration = duration
		}

		// Parse RefreshTokenExpiration from environment variable
		refreshExpStr := os.Getenv("REFRESH_TOKEN_EXPIRATION")
		if refreshExpStr == "" {
			authConfig.RefreshTokenExpiration = 24 * time.Hour // Default to 1 days
		} else {
			duration, err := parseDurationString(refreshExpStr)
			if err != nil {
				return nil, fmt.Errorf("invalid REFRESH_TOKEN_EXPIRATION: %v", err)
			}
			authConfig.RefreshTokenExpiration = duration
		}

		// Parse SecureCookie from environment variable
		secureCookieStr := os.Getenv("SECURE_COOKIE")
		if secureCookieStr == "" {
			authConfig.SecureCookie = true // Default to true for security
		} else {
			secureCookie, err := strconv.ParseBool(secureCookieStr)
			if err != nil {
				return nil, fmt.Errorf("invalid SECURE_COOKIE: %v", err)
			}
			authConfig.SecureCookie = secureCookie
		}

		// Parse SameSite from environment variable
		sameSiteStr := os.Getenv("COOKIE_SAMESITE")
		if sameSiteStr == "" {
			authConfig.CookieSameSite = http.SameSiteLaxMode // Default to Lax
		} else {
			sameSite, err := parseSameSite(sameSiteStr)
			if err != nil {
				return nil, fmt.Errorf("invalid COOKIE_SAMESITE: %v", err)
			}
			authConfig.CookieSameSite = sameSite
		}

		authConfig.OAuth2Config = &oauth2.Config{
			ClientID:     authConfig.OauthClientID,
			ClientSecret: authConfig.OauthClientSecret,
			RedirectURL:  authConfig.OauthRedirectURL,
			Scopes:       []string{"openid", "profile", "email"}, // Adjust scopes as needed
			// Scopes: []string{"openid", "profile", "email", "offline_access"}, // Add "offline_access"
			Endpoint: oauth2.Endpoint{
				AuthURL:  authConfig.OauthLoginURL,
				TokenURL: authConfig.OauthTokenURL,
			},
		}
	}

	return authConfig, nil
}
