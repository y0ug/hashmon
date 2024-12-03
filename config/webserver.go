package config

import (
	"os"
	"strings"

	"golang.org/x/oauth2"
)

type WebserverConfig struct {
	AuthType           string
	OauthClientID      string
	OauthClientSecret  string
	OauthRedirectURL   string
	OauthLoginURL      string
	OauthTokenURL      string
	OauthWellknownJwks string
	ListenTo           string
	CorsAllowedOrigins []string
	OAuth2Config       *oauth2.Config
	JwtSecret          []byte
	RedirectURL        string
}

func NewWebserverConfig() (*WebserverConfig, error) {
	config := &WebserverConfig{}

	config.AuthType = os.Getenv("AUTH_TYPE")
	if config.AuthType == "" {
		config.AuthType = "none"
	}

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	config.ListenTo = ":" + port

	if config.AuthType == "oauth2" {
		config.OauthClientID = os.Getenv("OAUTH_CLIENT_ID")
		config.OauthClientSecret = os.Getenv("OAUTH_CLIENT_SECRET")
		config.OauthRedirectURL = os.Getenv("OAUTH_REDIRECT_URL")
		config.OauthLoginURL = os.Getenv("OAUTH_LOGIN_URL")
		config.OauthTokenURL = os.Getenv("OAUTH_TOKEN_URL")
		config.OauthWellknownJwks = os.Getenv("OAUTH_JWKS_URL")

		config.JwtSecret = []byte(os.Getenv("JWT_SECRET"))

		config.OAuth2Config = &oauth2.Config{
			ClientID:     config.OauthClientID,
			ClientSecret: config.OauthClientSecret,
			RedirectURL:  config.OauthRedirectURL,
			Scopes:       []string{"openid", "profile", "email"}, // Adjust scopes as needed
			Endpoint: oauth2.Endpoint{
				AuthURL:  config.OauthLoginURL,
				TokenURL: config.OauthTokenURL,
			},
		}

		config.RedirectURL = os.Getenv("REDIRECT_URL")
	}

	corsAllowedOrigins := os.Getenv("CORS_ALLOWED_ORIGINS")
	if corsAllowedOrigins != "" {
		config.CorsAllowedOrigins = strings.Split(corsAllowedOrigins, ",")
	}

	return config, nil
}
