package providers

import (
	"context"

	"golang.org/x/oauth2"
)

// Provider defines the interface that each OAuth2 provider must implement.
type Provider interface {
	// Name returns the name of the provider (e.g., google, github).
	Name() string

	// OAuth2Config returns the OAuth2 configuration for the provider.
	OAuth2Config() *oauth2.Config

	// ExchangeCode exchanges the authorization code for an access token.
	ExchangeCode(ctx context.Context, code string) (*oauth2.Token, error)

	// FetchUserInfo retrieves user information using the access token.
	FetchUserInfo(ctx context.Context, accessToken string) (*ProviderUserInfo, error)

	// DecodeIDToken decodes and validates the ID token to extract user claims.
	DecodeIDToken(ctx context.Context, token *oauth2.Token) (*ProviderUserInfo, error)

	// RenewAccessToken refreshes the access token using the refresh token.
	RenewAccessToken(ctx context.Context, refreshToken string) (*oauth2.Token, error)

	// Config returns the provider configuration.
	Config() *ProviderConfig
}
