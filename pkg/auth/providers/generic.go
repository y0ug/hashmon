package providers

import (
	"fmt"

	"golang.org/x/net/context"
	"golang.org/x/oauth2"
)

// GenericProvider implements the Provider interface for Generic OAuth2.
type GenericProvider struct {
	config *ProviderConfig
}

// NewGenericProvider creates a new instance of GenericProvider.
func NewGenericProvider(config *ProviderConfig) *GenericProvider {
	return &GenericProvider{config: config}
}

// Name returns the name of the provider.
func (p *GenericProvider) Name() string {
	return p.config.Name
}

// Config returns the provider configuration.
func (p *GenericProvider) Config() *ProviderConfig {
	return p.config
}

// OAuth2Config returns the OAuth2 configuration.
func (p *GenericProvider) OAuth2Config() *oauth2.Config {
	return p.config.OAuth2Config
}

// ExchangeCode exchanges the authorization code for an access token.
func (p *GenericProvider) ExchangeCode(ctx context.Context, code string) (*oauth2.Token, error) {
	return defaultExchangeCode(ctx, p, code)
}

// FetchUserInfo retrieves user information from Generic using the access token.
func (p *GenericProvider) FetchUserInfo(ctx context.Context, accessToken string) (*ProviderUserInfo, error) {
	userInfo := ProviderUserInfo{}

	err := defaultFetchUserInfo(ctx, p, accessToken, &userInfo)
	if err != nil {
		return nil, err
	}

	userInfo.Provider = p.Name()
	return &userInfo, nil
}

// DecodeIDToken decodes and validates the ID token from Generic.
func (p *GenericProvider) DecodeIDToken(ctx context.Context, token *oauth2.Token) (*ProviderUserInfo, error) {
	userClaims, err := defaultDecodeIDToken(ctx, p, token.AccessToken)
	if err != nil {
		return nil, err
	}
	userID, ok := userClaims["sub"].(string)
	if !ok || userID == "" {
		return nil, fmt.Errorf("invalid user claims: missing 'sub'")
	}

	userName, ok := userClaims["name"].(string)
	if !ok || userName == "" {
		return nil, fmt.Errorf("invalid user claims: missing 'name'")
	}

	userEmail, ok := userClaims["email"].(string)
	if !ok || userEmail == "" {
		return nil, fmt.Errorf("invalid user claims: missing 'name'")
	}
	userInfo := ProviderUserInfo{
		Sub:        userID,
		Name:       userName,
		Email:      userEmail,
		Provider:   p.Name(),
		ProfileURL: "",
	}
	return &userInfo, nil
}

// RenewAccessToken refreshes the access token using the refresh token.
func (p *GenericProvider) RenewAccessToken(ctx context.Context, refreshToken string) (*oauth2.Token, error) {
	return defaultRenewAccessToken(ctx, p, refreshToken)
}
