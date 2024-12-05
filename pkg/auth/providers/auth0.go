package providers

import (
	"context"
	"fmt"

	"golang.org/x/oauth2"
)

// Auth0Provider implements the Provider interface for Auth0 OAuth2.
type Auth0Provider struct {
	config *ProviderConfig
}

// NewAuth0Provider creates a new instance of Auth0Provider.
func NewAuth0Provider(config *ProviderConfig) *Auth0Provider {
	return &Auth0Provider{config: config}
}

// Name returns the name of the provider.
func (p *Auth0Provider) Name() string {
	return p.config.Name
}

// Config returns the provider configuration.
func (p *Auth0Provider) Config() *ProviderConfig {
	return p.config
}

// OAuth2Config returns the OAuth2 configuration.
func (p *Auth0Provider) OAuth2Config() *oauth2.Config {
	return p.config.OAuth2Config
}

// ExchangeCode exchanges the authorization code for an access token.
func (p *Auth0Provider) ExchangeCode(ctx context.Context, code string) (*oauth2.Token, error) {
	return defaultExchangeCode(ctx, p, code)
}

// FetchUserInfo retrieves user information from Auth0 using the access token.
func (p *Auth0Provider) FetchUserInfo(ctx context.Context, accessToken string) (*ProviderUserInfo, error) {
	var auth0User struct {
		Sub       string `json:"sub"`
		Name      string `json:"name"`
		Email     string `json:"email"`
		Picture   string `json:"picture"`
		UpdatedAt string `json:"updated_at"`
		// Add other fields as needed
	}

	err := defaultFetchUserInfo(ctx, p, accessToken, &auth0User)
	if err != nil {
		return nil, err
	}

	userInfo := ProviderUserInfo{
		Sub:        auth0User.Sub,
		Name:       auth0User.Name,
		Email:      auth0User.Email,
		Provider:   p.Name(),
		Picture:    auth0User.Picture,
		ProfileURL: "", // Auth0 does not provide a direct profile URL
	}

	return &userInfo, nil
}

// DecodeIDToken decodes and validates the ID token from Auth0.
func (p *Auth0Provider) DecodeIDToken(ctx context.Context, token *oauth2.Token) (*ProviderUserInfo, error) {
	idToken, ok := token.Extra("id_token").(string)
	if !ok {
		return nil, fmt.Errorf("missing id_token in token")
	}

	userClaims, err := defaultDecodeIDToken(ctx, p, idToken)
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
		return nil, fmt.Errorf("invalid user claims: missing 'email'")
	}

	userInfo := ProviderUserInfo{
		Sub:        userID,
		Name:       userName,
		Email:      userEmail,
		Provider:   p.Name(),
		ProfileURL: "",
		Picture:    userClaims["picture"].(string),
	}

	return &userInfo, nil
}

// RenewAccessToken refreshes the access token using the refresh token.
func (p *Auth0Provider) RenewAccessToken(ctx context.Context, refreshToken string) (*oauth2.Token, error) {
	return defaultRenewAccessToken(ctx, p, refreshToken)
}
