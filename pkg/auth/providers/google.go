package providers

import (
	"context"
	"fmt"

	"golang.org/x/oauth2"
)

// GoogleProvider implements the Provider interface for Google OAuth2.
type GoogleProvider struct {
	config *ProviderConfig
}

// NewGoogleProvider creates a new instance of GoogleProvider.
func NewGoogleProvider(config *ProviderConfig) *GoogleProvider {
	return &GoogleProvider{config: config}
}

// Name returns the name of the provider.
func (p *GoogleProvider) Name() string {
	return p.config.Name
}

// OAuth2Config returns the OAuth2 configuration.
func (p *GoogleProvider) OAuth2Config() *oauth2.Config {
	return p.config.OAuth2Config
}

// Config returns the provider configuration.
func (p *GoogleProvider) Config() *ProviderConfig {
	return p.config
}

// ExchangeCode exchanges the authorization code for an access token.
func (p *GoogleProvider) ExchangeCode(ctx context.Context, code string) (*oauth2.Token, error) {
	token, err := defaultExchangeCode(ctx, p, code)
	if err != nil {
		return nil, err
	}
	return token, nil
}

// FetchUserInfo retrieves user information from Google using the access token.
func (p *GoogleProvider) FetchUserInfo(ctx context.Context, accessToken string) (*ProviderUserInfo, error) {
	// Parse the response
	var googleUser struct {
		Sub        string `json:"sub"`
		Name       string `json:"name"`
		Email      string `json:"email"`
		Picture    string `json:"picture"`
		ProfileURL string `json:"profile"`
	}

	err := defaultFetchUserInfo(ctx, p, accessToken, &googleUser)
	if err != nil {
		return nil, err
	}

	userInfo := ProviderUserInfo{
		Sub:        googleUser.Sub,
		Name:       googleUser.Name,
		Email:      googleUser.Email,
		Provider:   p.Name(),
		ProfileURL: googleUser.ProfileURL,
		Picture:    googleUser.Picture,
	}

	return &userInfo, nil
}

// DecodeIDToken decodes and validates the ID token from Google.
func (p *GoogleProvider) DecodeIDToken(ctx context.Context, token *oauth2.Token) (*ProviderUserInfo, error) {
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
		return nil, fmt.Errorf("invalid user claims: missing 'name'")
	}

	profileURL, ok := userClaims["profile"].(string)
	if !ok {
		profileURL = ""
	}
	pictureURL, ok := userClaims["picture"].(string)
	if !ok {
		pictureURL = ""
	}
	userInfo := ProviderUserInfo{
		Sub:        userID,
		Name:       userName,
		Email:      userEmail,
		Provider:   p.Name(),
		ProfileURL: profileURL,
		Picture:    pictureURL,
	}
	return &userInfo, nil
}

func (p *GoogleProvider) RenewAccessToken(ctx context.Context, refreshToken string) (*oauth2.Token, error) {
	return defaultRenewAccessToken(ctx, p, refreshToken)
}
