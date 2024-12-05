package providers

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"golang.org/x/oauth2"
)

type GitHubEmail struct {
	Email      string `json:"email"`
	Primary    bool   `json:"primary"`
	Verified   bool   `json:"verified"`
	Visibility string `json:"visibility,omitempty"` // can be null
}

// Set *string if when want to get the differance between "" and not Set
// the pointer will be nil
type GitHubUser struct {
	Login             string    `json:"login"`
	ID                int       `json:"id"`
	NodeID            string    `json:"node_id"`
	AvatarURL         string    `json:"avatar_url"`
	GravatarID        string    `json:"gravatar_id"`
	URL               string    `json:"url"`
	HTMLURL           string    `json:"html_url"`
	FollowersURL      string    `json:"followers_url"`
	FollowingURL      string    `json:"following_url"`
	GistsURL          string    `json:"gists_url"`
	StarredURL        string    `json:"starred_url"`
	SubscriptionsURL  string    `json:"subscriptions_url"`
	OrganizationsURL  string    `json:"organizations_url"`
	ReposURL          string    `json:"repos_url"`
	EventsURL         string    `json:"events_url"`
	ReceivedEventsURL string    `json:"received_events_url"`
	Type              string    `json:"type"`
	SiteAdmin         bool      `json:"site_admin"`
	Name              string    `json:"name,omitempty"`
	Company           string    `json:"company,omitempty"`
	Blog              string    `json:"blog,omitempty"`
	Location          string    `json:"location,omitempty"`
	Email             string    `json:"email,omitempty"`
	Hireable          bool      `json:"hireable,omitempty"`
	Bio               string    `json:"bio,omitempty"`
	TwitterUsername   string    `json:"twitter_username,omitempty"`
	PublicRepos       int       `json:"public_repos"`
	PublicGists       int       `json:"public_gists"`
	Followers         int       `json:"followers"`
	Following         int       `json:"following"`
	CreatedAt         time.Time `json:"created_at"`
	UpdatedAt         time.Time `json:"updated_at"`
}

// GitHubProvider implements the Provider interface for GitHub OAuth2.
type GitHubProvider struct {
	config *ProviderConfig
}

// NewGitHubProvider creates a new instance of GitHubProvider.
func NewGitHubProvider(config *ProviderConfig) *GitHubProvider {
	return &GitHubProvider{config: config}
}

// Name returns the name of the provider.
func (p *GitHubProvider) Name() string {
	return p.config.Name
}

// Config returns the provider configuration.
func (p *GitHubProvider) Config() *ProviderConfig {
	return p.config
}

// OAuth2Config returns the OAuth2 configuration.
func (p *GitHubProvider) OAuth2Config() *oauth2.Config {
	return p.config.OAuth2Config
}

// ExchangeCode exchanges the authorization code for an access token.
func (p *GitHubProvider) ExchangeCode(ctx context.Context, code string) (*oauth2.Token, error) {
	token, err := defaultExchangeCode(ctx, p, code)
	if err != nil {
		return nil, err
	}

	scope := token.Extra("scope")
	fmt.Printf("scope: %s\n", scope)
	return token, nil
}

// FetchUserInfo retrieves user information from GitHub using the access token.
func (p *GitHubProvider) FetchUserInfo(ctx context.Context, accessToken string) (*ProviderUserInfo, error) {
	// Parse the response
	var githubUser GitHubUser
	err := fetchGithub(ctx, accessToken, p.Config().UserInfoURL, &githubUser)
	if err != nil {
		return nil, err
	}
	fmt.Printf("GitHub User: %+v\n", githubUser)

	var emails []GitHubEmail
	err = fetchGithub(ctx, accessToken, "https://api.github.com/user/emails", &emails)
	if err != nil {
		return nil, err
	}

	email, err := getPrimaryEmail(emails)

	// fmt.Println("GitHub Emails:")
	// for _, email := range emails {
	// 	fmt.Printf("- %s (Primary: %t, Verified: %t, Visibility: %s)\n",
	// 		email.Email, email.Primary, email.Verified, email.Visibility)
	// }

	userInfo := ProviderUserInfo{
		Sub:      fmt.Sprintf("%d", githubUser.ID),
		Name:     githubUser.Name,
		Email:    email,
		Provider: p.Name(),
		// GitHub does not provide a direct profile URL, constructing it based on login
		ProfileURL: fmt.Sprintf("https://github.com/%s", githubUser.Login),
		Picture:    githubUser.AvatarURL,
	}

	return &userInfo, nil
}

// DecodeIDToken decodes and validates the ID token from GitHub.
func (p *GitHubProvider) DecodeIDToken(ctx context.Context, token *oauth2.Token) (*ProviderUserInfo, error) {
	// Github doesn't provide a JWT token so we return nil
	return p.FetchUserInfo(ctx, token.AccessToken)
}

// RenewAccessToken refreshes the access token using the refresh token.
func (p *GitHubProvider) RenewAccessToken(ctx context.Context, refreshToken string) (*oauth2.Token, error) {
	return defaultRenewAccessToken(ctx, p, refreshToken)
}

func fetchGithub(ctx context.Context, accessToken string, url string, data interface{}) error {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return err
	}

	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/vnd.github.v3+json")

	// Make the HTTP request
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	// Handle errors
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to get user info: status %d", resp.StatusCode)
	}

	if err := json.NewDecoder(resp.Body).Decode(data); err != nil {
		return fmt.Errorf("failed to decode provider user info response: %w", err)
	}
	return nil
}

func getPrimaryEmail(emails []GitHubEmail) (string, error) {
	for _, email := range emails {
		if email.Primary {
			return email.Email, nil
		}
	}
	return "", fmt.Errorf("no primary email found")
}
