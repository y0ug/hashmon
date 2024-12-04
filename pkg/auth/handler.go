package auth

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/sirupsen/logrus"
	"golang.org/x/oauth2"
)

// Handler holds the authentication handlers and dependencies.
type Handler struct {
	Config     *Config
	Database   Database
	Middleware *Middleware
	Logger     *logrus.Logger // Added Logger field

	// Function fields for methods we want to mock
	getUserInfoFunc                  func(string) (*UserInfo, error)
	exchangeProviderRefreshTokenFunc func(string) (*oauth2.Token, error)
}

// NewHandler initializes a new authentication handler.
func NewHandler(config *Config, db Database, logger *logrus.Logger) *Handler {
	h := &Handler{
		Config:     config,
		Database:   db,
		Middleware: NewMiddleware(config, db, logger),
		Logger:     logger,
	}

	// Initialize function fields with default methods
	h.getUserInfoFunc = h.defaultGetUserInfo
	h.exchangeProviderRefreshTokenFunc = h.defaultExchangeProviderRefreshToken

	return h
}

// AuthMiddleware returns the authentication middleware.
func (h *Handler) AuthMiddleware(next http.Handler) http.Handler {
	return h.Middleware.AuthMiddleware(next)
}

// HandleLogin handles the login endpoint.
func (h *Handler) HandleLogin(w http.ResponseWriter, r *http.Request) {
	h.Logger.Debug("HandleLogin invoked")

	state := generateStateString()
	h.Logger.Debugf("Generated state: %s", state)
	// TODO: Store 'state' in session for later validation

	url := h.Config.OAuth2Config.AuthCodeURL(state)
	h.Logger.Info("Redirecting user to OAuth provider for login")

	http.Redirect(w, r, url, http.StatusTemporaryRedirect)
	// WriteSuccessResponse(w, "Redirecting to OAuth provider", map[string]string{"url": url})
}

// HandleCallback handles the OAuth2 callback and exchanges the code for tokens.
func (h *Handler) HandleCallback(w http.ResponseWriter, r *http.Request) {
	h.Logger.Debug("HandleCallback invoked")

	// Extract the authorization code from the query parameters
	code := r.URL.Query().Get("code")
	if code == "" {
		h.Logger.Warn("Authorization code not found in the request")
		WriteErrorResponse(w, "Code not found in the request", http.StatusBadRequest)
		return
	}

	h.Logger.Debugf("Authorization code received: %s", code)

	// Exchange the code for tokens
	token, err := h.Config.OAuth2Config.Exchange(context.Background(), code)
	if err != nil {
		h.Logger.WithError(err).Error("Token exchange failed")
		WriteErrorResponse(w, "Failed to exchange token", http.StatusInternalServerError)
		return
	}

	h.Logger.WithField("token", token).Debug("Token exchange successful")

	// Extract user info from the ID token or access token
	idToken, ok := token.Extra("id_token").(string)
	if !ok {
		h.Logger.Warn("ID token extraction failed")
		WriteErrorResponse(w, "Failed to extract ID token", http.StatusInternalServerError)
		return
	}
	h.Logger.WithField("id_token", idToken).Debug("ID token extracted")

	userClaims, err := decodeIDToken(idToken, h.Config)
	if err != nil {
		h.Logger.WithError(err).Error("Failed to decode ID token")
		WriteErrorResponse(w, "Failed to decode ID token", http.StatusInternalServerError)
		return
	}

	userID := userClaims["sub"].(string)
	userName := userClaims["name"].(string)
	userEmail := userClaims["email"].(string)

	h.Logger.Infof("User authenticated: %s (%s)", userName, userEmail)

	// Create ProviderTokens struct
	providerTokens := ProviderTokens{
		AccessToken:  token.AccessToken,
		RefreshToken: token.RefreshToken,
		ExpiresAt:    token.Expiry,
	}

	// Store ProviderTokens in the database
	err = h.Database.StoreProviderTokens(userID, providerTokens)
	if err != nil {
		h.Logger.WithError(err).Error("Failed to store provider tokens")
		WriteErrorResponse(w, "Failed to store tokens", http.StatusInternalServerError)
		return
	}

	h.Logger.Debug("Provider tokens stored successfully")

	// Generate your application's tokens (if applicable)
	claimsMap := jwt.MapClaims{
		"sub":   userID,
		"name":  userName,
		"email": userEmail,
	}

	// Generate tokens
	tokens, err := generateTokens(claimsMap, h.Config)
	if err != nil {
		h.Logger.WithError(err).Error("Failed to generate tokens")
		WriteErrorResponse(w, "Failed to generate tokens", http.StatusInternalServerError)
		return
	}

	h.Logger.Debugf("Generated tokens: %+v", tokens)

	// Store your application's refresh token with expiration from config
	err = h.Database.StoreRefreshToken(tokens.RefreshToken, userID, time.Now().Add(h.Config.RefreshTokenExpiration))
	if err != nil {
		h.Logger.WithError(err).Error("Failed to store refresh token")
		WriteErrorResponse(w, "Failed to store refresh token", http.StatusInternalServerError)
		return
	}

	h.Logger.Debug("Refresh token stored successfully")

	// Set tokens in cookies
	setAuthCookies(w, tokens, h.Config)
	h.Logger.Debug("Auth cookies set")

	// Respond with tokens in the response body
	WriteSuccessResponse(w, "Token exchange successful", tokens)
	h.Logger.Info("User logged in successfully")
}

// HandleStatus checks authentication status and returns user info.
func (h *Handler) HandleStatus(w http.ResponseWriter, r *http.Request) {
	// Retrieve user claims from context (set by AuthMiddleware)
	claims, ok := r.Context().Value("user").(jwt.MapClaims)
	if !ok || claims == nil {
		WriteErrorResponse(w, "Failed to retrieve user information", http.StatusInternalServerError)
		return
	}

	// Extract user information from claims
	user := UserInfo{
		Sub:   claims["sub"].(string),
		Name:  claims["name"].(string),
		Email: claims["email"].(string),
	}

	// Respond with authenticated status and user info
	WriteSuccessResponse(w, "Authenticated", StatusResponse{
		Authenticated: true,
		User:          user,
	})
}

// HandleLogout logs the user out by removing the JWT cookie and blacklisting the token.
func (h *Handler) HandleLogout(w http.ResponseWriter, r *http.Request) {
	h.Logger.Debug("HandleLogout invoked")

	var accessTokenString, refreshTokenString string

	// Extract access token
	accessTokenString = extractToken(r, "access_token")
	h.Logger.Debugf("Access token extracted: %s", accessTokenString)

	// Extract refresh token from cookie
	refreshTokenString = extractToken(r, "refresh_token")
	h.Logger.Debugf("Refresh token extracted: %s", refreshTokenString)

	// Revoke tokens
	if err := h.revokeTokens(accessTokenString, refreshTokenString); err != nil {
		h.Logger.WithError(err).Error("Failed to revoke tokens during logout")
		WriteErrorResponse(w, "Failed to logout", http.StatusInternalServerError)
		return
	}

	h.Logger.Info("User logged out successfully")

	// Remove the cookies
	clearAuthCookies(w, h.Config)
	h.Logger.Debug("Auth cookies cleared")

	// Build the end-session URL
	if h.Config.OauthEndSessionURL != "" {
		endSessionURL, err := h.buildEndSessionURL(r)
		if err != nil {
			h.Logger.WithError(err).Error("Failed to build end session URL")
			WriteErrorResponse(w, "Failed to logout", http.StatusInternalServerError)
			return
		}

		h.Logger.Infof("Redirecting user to end session URL: %s", endSessionURL)
		WriteSuccessResponse(w, "Redirecting to end-session URL", map[string]string{"url": endSessionURL})
		return
	}

	// Respond to the client
	WriteSuccessResponse(w, "Successfully logged out", nil)
}

// HandleRefresh handles token refresh.
func (h *Handler) HandleRefresh(w http.ResponseWriter, r *http.Request) {
	h.Logger.Debug("HandleRefresh invoked")

	// Extract refresh token
	refreshTokenString := extractToken(r, "refresh_token")
	h.Logger.Debugf("Refresh token extracted: %s", refreshTokenString)

	if refreshTokenString == "" {
		h.Logger.Warn("Refresh token not found in the request")
		WriteErrorResponse(w, "Refresh token not found", http.StatusUnauthorized)
		return
	}

	// Validate application's refresh token locally
	userID, err := h.Database.ValidateRefreshToken(refreshTokenString)
	if err != nil {
		h.Logger.WithError(err).Warn("Invalid or expired refresh token")
		WriteErrorResponse(w, "Invalid or expired refresh token", http.StatusUnauthorized)
		return
	}

	h.Logger.Infof("Refresh token validated for user ID: %s", userID)

	// Retrieve the provider's tokens from the database
	providerTokens, err := h.Database.GetProviderTokens(userID)
	if err != nil {
		h.Logger.WithError(err).Error("Failed to retrieve provider tokens")
		WriteErrorResponse(w, "Failed to retrieve provider tokens", http.StatusInternalServerError)
		return
	}

	h.Logger.Debugf("Provider tokens retrieved: %+v", providerTokens)

	// Refresh provider tokens if needed
	if err := h.refreshProviderTokens(userID, &providerTokens); err != nil {
		h.Logger.WithError(err).Warn("Unable to refresh provider tokens")
		h.Database.RevokeRefreshToken(refreshTokenString)
		WriteErrorResponse(w, "Unable to refresh session, please log in again", http.StatusUnauthorized)
		return
	}

	h.Logger.Debug("Provider tokens refreshed successfully")

	// Use the access token to get the user's info
	userInfo, err := h.getUserInfoFunc(providerTokens.AccessToken)
	if err != nil {
		h.Logger.WithError(err).Error("Failed to retrieve user info")
		WriteErrorResponse(w, "Failed to retrieve user info", http.StatusUnauthorized)
		return
	}

	h.Logger.Infof("User info retrieved: %s (%s)", userInfo.Name, userInfo.Email)

	// Update claims
	claims := jwt.MapClaims{
		"sub":   userInfo.Sub,
		"name":  userInfo.Name,
		"email": userInfo.Email,
	}

	// Generate new tokens
	tokens, err := generateTokens(claims, h.Config)
	if err != nil {
		h.Logger.WithError(err).Error("Failed to generate new tokens")
		WriteErrorResponse(w, "Failed to generate tokens", http.StatusInternalServerError)
		return
	}

	h.Logger.Debugf("New tokens generated: %+v", tokens)

	// Store new refresh token and revoke the old one
	err = h.Database.StoreRefreshToken(tokens.RefreshToken, userID, time.Now().Add(h.Config.RefreshTokenExpiration))
	if err != nil {
		h.Logger.WithError(err).Error("Failed to store new refresh token")
		WriteErrorResponse(w, "Failed to store refresh token", http.StatusInternalServerError)
		return
	}
	h.Database.RevokeRefreshToken(refreshTokenString)
	h.Logger.Debug("Old refresh token revoked and new one stored")

	// Set the new tokens in cookies
	setAuthCookies(w, tokens, h.Config)
	h.Logger.Debug("New auth cookies set")

	// Respond with tokens in the response body
	WriteSuccessResponse(w, "Token refreshed successfully", tokens)
	h.Logger.Info("User tokens refreshed successfully")
}

// Helper methods for the Handler struct
func (h *Handler) revokeTokens(accessTokenString, refreshTokenString string) error {
	// Revoke access token if present
	if accessTokenString != "" {
		err := h.Database.AddBlacklistedToken(accessTokenString, getTokenExpiration(accessTokenString))
		if err != nil {
			logrus.WithError(err).Error("Failed to blacklist access token during logout")
			return err
		}
	}

	// Revoke refresh token if present
	if refreshTokenString != "" {
		err := h.Database.RevokeRefreshToken(refreshTokenString)
		if err != nil {
			logrus.WithError(err).Error("Failed to revoke refresh token during logout")
			return err
		}
	}

	return nil
}

func (h *Handler) refreshProviderTokens(userID string, providerTokens *ProviderTokens) error {
	if providerTokens.RefreshToken != "" {
		// Exchange the provider's refresh token for a new access token
		newProviderTokens, err := h.exchangeProviderRefreshTokenFunc(providerTokens.RefreshToken)
		if err != nil {
			return err
		}

		*providerTokens = ProviderTokens{
			AccessToken:  newProviderTokens.AccessToken,
			RefreshToken: newProviderTokens.RefreshToken,
			ExpiresAt:    newProviderTokens.Expiry,
		}
		// Update the provider's tokens in the database
		err = h.Database.UpdateProviderTokens(userID, *providerTokens)
		if err != nil {
			return err
		}
	}

	if providerTokens.ExpiresAt.Before(time.Now()) {
		return fmt.Errorf("oauth2 provider access_token expired")
	}

	return nil
}
