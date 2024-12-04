package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/sirupsen/logrus"
)

// TokenResponse represents the structure of token response.
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"`
}

// LogoutResponse defines the structure of the logout response.
type LogoutResponse struct {
	Message string `json:"message"`
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

// Handler holds the authentication handlers and dependencies.
type Handler struct {
	Config     *Config
	Database   Database
	Middleware *Middleware
}

// NewHandler initializes a new authentication handler.
func NewHandler(config *Config, db Database) *Handler {
	return &Handler{
		Config:     config,
		Database:   db,
		Middleware: NewMiddleware(config, db),
	}
}

// AuthMiddleware returns the authentication middleware.
func (h *Handler) AuthMiddleware(next http.Handler) http.Handler {
	return h.Middleware.AuthMiddleware(next)
}

// HandleLogin handles the login endpoint.
func (h *Handler) HandleLogin(w http.ResponseWriter, r *http.Request) {
	state := generateStateString()
	// TODO: Store 'state' in session for later validation

	url := h.Config.OAuth2Config.AuthCodeURL(state)
	http.Redirect(w, r, url, http.StatusTemporaryRedirect)
}

// HandleCallback handles the OAuth2 callback and exchanges the code for tokens.
func (h *Handler) HandleCallback(w http.ResponseWriter, r *http.Request) {
	// Extract the authorization code from the query parameters
	code := r.URL.Query().Get("code")
	if code == "" {
		http.Error(w, "Code not found in the request", http.StatusBadRequest)
		return
	}

	// Exchange the code for tokens
	token, err := h.Config.OAuth2Config.Exchange(context.Background(), code)
	if err != nil {
		logrus.WithError(err).Error("Token exchange failed")
		http.Error(w, "Failed to exchange token", http.StatusInternalServerError)
		return
	}

	logrus.WithField("token", token).Debug("Token exchange successful")

	// Check if the refresh token is present
	if token.RefreshToken == "" {
		logrus.Warn("No refresh token received from the provider")
		// Depending on your application's requirements, decide how to handle this
		// For example, you might prompt the user to re-authenticate with the necessary scopes
	}

	// Extract user info from the ID token or access token
	idToken, ok := token.Extra("id_token").(string)
	if !ok {
		http.Error(w, "Failed to extract ID token", http.StatusInternalServerError)
		return
	}
	logrus.WithField("id_token", idToken).Debug("id_token")

	userClaims, err := decodeIDToken(idToken, h.Config)
	if err != nil {
		fmt.Printf("Failed to decode ID token: %v\n", err)
		http.Error(w, "Failed to decode ID token", http.StatusInternalServerError)
		return
	}

	userID := userClaims["sub"].(string)
	userName := userClaims["name"].(string)
	userEmail := userClaims["email"].(string)

	// Create ProviderTokens struct
	providerTokens := ProviderTokens{
		AccessToken:  token.AccessToken,
		RefreshToken: token.RefreshToken,
		ExpiresAt:    token.Expiry,
	}

	// Store ProviderTokens in the database
	err = h.Database.StoreProviderTokens(userID, providerTokens)
	if err != nil {
		logrus.WithError(err).Error("Failed to store provider tokens")
		http.Error(w, "Failed to store tokens", http.StatusInternalServerError)
		return
	}

	// Generate your application's tokens (if applicable)
	claimsMap := jwt.MapClaims{
		"sub":   userID,
		"name":  userName,
		"email": userEmail,
		"exp":   time.Now().Add(15 * time.Minute).Unix(),
		"iat":   time.Now().Unix(),
	}

	// Generate your application's access token
	newAccessToken, err := generateAccessToken(claimsMap, h.Config)
	if err != nil {
		http.Error(w, "Failed to generate access token", http.StatusInternalServerError)
		return
	}

	// Generate your application's refresh token
	newRefreshToken, err := generateRefreshToken(claimsMap, h.Config)
	if err != nil {
		http.Error(w, "Failed to generate refresh token", http.StatusInternalServerError)
		return
	}

	// Store your application's refresh token
	err = h.Database.StoreRefreshToken(newRefreshToken, userID, time.Now().Add(7*24*time.Hour))
	if err != nil {
		http.Error(w, "Failed to store refresh token", http.StatusInternalServerError)
		return
	}

	// Revoke the old refresh token if implementing refresh token rotation
	// h.Database.RevokeRefreshToken(oldRefreshToken)

	// Set tokens in cookies or respond with tokens
	tokens := &TokenResponse{
		AccessToken:  newAccessToken,
		RefreshToken: newRefreshToken,
		TokenType:    "Bearer",
		ExpiresIn:    int64(time.Until(time.Now().Add(15 * time.Minute)).Seconds()),
	}
	setAuthCookies(w, tokens, h.Config)

	// Optionally, respond with tokens in the response body
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(tokens)
}

// HandleStatus checks authentication status and returns user info.
func (h *Handler) HandleStatus(w http.ResponseWriter, r *http.Request) {
	// Retrieve user claims from context (set by AuthMiddleware)
	claims, ok := r.Context().Value("user").(jwt.MapClaims)
	if !ok || claims == nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(StatusResponse{
			Authenticated: false,
			Message:       "Failed to retrieve user information",
		})
		return
	}

	// Extract user information from claims
	user := UserInfo{
		Sub:   claims["sub"].(string),
		Name:  claims["name"].(string),
		Email: claims["email"].(string),
	}

	// Respond with authenticated status and user info
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(StatusResponse{
		Authenticated: true,
		User:          user,
	})
}

// HandleLogout logs the user out by removing the JWT cookie and blacklisting the token.
func (h *Handler) HandleLogout(w http.ResponseWriter, r *http.Request) {
	var accessTokenString, refreshTokenString string

	// Extract access token from Authorization header or cookie
	authHeader := r.Header.Get("Authorization")
	if authHeader != "" {
		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) == 2 && strings.ToLower(parts[0]) == "bearer" {
			accessTokenString = parts[1]
		}
	}
	if accessTokenString == "" {
		cookie, err := r.Cookie("access_token")
		if err == nil {
			accessTokenString = cookie.Value
		}
	}

	// Extract refresh token from cookie
	cookie, err := r.Cookie("refresh_token")
	if err == nil {
		refreshTokenString = cookie.Value
	}

	// Revoke access token if present
	if accessTokenString != "" {
		err := h.Database.AddBlacklistedToken(accessTokenString, getTokenExpiration(accessTokenString))
		if err != nil {
			logrus.WithError(err).Error("Failed to blacklist access token during logout")
			http.Error(w, "Failed to logout", http.StatusInternalServerError)
			return
		}
	}

	// Revoke refresh token if present
	if refreshTokenString != "" {
		err := h.Database.RevokeRefreshToken(refreshTokenString)
		if err != nil {
			logrus.WithError(err).Error("Failed to revoke refresh token during logout")
			http.Error(w, "Failed to logout", http.StatusInternalServerError)
			return
		}
	}

	// Remove the access token cookie
	expiredAccessCookie := &http.Cookie{
		Name:     "access_token",
		Value:    "",
		Expires:  time.Unix(0, 0),
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   false,
		Path:     "/",
		SameSite: http.SameSiteLaxMode,
	}
	http.SetCookie(w, expiredAccessCookie)

	// Remove the refresh token cookie
	expiredRefreshCookie := &http.Cookie{
		Name:     "refresh_token",
		Value:    "",
		Expires:  time.Unix(0, 0),
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   false,
		Path:     "/auth/refresh",
		SameSite: http.SameSiteLaxMode,
	}
	http.SetCookie(w, expiredRefreshCookie)

	// Build the end-session URL
	if h.Config.OauthEndSessionURL != "" {
		endSessionURL, err := h.buildEndSessionURL(r)
		if err != nil {
			logrus.WithError(err).Error("Failed to build end session URL")
			http.Error(w, "Failed to logout", http.StatusInternalServerError)
			return
		}

		// Redirect the user to the end-session endpoint
		http.Redirect(w, r, endSessionURL, http.StatusFound)
	}

	// Respond to the client
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(LogoutResponse{
		Message: "Successfully logged out",
	})
}

// HandleRefresh handles token refresh.
func (h *Handler) HandleRefresh(w http.ResponseWriter, r *http.Request) {
	// Extract your application's refresh token from cookie
	cookie, err := r.Cookie("refresh_token")
	if err != nil {
		http.Error(w, "Refresh token not found", http.StatusUnauthorized)
		return
	}
	refreshTokenString := cookie.Value

	// Validate application's refresh token locally
	userID, err := h.Database.ValidateRefreshToken(refreshTokenString)
	if err != nil {
		http.Error(w, "Invalid or expired refresh token", http.StatusUnauthorized)
		return
	}

	// Parse and validate the token to get the user info
	token, err := jwt.Parse(refreshTokenString, func(token *jwt.Token) (interface{}, error) {
		// Ensure token is signed with HS256
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return h.Config.JwtSecret, nil
	})

	if err != nil || !token.Valid {
		logrus.WithError(err).Error("Invalid Refresh token")
		http.Error(w, "Invalid refresh token", http.StatusUnauthorized)
		return
	}

	// Validate token claims
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		http.Error(w, "Claim not available in refresh token", http.StatusUnauthorized)
		http.Error(w, "Invalid refresh token", http.StatusUnauthorized)
		return
	}

	// Retrieve the provider's tokens from the database
	providerTokens, err := h.Database.GetProviderTokens(userID)
	if err != nil {
		http.Error(w, "Failed to retrieve provider tokens", http.StatusInternalServerError)
		return
	}

	if providerTokens.RefreshToken != "" {
		// logrus.Info("Provider refresh token found")

		// Exchange the provider's refresh token for a new access token
		newProviderTokens, err := h.exchangeProviderRefreshToken(providerTokens.RefreshToken)
		if err != nil {
			// Handle token exchange errors, possibly revoke the refresh token
			h.Database.RevokeRefreshToken(refreshTokenString)
			http.Error(w, "Unable to refresh session, please log in again", http.StatusUnauthorized)
			return
		}

		providerTokens = ProviderTokens{
			AccessToken:  newProviderTokens.AccessToken,
			RefreshToken: newProviderTokens.RefreshToken,
			ExpiresAt:    newProviderTokens.Expiry,
		}
		// Update the provider's tokens in the database
		err = h.Database.UpdateProviderTokens(userID, providerTokens)
		if err != nil {
			http.Error(w, "Failed to update provider tokens", http.StatusInternalServerError)
			return
		}
	}

	if providerTokens.ExpiresAt.Before(time.Now()) {
		http.Error(w, "oauth2 provider access_token expired", http.StatusUnauthorized)
		h.Database.RevokeRefreshToken(refreshTokenString)
		// TODO: black list the access token
		return
	}

	// Use the access token to get the user's info
	userInfo, err := h.getUserInfo(providerTokens.AccessToken)
	if err != nil {
		http.Error(w, "Failed to retrieve user info", http.StatusInternalServerError)
		return
	}

	// Update claims
	claims = jwt.MapClaims{
		"sub":   userInfo.Sub,
		"name":  userInfo.Name,
		"email": userInfo.Email,
		"exp":   time.Now().Add(15 * time.Minute).Unix(),
		"iat":   time.Now().Unix(),
	}

	// Generate your application's new access token
	newAccessToken, err := generateAccessToken(claims, h.Config)
	if err != nil {
		http.Error(w, "Failed to generate access token", http.StatusInternalServerError)
		return
	}

	// Generate your application's new refresh token
	newRefreshToken, err := generateRefreshToken(claims, h.Config)
	if err != nil {
		http.Error(w, "Failed to generate refresh token", http.StatusInternalServerError)
		return
	}

	// Store your application's new refresh token and revoke the old one
	err = h.Database.StoreRefreshToken(newRefreshToken, userID, time.Now().Add(7*24*time.Hour))
	if err != nil {
		http.Error(w, "Failed to store refresh token", http.StatusInternalServerError)
		return
	}
	h.Database.RevokeRefreshToken(refreshTokenString)

	// Set the new tokens in cookies or respond with tokens
	tokens := &TokenResponse{
		AccessToken:  newAccessToken,
		RefreshToken: newRefreshToken,
		TokenType:    "Bearer",
		ExpiresIn:    int64(time.Until(time.Now().Add(15 * time.Minute)).Seconds()),
	}
	setAuthCookies(w, tokens, h.Config)

	// Optionally, respond with tokens in the response body
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(tokens)
}
