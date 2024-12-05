package auth

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/gorilla/mux"
	"github.com/sirupsen/logrus"
	"github.com/y0ug/hashmon/pkg/auth/providers"
)

// Handler holds the authentication handlers and dependencies.
type Handler struct {
	Config     *Config
	Database   Database
	Middleware *Middleware
	Logger     *logrus.Logger // Logger instance
}

// NewHandler initializes a new authentication handler.
func NewHandler(config *Config, db Database, logger *logrus.Logger) *Handler {
	h := &Handler{
		Config:     config,
		Database:   db,
		Middleware: NewMiddleware(config, db, logger),
		Logger:     logger,
	}

	return h
}

// AuthMiddleware returns the authentication middleware.
func (h *Handler) AuthMiddleware(next http.Handler) http.Handler {
	return h.Middleware.AuthMiddleware(next)
}

type ProviderResponse struct {
	Name string `json:"name"`
	Type string `json:"type"`
}

func (h *Handler) HandlerProviders(w http.ResponseWriter, r *http.Request) {
	providers := make([]ProviderResponse, 0, len(h.Config.Providers))
	for name, p := range h.Config.Providers {
		providers = append(providers, ProviderResponse{
			Name: name,
			Type: p.Config().Type,
		})
	}
	WriteSuccessResponse(w, "Providers list", providers)
}

// HandleLogin handles the login endpoint.
func (h *Handler) HandleLogin(w http.ResponseWriter, r *http.Request) {
	h.Logger.Debug("HandleLogin invoked")

	providerName, err := h.extractProvider(r)
	if err != nil {
		h.logAndRespondError(w, "HandleLogin", err, http.StatusBadRequest)
		return
	}

	provider, exists := h.Config.Providers[providerName]
	if !exists {
		h.logAndRespondError(w, "HandleLogin", ErrProviderNotFound, http.StatusBadRequest)
		return
	}

	state := generateStateString()
	h.Logger.WithFields(logrus.Fields{
		"provider": providerName,
		"state":    state,
	}).Debug("Generated state for OAuth2 login")

	// TODO: Store 'state' in session for later validation

	url := provider.OAuth2Config().AuthCodeURL(state)
	h.Logger.WithFields(logrus.Fields{
		"provider":     providerName,
		"redirect_url": url,
	}).Info("Redirecting user to OAuth2 provider for login")

	http.Redirect(w, r, url, http.StatusTemporaryRedirect)
}

// HandleCallback handles the OAuth2 callback and exchanges the code for tokens.
func (h *Handler) HandleCallback(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	h.Logger.Debug("HandleCallback invoked")

	providerName, err := h.extractProvider(r)
	if err != nil {
		h.logAndRespondError(w, "HandleCallback", err, http.StatusBadRequest)
		return
	}

	provider, exists := h.Config.Providers[providerName]
	if !exists {
		h.logAndRespondError(w, "HandleCallback", ErrProviderNotFound, http.StatusBadRequest)
		return
	}

	code := r.URL.Query().Get("code")
	if code == "" {
		h.Logger.Warn("Authorization code not found in the request")
		h.logAndRespondError(w, "HandleCallback", fmt.Errorf("code not found"), http.StatusBadRequest)
		return
	}

	h.Logger.WithField("code", code).Debug("Authorization code received")

	// Exchange the code for tokens
	token, err := provider.ExchangeCode(ctx, code)
	if err != nil {
		h.Logger.WithError(err).Error("Token exchange failed")
		h.logAndRespondError(w, "HandleCallback", fmt.Errorf("failed to exchange token: %w", err), http.StatusInternalServerError)
		return
	}

	h.Logger.WithFields(logrus.Fields{
		"access_token":  token.AccessToken,
		"refresh_token": token.RefreshToken,
		"expiry":        token.Expiry,
	}).Debug("Token exchange successful")

	// Create ProviderTokens struct
	providerTokens := ProviderTokens{
		AccessToken:  token.AccessToken,
		RefreshToken: token.RefreshToken,
		ExpiresAt:    token.Expiry,
	}

	// Extract user info from the ID token or access token using provider interface
	userProviderInfo, err := provider.DecodeIDToken(ctx, token)
	if err != nil {
		h.logAndRespondError(w, "HandleCallback", err, http.StatusInternalServerError)
		return
	}

	h.Logger.WithFields(logrus.Fields{
		"userInfoProvider": userProviderInfo,
	}).Info("User authenticated successfully")

	userID := fmt.Sprintf("%s:%s", provider.Name(), userProviderInfo.Sub)

	// Store ProviderTokens in the database using request context
	err = h.Database.StoreProviderTokens(ctx, userID, providerName, providerTokens)
	if err != nil {
		h.Logger.WithError(err).Error("Failed to store provider tokens")
		h.logAndRespondError(w, "HandleCallback", fmt.Errorf("failed to store tokens: %w", err), http.StatusInternalServerError)
		return
	}

	h.Logger.Debug("Provider tokens stored successfully")

	// Generate your application's tokens
	claimsMap := jwt.MapClaims{
		"sub":      userID,
		"name":     userProviderInfo.Name,
		"email":    userProviderInfo.Email,
		"picture":  userProviderInfo.Picture,
		"provider": providerName,
	}

	tokens, err := generateTokens(claimsMap, h.Config)
	if err != nil {
		h.Logger.WithError(err).Error("Failed to generate tokens")
		h.logAndRespondError(w, "HandleCallback", fmt.Errorf("failed to generate tokens: %w", err), http.StatusInternalServerError)
		return
	}

	h.Logger.WithFields(logrus.Fields{
		"access_token":  tokens.AccessToken,
		"refresh_token": tokens.RefreshToken,
	}).Debug("Generated application tokens")

	// Store your application's refresh token with expiration from config
	err = h.Database.StoreRefreshToken(ctx, tokens.RefreshToken, userID, time.Now().Add(h.Config.RefreshTokenExpiration))
	if err != nil {
		h.Logger.WithError(err).Error("Failed to store refresh token")
		h.logAndRespondError(w, "HandleCallback", fmt.Errorf("failed to store refresh token: %w", err), http.StatusInternalServerError)
		return
	}

	h.Logger.Debug("Refresh token stored successfully")

	// Set tokens in cookies
	setAuthCookies(w, tokens, h.Config)
	h.Logger.Debug("Auth cookies set successfully")

	// Respond with tokens in the response body
	WriteSuccessResponse(w, "Token exchange successful", tokens)
	h.Logger.Info("User logged in successfully")
}

// HandleStatus checks authentication status and returns user info.
func (h *Handler) HandleStatus(w http.ResponseWriter, r *http.Request) {
	claims, err := h.getUserClaimsFromContext(r.Context())
	if err != nil {
		h.logAndRespondError(w, "HandleStatus", err, http.StatusInternalServerError)
		return
	}

	user := UserInfo{
		Sub:      claims["sub"].(string),
		Name:     claims["name"].(string),
		Email:    claims["email"].(string),
		Picture:  claims["picture"].(string),
		Provider: claims["provider"].(string),
	}

	WriteSuccessResponse(w, "Authenticated", StatusResponse{
		Authenticated: true,
		User:          user,
	})
}

// HandleLogout logs the user out by removing the JWT cookie and blacklisting the token.
func (h *Handler) HandleLogout(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	h.Logger.Debug("HandleLogout invoked")

	claims, err := h.getUserClaimsFromContext(ctx)
	if err != nil {
		h.logAndRespondError(w, "HandleLogout", err, http.StatusInternalServerError)
		return
	}

	providerName, ok := claims["provider"].(string)
	if !ok || providerName == "" {
		h.Logger.Debug("Provider information missing in user claims")
		h.logAndRespondError(w, "HandleLogout", fmt.Errorf("provider information missing"), http.StatusInternalServerError)
		return
	}

	provider, exists := h.Config.Providers[providerName]
	if !exists {
		h.logAndRespondError(w, "HandleLogout", ErrProviderNotFound, http.StatusBadRequest)
		return
	}

	// Extract tokens using helper function
	accessTokenString := extractToken(r, "access_token")
	refreshTokenString := extractToken(r, "refresh_token")

	h.Logger.WithFields(logrus.Fields{
		"access_token":  accessTokenString,
		"refresh_token": refreshTokenString,
		"provider":      providerName,
	}).Debug("Extracted tokens for logout")

	// Revoke tokens using provider-specific logic
	if err := h.revokeTokens(ctx, provider, accessTokenString, refreshTokenString); err != nil {
		h.logAndRespondError(w, "HandleLogout", err, http.StatusInternalServerError)
		return
	}

	h.Logger.Info("User tokens revoked successfully")

	// Remove the cookies
	clearAuthCookies(w, h.Config)
	h.Logger.Debug("Auth cookies cleared successfully")

	// Optionally, handle end-session URL redirection here

	WriteSuccessResponse(w, "Successfully logged out", nil)
}

// HandleRefresh handles token refresh.
func (h *Handler) HandleRefresh(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	h.Logger.Debug("HandleRefresh invoked")

	// Extract refresh token
	refreshTokenString := extractToken(r, "refresh_token")
	if refreshTokenString == "" {
		h.Logger.Warn("Refresh token not found in the request")
		WriteErrorResponse(w, "Refresh token not found", http.StatusUnauthorized)
		return
	}

	h.Logger.WithField("refresh_token", refreshTokenString).Debug("Refresh token extracted")

	// Validate application's refresh token
	userID, err := h.Database.ValidateRefreshToken(ctx, refreshTokenString)
	if err != nil {
		h.Logger.WithError(err).Warn("Invalid or expired refresh token")
		WriteErrorResponse(w, "Invalid or expired refresh token", http.StatusUnauthorized)
		return
	}

	h.Logger.WithField("user_id", userID).Info("Refresh token validated")

	// Parse and validate the refresh token
	claims, err := parseJWT(refreshTokenString, h.Config.JwtSecret)
	if err != nil {
		h.Logger.WithError(err).Warn("Invalid refresh token")
		WriteErrorResponse(w, "Invalid token", http.StatusUnauthorized)
		return
	}

	providerName, ok := claims["provider"].(string)
	if !ok || providerName == "" {
		h.Logger.Warn("Provider information missing in refresh token claims")
		WriteErrorResponse(w, "Invalid token claims", http.StatusUnauthorized)
		return
	}

	provider, exists := h.Config.Providers[providerName]
	if !exists {
		h.Logger.Warn("Provider not found for refresh token")
		WriteErrorResponse(w, "Unknown provider", http.StatusBadRequest)
		return
	}

	// Retrieve the provider's tokens from the database
	providerTokens, err := h.Database.GetProviderTokens(ctx, userID, providerName)
	if err != nil {
		h.Logger.WithError(err).Error("Failed to retrieve provider tokens")
		WriteErrorResponse(w, "Failed to retrieve provider tokens", http.StatusInternalServerError)
		return
	}

	h.Logger.WithField("provider_tokens", providerTokens).Debug("Provider tokens retrieved")

	// Refresh provider tokens if needed
	if err := h.refreshProviderTokens(ctx, userID, &providerTokens, provider); err != nil {
		h.Logger.WithError(err).Warn("Unable to refresh provider tokens")
		h.Database.RevokeRefreshToken(ctx, refreshTokenString)
		WriteErrorResponse(w, "Unable to refresh session, please log in again", http.StatusUnauthorized)
		return
	}

	h.Logger.Debug("Provider tokens refreshed successfully")

	// Use the access token to get the user's info
	userInfo, err := provider.FetchUserInfo(ctx, providerTokens.AccessToken)
	if err != nil {
		h.Logger.WithError(err).Error("Failed to retrieve user info")
		WriteErrorResponse(w, "Failed to retrieve user info", http.StatusUnauthorized)
		return
	}

	h.Logger.WithFields(logrus.Fields{
		"user_info": userInfo,
	}).Info("User info retrieved from provider successfully")

	// Update claims
	newClaimsMap := jwt.MapClaims{
		"sub":      userID,
		"name":     userInfo.Name,
		"email":    userInfo.Email,
		"picture":  userInfo.Picture,
		"provider": providerName,
	}

	// Generate new tokens
	newTokens, err := generateTokens(newClaimsMap, h.Config)
	if err != nil {
		h.Logger.WithError(err).Error("Failed to generate new tokens")
		WriteErrorResponse(w, "Failed to generate tokens", http.StatusInternalServerError)
		return
	}

	h.Logger.WithFields(logrus.Fields{
		"access_token":  newTokens.AccessToken,
		"refresh_token": newTokens.RefreshToken,
	}).Debug("New tokens generated successfully")

	// Store new refresh token and revoke the old one
	err = h.Database.StoreRefreshToken(ctx, newTokens.RefreshToken, userID, time.Now().Add(h.Config.RefreshTokenExpiration))
	if err != nil {
		h.Logger.WithError(err).Error("Failed to store new refresh token")
		WriteErrorResponse(w, "Failed to store refresh token", http.StatusInternalServerError)
		return
	}
	err = h.Database.RevokeRefreshToken(ctx, refreshTokenString)
	if err != nil {
		h.Logger.WithError(err).Error("Failed to revoke old refresh token")
		// Proceeding even if revoking fails
	}
	h.Logger.Debug("Old refresh token revoked and new one stored")

	// Set the new tokens in cookies
	setAuthCookies(w, newTokens, h.Config)
	h.Logger.Debug("New auth cookies set successfully")

	// Respond with tokens in the response body
	WriteSuccessResponse(w, "Token refreshed successfully", newTokens)
	h.Logger.Info("User tokens refreshed successfully")
}

// Helper Methods

// extractProvider extracts the provider name from the request.
func (h *Handler) extractProvider(r *http.Request) (string, error) {
	providerName := mux.Vars(r)["provider"] // Assuming using gorilla/mux
	if providerName == "" {
		providerName = r.URL.Query().Get("provider")
	}
	if providerName == "" {
		return "", fmt.Errorf("provider not specified")
	}
	return providerName, nil
}

// logAndRespondError logs the error with context and sends an error response.
func (h *Handler) logAndRespondError(w http.ResponseWriter, context string, err error, statusCode int) {
	h.Logger.WithFields(logrus.Fields{
		"context": context,
		"error":   err,
	}).Errorf("%s encountered an error: %v", context, err)
	WriteErrorResponse(w, err.Error(), statusCode)
}

// getUserClaimsFromContext retrieves user claims from the request context.
func (h *Handler) getUserClaimsFromContext(ctx context.Context) (jwt.MapClaims, error) {
	claims, ok := ctx.Value("user").(jwt.MapClaims)
	if !ok || claims == nil {
		return nil, fmt.Errorf("failed to retrieve user information from context")
	}
	return claims, nil
}

// revokeTokens revokes access and refresh tokens.
func (h *Handler) revokeTokens(ctx context.Context, provider providers.Provider, accessTokenString, refreshTokenString string) error {
	if accessTokenString != "" {
		expiration := getTokenExpiration(accessTokenString)
		err := h.Database.AddBlacklistedToken(ctx, accessTokenString, expiration)
		if err != nil {
			h.Logger.WithError(err).Error("Failed to blacklist access token during logout")
			return err
		}
	}

	if refreshTokenString != "" {
		err := h.Database.RevokeRefreshToken(ctx, refreshTokenString)
		if err != nil {
			h.Logger.WithError(err).Error("Failed to revoke refresh token during logout")
			return err
		}
	}

	return nil
}

// refreshProviderTokens refreshes tokens from the OAuth2 provider.
func (h *Handler) refreshProviderTokens(ctx context.Context, userID string, providerTokens *ProviderTokens, provider providers.Provider) error {
	if providerTokens.RefreshToken != "" {
		newProviderToken, err := provider.RenewAccessToken(ctx, providerTokens.RefreshToken)
		if err != nil {
			return fmt.Errorf("failed to exchange provider refresh token: %w", err)
		}

		providerTokens.AccessToken = newProviderToken.AccessToken
		providerTokens.RefreshToken = newProviderToken.RefreshToken
		providerTokens.ExpiresAt = newProviderToken.Expiry

		err = h.Database.UpdateProviderTokens(ctx, userID, provider.Name(), *providerTokens)
		if err != nil {
			return fmt.Errorf("failed to update provider tokens: %w", err)
		}
	}

	// Github access token does not expire (value is 0)
	if providerTokens.ExpiresAt.IsZero() {
		return nil
	}

	if providerTokens.ExpiresAt.Before(time.Now()) {
		return fmt.Errorf("oauth2 provider access token expired")
	}

	return nil
}
