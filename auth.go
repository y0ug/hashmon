package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/sirupsen/logrus"
	"github.com/y0ug/hashmon/config"
)

type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"`
}

// Generate a random state string for CSRF protection
func generateStateString() string {
	b := make([]byte, 16)
	_, err := rand.Read(b)
	if err != nil {
		// Handle error appropriately in production
		panic(err)
	}
	return base64.URLEncoding.EncodeToString(b)
}

// Placeholder for state validation
func validateState(state string) bool {
	// Implement state validation using sessions or secure storage
	return true
}

func (ws *WebServer) handleLogin(w http.ResponseWriter, r *http.Request) {
	state := generateStateString()
	// TODO: Store 'state' in session for later validation

	url := ws.config.OAuth2Config.AuthCodeURL(state)
	http.Redirect(w, r, url, http.StatusTemporaryRedirect)
}

// generateTokens creates both access and refresh JWT tokens
func generateTokens(claims jwt.MapClaims, config *config.WebserverConfig) (*TokenResponse, error) {
	// Define access token expiration (e.g., 15 minutes)
	accessExpirationTime := time.Now().Add(15 * time.Minute)
	accessClaims := jwt.MapClaims{
		"sub":   claims["sub"],
		"name":  claims["name"],
		"email": claims["email"],
		"exp":   accessExpirationTime.Unix(),
		"iat":   time.Now().Unix(),
		// Add more custom claims as needed
	}

	// Create access token
	accessToken := jwt.NewWithClaims(jwt.SigningMethodHS256, accessClaims)
	accessTokenString, err := accessToken.SignedString(config.JwtSecret)
	if err != nil {
		return nil, err
	}

	// Define refresh token expiration (e.g., 7 days)
	refreshExpirationTime := time.Now().Add(7 * 24 * time.Hour)
	refreshClaims := jwt.MapClaims{
		"sub":  claims["sub"],
		"exp":  refreshExpirationTime.Unix(),
		"iat":  time.Now().Unix(),
		"type": "refresh",
	}

	// Create refresh token
	refreshToken := jwt.NewWithClaims(jwt.SigningMethodHS256, refreshClaims)
	refreshTokenString, err := refreshToken.SignedString(config.JwtSecret)
	if err != nil {
		return nil, err
	}

	return &TokenResponse{
		AccessToken:  accessTokenString,
		RefreshToken: refreshTokenString,
		TokenType:    "Bearer",
		ExpiresIn:    int64(accessExpirationTime.Sub(time.Now()).Seconds()),
	}, nil
}

func (ws *WebServer) handleCallback(w http.ResponseWriter, r *http.Request) {
	state := r.URL.Query().Get("state")
	if !validateState(state) {
		http.Error(w, "Invalid state parameter", http.StatusBadRequest)
		return
	}

	code := r.URL.Query().Get("code")
	if code == "" {
		http.Error(w, "Code not found", http.StatusBadRequest)
		return
	}

	// Exchange code for tokens
	token, err := ws.config.OAuth2Config.Exchange(context.Background(), code)
	if err != nil {
		fmt.Printf("Token exchange failed: %v\n", err)
		http.Error(w, "Failed to exchange token", http.StatusInternalServerError)
		return
	}

	// Extract ID token
	idToken, ok := token.Extra("id_token").(string)
	if !ok {
		http.Error(w, "No id_token field in oauth2 token", http.StatusInternalServerError)
		return
	}

	// Decode ID token to get user info
	userInfo, err := decodeIDToken(idToken, ws.config)
	if err != nil {
		fmt.Printf("Failed to decode ID token: %v\n", err)
		http.Error(w, "Failed to decode ID token", http.StatusInternalServerError)
		return
	}
	// Generate both access and refresh tokens
	tokens, err := generateTokens(userInfo, ws.config)
	if err != nil {
		fmt.Printf("Failed to generate tokens: %v\n", err)
		http.Error(w, "Failed to generate tokens", http.StatusInternalServerError)
		return
	}

	// Extracting the exp
	expFloat, ok := userInfo["exp"].(float64)
	if !ok {
		http.Error(w, "Invalid expiration in token", http.StatusUnauthorized)
		return
	}
	// Store the refresh token in the database
	err = ws.Monitor.Config.Database.StoreRefreshToken(tokens.RefreshToken,
		userInfo["sub"].(string),
		time.Unix(int64(expFloat), 0))
	if err != nil {
		fmt.Printf("Failed to store refresh token: %v\n", err)
		http.Error(w, "Failed to store refresh token", http.StatusInternalServerError)
		return
	}

	// Define token expiration (e.g., 1 hour)
	expirationTime := time.Now().Add(1 * time.Hour)

	accessCookie := &http.Cookie{
		Name:     "access_token",
		Value:    tokens.AccessToken,
		Expires:  expirationTime,
		HttpOnly: true,                 // Prevents JavaScript access
		Secure:   false,                // Ensures the cookie is sent over HTTPS
		Path:     "/",                  // Cookie is valid for all paths
		SameSite: http.SameSiteLaxMode, // Adjust based on your needs
	}

	// Set the cookie in the response
	http.SetCookie(w, accessCookie)

	// Set the refresh token in a secure HttpOnly cookie
	refreshCookie := &http.Cookie{
		Name:     "refresh_token",
		Value:    tokens.RefreshToken,
		Expires:  time.Now().Add(7 * 24 * time.Hour),
		HttpOnly: true,
		Secure:   false,
		Path:     "/auth/refresh",
		SameSite: http.SameSiteLaxMode,
	}
	http.SetCookie(w, refreshCookie)

	http.Redirect(w, r, ws.config.RedirectURL, http.StatusSeeOther)

	// // Create the response
	// response := TokenResponse{
	// 	AccessToken: jwtToken,
	// 	TokenType:   "Bearer",
	// 	ExpiresIn:   int64(time.Until(expirationTime).Seconds()),
	// }
	//
	// fmt.Printf("User Info: %v", userInfo)
	// // Set Content-Type to application/json
	// w.Header().Set("Content-Type", "application/json")
	// // Send the response
	// json.NewEncoder(w).Encode(response)
	// // TODO: Create a session for the user or issue your own JWT
}

// Decode and validate ID token
func decodeIDToken(idToken string, config *config.WebserverConfig) (jwt.MapClaims, error) {
	// Fetch JWKS
	// jwksURL := fmt.Sprintf("https://%s/.well-known/jwks.json", config.Auth0Domain)
	set, err := jwk.Fetch(context.Background(), config.OauthWellknownJwks)
	if err != nil {
		return nil, err
	}

	token, err := jwt.Parse(idToken, func(token *jwt.Token) (interface{}, error) {
		// Ensure token is signed with RSA
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}

		// Get kid from token header
		kid, ok := token.Header["kid"].(string)
		if !ok {
			return nil, fmt.Errorf("kid header not found")
		}

		// Lookup the key
		key, exists := set.LookupKeyID(kid)
		if !exists {
			return nil, fmt.Errorf("unable to find key %s", kid)
		}

		var publicKey interface{}
		if err := key.Raw(&publicKey); err != nil {
			return nil, err
		}

		return publicKey, nil
	})
	if err != nil {
		return nil, err
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		return claims, nil
	}

	return nil, fmt.Errorf("invalid token")
}

func authMiddleware(ws *WebServer) func(http.Handler) http.Handler {
	// Fetch JWKS at startup
	// jwks, err := jwk.Fetch(context.Background(), fmt.Sprintf("https://%s/.well-known/jwks.json", config.Auth0Domain))
	// jwks, err := jwk.Fetch(context.Background(), ws.config.OauthWellknownJwks)
	// if err != nil {
	// 	panic(fmt.Sprintf("Failed to fetch JWKS: %v", err))
	// }

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var tokenString string

			// Check the Authorization header for a Bearer token
			authHeader := r.Header.Get("Authorization")
			if authHeader != "" {
				parts := strings.SplitN(authHeader, " ", 2)
				if len(parts) == 2 && strings.ToLower(parts[0]) == "bearer" {
					tokenString = parts[1]
				}
			}

			// If no Bearer token, check for JWT in the cookie
			if tokenString == "" {
				cookie, err := r.Cookie("access_token")
				if err == nil {
					tokenString = cookie.Value
				}
			}

			// If no token found, reject the request
			if tokenString == "" {
				http.Error(w, "Authorization token not found", http.StatusUnauthorized)
				return
			}

			// Check if the token is blacklisted
			blacklisted, err := ws.Monitor.Config.Database.IsTokenBlacklisted(tokenString)
			if err != nil {
				http.Error(w, "Internal server error", http.StatusInternalServerError)
				return
			}
			if blacklisted {
				http.Error(w, "Token has been revoked", http.StatusUnauthorized)
				return
			}

			// Parse and validate the token
			token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
				// Ensure token is signed with HS256
				if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
					return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
				}
				return ws.config.JwtSecret, nil
			})

			if err != nil || !token.Valid {
				fmt.Printf("Token error: %v\n", err)
				http.Error(w, "Invalid token", http.StatusUnauthorized)
				return
			}

			// Validate token claims
			if claims, ok := token.Claims.(jwt.MapClaims); ok {
				// Validate expiration
				if exp, ok := claims["exp"].(float64); !ok || float64(time.Now().Unix()) > exp {
					http.Error(w, "Token has expired", http.StatusUnauthorized)
					return
				}

				// (Optional) Validate other claims like issuer, audience, etc.

				// Attach claims to the request context
				ctx := context.WithValue(r.Context(), "user", claims)
				next.ServeHTTP(w, r.WithContext(ctx))
				return
			}

			http.Error(w, "Invalid token claims", http.StatusUnauthorized)
		})
	}
}

// StatusResponse defines the structure of the /status response
type StatusResponse struct {
	Authenticated bool     `json:"authenticated"`
	User          UserInfo `json:"user,omitempty"`
	Message       string   `json:"message,omitempty"`
}

// UserInfo represents the authenticated user's information
type UserInfo struct {
	Sub   string `json:"sub"`
	Name  string `json:"name"`
	Email string `json:"email"`
	// Add more fields as needed
}

// handleStatus checks authentication status and returns user info
func (ws *WebServer) handleStatus(w http.ResponseWriter, r *http.Request) {
	// Retrieve user claims from context (set by authMiddleware)
	claims, ok := r.Context().Value("user").(jwt.MapClaims)
	if !ok || claims == nil {
		// This should not happen as authMiddleware already validates the token
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
		// Extract additional fields as needed
	}

	// Respond with authenticated status and user info
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(StatusResponse{
		Authenticated: true,
		User:          user,
	})
}

// LogoutResponse defines the structure of the logout response
type LogoutResponse struct {
	Message string `json:"message"`
}

// handleLogout logs the user out by removing the JWT cookie and blacklisting the token.
func (ws *WebServer) handleLogout(w http.ResponseWriter, r *http.Request) {
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
		err := ws.Monitor.Config.Database.AddBlacklistedToken(accessTokenString, getTokenExpiration(accessTokenString))
		if err != nil {
			logrus.WithError(err).Error("Failed to blacklist access token during logout")
			http.Error(w, "Failed to logout", http.StatusInternalServerError)
			return
		}
	}

	// Revoke refresh token if present
	if refreshTokenString != "" {
		err := ws.Monitor.Config.Database.RevokeRefreshToken(refreshTokenString)
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

	// Respond to the client
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(LogoutResponse{
		Message: "Successfully logged out",
	})
}

// Helper function to extract token expiration
func getTokenExpiration(tokenString string) int64 {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return nil, nil // We don't need to validate the token here
	})
	if err != nil || !token.Valid {
		return time.Now().Unix()
	}
	if claims, ok := token.Claims.(jwt.MapClaims); ok {
		if exp, ok := claims["exp"].(float64); ok {
			return int64(exp)
		}
	}
	return time.Now().Unix()
}

func (ws *WebServer) handleRefresh(w http.ResponseWriter, r *http.Request) {
	// Extract refresh token from cookie
	cookie, err := r.Cookie("refresh_token")
	if err != nil {
		http.Error(w, "Refresh token not found", http.StatusUnauthorized)
		return
	}
	refreshTokenString := cookie.Value

	// Validate the refresh token
	userID, err := ws.Monitor.Config.Database.ValidateRefreshToken(refreshTokenString)
	if err != nil {
		http.Error(w, "Invalid or expired refresh token", http.StatusUnauthorized)
		return
	}

	// Optionally, you can parse the refresh token to extract claims
	token, err := jwt.Parse(refreshTokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return ws.config.JwtSecret, nil
	})
	if err != nil || !token.Valid {
		http.Error(w, "Invalid refresh token", http.StatusUnauthorized)
		return
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		http.Error(w, "Invalid token claims", http.StatusUnauthorized)
		return
	}

	// Optionally, check if the token type is 'refresh'
	if tokenType, ok := claims["type"].(string); !ok || tokenType != "refresh" {
		http.Error(w, "Invalid token type", http.StatusUnauthorized)
		return
	}

	// Retrieve user information from database or cache as needed
	// For simplicity, we'll assume user information is stored in the token claims

	// Generate new access token
	newAccessToken, err := generateAccessToken(claims, ws.config)
	if err != nil {
		http.Error(w, "Failed to generate access token", http.StatusInternalServerError)
		return
	}

	// Optionally, implement refresh token rotation
	// Generate a new refresh token and revoke the old one
	newRefreshToken, err := generateRefreshToken(claims, ws.config)
	if err != nil {
		http.Error(w, "Failed to generate refresh token", http.StatusInternalServerError)
		return
	}

	// Store the new refresh token
	err = ws.Monitor.Config.Database.StoreRefreshToken(newRefreshToken, userID, time.Now().Add(7*24*time.Hour))
	if err != nil {
		http.Error(w, "Failed to store refresh token", http.StatusInternalServerError)
		return
	}

	// Revoke the old refresh token
	err = ws.Monitor.Config.Database.RevokeRefreshToken(refreshTokenString)
	if err != nil {
		http.Error(w, "Failed to revoke old refresh token", http.StatusInternalServerError)
		return
	}

	// Set the new access token in a cookie
	accessExpirationTime := time.Now().Add(15 * time.Minute)
	accessCookie := &http.Cookie{
		Name:     "access_token",
		Value:    newAccessToken,
		Expires:  accessExpirationTime,
		HttpOnly: true,
		Secure:   false,
		Path:     "/",
		SameSite: http.SameSiteLaxMode,
	}
	http.SetCookie(w, accessCookie)

	// Set the new refresh token in a cookie
	refreshCookie := &http.Cookie{
		Name:     "refresh_token",
		Value:    newRefreshToken,
		Expires:  time.Now().Add(7 * 24 * time.Hour),
		HttpOnly: true,
		Secure:   false,
		Path:     "/auth/refresh",
		SameSite: http.SameSiteLaxMode,
	}
	http.SetCookie(w, refreshCookie)

	// Respond with the new access token
	response := TokenResponse{
		AccessToken:  newAccessToken,
		RefreshToken: newRefreshToken,
		TokenType:    "Bearer",
		ExpiresIn:    int64(accessExpirationTime.Sub(time.Now()).Seconds()),
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// Helper functions to generate access and refresh tokens separately

func generateAccessToken(claims jwt.MapClaims, config *config.WebserverConfig) (string, error) {
	accessExpirationTime := time.Now().Add(15 * time.Minute)
	accessClaims := jwt.MapClaims{
		"sub":   claims["sub"],
		"name":  claims["name"],
		"email": claims["email"],
		"exp":   accessExpirationTime.Unix(),
		"iat":   time.Now().Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, accessClaims)
	return token.SignedString(config.JwtSecret)
}

func generateRefreshToken(claims jwt.MapClaims, config *config.WebserverConfig) (string, error) {
	refreshExpirationTime := time.Now().Add(7 * 24 * time.Hour)
	refreshClaims := jwt.MapClaims{
		"sub":  claims["sub"],
		"exp":  refreshExpirationTime.Unix(),
		"iat":  time.Now().Unix(),
		"type": "refresh",
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, refreshClaims)
	return token.SignedString(config.JwtSecret)
}
