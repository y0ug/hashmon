package auth

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v4"
)

// generateStateString generates a random state string for CSRF protection.
func generateStateString() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		// In production, handle the error appropriately
		panic("unable to generate state string")
	}
	return base64.URLEncoding.EncodeToString(b)
}

// parseJWT parses and validates a JWT token string.
func parseJWT(tokenString string, secret []byte) (jwt.MapClaims, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Ensure token is signed with HS256
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return secret, nil
	})

	if err != nil || !token.Valid {
		return nil, fmt.Errorf("invalid token: %w", err)
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, fmt.Errorf("invalid token claims")
	}

	return claims, nil
}

// generateTokens creates both access and refresh JWT tokens.
func generateTokens(claims jwt.MapClaims, config *Config) (*TokenResponse, error) {
	// Define access token expiration using configuration
	accessExpirationTime := time.Now().Add(config.AccessTokenExpiration)
	accessClaims := claims
	accessClaims["exp"] = accessExpirationTime.Unix()
	accessClaims["iat"] = time.Now().Unix()
	accessClaims["type"] = "bearer"

	// Create access token
	accessToken := jwt.NewWithClaims(jwt.SigningMethodHS256, accessClaims)
	accessTokenString, err := accessToken.SignedString(config.JwtSecret)
	if err != nil {
		return nil, fmt.Errorf("failed to sign access token: %w", err)
	}

	// Define refresh token expiration using configuration
	refreshExpirationTime := time.Now().Add(config.RefreshTokenExpiration)
	refreshClaims := jwt.MapClaims{
		"sub":      claims["sub"],
		"exp":      refreshExpirationTime.Unix(),
		"iat":      time.Now().Unix(),
		"type":     "refresh",
		"provider": claims["provider"],
	}

	// Create refresh token
	refreshToken := jwt.NewWithClaims(jwt.SigningMethodHS256, refreshClaims)
	refreshTokenString, err := refreshToken.SignedString(config.JwtSecret)
	if err != nil {
		return nil, fmt.Errorf("failed to sign refresh token: %w", err)
	}

	return &TokenResponse{
		AccessToken:  accessTokenString,
		RefreshToken: refreshTokenString,
		TokenType:    "Bearer",
		ExpiresIn:    int64(time.Until(accessExpirationTime).Seconds()),
	}, nil
}

// getTokenExpiration extracts the expiration time from a token.
func getTokenExpiration(tokenString string) int64 {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return nil, nil // No need to validate the token here
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

// setAuthCookies sets the authentication tokens in HTTP cookies.
func setAuthCookies(w http.ResponseWriter, tokens *TokenResponse, config *Config) {
	// Define token expiration using configuration
	accessExpirationTime := time.Now().Add(config.AccessTokenExpiration)
	refreshExpirationTime := time.Now().Add(config.RefreshTokenExpiration)

	accessCookie := &http.Cookie{
		Name:     "access_token",
		Value:    tokens.AccessToken,
		Expires:  accessExpirationTime,
		HttpOnly: true,
		Secure:   config.SecureCookie,
		Path:     "/",                   // Cookie is valid for all paths
		SameSite: config.CookieSameSite, // Adjust based on your needs
	}

	// Set the access token cookie
	http.SetCookie(w, accessCookie)

	// Set the refresh token in a secure HttpOnly cookie
	refreshCookie := &http.Cookie{
		Name:     "refresh_token",
		Value:    tokens.RefreshToken,
		Expires:  refreshExpirationTime,
		HttpOnly: true,
		Secure:   config.SecureCookie,
		Path:     "/auth/refresh",
		SameSite: config.CookieSameSite, // Adjust based on your needs
	}
	http.SetCookie(w, refreshCookie)
}

// clearAuthCookies removes the authentication cookies.
func clearAuthCookies(w http.ResponseWriter, config *Config) {
	// Remove the access token cookie
	expiredAccessCookie := &http.Cookie{
		Name:     "access_token",
		Value:    "",
		Expires:  time.Unix(0, 0),
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   config.SecureCookie,
		Path:     "/",
		SameSite: config.CookieSameSite,
	}
	http.SetCookie(w, expiredAccessCookie)

	// Remove the refresh token cookie
	expiredRefreshCookie := &http.Cookie{
		Name:     "refresh_token",
		Value:    "",
		Expires:  time.Unix(0, 0),
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   config.SecureCookie,
		Path:     "/auth/refresh",
		SameSite: config.CookieSameSite,
	}
	http.SetCookie(w, expiredRefreshCookie)
}

// WriteJSONResponse writes a JSON response with the specified HTTP status and data.
func WriteJSONResponse(w http.ResponseWriter, httpStatus int, data *HttpResp) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(httpStatus)

	if err := json.NewEncoder(w).Encode(data); err != nil {
		// In production, consider logging this error
		http.Error(w, "Failed to encode response", http.StatusInternalServerError)
	}
}

// WriteSuccessResponse sends a successful JSON response.
func WriteSuccessResponse(w http.ResponseWriter, message string, data interface{}) {
	WriteJSONResponse(w,
		http.StatusOK,
		&HttpResp{Status: "success", Data: data, Message: message})
}

// WriteErrorResponse sends an error JSON response.
func WriteErrorResponse(w http.ResponseWriter, message string, httpStatus int) {
	WriteJSONResponse(w,
		httpStatus,
		&HttpResp{Status: "error", Data: nil, Message: message})
}

// WriteErrorResponseData sends an error JSON response with additional data.
func WriteErrorResponseData(w http.ResponseWriter, message string, data interface{}, httpStatus int) {
	WriteJSONResponse(w,
		httpStatus,
		&HttpResp{Status: "error", Data: data, Message: message})
}

// extractToken extracts a token from the request headers or cookies.
func extractToken(r *http.Request, tokenName string) string {
	// Check the Authorization header for a Bearer token
	if tokenName == "access_token" {
		authHeader := r.Header.Get("Authorization")
		if authHeader != "" {
			parts := strings.SplitN(authHeader, " ", 2)
			if len(parts) == 2 && strings.ToLower(parts[0]) == "bearer" {
				return parts[1]
			}
		}
	}

	// Check for token in the cookie
	cookie, err := r.Cookie(tokenName)
	if err == nil {
		return cookie.Value
	}

	return ""
}

// getClientIP retrieves the client's IP address from the request.
func getClientIP(r *http.Request) string {
	// Look for X-Forwarded-For header
	xff := r.Header.Get("X-Forwarded-For")
	if xff != "" {
		// X-Forwarded-For can have multiple IPs; the first one is usually the original client IP
		ips := strings.Split(xff, ",")
		return strings.TrimSpace(ips[0])
	}

	// Fallback to RemoteAddr if X-Forwarded-For is not set
	clientIP, _, _ := net.SplitHostPort(r.RemoteAddr)
	return clientIP
}
