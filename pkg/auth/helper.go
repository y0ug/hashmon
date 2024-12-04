package auth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/lestrrat-go/jwx/jwk"
	"golang.org/x/oauth2"
)

// generateStateString generates a random state string for CSRF protection.
func generateStateString() string {
	b := make([]byte, 16)
	_, err := rand.Read(b)
	if err != nil {
		panic(err) // Handle error appropriately in production
	}
	return base64.URLEncoding.EncodeToString(b)
}

// generateTokens creates both access and refresh JWT tokens.
func generateTokens(claims jwt.MapClaims, config *Config) (*TokenResponse, error) {
	// Define access token expiration using configuration
	accessExpirationTime := time.Now().Add(config.AccessTokenExpiration)
	accessClaims := jwt.MapClaims{
		"sub":   claims["sub"],
		"name":  claims["name"],
		"email": claims["email"],
		"exp":   accessExpirationTime.Unix(),
		"iat":   time.Now().Unix(),
	}

	// Create access token
	accessToken := jwt.NewWithClaims(jwt.SigningMethodHS256, accessClaims)
	accessTokenString, err := accessToken.SignedString(config.JwtSecret)
	if err != nil {
		return nil, err
	}

	// Define refresh token expiration using configuration
	refreshExpirationTime := time.Now().Add(config.RefreshTokenExpiration)
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
		ExpiresIn:    int64(time.Until(accessExpirationTime).Seconds()),
	}, nil
}

// decodeIDToken decodes and validates the ID token.
func decodeIDToken(idToken string, config *Config) (jwt.MapClaims, error) {
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

// Get user info from the OAuth provider
func (h *Handler) defaultGetUserInfo(accessToken string) (*UserInfo, error) {
	req, err := http.NewRequest("GET", h.Config.OauthUserInfoURL, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", "Bearer "+accessToken)

	// Make the HTTP request
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// Handle errors
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to get user info: status %d", resp.StatusCode)
	}

	// Parse the user info
	var userInfo UserInfo
	if err := json.NewDecoder(resp.Body).Decode(&userInfo); err != nil {
		return nil, err
	}

	return &userInfo, nil
}

// Refresh the access token using the refresh token for the oauth2 provider
func (h *Handler) defaultExchangeProviderRefreshToken(refreshToken string) (*oauth2.Token, error) {
	tokenSource := h.Config.OAuth2Config.TokenSource(context.Background(), &oauth2.Token{
		RefreshToken: refreshToken,
	})

	newToken, err := tokenSource.Token()
	if err != nil {
		fmt.Printf("Error in exchangeProviderRefreshToken: %v\n", err)
		return nil, err
	}

	return newToken, nil
}

// buildEndSessionURL constructs the end-session endpoint URL with necessary parameters
func (h *Handler) buildEndSessionURL(r *http.Request) (string, error) {
	u, err := url.Parse(h.Config.OauthEndSessionURL)
	if err != nil {
		return "", err
	}

	// Add the required parameters
	params := url.Values{}
	params.Add("post_logout_redirect_uri", h.Config.PostLogoutRedirectURI)

	u.RawQuery = params.Encode()
	return u.String(), nil
}

// parseDurationString parses a duration string formatted as "minutes=1, hours=2, days=3, seconds=30"
func parseDurationString(s string) (time.Duration, error) {
	parts := strings.Split(s, ",")
	var totalDuration time.Duration

	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		keyValue := strings.SplitN(part, "=", 2)
		if len(keyValue) != 2 {
			return 0, fmt.Errorf("invalid format for part: '%s'", part)
		}
		key := strings.ToLower(strings.TrimSpace(keyValue[0]))
		valueStr := strings.TrimSpace(keyValue[1])
		value, err := strconv.Atoi(valueStr)
		if err != nil {
			return 0, fmt.Errorf("invalid value for %s: '%s'", key, valueStr)
		}

		switch key {
		case "minutes":
			totalDuration += time.Duration(value) * time.Minute
		case "hours":
			totalDuration += time.Duration(value) * time.Hour
		case "days":
			totalDuration += time.Duration(value) * 24 * time.Hour
		case "seconds":
			totalDuration += time.Duration(value) * time.Second
		default:
			return 0, fmt.Errorf("unknown time unit: '%s'", key)
		}
	}

	return totalDuration, nil
}

func parseSameSite(s string) (http.SameSite, error) {
	switch strings.ToLower(s) {
	case "lax":
		return http.SameSiteLaxMode, nil
	case "strict":
		return http.SameSiteStrictMode, nil
	case "none":
		return http.SameSiteNoneMode, nil
	default:
		return http.SameSiteDefaultMode, fmt.Errorf("invalid SameSite value: '%s'", s)
	}
}

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

func WriteJSONResponse(w http.ResponseWriter, httpStatus int, data *HttpResp) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(httpStatus)

	json.NewEncoder(w).Encode(data)
}

func WriteSuccessResponse(w http.ResponseWriter, message string, data interface{}) {
	WriteJSONResponse(w,
		http.StatusOK,
		&HttpResp{Status: "success", Data: data, Message: message})
}

func WriteErrorResponse(w http.ResponseWriter, message string, httpStatus int) {
	WriteJSONResponse(w,
		httpStatus,
		&HttpResp{Status: "error", Data: nil, Message: message})
}

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
