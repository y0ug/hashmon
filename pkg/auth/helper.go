package auth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
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

// validateState validates the state parameter to prevent CSRF attacks.
func validateState(state string) bool {
	// Implement state validation using sessions or secure storage
	return true
}

// generateTokens creates both access and refresh JWT tokens.
func generateTokens(claims jwt.MapClaims, config *Config) (*TokenResponse, error) {
	// Define access token expiration (e.g., 15 minutes)
	accessExpirationTime := time.Now().Add(15 * time.Minute)
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

// generateAccessToken creates a new access JWT token.
func generateAccessToken(claims jwt.MapClaims, config *Config) (string, error) {
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

// generateRefreshToken creates a new refresh JWT token.
func generateRefreshToken(claims jwt.MapClaims, config *Config) (string, error) {
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
	// Define token expiration
	accessExpirationTime := time.Now().Add(15 * time.Minute)

	accessCookie := &http.Cookie{
		Name:     "access_token",
		Value:    tokens.AccessToken,
		Expires:  accessExpirationTime,
		HttpOnly: true,
		Secure:   false,                // Adjust based on your needs
		Path:     "/",                  // Cookie is valid for all paths
		SameSite: http.SameSiteLaxMode, // Adjust based on your needs
	}

	// Set the access token cookie
	http.SetCookie(w, accessCookie)

	// Set the refresh token in a secure HttpOnly cookie
	refreshCookie := &http.Cookie{
		Name:     "refresh_token",
		Value:    tokens.RefreshToken,
		Expires:  time.Now().Add(7 * 24 * time.Hour),
		HttpOnly: true,
		Secure:   false, // Adjust based on your needs
		Path:     "/auth/refresh",
		SameSite: http.SameSiteLaxMode, // Adjust based on your needs
	}
	http.SetCookie(w, refreshCookie)
}

// Get user info from the OAuth provider
func (h *Handler) getUserInfo(accessToken string) (*UserInfo, error) {
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
func (h *Handler) exchangeProviderRefreshToken(refreshToken string) (*oauth2.Token, error) {
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
	// If using ID token hints, include the ID token
	// idToken, err := h.getIDTokenFromCookie(r)
	// if err == nil {
	//     params.Add("id_token_hint", idToken)
	// }

	u.RawQuery = params.Encode()
	return u.String(), nil
}
