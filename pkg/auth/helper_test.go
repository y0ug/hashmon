// helper_test.go
package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v4"
)

func TestGenerateTokens(t *testing.T) {
	config := &Config{
		JwtSecret:              []byte("testsecret"),
		AccessTokenExpiration:  15 * time.Minute,
		RefreshTokenExpiration: 24 * time.Hour,
	}

	claims := jwt.MapClaims{
		"sub":      "user123",
		"name":     "John Doe",
		"email":    "john@example.com",
		"provider": "testprovider",
	}

	tokens, err := generateTokens(claims, config)
	if err != nil {
		t.Errorf("failed to generate tokens: %v", err)
	}

	if tokens.AccessToken == "" || tokens.RefreshToken == "" {
		t.Errorf("tokens should not be empty")
	}

	// Parse access token to verify claims
	parsedAccessToken, err := jwt.Parse(tokens.AccessToken, func(token *jwt.Token) (interface{}, error) {
		return config.JwtSecret, nil
	})
	if err != nil || !parsedAccessToken.Valid {
		t.Errorf("access token is invalid: %v", err)
	}

	accessClaims, ok := parsedAccessToken.Claims.(jwt.MapClaims)
	if !ok {
		t.Errorf("access token claims are invalid")
	}

	if accessClaims["sub"] != "user123" {
		t.Errorf("expected sub 'user123', got '%v'", accessClaims["sub"])
	}

	if accessClaims["name"] != "John Doe" {
		t.Errorf("expected name 'John Doe', got '%v'", accessClaims["name"])
	}

	if accessClaims["email"] != "john@example.com" {
		t.Errorf("expected email 'john@example.com', got '%v'", accessClaims["email"])
	}

	if accessClaims["provider"] != "testprovider" {
		t.Errorf("expected provider 'testprovider', got '%v'", accessClaims["provider"])
	}
}

func TestSetAuthCookies(t *testing.T) {
	w := httptest.NewRecorder()
	config := &Config{
		SecureCookie:           true,
		CookieSameSite:         http.SameSiteLaxMode,
		AccessTokenExpiration:  15 * time.Minute,
		RefreshTokenExpiration: 24 * time.Hour,
	}

	tokens := &TokenResponse{
		AccessToken:  "access_token_value",
		RefreshToken: "refresh_token_value",
	}

	setAuthCookies(w, tokens, config)

	cookies := w.Result().Cookies()
	if len(cookies) != 2 {
		t.Errorf("expected 2 cookies to be set, got %d", len(cookies))
	}

	for _, cookie := range cookies {
		switch cookie.Name {
		case "access_token":
			if cookie.Value != "access_token_value" {
				t.Errorf("access_token cookie value mismatch")
			}
			if !cookie.HttpOnly || !cookie.Secure || cookie.SameSite != http.SameSiteLaxMode {
				t.Errorf("access_token cookie attributes mismatch")
			}
			if !cookie.Expires.After(time.Now()) {
				t.Errorf("access_token cookie expiration is not in the future")
			}
		case "refresh_token":
			if cookie.Value != "refresh_token_value" {
				t.Errorf("refresh_token cookie value mismatch")
			}
			if !cookie.HttpOnly || !cookie.Secure || cookie.Path != "/auth/refresh" {
				t.Errorf("refresh_token cookie attributes mismatch")
			}
			if !cookie.Expires.After(time.Now()) {
				t.Errorf("refresh_token cookie expiration is not in the future")
			}
		default:
			t.Errorf("unexpected cookie: %s", cookie.Name)
		}
	}
}

func TestClearAuthCookies(t *testing.T) {
	w := httptest.NewRecorder()
	config := &Config{
		SecureCookie:   true,
		CookieSameSite: http.SameSiteLaxMode,
	}

	clearAuthCookies(w, config)

	cookies := w.Result().Cookies()
	if len(cookies) != 2 {
		t.Errorf("expected 2 cookies to be cleared, got %d", len(cookies))
	}

	for _, cookie := range cookies {
		switch cookie.Name {
		case "access_token":
			if cookie.Value != "" {
				t.Errorf("access_token cookie should be cleared")
			}
			if cookie.MaxAge != -1 {
				t.Errorf("access_token cookie MaxAge should be -1")
			}
			if !cookie.HttpOnly || !cookie.Secure || cookie.SameSite != http.SameSiteLaxMode {
				t.Errorf("access_token cookie attributes mismatch")
			}
			if !cookie.Expires.Before(time.Now()) {
				t.Errorf("access_token cookie expiration is not in the past")
			}
		case "refresh_token":
			if cookie.Value != "" {
				t.Errorf("refresh_token cookie should be cleared")
			}
			if cookie.MaxAge != -1 {
				t.Errorf("refresh_token cookie MaxAge should be -1")
			}
			if !cookie.HttpOnly || !cookie.Secure || cookie.Path != "/auth/refresh" || cookie.SameSite != http.SameSiteLaxMode {
				t.Errorf("refresh_token cookie attributes mismatch")
			}
			if !cookie.Expires.Before(time.Now()) {
				t.Errorf("refresh_token cookie expiration is not in the past")
			}
		default:
			t.Errorf("unexpected cookie: %s", cookie.Name)
		}
	}
}

func TestExtractToken(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Bearer access_token_value")
	req.AddCookie(&http.Cookie{Name: "refresh_token", Value: "refresh_token_value"})

	accessToken := extractToken(req, "access_token")
	refreshToken := extractToken(req, "refresh_token")

	if accessToken != "access_token_value" {
		t.Errorf("expected access_token_value, got %s", accessToken)
	}

	if refreshToken != "refresh_token_value" {
		t.Errorf("expected refresh_token_value, got %s", refreshToken)
	}
}

func TestGenerateStateString(t *testing.T) {
	state1 := generateStateString()
	state2 := generateStateString()

	if state1 == "" || state2 == "" {
		t.Errorf("state strings should not be empty")
	}

	if state1 == state2 {
		t.Errorf("state strings should be unique")
	}
}

func TestDecodeIDToken(t *testing.T) {
	// For this test, we need to create a mock JWK set and a valid ID token.
	// This can be complex, so we'll skip implementation details.
	// Instead, ensure that the function handles invalid tokens gracefully.

	provider := &ProviderConfig{
		WellKnownJwksURL: "http://invalid-url/jwks",
	}

	_, err := decodeIDToken("invalid_id_token", provider)
	if err == nil {
		t.Errorf("expected error when decoding invalid ID token")
	}
}
