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
		"sub":   "user123",
		"name":  "John Doe",
		"email": "john@example.com",
	}

	tokens, err := generateTokens(claims, config)
	if err != nil {
		t.Errorf("failed to generate tokens: %v", err)
	}

	if tokens.AccessToken == "" || tokens.RefreshToken == "" {
		t.Errorf("tokens should not be empty")
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
		t.Errorf("expected 2 cookies to be set")
	}

	for _, cookie := range cookies {
		if cookie.Name == "access_token" {
			if cookie.Value != "access_token_value" {
				t.Errorf("access_token cookie value mismatch")
			}
			if !cookie.HttpOnly || !cookie.Secure || cookie.SameSite != http.SameSiteLaxMode {
				t.Errorf("access_token cookie attributes mismatch")
			}
		} else if cookie.Name == "refresh_token" {
			if cookie.Value != "refresh_token_value" {
				t.Errorf("refresh_token cookie value mismatch")
			}
			if !cookie.HttpOnly || !cookie.Secure || cookie.Path != "/auth/refresh" {
				t.Errorf("refresh_token cookie attributes mismatch")
			}
		} else {
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
		t.Errorf("expected 2 cookies to be cleared")
	}

	for _, cookie := range cookies {
		if cookie.Name == "access_token" || cookie.Name == "refresh_token" {
			if cookie.Value != "" || cookie.MaxAge != -1 {
				t.Errorf("cookie %s should be cleared", cookie.Name)
			}
		} else {
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
