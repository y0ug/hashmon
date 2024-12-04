package auth

import (
	"net/http"
	"os"
	"testing"
	"time"
)

func TestNewConfigDefaultAuthType(t *testing.T) {
	os.Clearenv()
	config, err := NewConfig()
	if err != nil {
		t.Fatalf("failed to create config: %v", err)
	}
	if config.AuthType != "none" {
		t.Errorf("expected AuthType 'none', got '%s'", config.AuthType)
	}
}

func TestNewConfigWithOAuth2(t *testing.T) {
	os.Setenv("AUTH_TYPE", "oauth2")
	os.Setenv("OAUTH_CLIENT_ID", "testclientid")
	os.Setenv("OAUTH_CLIENT_SECRET", "testclientsecret")
	os.Setenv("OAUTH_REDIRECT_URL", "http://localhost/callback")
	os.Setenv("OAUTH_LOGIN_URL", "http://localhost/auth")
	os.Setenv("OAUTH_TOKEN_URL", "http://localhost/token")
	os.Setenv("OAUTH_JWKS_URL", "http://localhost/jwks")
	os.Setenv("JWT_SECRET", "testjwtsecret")
	os.Setenv("REDIRECT_URL", "http://localhost")
	os.Setenv("OAUTH_USERINFO_URL", "http://localhost/userinfo")
	os.Setenv("OAUTH_END_SESSION_URL", "http://localhost/logout")
	os.Setenv("ACCESS_TOKEN_EXPIRATION", "minutes=15")
	os.Setenv("REFRESH_TOKEN_EXPIRATION", "hours=24")
	os.Setenv("SECURE_COOKIE", "false")
	os.Setenv("COOKIE_SAMESITE", "lax")

	config, err := NewConfig()
	if err != nil {
		t.Fatalf("failed to create config: %v", err)
	}

	if config.AuthType != "oauth2" {
		t.Errorf("expected AuthType 'oauth2', got '%s'", config.AuthType)
	}
	if config.OauthClientID != "testclientid" {
		t.Errorf("OauthClientID mismatch")
	}
	if string(config.JwtSecret) != "testjwtsecret" {
		t.Errorf("JwtSecret mismatch")
	}
}

func TestParseDurationString(t *testing.T) {
	duration, err := parseDurationString("minutes=15")
	if err != nil {
		t.Errorf("failed to parse duration: %v", err)
	}
	if duration != 15*time.Minute {
		t.Errorf("expected 15 minutes, got %v", duration)
	}

	duration, err = parseDurationString("hours=1, minutes=30")
	if err != nil {
		t.Errorf("failed to parse duration: %v", err)
	}
	if duration != 90*time.Minute {
		t.Errorf("expected 90 minutes, got %v", duration)
	}
}

func TestParseSameSite(t *testing.T) {
	sameSite, err := parseSameSite("lax")
	if err != nil {
		t.Errorf("failed to parse SameSite: %v", err)
	}
	if sameSite != http.SameSiteLaxMode {
		t.Errorf("expected SameSiteLaxMode, got %v", sameSite)
	}

	_, err = parseSameSite("invalid")
	if err == nil {
		t.Errorf("expected error for invalid SameSite value")
	}
}
