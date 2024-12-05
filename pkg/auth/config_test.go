package auth

import (
	"net/http"
	"os"
	"testing"
	"time"

	"golang.org/x/oauth2"
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
	// Set up environment variables for OAuth2 configuration
	os.Clearenv()
	os.Setenv("AUTH_TYPE", "oauth2")
	os.Setenv("OAUTH_PROVIDERS", "testprovider")

	// Provider-specific environment variables
	prefix := "OAUTH_TESTPROVIDER_"
	os.Setenv(prefix+"TYPE", "generic")
	os.Setenv(prefix+"CLIENT_ID", "testclientid")
	os.Setenv(prefix+"CLIENT_SECRET", "testclientsecret")
	os.Setenv(prefix+"REDIRECT_URL", "http://localhost/callback")
	os.Setenv(prefix+"AUTH_URL", "http://localhost/auth")
	os.Setenv(prefix+"TOKEN_URL", "http://localhost/token")
	os.Setenv(prefix+"USERINFO_URL", "http://localhost/userinfo")
	os.Setenv(prefix+"JWKS_URL", "http://localhost/jwks")
	os.Setenv(prefix+"END_SESSION_URL", "http://localhost/logout")
	os.Setenv(prefix+"SCOPES", "read,write")
	os.Setenv(prefix+"ADDITIONAL_PARAMS", "prompt=consent")

	// Common environment variables
	os.Setenv("JWT_SECRET", "testjwtsecret")
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
	if string(config.JwtSecret) != "testjwtsecret" {
		t.Errorf("JwtSecret mismatch")
	}
	if len(config.Providers) != 1 {
		t.Fatalf("expected 1 provider, got %d", len(config.Providers))
	}

	provider, exists := config.Providers["testprovider"]
	if !exists {
		t.Fatalf("provider 'testprovider' not found in config")
	}

	expectedScopes := []string{"read", "write", "openid", "profile", "email"}
	if len(provider.Config().Scopes) != len(expectedScopes) {
		t.Errorf("expected scopes %v, got %v", expectedScopes, provider.Config().Scopes)
	}
	for i, scope := range expectedScopes {
		if provider.Config().Scopes[i] != scope {
			t.Errorf("expected scope '%s', got '%s'", scope, provider.Config().Scopes[i])
		}
	}

	expectedParams := map[string]string{
		"prompt": "consent",
	}
	if len(provider.Config().AdditionalParams) != len(expectedParams) {
		t.Errorf("expected AdditionalParams %v, got %v", expectedParams, provider.Config().AdditionalParams)
	}
	for key, value := range expectedParams {
		if provider.Config().AdditionalParams[key] != value {
			t.Errorf("expected AdditionalParams[%s] = '%s', got '%s'", key, value, provider.Config().AdditionalParams[key])
		}
	}

	// Check OAuth2Config
	oauthConfig := provider.OAuth2Config()
	if oauthConfig.ClientID != "testclientid" {
		t.Errorf("OAuth2Config.ClientID mismatch")
	}
	if oauthConfig.ClientSecret != "testclientsecret" {
		t.Errorf("OAuth2Config.ClientSecret mismatch")
	}
	if oauthConfig.RedirectURL != "http://localhost/callback" {
		t.Errorf("OAuth2Config.RedirectURL mismatch")
	}
	if oauthConfig.Endpoint.AuthStyle != oauth2.AuthStyleInParams {
		t.Errorf("OAuth2Config.Endpoint.AuthStyle expected AuthStyleInParams, got %v", oauthConfig.Endpoint.AuthStyle)
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

	duration, err = parseDurationString("days=1, hours=2, minutes=3")
	if err != nil {
		t.Errorf("failed to parse duration: %v", err)
	}
	expected := 1*24*time.Hour + 2*time.Hour + 3*time.Minute
	if duration != expected {
		t.Errorf("expected %v, got %v", expected, duration)
	}

	_, err = parseDurationString("invalid=10")
	if err == nil {
		t.Errorf("expected error for invalid duration part")
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

	sameSite, err = parseSameSite("strict")
	if err != nil {
		t.Errorf("failed to parse SameSite: %v", err)
	}
	if sameSite != http.SameSiteStrictMode {
		t.Errorf("expected SameSiteStrictMode, got %v", sameSite)
	}

	sameSite, err = parseSameSite("none")
	if err != nil {
		t.Errorf("failed to parse SameSite: %v", err)
	}
	if sameSite != http.SameSiteNoneMode {
		t.Errorf("expected SameSiteNoneMode, got %v", sameSite)
	}

	_, err = parseSameSite("invalid")
	if err == nil {
		t.Errorf("expected error for invalid SameSite value")
	}
}
