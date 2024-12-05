package auth

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/sirupsen/logrus"
	"golang.org/x/oauth2"
)

// MockDatabase is a mock implementation of the Database interface for testing.
type MockDatabase struct {
	RefreshTokens      map[string]string
	BlacklistedTokens  map[string]int64
	ProviderTokensData map[string]map[string]ProviderTokens // userID -> provider -> tokens
}

func NewMockDatabase() *MockDatabase {
	return &MockDatabase{
		RefreshTokens:      make(map[string]string),
		BlacklistedTokens:  make(map[string]int64),
		ProviderTokensData: make(map[string]map[string]ProviderTokens),
	}
}

func (db *MockDatabase) StoreRefreshToken(ctx context.Context, token, userID string, expiresAt time.Time) error {
	db.RefreshTokens[token] = userID
	return nil
}

func (db *MockDatabase) ValidateRefreshToken(ctx context.Context, token string) (string, error) {
	userID, exists := db.RefreshTokens[token]
	if !exists {
		return "", ErrInvalidToken
	}
	return userID, nil
}

func (db *MockDatabase) AddBlacklistedToken(ctx context.Context, token string, expiresAt int64) error {
	db.BlacklistedTokens[token] = expiresAt
	return nil
}

func (db *MockDatabase) IsTokenBlacklisted(ctx context.Context, token string) (bool, error) {
	_, exists := db.BlacklistedTokens[token]
	return exists, nil
}

func (db *MockDatabase) RevokeRefreshToken(ctx context.Context, token string) error {
	delete(db.RefreshTokens, token)
	return nil
}

func (db *MockDatabase) StoreProviderTokens(ctx context.Context, userID, provider string, tokens ProviderTokens) error {
	if _, exists := db.ProviderTokensData[userID]; !exists {
		db.ProviderTokensData[userID] = make(map[string]ProviderTokens)
	}
	db.ProviderTokensData[userID][provider] = tokens
	return nil
}

func (db *MockDatabase) GetProviderTokens(ctx context.Context, userID, provider string) (ProviderTokens, error) {
	providers, exists := db.ProviderTokensData[userID]
	if !exists {
		return ProviderTokens{}, ErrTokenNotFound
	}
	tokens, exists := providers[provider]
	if !exists {
		return ProviderTokens{}, ErrTokenNotFound
	}
	return tokens, nil
}

func (db *MockDatabase) UpdateProviderTokens(ctx context.Context, userID string, provider string, tokens ProviderTokens) error {
	if _, exists := db.ProviderTokensData[userID]; !exists {
		db.ProviderTokensData[userID] = make(map[string]ProviderTokens)
	}
	db.ProviderTokensData[userID][provider] = tokens
	return nil
}

// Helper function to create a new Handler with a mock database
func newTestHandler() *Handler {
	config := &Config{
		JwtSecret:              []byte("testsecret"),
		AccessTokenExpiration:  15 * time.Minute,
		RefreshTokenExpiration: 24 * time.Hour,
		SecureCookie:           false,
		CookieSameSite:         http.SameSiteLaxMode,
		Providers: map[string]*ProviderConfig{
			"testprovider": {
				Name:          "testprovider",
				Type:          "generic",
				ClientID:      "testclientid",
				ClientSecret:  "testclientsecret",
				RedirectURL:   "http://localhost/callback",
				AuthURL:       "http://localhost/auth",
				TokenURL:      "http://localhost/token",
				UserInfoURL:   "http://localhost/userinfo",
				JWKS_URL:      "http://localhost/jwks",
				EndSessionURL: "http://localhost/logout",
				Scopes:        []string{"read", "write", "openid", "profile", "email"},
				AdditionalParams: map[string]string{
					"prompt": "consent",
				},
				OAuth2Config: &oauth2.Config{
					ClientID:     "testclientid",
					ClientSecret: "testclientsecret",
					RedirectURL:  "http://localhost/callback",
					Scopes:       []string{"read", "write", "openid", "profile", "email"},
					Endpoint: oauth2.Endpoint{
						AuthURL:  "http://localhost/auth",
						TokenURL: "http://localhost/token",
					},
				},
			},
		},
	}

	db := NewMockDatabase()

	testLogger := logrus.New()
	testLogger.SetOutput(&bytes.Buffer{}) // Discard output during tests
	testLogger.SetLevel(logrus.DebugLevel)

	return NewHandler(config, db, testLogger)
}

func TestHandleStatusUnauthenticated(t *testing.T) {
	handler := newTestHandler()

	req := httptest.NewRequest("GET", "/status", nil)
	w := httptest.NewRecorder()

	handler.HandleStatus(w, req)

	resp := w.Result()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusInternalServerError {
		t.Errorf("expected status 500, got %d", resp.StatusCode)
	}
}

func TestHandleStatusAuthenticated(t *testing.T) {
	handler := newTestHandler()

	// Create a context with user claims
	claims := jwt.MapClaims{
		"sub":      "user123",
		"name":     "John Doe",
		"email":    "john@example.com",
		"provider": "testprovider",
	}
	ctx := context.WithValue(context.Background(), "user", claims)

	req := httptest.NewRequest("GET", "/status", nil)
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()

	handler.HandleStatus(w, req)

	resp := w.Result()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected status 200, got %d", resp.StatusCode)
	}
}

func TestHandleLogout(t *testing.T) {
	handler := newTestHandler()

	// Mock tokens
	accessToken := "testaccesstoken"
	refreshToken := "testrefreshtoken"

	// Add tokens to the mock database
	handler.Database.StoreRefreshToken(context.Background(), refreshToken, "user123", time.Now().Add(24*time.Hour))
	handler.Database.StoreProviderTokens(context.Background(), "user123", "testprovider", ProviderTokens{
		AccessToken:  "provideraccesstoken",
		RefreshToken: "providerrefreshtoken",
		ExpiresAt:    time.Now().Add(1 * time.Hour),
	})

	// Create a context with user claims
	claims := jwt.MapClaims{
		"sub":      "user123",
		"name":     "John Doe",
		"email":    "john@example.com",
		"provider": "testprovider",
	}
	ctx := context.WithValue(context.Background(), "user", claims)

	req := httptest.NewRequest("POST", "/logout", nil)
	req = req.WithContext(ctx)
	req.AddCookie(&http.Cookie{Name: "access_token", Value: accessToken})
	req.AddCookie(&http.Cookie{Name: "refresh_token", Value: refreshToken})
	w := httptest.NewRecorder()

	handler.HandleLogout(w, req)

	resp := w.Result()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected status 200, got %d", resp.StatusCode)
	}

	// Check that tokens are revoked
	if _, err := handler.Database.ValidateRefreshToken(context.Background(), refreshToken); err == nil {
		t.Errorf("refresh token should be revoked")
	}

	blacklisted, _ := handler.Database.IsTokenBlacklisted(context.Background(), accessToken)
	if !blacklisted {
		t.Errorf("access token should be blacklisted")
	}
}

func TestHandleRefresh(t *testing.T) {
	handler := newTestHandler()
	mockDB := handler.Database.(*MockDatabase)

	// Mock tokens
	refreshToken := "testrefreshtoken"
	userID := "user123"

	// Store the refresh token
	handler.Database.StoreRefreshToken(context.Background(), refreshToken, userID, time.Now().Add(24*time.Hour))

	// Store provider tokens
	providerTokens := ProviderTokens{
		AccessToken:  "provideraccesstoken",
		RefreshToken: "providerrefreshtoken",
		ExpiresAt:    time.Now().Add(1 * time.Hour),
	}
	handler.Database.StoreProviderTokens(context.Background(), userID, "testprovider", providerTokens)

	req := httptest.NewRequest("POST", "/refresh", nil)
	req.AddCookie(&http.Cookie{Name: "refresh_token", Value: refreshToken})
	w := httptest.NewRecorder()

	// Mock getUserInfo
	handler.getUserInfoFunc = func(providerName string, accessToken string) (*ProviderUserInfo, error) {
		return &ProviderUserInfo{
			Sub:      "user123",
			Name:     "John Doe",
			Email:    "john@example.com",
			Provider: providerName,
		}, nil
	}

	// Mock exchangeProviderRefreshToken
	handler.exchangeProviderRefreshTokenFunc = func(refreshToken string, providerName string) (*oauth2.Token, error) {
		return &oauth2.Token{
			AccessToken:  "newprovideraccesstoken",
			RefreshToken: "newproviderrefreshtoken",
			Expiry:       time.Now().Add(1 * time.Hour),
		}, nil
	}

	handler.HandleRefresh(w, req)

	resp := w.Result()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected status 200, got %d", resp.StatusCode)
	}

	// Check that the old refresh token is revoked
	if _, err := handler.Database.ValidateRefreshToken(context.Background(), refreshToken); err == nil {
		t.Errorf("old refresh token should be revoked")
	}

	// Check that a new refresh token is stored
	if len(mockDB.RefreshTokens) != 1 {
		t.Errorf("new refresh token should be stored")
	}

	// Verify new refresh token details
	for token, uid := range mockDB.RefreshTokens {
		if token != "newproviderrefreshtoken" || uid != userID {
			t.Errorf("new refresh token details mismatch")
		}
	}
}
