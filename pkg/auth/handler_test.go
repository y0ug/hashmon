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
	ProviderTokensData map[string]ProviderTokens
}

func NewMockDatabase() *MockDatabase {
	return &MockDatabase{
		RefreshTokens:      make(map[string]string),
		BlacklistedTokens:  make(map[string]int64),
		ProviderTokensData: make(map[string]ProviderTokens),
	}
}

func (db *MockDatabase) StoreRefreshToken(token, userID string, expiresAt time.Time) error {
	db.RefreshTokens[token] = userID
	return nil
}

func (db *MockDatabase) ValidateRefreshToken(token string) (string, error) {
	userID, exists := db.RefreshTokens[token]
	if !exists {
		return "", ErrInvalidToken
	}
	return userID, nil
}

func (db *MockDatabase) AddBlacklistedToken(token string, expiresAt int64) error {
	db.BlacklistedTokens[token] = expiresAt
	return nil
}

func (db *MockDatabase) IsTokenBlacklisted(token string) (bool, error) {
	_, exists := db.BlacklistedTokens[token]
	return exists, nil
}

func (db *MockDatabase) RevokeRefreshToken(token string) error {
	delete(db.RefreshTokens, token)
	return nil
}

func (db *MockDatabase) StoreProviderTokens(userID string, tokens ProviderTokens) error {
	db.ProviderTokensData[userID] = tokens
	return nil
}

func (db *MockDatabase) GetProviderTokens(userID string) (ProviderTokens, error) {
	tokens, exists := db.ProviderTokensData[userID]
	if !exists {
		return ProviderTokens{}, ErrTokenNotFound
	}
	return tokens, nil
}

func (db *MockDatabase) UpdateProviderTokens(userID string, tokens ProviderTokens) error {
	db.ProviderTokensData[userID] = tokens
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
		OAuth2Config: &oauth2.Config{
			ClientID:     "testclientid",
			ClientSecret: "testclientsecret",
			RedirectURL:  "http://localhost/callback",
			Scopes:       []string{"openid", "profile", "email"},
			Endpoint: oauth2.Endpoint{
				AuthURL:  "http://localhost/auth",
				TokenURL: "http://localhost/token",
			},
		},
		OauthUserInfoURL: "http://localhost/userinfo",
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
		"sub":   "user123",
		"name":  "John Doe",
		"email": "john@example.com",
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
	handler.Database.StoreRefreshToken(refreshToken, "user123", time.Now().Add(24*time.Hour))

	req := httptest.NewRequest("POST", "/logout", nil)
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
	if _, err := handler.Database.ValidateRefreshToken(refreshToken); err == nil {
		t.Errorf("refresh token should be revoked")
	}

	blacklisted, _ := handler.Database.IsTokenBlacklisted(accessToken)
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
	handler.Database.StoreRefreshToken(refreshToken, userID, time.Now().Add(24*time.Hour))

	// Store provider tokens
	providerTokens := ProviderTokens{
		AccessToken:  "provideraccesstoken",
		RefreshToken: "providerrefreshtoken",
		ExpiresAt:    time.Now().Add(1 * time.Hour),
	}
	handler.Database.StoreProviderTokens(userID, providerTokens)

	req := httptest.NewRequest("POST", "/refresh", nil)
	req.AddCookie(&http.Cookie{Name: "refresh_token", Value: refreshToken})
	w := httptest.NewRecorder()

	// Mock getUserInfo
	handler.getUserInfoFunc = func(accessToken string) (*UserInfo, error) {
		return &UserInfo{
			Sub:   "user123",
			Name:  "John Doe",
			Email: "john@example.com",
		}, nil
	}

	// Mock exchangeProviderRefreshToken
	handler.exchangeProviderRefreshTokenFunc = func(refreshToken string) (*oauth2.Token, error) {
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
	if _, err := handler.Database.ValidateRefreshToken(refreshToken); err == nil {
		t.Errorf("old refresh token should be revoked")
	}

	// Check that a new refresh token is stored
	if len(mockDB.RefreshTokens) != 1 {
		t.Errorf("new refresh token should be stored")
	}
}
