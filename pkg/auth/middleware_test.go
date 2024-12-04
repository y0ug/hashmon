package auth

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/sirupsen/logrus"
)

// Helper function to create a new Middleware with a mock database
func newTestMiddleware() *Middleware {
	config := &Config{
		JwtSecret: []byte("testsecret"),
	}
	db := NewMockDatabase()

	testLogger := logrus.New()
	testLogger.SetOutput(&bytes.Buffer{}) // Discard output during tests
	testLogger.SetLevel(logrus.DebugLevel)

	return NewMiddleware(config, db, testLogger)
}

func TestAuthMiddlewareValidToken(t *testing.T) {
	middleware := newTestMiddleware()

	// Create a valid token
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": "user123",
		"exp": time.Now().Add(15 * time.Minute).Unix(),
	})
	tokenString, _ := token.SignedString(middleware.Config.JwtSecret)

	req := httptest.NewRequest("GET", "/protected", nil)
	req.Header.Set("Authorization", "Bearer "+tokenString)
	w := httptest.NewRecorder()

	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check if the context has the user claims
		claims, ok := r.Context().Value("user").(jwt.MapClaims)
		if !ok || claims["sub"] != "user123" {
			t.Errorf("user claims not found in context")
		}
		w.WriteHeader(http.StatusOK)
	})

	middleware.AuthMiddleware(nextHandler).ServeHTTP(w, req)

	resp := w.Result()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected status 200, got %d", resp.StatusCode)
	}
}

func TestAuthMiddlewareExpiredToken(t *testing.T) {
	middleware := newTestMiddleware()

	// Create an expired token
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": "user123",
		"exp": time.Now().Add(-15 * time.Minute).Unix(),
	})
	tokenString, _ := token.SignedString(middleware.Config.JwtSecret)

	req := httptest.NewRequest("GET", "/protected", nil)
	req.Header.Set("Authorization", "Bearer "+tokenString)
	w := httptest.NewRecorder()

	middleware.AuthMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("handler should not be called with expired token")
	})).ServeHTTP(w, req)

	resp := w.Result()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected status 401, got %d", resp.StatusCode)
	}
}

func TestAuthMiddlewareInvalidToken(t *testing.T) {
	middleware := newTestMiddleware()

	req := httptest.NewRequest("GET", "/protected", nil)
	req.Header.Set("Authorization", "Bearer invalidtoken")
	w := httptest.NewRecorder()

	middleware.AuthMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("handler should not be called with invalid token")
	})).ServeHTTP(w, req)

	resp := w.Result()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected status 401, got %d", resp.StatusCode)
	}
}

func TestAuthMiddlewareNoToken(t *testing.T) {
	middleware := newTestMiddleware()

	req := httptest.NewRequest("GET", "/protected", nil)
	w := httptest.NewRecorder()

	middleware.AuthMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("handler should not be called without token")
	})).ServeHTTP(w, req)

	resp := w.Result()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected status 401, got %d", resp.StatusCode)
	}
}
