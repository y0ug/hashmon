package auth

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/sirupsen/logrus"
)

// Middleware handles authentication for incoming HTTP requests.
type Middleware struct {
	Config   *Config
	Database Database
}

// NewMiddleware initializes a new authentication middleware.
func NewMiddleware(config *Config, db Database) *Middleware {
	return &Middleware{
		Config:   config,
		Database: db,
	}
}

// AuthMiddleware is the HTTP middleware for authentication.
func (m *Middleware) AuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var tokenString string

		// Check the Authorization header for a Bearer token
		authHeader := r.Header.Get("Authorization")
		if authHeader != "" {
			parts := strings.SplitN(authHeader, " ", 2)
			if len(parts) == 2 && strings.ToLower(parts[0]) == "bearer" {
				tokenString = parts[1]
			}
		}

		// If no Bearer token, check for JWT in the cookie
		if tokenString == "" {
			cookie, err := r.Cookie("access_token")
			if err == nil {
				tokenString = cookie.Value
			}
		}

		// If no token found, reject the request
		if tokenString == "" {
			http.Error(w, "Authorization token not found", http.StatusUnauthorized)
			return
		}

		// Check if the token is blacklisted
		blacklisted, err := m.Database.IsTokenBlacklisted(tokenString)
		if err != nil {
			logrus.WithError(err).Error("Failed to check token blacklist")
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}
		if blacklisted {
			http.Error(w, "Token has been revoked", http.StatusUnauthorized)
			return
		}

		// Parse and validate the token
		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			// Ensure token is signed with HS256
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
			return m.Config.JwtSecret, nil
		})

		if err != nil || !token.Valid {
			logrus.WithError(err).Error("Invalid token")
			http.Error(w, "Invalid token", http.StatusUnauthorized)
			return
		}

		// Validate token claims
		if claims, ok := token.Claims.(jwt.MapClaims); ok {
			// Validate expiration
			if exp, ok := claims["exp"].(float64); !ok || float64(time.Now().Unix()) > exp {
				http.Error(w, "Token has expired", http.StatusUnauthorized)
				return
			}

			// Attach claims to the request context
			ctx := context.WithValue(r.Context(), "user", claims)
			next.ServeHTTP(w, r.WithContext(ctx))
			return
		}

		http.Error(w, "Invalid token claims", http.StatusUnauthorized)
	})
}
