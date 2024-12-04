package auth

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/sirupsen/logrus"
)

// Middleware handles authentication for incoming HTTP requests.
type Middleware struct {
	Config   *Config
	Database Database
	Logger   *logrus.Logger // Added Logger field
}

// NewMiddleware initializes a new authentication middleware.
func NewMiddleware(config *Config, db Database, logger *logrus.Logger) *Middleware {
	return &Middleware{
		Config:   config,
		Database: db,
		Logger:   logger, // Initialize Logger
	}
}

// AuthMiddleware is the HTTP middleware for authentication.
func (m *Middleware) AuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		m.Logger.Debug("AuthMiddleware invoked")

		// Extract access token
		tokenString := extractToken(r, "access_token")
		m.Logger.Debugf("Access token extracted: %s", tokenString)

		// If no token found, reject the request
		if tokenString == "" {
			m.Logger.Warn("Authorization token not found")
			WriteErrorResponse(w, "Authorization token not found", http.StatusUnauthorized)
			return
		}

		// Check if the token is blacklisted
		blacklisted, err := m.Database.IsTokenBlacklisted(tokenString)
		if err != nil {
			m.Logger.WithError(err).Error("Failed to check token blacklist")
			WriteErrorResponse(w, "Internal server error", http.StatusInternalServerError)
			return
		}
		if blacklisted {
			m.Logger.Warn("Token has been revoked")
			WriteErrorResponse(w, "Token has been revoked", http.StatusUnauthorized)
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
			m.Logger.WithError(err).Warn("Invalid token")
			WriteErrorResponse(w, "Invalid token", http.StatusUnauthorized)
			return
		}

		// Validate token claims
		if claims, ok := token.Claims.(jwt.MapClaims); ok {
			// Validate expiration
			if exp, ok := claims["exp"].(float64); !ok || float64(time.Now().Unix()) > exp {
				m.Logger.Warn("Token has expired")
				WriteErrorResponse(w, "Token has expired", http.StatusUnauthorized)
				return
			}

			m.Logger.Debug("Token validated successfully")

			// Attach claims to the request context
			ctx := context.WithValue(r.Context(), "user", claims)
			next.ServeHTTP(w, r.WithContext(ctx))
			return
		}

		m.Logger.Warn("Invalid token claims")
		WriteErrorResponse(w, "Invalid token claims", http.StatusUnauthorized)
	})
}
