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
	Logger   *logrus.Logger // Logger instance
}

// NewMiddleware initializes a new authentication middleware.
func NewMiddleware(config *Config, db Database, logger *logrus.Logger) *Middleware {
	return &Middleware{
		Config:   config,
		Database: db,
		Logger:   logger,
	}
}

// AuthMiddleware is the HTTP middleware for authentication.
func (m *Middleware) AuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// m.Logger.Debug("AuthMiddleware invoked")

		// Extract access token
		tokenString := extractToken(r, "access_token")
		if tokenString == "" {
			m.Logger.Warn("Authorization token not found")
			WriteErrorResponse(w, "Authorization token not found", http.StatusUnauthorized)
			return
		}

		// m.Logger.WithField("access_token", tokenString).Debug("Access token extracted")

		// Check if the token is blacklisted using request context
		blacklisted, err := m.Database.IsTokenBlacklisted(r.Context(), tokenString)
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
		claims, err := m.parseAndValidateToken(tokenString)
		if err != nil {
			m.Logger.WithError(err).Warn("Invalid token")
			WriteErrorResponse(w, "Invalid token", http.StatusUnauthorized)
			return
		}

		// Attach claims to the request context
		ctx := context.WithValue(r.Context(), "user", claims)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// parseAndValidateToken parses and validates a JWT token string.
func (m *Middleware) parseAndValidateToken(tokenString string) (jwt.MapClaims, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Ensure token is signed with HS256
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return m.Config.JwtSecret, nil
	})

	if err != nil || !token.Valid {
		return nil, fmt.Errorf("invalid token: %w", err)
	}

	// Validate token claims
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, fmt.Errorf("invalid token claims")
	}

	// Validate expiration
	if exp, ok := claims["exp"].(float64); !ok || float64(time.Now().Unix()) > exp {
		return nil, fmt.Errorf("token has expired")
	}

	// m.Logger.WithFields(logrus.Fields{
	// 	"user_id":  claims["sub"],
	// 	"provider": claims["provider"],
	// }).Debug("Token validated successfully")
	//
	return claims, nil
}
