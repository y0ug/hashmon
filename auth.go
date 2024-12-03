package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/sirupsen/logrus"
	"github.com/y0ug/hashmon/config"
)

type TokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int64  `json:"expires_in"`
}

// Generate a random state string for CSRF protection
func generateStateString() string {
	b := make([]byte, 16)
	_, err := rand.Read(b)
	if err != nil {
		// Handle error appropriately in production
		panic(err)
	}
	return base64.URLEncoding.EncodeToString(b)
}

// Placeholder for state validation
func validateState(state string) bool {
	// Implement state validation using sessions or secure storage
	return true
}

func (ws *WebServer) handleLogin(w http.ResponseWriter, r *http.Request) {
	state := generateStateString()
	// TODO: Store 'state' in session for later validation

	url := ws.config.OAuth2Config.AuthCodeURL(state)
	http.Redirect(w, r, url, http.StatusTemporaryRedirect)
}

func (ws *WebServer) handleCallback(w http.ResponseWriter, r *http.Request) {
	state := r.URL.Query().Get("state")
	if !validateState(state) {
		http.Error(w, "Invalid state parameter", http.StatusBadRequest)
		return
	}

	code := r.URL.Query().Get("code")
	if code == "" {
		http.Error(w, "Code not found", http.StatusBadRequest)
		return
	}

	// Exchange code for tokens
	token, err := ws.config.OAuth2Config.Exchange(context.Background(), code)
	if err != nil {
		fmt.Printf("Token exchange failed: %v\n", err)
		http.Error(w, "Failed to exchange token", http.StatusInternalServerError)
		return
	}

	// Extract ID token
	idToken, ok := token.Extra("id_token").(string)
	if !ok {
		http.Error(w, "No id_token field in oauth2 token", http.StatusInternalServerError)
		return
	}

	// Decode ID token to get user info
	userInfo, err := decodeIDToken(idToken, ws.config)
	if err != nil {
		fmt.Printf("Failed to decode ID token: %v\n", err)
		http.Error(w, "Failed to decode ID token", http.StatusInternalServerError)
		return
	}

	// Generate your own JWT for the client
	jwtToken, err := generateJWT(userInfo, ws.config)
	if err != nil {
		fmt.Printf("Failed to generate JWT: %v\n", err)
		http.Error(w, "Failed to generate token", http.StatusInternalServerError)
		return
	}

	// Define token expiration (e.g., 1 hour)
	expirationTime := time.Now().Add(1 * time.Hour)

	cookie := &http.Cookie{
		Name:     "access_token",
		Value:    jwtToken,
		Expires:  expirationTime,
		HttpOnly: true,                 // Prevents JavaScript access
		Secure:   true,                 // Ensures the cookie is sent over HTTPS
		Path:     "/",                  // Cookie is valid for all paths
		SameSite: http.SameSiteLaxMode, // Adjust based on your needs
	}

	// Set the cookie in the response
	http.SetCookie(w, cookie)

	http.Redirect(w, r, ws.config.RedirectURL, http.StatusSeeOther)

	// // Create the response
	// response := TokenResponse{
	// 	AccessToken: jwtToken,
	// 	TokenType:   "Bearer",
	// 	ExpiresIn:   int64(time.Until(expirationTime).Seconds()),
	// }
	//
	// fmt.Printf("User Info: %v", userInfo)
	// // Set Content-Type to application/json
	// w.Header().Set("Content-Type", "application/json")
	// // Send the response
	// json.NewEncoder(w).Encode(response)
	// // TODO: Create a session for the user or issue your own JWT
}

// Decode and validate ID token
func decodeIDToken(idToken string, config *config.WebserverConfig) (jwt.MapClaims, error) {
	// Fetch JWKS
	// jwksURL := fmt.Sprintf("https://%s/.well-known/jwks.json", config.Auth0Domain)
	set, err := jwk.Fetch(context.Background(), config.OauthWellknownJwks)
	if err != nil {
		return nil, err
	}

	token, err := jwt.Parse(idToken, func(token *jwt.Token) (interface{}, error) {
		// Ensure token is signed with RSA
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}

		// Get kid from token header
		kid, ok := token.Header["kid"].(string)
		if !ok {
			return nil, fmt.Errorf("kid header not found")
		}

		// Lookup the key
		key, exists := set.LookupKeyID(kid)
		if !exists {
			return nil, fmt.Errorf("unable to find key %s", kid)
		}

		var publicKey interface{}
		if err := key.Raw(&publicKey); err != nil {
			return nil, err
		}

		return publicKey, nil
	})
	if err != nil {
		return nil, err
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		return claims, nil
	}

	return nil, fmt.Errorf("invalid token")
}

// generateJWT creates a JWT token with user claims
func generateJWT(claims jwt.MapClaims, config *config.WebserverConfig) (string, error) {
	// Define token expiration
	expirationTime := time.Now().Add(1 * time.Hour)

	// Create the JWT claims, including standard claims
	tokenClaims := jwt.MapClaims{
		"sub":   claims["sub"], // Subject (unique identifier for the user)
		"name":  claims["name"],
		"email": claims["email"],
		"exp":   expirationTime.Unix(),
		"iat":   time.Now().Unix(),
		// Add more custom claims as needed
	}

	// Create the token using HS256 (HMAC) signing method
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, tokenClaims)

	// Sign the token with your secret
	tokenString, err := token.SignedString(config.JwtSecret)
	if err != nil {
		return "", err
	}

	return tokenString, nil
}

func authMiddleware(ws *WebServer) func(http.Handler) http.Handler {
	// Fetch JWKS at startup
	// jwks, err := jwk.Fetch(context.Background(), fmt.Sprintf("https://%s/.well-known/jwks.json", config.Auth0Domain))
	// jwks, err := jwk.Fetch(context.Background(), ws.config.OauthWellknownJwks)
	// if err != nil {
	// 	panic(fmt.Sprintf("Failed to fetch JWKS: %v", err))
	// }

	return func(next http.Handler) http.Handler {
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

			// 4. Check if the token is blacklisted
			blacklisted, err := ws.Monitor.Config.Database.IsTokenBlacklisted(tokenString)
			if err != nil {
				http.Error(w, "Internal server error", http.StatusInternalServerError)
				return
			}
			if blacklisted {
				http.Error(w, "Token has been revoked", http.StatusUnauthorized)
				return
			}

			// Parse and validate the token
			token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
				// Ensure token is signed with RSA
				if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
					return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
				}
				return ws.config.JwtSecret, nil
			})

			if err != nil || !token.Valid {
				fmt.Printf("Token error: %v\n", err)
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

				// (Optional) Validate other claims like issuer, audience, etc.
				// Example:
				/*
				   expectedIssuer := "https://your-authentik-domain.com/"
				   if iss, ok := claims["iss"].(string); !ok || iss != expectedIssuer {
				       http.Error(w, "Invalid issuer", http.StatusUnauthorized)
				       return
				   }
				*/

				// Attach claims to the request context
				ctx := context.WithValue(r.Context(), "user", claims)
				next.ServeHTTP(w, r.WithContext(ctx))
				return
			}

			http.Error(w, "Invalid token claims", http.StatusUnauthorized)
		})
	}
}

// StatusResponse defines the structure of the /status response
type StatusResponse struct {
	Authenticated bool     `json:"authenticated"`
	User          UserInfo `json:"user,omitempty"`
	Message       string   `json:"message,omitempty"`
}

// UserInfo represents the authenticated user's information
type UserInfo struct {
	Sub   string `json:"sub"`
	Name  string `json:"name"`
	Email string `json:"email"`
	// Add more fields as needed
}

// handleStatus checks authentication status and returns user info
func (ws *WebServer) handleStatus(w http.ResponseWriter, r *http.Request) {
	// Retrieve user claims from context (set by authMiddleware)
	claims, ok := r.Context().Value("user").(jwt.MapClaims)
	if !ok || claims == nil {
		// This should not happen as authMiddleware already validates the token
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(StatusResponse{
			Authenticated: false,
			Message:       "Failed to retrieve user information",
		})
		return
	}

	// Extract user information from claims
	user := UserInfo{
		Sub:   claims["sub"].(string),
		Name:  claims["name"].(string),
		Email: claims["email"].(string),
		// Extract additional fields as needed
	}

	// Respond with authenticated status and user info
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(StatusResponse{
		Authenticated: true,
		User:          user,
	})
}

// LogoutResponse defines the structure of the logout response
type LogoutResponse struct {
	Message string `json:"message"`
}

// handleLogout logs the user out by removing the JWT cookie and blacklisting the token.
func (ws *WebServer) handleLogout(w http.ResponseWriter, r *http.Request) {
	var tokenString string

	// 1. Extract the token from the Authorization header
	authHeader := r.Header.Get("Authorization")
	if authHeader != "" {
		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) == 2 && strings.ToLower(parts[0]) == "bearer" {
			tokenString = parts[1]
		}
	}

	// 2. If not found in header, extract from cookie
	if tokenString == "" {
		cookie, err := r.Cookie("access_token")
		if err == nil {
			tokenString = cookie.Value
		}
	}

	// 3. If token is still not found, respond with unauthorized
	if tokenString == "" {
		http.Error(w, "Authorization token not found", http.StatusUnauthorized)
		return
	}

	// 4. Parse the token to extract expiration time
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Ensure the signing method is HS256 or RS256 based on your setup
		switch token.Method.(type) {
		case *jwt.SigningMethodHMAC:
			return ws.config.JwtSecret, nil
		default:
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
	})

	if err != nil || !token.Valid {
		http.Error(w, "Invalid token", http.StatusUnauthorized)
		return
	}

	// 5. Extract claims to get expiration time
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		http.Error(w, "Invalid token claims", http.StatusUnauthorized)
		return
	}

	var exp int64
	if expFloat, ok := claims["exp"].(float64); ok {
		exp = int64(expFloat)
	} else {
		http.Error(w, "Invalid expiration in token", http.StatusUnauthorized)
		return
	}

	// 6. Add the token to the blacklist
	err = ws.Monitor.Config.Database.AddBlacklistedToken(tokenString, exp)
	if err != nil {
		logrus.WithError(err).Error("Failed to blacklist token during logout")
		http.Error(w, "Failed to logout", http.StatusInternalServerError)
		return
	}

	// 7. Remove the cookie by setting it to expire in the past
	expiredCookie := &http.Cookie{
		Name:     "access_token",
		Value:    "",
		Expires:  time.Unix(0, 0), // Expired in the past
		MaxAge:   -1,              // Delete the cookie
		HttpOnly: true,
		Secure:   true, // Ensure this matches your cookie settings
		Path:     "/",
		SameSite: http.SameSiteLaxMode,
	}
	http.SetCookie(w, expiredCookie)

	// 8. Respond to the client
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(LogoutResponse{
		Message: "Successfully logged out",
	})
}
