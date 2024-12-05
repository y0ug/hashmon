package auth

import "errors"

// Predefined errors used throughout the auth package.
var (
	// ErrInvalidToken indicates that the provided token is invalid.
	ErrInvalidToken = errors.New("invalid token")

	// ErrTokenNotFound indicates that the token was not found in the store.
	ErrTokenNotFound = errors.New("token not found")

	// ErrProviderNotFound indicates that the specified OAuth2 provider does not exist.
	ErrProviderNotFound = errors.New("provider not found")

	// ErrUserNotAuthenticated indicates that the user is not authenticated.
	ErrUserNotAuthenticated = errors.New("user not authenticated")
)
