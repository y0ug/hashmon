package providers

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/golang-jwt/jwt/v4"
	"github.com/lestrrat-go/jwx/jwk"
	"golang.org/x/oauth2"
)

// Refresh the access token using the refresh token for the oauth2 provider
func defaultRenewAccessToken(ctx context.Context, p Provider, refreshToken string) (*oauth2.Token, error) {
	tokenSource := p.OAuth2Config().TokenSource(ctx, &oauth2.Token{
		RefreshToken: refreshToken,
	})

	newToken, err := tokenSource.Token()
	if err != nil {
		fmt.Printf("Error in exchangeProviderRefreshToken: %v\n", err)
		return nil, err
	}

	return newToken, nil
}

// Fetch the user info using the access token for the oauth2 provider
func defaultFetchUserInfo(ctx context.Context, p Provider, accessToken string, providerUserInfo interface{}) error {
	req, err := http.NewRequestWithContext(ctx, "GET", p.Config().UserInfoURL, nil)
	if err != nil {
		return err
	}

	req.Header.Set("Authorization", "Bearer "+accessToken)

	// Make the HTTP request
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	// Handle errors
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to get user info: status %d", resp.StatusCode)
	}

	if err := json.NewDecoder(resp.Body).Decode(providerUserInfo); err != nil {
		return fmt.Errorf("failed to decode provider user info response: %w", err)
	}
	return nil
}

// decodeIDToken decodes and validates the ID token using the provider's JWKs.
func defaultDecodeIDToken(ctx context.Context, p Provider, idToken string) (jwt.MapClaims, error) {
	set, err := jwk.Fetch(ctx, p.Config().WellKnownJwksURL)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch JWKs: %w", err)
	}

	token, err := jwt.Parse(idToken, func(token *jwt.Token) (interface{}, error) {
		// Ensure token is signed with the expected signing method
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
			return nil, fmt.Errorf("failed to parse JWK: %w", err)
		}

		return publicKey, nil
	})
	if err != nil {
		return nil, fmt.Errorf("failed to parse ID token: %w", err)
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		return claims, nil
	}

	return nil, fmt.Errorf("invalid ID token")
}

func defaultExchangeCode(ctx context.Context, p Provider, code string) (*oauth2.Token, error) {
	return p.OAuth2Config().Exchange(ctx, code)
}
