package auth

import (
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/y0ug/hashmon/pkg/auth/providers"
	"golang.org/x/oauth2"
)

// NewConfig initializes the authentication configuration from environment variables.
func NewConfig() (*Config, error) {
	authConfig := &Config{
		Providers: make(map[string]providers.Provider),
	}

	// Load AuthType with default
	authConfig.AuthType = getEnv("AUTH_TYPE", "none")
	if authConfig.AuthType != "none" {
		// Load common configurations
		jwtSecret, err := getEnvBytes("JWT_SECRET")
		if err != nil {
			return nil, fmt.Errorf("error loading JWT_SECRET: %w", err)
		}
		authConfig.JwtSecret = jwtSecret

		authConfig.AccessTokenExpiration, err = parseDurationString(getEnv("ACCESS_TOKEN_EXPIRATION", "minutes=15"))
		if err != nil {
			return nil, fmt.Errorf("error parsing ACCESS_TOKEN_EXPIRATION: %w", err)
		}

		authConfig.RefreshTokenExpiration, err = parseDurationString(getEnv("REFRESH_TOKEN_EXPIRATION", "hours=24"))
		if err != nil {
			return nil, fmt.Errorf("error parsing REFRESH_TOKEN_EXPIRATION: %w", err)
		}

		authConfig.SecureCookie, err = strconv.ParseBool(getEnv("SECURE_COOKIE", "false"))
		if err != nil {
			return nil, fmt.Errorf("error parsing SECURE_COOKIE: %w", err)
		}

		authConfig.CookieSameSite, err = parseSameSite(getEnv("COOKIE_SAMESITE", "lax"))
		if err != nil {
			return nil, fmt.Errorf("error parsing COOKIE_SAMESITE: %w", err)
		}

		redirectWhitelistStr := getEnv("REDIRECT_WHITELIST", "")
		if redirectWhitelistStr != "" {
			authConfig.RedirectWhitelist = strings.Split(redirectWhitelistStr, ",")
		}
	}
	if authConfig.AuthType == "oauth2" {

		// Load multiple providers
		providersEnv := getEnv("OAUTH_PROVIDERS", "")
		if providersEnv == "" {
			return nil, fmt.Errorf("OAUTH_PROVIDERS is not set")
		}
		providerNames := strings.Split(providersEnv, ",")

		for _, providerName := range providerNames {
			providerName = strings.TrimSpace(providerName)
			if providerName == "" {
				continue
			}

			providerConfig, err := loadProviderConfig(providerName)
			if err != nil {
				return nil, fmt.Errorf("error loading config for provider '%s': %w", providerName, err)
			}

			// Append default scopes if not already present
			defaultScopes := []string{"openid", "profile", "email"}
			for _, scope := range defaultScopes {
				if !contains(providerConfig.Scopes, scope) {
					providerConfig.Scopes = append(providerConfig.Scopes, scope)
				}
			}

			// Initialize OAuth2 config
			err = initializeOAuth2Config(providerConfig)
			if err != nil {
				return nil, fmt.Errorf("error initializing OAuth2 config for provider '%s': %w", providerName, err)
			}

			// Instantiate the provider based on type
			var provider providers.Provider
			switch strings.ToLower(providerConfig.Type) {
			case "google":
				provider = providers.NewGoogleProvider(providerConfig)
			case "github":
				provider = providers.NewGitHubProvider(providerConfig)
			case "auth0":
				provider = providers.NewAuth0Provider(providerConfig)
			default:
				provider = providers.NewGenericProvider(providerConfig)
			}

			authConfig.Providers[providerName] = provider
		}
	}

	return authConfig, nil
}

// contains checks if a slice contains a specific string.
func contains(slice []string, item string) bool {
	for _, s := range slice {
		if strings.EqualFold(s, item) {
			return true
		}
	}
	return false
}

// loadProviderConfig loads the configuration for a single OAuth2 provider.
func loadProviderConfig(providerName string) (*providers.ProviderConfig, error) {
	prefix := fmt.Sprintf("OAUTH_%s_", strings.ToUpper(providerName))

	// Start with default configuration if available
	defaultConfig, hasDefault := providers.DefaultConfigs[providerName]
	var providerConfig providers.ProviderConfig
	if hasDefault {
		providerConfig = *defaultConfig
	} else {
		providerConfig = providers.ProviderConfig{Name: providerName}
	}

	// Overwrite with environment variables
	providerConfig.Type = getEnv(prefix+"TYPE", providerConfig.Type)
	providerConfig.ClientID = getEnv(prefix+"CLIENT_ID", providerConfig.ClientID)
	providerConfig.ClientSecret = getEnv(prefix+"CLIENT_SECRET", providerConfig.ClientSecret)
	providerConfig.RedirectURL = getEnv(prefix+"REDIRECT_URL", providerConfig.RedirectURL)
	providerConfig.AuthURL = getEnv(prefix+"AUTH_URL", providerConfig.AuthURL)
	providerConfig.TokenURL = getEnv(prefix+"TOKEN_URL", providerConfig.TokenURL)
	providerConfig.UserInfoURL = getEnv(prefix+"USERINFO_URL", providerConfig.UserInfoURL)
	providerConfig.WellKnownJwksURL = getEnv(prefix+"JWKS_URL", providerConfig.WellKnownJwksURL)
	providerConfig.EndSessionURL = getEnv(prefix+"END_SESSION_URL", providerConfig.EndSessionURL)

	scopes := strings.Split(getEnv(prefix+"SCOPES", strings.Join(providerConfig.Scopes, ",")), ",")
	providerConfig.Scopes = append(providerConfig.Scopes[:0], scopes...) // Overwrite default scopes

	additionalParams := parseAdditionalParams(getEnv(prefix+"ADDITIONAL_PARAMS", ""))
	providerConfig.AdditionalParams = additionalParams

	return &providerConfig, nil
}

// initializeOAuth2Config sets up the OAuth2 configuration for a provider.
func initializeOAuth2Config(providerConfig *providers.ProviderConfig) error {
	providerConfig.OAuth2Config = &oauth2.Config{
		ClientID:     providerConfig.ClientID,
		ClientSecret: providerConfig.ClientSecret,
		RedirectURL:  providerConfig.RedirectURL,
		Scopes:       providerConfig.Scopes,
		Endpoint: oauth2.Endpoint{
			AuthURL:  providerConfig.AuthURL,
			TokenURL: providerConfig.TokenURL,
		},
	}

	if len(providerConfig.AdditionalParams) > 0 {
		providerConfig.OAuth2Config.Endpoint.AuthStyle = oauth2.AuthStyleInParams
	}

	return nil
}

// getEnv retrieves the value of the environment variable named by the key.
// It returns the value, or the defaultValue if the variable is not present.
func getEnv(key, defaultValue string) string {
	if value, exists := os.LookupEnv(key); exists {
		return value
	}
	return defaultValue
}

// getEnvBytes retrieves the byte slice value of the environment variable named by the key.
// It returns the byte slice, or an error if the variable is not set.
func getEnvBytes(key string) ([]byte, error) {
	value, exists := os.LookupEnv(key)
	if !exists {
		return nil, fmt.Errorf("environment variable %s not set", key)
	}
	return []byte(value), nil
}

func parseAdditionalParams(s string) map[string]string {
	params := make(map[string]string)
	if s == "" {
		return params
	}
	pairs := strings.Split(s, ",")
	for _, pair := range pairs {
		kv := strings.SplitN(pair, "=", 2)
		if len(kv) == 2 {
			key := strings.TrimSpace(kv[0])
			value := strings.TrimSpace(kv[1])
			params[key] = value
		}
	}
	return params
}

// parseDurationString parses a duration string formatted as "minutes=1, hours=2, days=3, seconds=30"
func parseDurationString(s string) (time.Duration, error) {
	parts := strings.Split(s, ",")
	var totalDuration time.Duration

	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		keyValue := strings.SplitN(part, "=", 2)
		if len(keyValue) != 2 {
			return 0, fmt.Errorf("invalid format for part: '%s'", part)
		}
		key := strings.ToLower(strings.TrimSpace(keyValue[0]))
		valueStr := strings.TrimSpace(keyValue[1])
		value, err := strconv.Atoi(valueStr)
		if err != nil {
			return 0, fmt.Errorf("invalid value for %s: '%s'", key, valueStr)
		}

		switch key {
		case "minutes":
			totalDuration += time.Duration(value) * time.Minute
		case "hours":
			totalDuration += time.Duration(value) * time.Hour
		case "days":
			totalDuration += time.Duration(value) * 24 * time.Hour
		case "seconds":
			totalDuration += time.Duration(value) * time.Second
		default:
			return 0, fmt.Errorf("unknown time unit: '%s'", key)
		}
	}

	return totalDuration, nil
}

func parseSameSite(s string) (http.SameSite, error) {
	switch strings.ToLower(s) {
	case "lax":
		return http.SameSiteLaxMode, nil
	case "strict":
		return http.SameSiteStrictMode, nil
	case "none":
		return http.SameSiteNoneMode, nil
	default:
		return http.SameSiteDefaultMode, fmt.Errorf("invalid SameSite value: '%s'", s)
	}
}
