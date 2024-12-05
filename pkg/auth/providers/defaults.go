package providers

// DefaultConfigs holds default configurations for well-known providers.
var DefaultConfigs = map[string]*ProviderConfig{
	"google": {
		Name:             "google",
		Type:             "google",
		AuthURL:          "https://accounts.google.com/o/oauth2/auth",
		TokenURL:         "https://oauth2.googleapis.com/token",
		UserInfoURL:      "https://openidconnect.googleapis.com/v1/userinfo",
		WellKnownJwksURL: "https://www.googleapis.com/oauth2/v3/certs",
		EndSessionURL:    "https://accounts.google.com/logout",
		Scopes:           []string{"openid", "profile", "email"},
	},
	"github": {
		Name:          "github",
		Type:          "github",
		AuthURL:       "https://github.com/login/oauth/authorize",
		TokenURL:      "https://github.com/login/oauth/access_token",
		UserInfoURL:   "https://api.github.com/user",
		EndSessionURL: "https://github.com/logout",
		Scopes:        []string{"read:user", "user:email"},
	},
}
