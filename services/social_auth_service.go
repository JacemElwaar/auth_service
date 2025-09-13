package services

import (
	"crypto/rand"
	"encoding/base64"
	"errors"

	"auth-service/config"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"golang.org/x/oauth2/linkedin"
)

// SocialAuthService handles OAuth2 for social providers
type SocialAuthService struct {
	configs map[string]*oauth2.Config
}

// NewSocialAuthService creates and configures a new SocialAuthService
func NewSocialAuthService(cfg *config.Config) (*SocialAuthService, error) {
	configs := make(map[string]*oauth2.Config)

	// Google
	if cfg.GoogleClientID != "" && cfg.GoogleClientSecret != "" {
		configs["google"] = &oauth2.Config{
			ClientID:     cfg.GoogleClientID,
			ClientSecret: cfg.GoogleClientSecret,
			RedirectURL:  cfg.BaseURL + "/api/v1/social/callback/google",
			Scopes:       []string{"https://www.googleapis.com/auth/userinfo.email", "https://www.googleapis.com/auth/userinfo.profile"},
			Endpoint:     google.Endpoint,
		}
	}

	// LinkedIn
	if cfg.LinkedInClientID != "" && cfg.LinkedInClientSecret != "" {
		configs["linkedin"] = &oauth2.Config{
			ClientID:     cfg.LinkedInClientID,
			ClientSecret: cfg.LinkedInClientSecret,
			RedirectURL:  cfg.BaseURL + "/api/v1/social/callback/linkedin",
			Scopes:       []string{"r_emailaddress", "r_liteprofile"},
			Endpoint:     linkedin.Endpoint,
		}
	}

	// Twitter (Note: Twitter/X uses OAuth2 with PKCE, which is more complex)
	// This is a simplified setup. A real implementation may need more work.
	if cfg.TwitterClientID != "" && cfg.TwitterClientSecret != "" {
		configs["twitter"] = &oauth2.Config{
			ClientID:     cfg.TwitterClientID,
			ClientSecret: cfg.TwitterClientSecret,
			RedirectURL:  cfg.BaseURL + "/api/v1/social/callback/twitter",
			Scopes:       []string{"users.read", "tweet.read"},
			Endpoint: oauth2.Endpoint{
				AuthURL:  "https://twitter.com/i/oauth2/authorize",
				TokenURL: "https://api.twitter.com/2/oauth2/token",
			},
		}
	}

	return &SocialAuthService{configs: configs}, nil
}

// GetAuthCodeURL returns the URL for the provider's consent page
func (s *SocialAuthService) GetAuthCodeURL(provider string) (string, string, error) {
	conf, ok := s.configs[provider]
	if !ok {
		return "", "", errors.New("provider not supported")
	}

	// Generate a random state string to prevent CSRF attacks
	b := make([]byte, 32)
	_, err := rand.Read(b)
	if err != nil {
		return "", "", err
	}
	state := base64.URLEncoding.EncodeToString(b)

	return conf.AuthCodeURL(state), state, nil
}

// ExchangeCodeForToken exchanges an auth code for an access token
func (s *SocialAuthService) ExchangeCodeForToken(provider, code string) (*oauth2.Token, error) {
	conf, ok := s.configs[provider]
	if !ok {
		return nil, errors.New("provider not supported")
	}
	return conf.Exchange(oauth2.NoContext, code)
}
