package handlers

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"auth-service/services"

	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
)

// SocialAuthHandler handles social login operations
type SocialAuthHandler struct {
	socialAuthService *services.SocialAuthService
	authService       *services.AuthService
}

// NewSocialAuthHandler creates a new SocialAuthHandler
func NewSocialAuthHandler(socialAuthService *services.SocialAuthService, authService *services.AuthService) *SocialAuthHandler {
	return &SocialAuthHandler{
		socialAuthService: socialAuthService,
		authService:       authService,
	}
}

// SocialLoginRedirect redirects the user to the provider's consent page
func (h *SocialAuthHandler) SocialLoginRedirect(c *gin.Context) {
	provider := c.Param("provider")
	authURL, state, err := h.socialAuthService.GetAuthCodeURL(provider)
	if err != nil {
		logrus.WithError(err).Error("Failed to get auth code URL")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to initiate social login"})
		return
	}

	// Store state in a short-lived cookie to prevent CSRF
	c.SetCookie("oauthstate", state, 3600, "/", "", false, true)

	c.Redirect(http.StatusTemporaryRedirect, authURL)
}

// SocialLoginCallback handles the callback from the social provider
func (h *SocialAuthHandler) SocialLoginCallback(c *gin.Context) {
	provider := c.Param("provider")

	// Check for state cookie
	state, err := c.Cookie("oauthstate")
	if err != nil {
		c.Redirect(http.StatusTemporaryRedirect, "/login?error=invalid_state")
		return
	}

	if c.Query("state") != state {
		c.Redirect(http.StatusTemporaryRedirect, "/login?error=invalid_state")
		return
	}

	// Exchange authorization code for a token
	code := c.Query("code")
	token, err := h.socialAuthService.ExchangeCodeForToken(provider, code)
	if err != nil {
		logrus.WithError(err).Errorf("Failed to exchange code for token with %s", provider)
		c.Redirect(http.StatusTemporaryRedirect, "/login?error=token_exchange_failed")
		return
	}

	// Get user info from the provider
	userInfo, err := h.getUserInfo(provider, token.AccessToken)
	if err != nil {
		logrus.WithError(err).Errorf("Failed to get user info from %s", provider)
		c.Redirect(http.StatusTemporaryRedirect, "/login?error=user_info_failed")
		return
	}

	// Find or create the user in our database
	user, err := h.authService.FindOrCreateSocialUser(userInfo.Email, userInfo.FirstName, userInfo.LastName, provider, userInfo.ID)
	if err != nil {
		logrus.WithError(err).Error("Failed to find or create social user")
		c.Redirect(http.StatusTemporaryRedirect, "/login?error=user_creation_failed")
		return
	}

	// Generate JWT tokens for our application
	jwtTokens, err := h.authService.GenerateTokens(user)
	if err != nil {
		logrus.WithError(err).Error("Failed to generate JWT tokens")
		c.Redirect(http.StatusTemporaryRedirect, "/login?error=token_generation_failed")
		return
	}

	// Redirect back to the frontend with tokens
	redirectURL := fmt.Sprintf("http://localhost:3000/social-login-callback?access_token=%s&refresh_token=%s", jwtTokens.AccessToken, jwtTokens.RefreshToken)
	c.Redirect(http.StatusTemporaryRedirect, redirectURL)
}

// SocialUserInfo holds the basic user info from a social provider
type SocialUserInfo struct {
	ID        string
	Email     string
	FirstName string
	LastName  string
}

// getUserInfo fetches user information from the specified provider
func (h *SocialAuthHandler) getUserInfo(provider, accessToken string) (*SocialUserInfo, error) {
	var userInfoURL string

	switch provider {
	case "google":
		userInfoURL = "https://www.googleapis.com/oauth2/v2/userinfo"
	case "linkedin":
		// For LinkedIn, you need to specify the fields you want
		userInfoURL = "https://api.linkedin.com/v2/me?projection=(id,firstName,lastName,profilePicture(displayImage~:playableStreams))"
	case "twitter":
		// Twitter API v2 user lookup
		userInfoURL = "https://api.twitter.com/2/users/me"
	default:
		return nil, fmt.Errorf("provider %s not supported", provider)
	}

	req, err := http.NewRequest("GET", userInfoURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var info SocialUserInfo
	switch provider {
	case "google":
		var googleInfo struct {
			ID         string `json:"id"`
			Email      string `json:"email"`
			GivenName  string `json:"given_name"`
			FamilyName string `json:"family_name"`
		}
		if err := json.Unmarshal(body, &googleInfo); err != nil {
			return nil, err
		}
		info.ID = googleInfo.ID
		info.Email = googleInfo.Email
		info.FirstName = googleInfo.GivenName
		info.LastName = googleInfo.FamilyName
	case "linkedin":
		// LinkedIn's structure is more complex
		// This is a simplified parsing. You may need to adjust based on the exact response.
		var linkedInInfo struct {
			ID        string `json:"id"`
			FirstName struct {
				Localized map[string]string `json:"localized"`
			} `json:"firstName"`
			LastName struct {
				Localized map[string]string `json:"localized"`
			} `json:"lastName"`
		}
		if err := json.Unmarshal(body, &linkedInInfo); err != nil {
			return nil, err
		}
		info.ID = linkedInInfo.ID
		// This assumes a 'en_US' locale, adjust as needed
		info.FirstName = linkedInInfo.FirstName.Localized["en_US"]
		info.LastName = linkedInInfo.LastName.Localized["en_US"]
		// Note: LinkedIn does not provide email directly from this endpoint anymore without extra permissions.
		// You would need to make a separate call to the emailAddress endpoint.
		info.Email = "temp-" + info.ID + "@linkedin.local" // Placeholder
	case "twitter":
		var twitterInfo struct {
			Data struct {
				ID       string `json:"id"`
				Name     string `json:"name"`
				Username string `json:"username"`
			} `json:"data"`
		}
		if err := json.Unmarshal(body, &twitterInfo); err != nil {
			return nil, err
		}
		info.ID = twitterInfo.Data.ID
		info.FirstName = twitterInfo.Data.Name
		// Twitter doesn't provide email by default
		info.Email = "temp-" + twitterInfo.Data.Username + "@twitter.local" // Placeholder
	}

	return &info, nil
}
