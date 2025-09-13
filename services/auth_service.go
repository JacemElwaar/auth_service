package services

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"auth-service/config"
	"auth-service/models"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

type AuthService struct {
	db     *gorm.DB
	config *config.Config
}

type JWTClaims struct {
	UserID string `json:"user_id"`
	Email  string `json:"email"`
	jwt.RegisteredClaims
}

type TokenPair struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int64  `json:"expires_in"`
}

func NewAuthService(db *gorm.DB, cfg *config.Config) *AuthService {
	return &AuthService{
		db:     db,
		config: cfg,
	}
}

// Register creates a new user account
func (as *AuthService) Register(email, password string, profileData *models.ProfileDataStruct) (*models.User, error) {
	// Check if user already exists
	var existingUser models.User
	if err := as.db.Where("email = ?", email).First(&existingUser).Error; err == nil {
		return nil, fmt.Errorf("user with email %s already exists", email)
	}

	// Hash password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), as.config.BCryptCost)
	if err != nil {
		return nil, fmt.Errorf("failed to hash password: %w", err)
	}

	// Convert profile data to JSON
	var profileJSON string
	if profileData != nil {
		profileBytes, err := json.Marshal(profileData)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal profile data: %w", err)
		}
		profileJSON = string(profileBytes)
	}

	// Create user
	user := &models.User{
		Email:        email,
		PasswordHash: string(hashedPassword),
		ProfileData:  profileJSON,
	}

	if err := as.db.Create(user).Error; err != nil {
		return nil, fmt.Errorf("failed to create user: %w", err)
	}

	return user, nil
}

// Login authenticates a user and returns tokens
func (as *AuthService) Login(email, password string) (*TokenPair, *models.User, error) {
	// Find user
	var user models.User
	if err := as.db.Where("email = ?", email).First(&user).Error; err != nil {
		return nil, nil, fmt.Errorf("invalid credentials")
	}

	// Check password
	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password)); err != nil {
		return nil, nil, fmt.Errorf("invalid credentials")
	}

	// Generate tokens
	tokens, err := as.GenerateTokens(&user)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate tokens: %w", err)
	}

	return tokens, &user, nil
}

// GenerateTokens creates JWT access token and refresh token
func (as *AuthService) GenerateTokens(user *models.User) (*TokenPair, error) {
	// Generate access token
	accessClaims := &JWTClaims{
		UserID: user.ID.String(),
		Email:  user.Email,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(as.config.AccessTokenExpiry)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now()),
			Issuer:    "auth-service",
		},
	}

	accessToken := jwt.NewWithClaims(jwt.SigningMethodHS256, accessClaims)
	accessTokenString, err := accessToken.SignedString([]byte(as.config.JWTSecret))
	if err != nil {
		return nil, fmt.Errorf("failed to sign access token: %w", err)
	}

	// Generate refresh token
	refreshTokenString, err := as.generateRandomToken()
	if err != nil {
		return nil, fmt.Errorf("failed to generate refresh token: %w", err)
	}

	// Store refresh token in database
	refreshToken := &models.RefreshToken{
		UserID:    user.ID,
		Token:     refreshTokenString,
		ExpiresAt: time.Now().Add(as.config.RefreshTokenExpiry),
	}

	if err := as.db.Create(refreshToken).Error; err != nil {
		return nil, fmt.Errorf("failed to store refresh token: %w", err)
	}

	return &TokenPair{
		AccessToken:  accessTokenString,
		RefreshToken: refreshTokenString,
		ExpiresIn:    int64(as.config.AccessTokenExpiry.Seconds()),
	}, nil
}

// RefreshTokens validates refresh token and generates new token pair
func (as *AuthService) RefreshTokens(refreshTokenString string) (*TokenPair, error) {
	// Find refresh token
	var refreshToken models.RefreshToken
	if err := as.db.Preload("User").Where("token = ?", refreshTokenString).First(&refreshToken).Error; err != nil {
		return nil, fmt.Errorf("invalid refresh token")
	}

	// Check if token is valid
	if !refreshToken.IsValid() {
		return nil, fmt.Errorf("refresh token expired or revoked")
	}

	// Revoke old refresh token
	refreshToken.Revoked = true
	as.db.Save(&refreshToken)

	// Generate new token pair
	return as.GenerateTokens(&refreshToken.User)
}

// ValidateAccessToken validates and parses JWT access token
func (as *AuthService) ValidateAccessToken(tokenString string) (*JWTClaims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &JWTClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(as.config.JWTSecret), nil
	})

	if err != nil {
		return nil, fmt.Errorf("invalid token: %w", err)
	}

	if claims, ok := token.Claims.(*JWTClaims); ok && token.Valid {
		return claims, nil
	}

	return nil, fmt.Errorf("invalid token claims")
}

// GetUserByID retrieves user by ID
func (as *AuthService) GetUserByID(userID string) (*models.User, error) {
	var user models.User
	if err := as.db.Where("id = ?", userID).First(&user).Error; err != nil {
		return nil, fmt.Errorf("user not found")
	}
	return &user, nil
}

// GetUserByEmail retrieves user by email
func (as *AuthService) GetUserByEmail(email string) (*models.User, error) {
	var user models.User
	if err := as.db.Where("email = ?", email).First(&user).Error; err != nil {
		return nil, fmt.Errorf("user not found")
	}
	return &user, nil
}

// UpdateProfile updates user profile data
func (as *AuthService) UpdateProfile(userID string, profileData *models.ProfileDataStruct) error {
	profileBytes, err := json.Marshal(profileData)
	if err != nil {
		return fmt.Errorf("failed to marshal profile data: %w", err)
	}

	if err := as.db.Model(&models.User{}).Where("id = ?", userID).Update("profile_data", string(profileBytes)).Error; err != nil {
		return fmt.Errorf("failed to update profile: %w", err)
	}

	return nil
}

// ChangePassword updates user password
func (as *AuthService) ChangePassword(userID, newPassword string) error {
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(newPassword), as.config.BCryptCost)
	if err != nil {
		return fmt.Errorf("failed to hash password: %w", err)
	}

	if err := as.db.Model(&models.User{}).Where("id = ?", userID).Update("password_hash", string(hashedPassword)).Error; err != nil {
		return fmt.Errorf("failed to update password: %w", err)
	}

	// Revoke all refresh tokens for security
	if err := as.db.Model(&models.RefreshToken{}).Where("user_id = ?", userID).Update("revoked", true).Error; err != nil {
		return fmt.Errorf("failed to revoke refresh tokens: %w", err)
	}

	return nil
}

// CreateEmailToken creates a token for email verification or password reset
func (as *AuthService) CreateEmailToken(userID uuid.UUID, tokenType models.EmailTokenType, expiryDuration time.Duration) (string, error) {
	token, err := as.generateRandomToken()
	if err != nil {
		return "", fmt.Errorf("failed to generate token: %w", err)
	}

	emailToken := &models.EmailToken{
		UserID:    userID,
		Token:     token,
		Type:      tokenType,
		ExpiresAt: time.Now().Add(expiryDuration),
	}

	if err := as.db.Create(emailToken).Error; err != nil {
		return "", fmt.Errorf("failed to create email token: %w", err)
	}

	return token, nil
}

// ValidateEmailToken validates and marks email token as used
func (as *AuthService) ValidateEmailToken(token string, tokenType models.EmailTokenType) (*models.User, error) {
	var emailToken models.EmailToken
	if err := as.db.Preload("User").Where("token = ? AND type = ?", token, tokenType).First(&emailToken).Error; err != nil {
		return nil, fmt.Errorf("invalid token")
	}

	if !emailToken.IsValid() {
		return nil, fmt.Errorf("token expired or already used")
	}

	// Mark token as used
	emailToken.Used = true
	as.db.Save(&emailToken)

	return &emailToken.User, nil
}

// VerifyEmail marks user email as verified
func (as *AuthService) VerifyEmail(userID uuid.UUID) error {
	return as.db.Model(&models.User{}).Where("id = ?", userID).Update("email_verified", true).Error
}

// EnableMFA enables MFA for a user
func (as *AuthService) EnableMFA(userID, secret string) error {
	return as.db.Model(&models.User{}).Where("id = ?", userID).Updates(map[string]interface{}{
		"mfa_enabled": true,
		"mfa_secret":  secret,
	}).Error
}

// DisableMFA disables MFA for a user
func (as *AuthService) DisableMFA(userID string) error {
	return as.db.Model(&models.User{}).Where("id = ?", userID).Updates(map[string]interface{}{
		"mfa_enabled": false,
		"mfa_secret":  "",
	}).Error
}

// DeleteUser soft deletes a user account
func (as *AuthService) DeleteUser(userID string) error {
	// Revoke all refresh tokens
	if err := as.db.Model(&models.RefreshToken{}).Where("user_id = ?", userID).Update("revoked", true).Error; err != nil {
		return fmt.Errorf("failed to revoke refresh tokens: %w", err)
	}

	// Soft delete user
	if err := as.db.Delete(&models.User{}, "id = ?", userID).Error; err != nil {
		return fmt.Errorf("failed to delete user: %w", err)
	}

	return nil
}

// FindOrCreateSocialUser finds an existing user or creates a new one based on social provider info.
func (as *AuthService) FindOrCreateSocialUser(email, firstName, lastName, provider, providerID string) (*models.User, error) {
	// Check if a user with this social provider ID already exists
	var socialProvider models.SocialProvider
	if err := as.db.Where("provider = ? AND provider_user_id = ?", provider, providerID).First(&socialProvider).Error; err == nil {
		// Social provider found, return the associated user
		var user models.User
		if err := as.db.First(&user, socialProvider.UserID).Error; err != nil {
			return nil, err
		}
		return &user, nil
	}

	// Check if a user with this email already exists
	var user models.User
	if err := as.db.Where("email = ?", email).First(&user).Error; err == nil {
		// User with this email exists, link the new social provider to them
		newSocialProvider := models.SocialProvider{
			UserID:         user.ID,
			Provider:       provider,
			ProviderUserID: providerID,
		}
		if err := as.db.Create(&newSocialProvider).Error; err != nil {
			return nil, err
		}
		return &user, nil
	}

	// No user found, create a new user and social provider record
	profileData := &models.ProfileDataStruct{
		FirstName: firstName,
		LastName:  lastName,
	}
	profileBytes, err := json.Marshal(profileData)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal profile data: %w", err)
	}

	newUser := models.User{
		Email:         email,
		EmailVerified: true, // Social logins are considered verified
		ProfileData:   string(profileBytes),
	}

	// Use a transaction to ensure both user and social provider are created
	tx := as.db.Begin()
	if err := tx.Create(&newUser).Error; err != nil {
		tx.Rollback()
		return nil, err
	}

	newSocialProvider := models.SocialProvider{
		UserID:         newUser.ID,
		Provider:       provider,
		ProviderUserID: providerID,
	}
	if err := tx.Create(&newSocialProvider).Error; err != nil {
		tx.Rollback()
		return nil, err
	}

	return &newUser, tx.Commit().Error
}

// generateRandomToken generates a cryptographically secure random token
func (as *AuthService) generateRandomToken() (string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}
