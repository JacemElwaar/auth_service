package handlers

import (
	"encoding/json"
	"net/http"
	"time"

	"auth-service/middleware"
	"auth-service/models"
	"auth-service/services"

	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/bcrypt"
)

type AuthHandler struct {
	authService  *services.AuthService
	emailService *services.EmailService
	mfaService   *services.MFAService
}

type RegisterRequest struct {
	Email       string                    `json:"email" binding:"required,email"`
	Password    string                    `json:"password" binding:"required,min=8"`
	ProfileData *models.ProfileDataStruct `json:"profile_data,omitempty"`
}

type LoginRequest struct {
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password" binding:"required"`
	MFACode  string `json:"mfa_code,omitempty"`
}

type SocialRegisterRequest struct {
	Provider    string                    `json:"provider" binding:"required"`
	AccessToken string                    `json:"access_token" binding:"required"`
	Email       string                    `json:"email" binding:"required,email"`
	ProfileData *models.ProfileDataStruct `json:"profile_data,omitempty"`
}

type ForgotPasswordRequest struct {
	Email string `json:"email" binding:"required,email"`
}

type ResetPasswordRequest struct {
	Token       string `json:"token" binding:"required"`
	NewPassword string `json:"new_password" binding:"required,min=8"`
}

type VerifyEmailRequest struct {
	Token string `json:"token" binding:"required"`
}

type RefreshTokenRequest struct {
	RefreshToken string `json:"refresh_token" binding:"required"`
}

func NewAuthHandler(authService *services.AuthService, emailService *services.EmailService, mfaService *services.MFAService) *AuthHandler {
	return &AuthHandler{
		authService:  authService,
		emailService: emailService,
		mfaService:   mfaService,
	}
}

// Register handles user registration
func (h *AuthHandler) Register(c *gin.Context) {
	var req RegisterRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Create user
	user, err := h.authService.Register(req.Email, req.Password, req.ProfileData)
	if err != nil {
		middleware.RecordAuthAttempt("register", "failed")
		logrus.WithError(err).Error("Failed to register user")
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Create email verification token
	token, err := h.authService.CreateEmailToken(user.ID, models.EmailVerificationToken, 24*time.Hour)
	if err != nil {
		logrus.WithError(err).Error("Failed to create email verification token")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create verification token"})
		return
	}

	// Send verification email
	if err := h.emailService.SendVerificationEmail(user.Email, token); err != nil {
		middleware.RecordEmailSent("verification", "failed")
		logrus.WithError(err).Error("Failed to send verification email")
	} else {
		middleware.RecordEmailSent("verification", "success")
	}

	middleware.RecordAuthAttempt("register", "success")
	c.JSON(http.StatusCreated, gin.H{
		"message": "User registered successfully. Please check your email for verification.",
		"user_id": user.ID,
	})
}

// Login handles user authentication
func (h *AuthHandler) Login(c *gin.Context) {
	var req LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Authenticate user
	tokens, user, err := h.authService.Login(req.Email, req.Password)
	if err != nil {
		middleware.RecordAuthAttempt("login", "failed")
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
		return
	}

	// Check if MFA is enabled
	if user.MFAEnabled {
		if req.MFACode == "" {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error":        "MFA code required",
				"mfa_required": true,
			})
			return
		}

		// Verify MFA code
		if !h.mfaService.VerifyTOTP(user.MFASecret, req.MFACode) {
			middleware.RecordAuthAttempt("mfa", "failed")
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid MFA code"})
			return
		}
		middleware.RecordAuthAttempt("mfa", "success")
	}

	middleware.RecordAuthAttempt("login", "success")
	c.JSON(http.StatusOK, gin.H{
		"message": "Login successful",
		"tokens":  tokens,
		"user":    user,
	})
}

// SocialRegister handles social provider registration
func (h *AuthHandler) SocialRegister(c *gin.Context) {
	var req SocialRegisterRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// TODO: Validate social provider token
	// This would involve calling the provider's API to verify the token

	// Create user
	user, err := h.authService.Register(req.Email, "", req.ProfileData)
	if err != nil {
		middleware.RecordAuthAttempt("social_register", "failed")
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Mark email as verified for social logins
	h.authService.VerifyEmail(user.ID)

	// TODO: Create social provider record
	// This would store the social provider information

	middleware.RecordAuthAttempt("social_register", "success")
	c.JSON(http.StatusCreated, gin.H{
		"message": "Social registration successful",
		"user_id": user.ID,
	})
}

// SocialLogin handles social provider login
func (h *AuthHandler) SocialLogin(c *gin.Context) {
	// TODO: Implement social login logic
	c.JSON(http.StatusNotImplemented, gin.H{"error": "Social login not implemented yet"})
}

// ForgotPassword initiates password reset process
func (h *AuthHandler) ForgotPassword(c *gin.Context) {
	var req ForgotPasswordRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Find user by email
	user, err := h.authService.GetUserByEmail(req.Email)
	if err != nil {
		// Don't reveal if email exists or not
		c.JSON(http.StatusOK, gin.H{"message": "If the email exists, a password reset link has been sent."})
		return
	}

	// Create password reset token
	token, err := h.authService.CreateEmailToken(user.ID, models.PasswordResetToken, 1*time.Hour)
	if err != nil {
		logrus.WithError(err).Error("Failed to create password reset token")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create reset token"})
		return
	}

	// Send password reset email
	if err := h.emailService.SendPasswordResetEmail(user.Email, token); err != nil {
		middleware.RecordEmailSent("password_reset", "failed")
		logrus.WithError(err).Error("Failed to send password reset email")
	} else {
		middleware.RecordEmailSent("password_reset", "success")
	}

	c.JSON(http.StatusOK, gin.H{"message": "If the email exists, a password reset link has been sent."})
}

// ResetPassword handles password reset with token
func (h *AuthHandler) ResetPassword(c *gin.Context) {
	var req ResetPasswordRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Validate reset token
	user, err := h.authService.ValidateEmailToken(req.Token, models.PasswordResetToken)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid or expired reset token"})
		return
	}

	// Update password
	if err := h.authService.ChangePassword(user.ID.String(), req.NewPassword); err != nil {
		logrus.WithError(err).Error("Failed to change password")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update password"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Password reset successful"})
}

// VerifyEmail handles email verification
func (h *AuthHandler) VerifyEmail(c *gin.Context) {
	token := c.Query("token")
	if token == "" {
		var req VerifyEmailRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Token required"})
			return
		}
		token = req.Token
	}

	// Validate verification token
	user, err := h.authService.ValidateEmailToken(token, models.EmailVerificationToken)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid or expired verification token"})
		return
	}

	// Mark email as verified
	if err := h.authService.VerifyEmail(user.ID); err != nil {
		logrus.WithError(err).Error("Failed to verify email")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to verify email"})
		return
	}

	// Send welcome email
	if profileData := user.ProfileData; profileData != "" {
		var profile models.ProfileDataStruct
		if err := json.Unmarshal([]byte(profileData), &profile); err == nil {
			h.emailService.SendWelcomeEmail(user.Email, profile.DisplayName)
		}
	}

	c.JSON(http.StatusOK, gin.H{"message": "Email verified successfully"})
}

// ResendVerification resends email verification
func (h *AuthHandler) ResendVerification(c *gin.Context) {
	var req struct {
		Email string `json:"email" binding:"required,email"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Find user
	user, err := h.authService.GetUserByEmail(req.Email)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{"message": "If the email exists and is unverified, a verification email has been sent."})
		return
	}

	if user.EmailVerified {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Email already verified"})
		return
	}

	// Create new verification token
	token, err := h.authService.CreateEmailToken(user.ID, models.EmailVerificationToken, 24*time.Hour)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create verification token"})
		return
	}

	// Send verification email
	if err := h.emailService.SendVerificationEmail(user.Email, token); err != nil {
		middleware.RecordEmailSent("verification", "failed")
		logrus.WithError(err).Error("Failed to send verification email")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to send verification email"})
		return
	}

	middleware.RecordEmailSent("verification", "success")
	c.JSON(http.StatusOK, gin.H{"message": "Verification email sent"})
}

// RefreshToken handles token refresh
func (h *AuthHandler) RefreshToken(c *gin.Context) {
	var req RefreshTokenRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Refresh tokens
	tokens, err := h.authService.RefreshTokens(req.RefreshToken)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid refresh token"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "Tokens refreshed successfully",
		"tokens":  tokens,
	})
}

// Logout handles user logout
func (h *AuthHandler) Logout(c *gin.Context) {
	var req RefreshTokenRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// TODO: Revoke refresh token
	// This would mark the refresh token as revoked in the database

	c.JSON(http.StatusOK, gin.H{"message": "Logged out successfully"})
}

// SetupMFA initiates MFA setup for a user
func (h *AuthHandler) SetupMFA(c *gin.Context) {
	userEmail := c.GetString("userEmail")

	// Generate MFA secret
	secret, err := h.mfaService.GenerateSecret(userEmail)
	if err != nil {
		logrus.WithError(err).Error("Failed to generate MFA secret")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate MFA secret"})
		return
	}

	// Generate QR code URL
	qrCodeURL, err := h.mfaService.GenerateQRCode(userEmail, secret)
	if err != nil {
		logrus.WithError(err).Error("Failed to generate QR code")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate QR code"})
		return
	}

	// Generate backup codes
	backupCodes, err := h.mfaService.GenerateBackupCodes()
	if err != nil {
		logrus.WithError(err).Error("Failed to generate backup codes")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate backup codes"})
		return
	}

	// Store secret temporarily (user needs to verify before enabling)
	// In a real implementation, you'd store this in a temporary table or cache
	c.JSON(http.StatusOK, gin.H{
		"secret":       secret,
		"qr_code_url":  qrCodeURL,
		"backup_codes": backupCodes,
		"message":      "Scan the QR code with your authenticator app and verify with a code to enable MFA",
	})
}

// VerifyMFA verifies and enables MFA for a user
func (h *AuthHandler) VerifyMFA(c *gin.Context) {
	userID := c.GetString("userID")

	var req struct {
		Secret string `json:"secret" binding:"required"`
		Code   string `json:"code" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Verify the TOTP code
	if !h.mfaService.VerifyTOTP(req.Secret, req.Code) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid MFA code"})
		return
	}

	// Enable MFA for the user
	if err := h.authService.EnableMFA(userID, req.Secret); err != nil {
		logrus.WithError(err).Error("Failed to enable MFA")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to enable MFA"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "MFA enabled successfully"})
}

// DisableMFA disables MFA for a user
func (h *AuthHandler) DisableMFA(c *gin.Context) {
	userID := c.GetString("userID")

	var req struct {
		Password string `json:"password" binding:"required"`
		Code     string `json:"code,omitempty"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Get user to verify password
	user, err := h.authService.GetUserByID(userID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	}

	// Verify password
	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(req.Password)); err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid password"})
		return
	}

	// If MFA is enabled, verify current MFA code
	if user.MFAEnabled && req.Code != "" {
		if !h.mfaService.VerifyTOTP(user.MFASecret, req.Code) {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid MFA code"})
			return
		}
	}

	// Disable MFA
	if err := h.authService.DisableMFA(userID); err != nil {
		logrus.WithError(err).Error("Failed to disable MFA")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to disable MFA"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "MFA disabled successfully"})
}

// GetProfile retrieves user profile
func (h *AuthHandler) GetProfile(c *gin.Context) {
	userID := c.GetString("userID")

	user, err := h.authService.GetUserByID(userID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	}

	// Parse profile data
	var profileData models.ProfileDataStruct
	if user.ProfileData != "" {
		if err := json.Unmarshal([]byte(user.ProfileData), &profileData); err != nil {
			logrus.WithError(err).Error("Failed to unmarshal profile data")
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"user_id":        user.ID,
		"email":          user.Email,
		"email_verified": user.EmailVerified,
		"mfa_enabled":    user.MFAEnabled,
		"profile_data":   profileData,
		"created_at":     user.CreatedAt,
		"updated_at":     user.UpdatedAt,
	})
}

// UpdateProfile updates user profile
func (h *AuthHandler) UpdateProfile(c *gin.Context) {
	userID := c.GetString("userID")

	var profileData models.ProfileDataStruct
	if err := c.ShouldBindJSON(&profileData); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if err := h.authService.UpdateProfile(userID, &profileData); err != nil {
		logrus.WithError(err).Error("Failed to update profile")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update profile"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Profile updated successfully"})
}

// DeleteProfile deletes user account
func (h *AuthHandler) DeleteProfile(c *gin.Context) {
	userID := c.GetString("userID")

	var req struct {
		Password string `json:"password" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Get user to verify password
	user, err := h.authService.GetUserByID(userID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	}

	// Verify password
	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(req.Password)); err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid password"})
		return
	}

	// Delete user account
	if err := h.authService.DeleteUser(userID); err != nil {
		logrus.WithError(err).Error("Failed to delete user")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete account"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Account deleted successfully"})
}
