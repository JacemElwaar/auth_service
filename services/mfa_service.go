package services

import (
	"crypto/rand"
	"encoding/base32"
	"fmt"
	"strings"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

type MFAService struct{}

func NewMFAService() *MFAService {
	return &MFAService{}
}

// GenerateSecret generates a new TOTP secret for a user
func (mfa *MFAService) GenerateSecret(userEmail string) (string, error) {
	// Generate random secret
	secret := make([]byte, 20)
	_, err := rand.Read(secret)
	if err != nil {
		return "", fmt.Errorf("failed to generate random secret: %w", err)
	}

	// Encode to base32
	secretBase32 := base32.StdEncoding.EncodeToString(secret)
	return secretBase32, nil
}

// GenerateQRCode generates a QR code URL for TOTP setup
func (mfa *MFAService) GenerateQRCode(userEmail, secret string) (string, error) {
	key, err := otp.NewKeyFromURL(fmt.Sprintf(
		"otpauth://totp/Auth%%20Service:%s?secret=%s&issuer=Auth%%20Service",
		userEmail,
		secret,
	))
	if err != nil {
		return "", fmt.Errorf("failed to create OTP key: %w", err)
	}

	return key.URL(), nil
}

// VerifyTOTP verifies a TOTP code against a secret
func (mfa *MFAService) VerifyTOTP(secret, code string) bool {
	// Remove any spaces from the code
	code = strings.ReplaceAll(code, " ", "")
	
	// Verify the TOTP code
	return totp.Validate(code, secret)
}

// GenerateBackupCodes generates backup codes for MFA
func (mfa *MFAService) GenerateBackupCodes() ([]string, error) {
	codes := make([]string, 10)
	
	for i := 0; i < 10; i++ {
		// Generate 8-character backup code
		bytes := make([]byte, 4)
		_, err := rand.Read(bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to generate backup code: %w", err)
		}
		
		// Convert to hex and format as XXXX-XXXX
		code := fmt.Sprintf("%X", bytes)
		codes[i] = fmt.Sprintf("%s-%s", code[:4], code[4:])
	}
	
	return codes, nil
}

// ValidateBackupCode validates a backup code format
func (mfa *MFAService) ValidateBackupCode(code string) bool {
	// Remove spaces and convert to uppercase
	code = strings.ToUpper(strings.ReplaceAll(code, " ", ""))
	
	// Check format: XXXX-XXXX (8 hex characters with dash)
	if len(code) != 9 || code[4] != '-' {
		return false
	}
	
	// Check if all characters except dash are hex
	for i, char := range code {
		if i == 4 {
			continue // Skip the dash
		}
		if !((char >= '0' && char <= '9') || (char >= 'A' && char <= 'F')) {
			return false
		}
	}
	
	return true
}
