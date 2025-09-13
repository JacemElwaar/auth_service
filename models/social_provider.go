package models

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

type SocialProvider struct {
	ID             uuid.UUID      `gorm:"type:uuid;primary_key" json:"id"`
	UserID         uuid.UUID      `gorm:"type:uuid;not null;index" json:"user_id"`
	Provider       string         `gorm:"not null;index" json:"provider"` // google, linkedin, twitter
	ProviderUserID string         `gorm:"not null" json:"provider_user_id"`
	AccessToken    string         `gorm:"type:text" json:"-"`
	RefreshToken   string         `gorm:"type:text" json:"-"`
	TokenExpiresAt *time.Time     `json:"token_expires_at,omitempty"`
	CreatedAt      time.Time      `json:"created_at"`
	UpdatedAt      time.Time      `json:"updated_at"`
	DeletedAt      gorm.DeletedAt `gorm:"index" json:"-"`

	// Relationships
	User User `gorm:"foreignKey:UserID" json:"user,omitempty"`
}

// BeforeCreate will set a UUID rather than numeric ID.
func (sp *SocialProvider) BeforeCreate(tx *gorm.DB) error {
	if sp.ID == uuid.Nil {
		sp.ID = uuid.New()
	}
	return nil
}

// TableName specifies the table name for the SocialProvider model
func (SocialProvider) TableName() string {
	return "social_providers"
}

// IsTokenExpired checks if the access token is expired
func (sp *SocialProvider) IsTokenExpired() bool {
	if sp.TokenExpiresAt == nil {
		return false
	}
	return time.Now().After(*sp.TokenExpiresAt)
}

// SupportedProviders lists all supported OAuth providers
var SupportedProviders = []string{"google", "linkedin", "twitter"}
