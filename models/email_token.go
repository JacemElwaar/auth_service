package models

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

type EmailTokenType string

const (
	EmailVerificationToken EmailTokenType = "verification"
	PasswordResetToken     EmailTokenType = "password_reset"
)

type EmailToken struct {
	ID        uuid.UUID      `gorm:"type:uuid;primary_key" json:"id"`
	UserID    uuid.UUID      `gorm:"type:uuid;not null;index" json:"user_id"`
	Token     string         `gorm:"uniqueIndex;not null" json:"-"`
	Type      EmailTokenType `gorm:"not null;index" json:"type"`
	ExpiresAt time.Time      `gorm:"not null;index" json:"expires_at"`
	Used      bool           `gorm:"default:false" json:"used"`
	CreatedAt time.Time      `json:"created_at"`
	UpdatedAt time.Time      `json:"updated_at"`
	DeletedAt gorm.DeletedAt `gorm:"index" json:"-"`

	// Relationships
	User User `gorm:"foreignKey:UserID" json:"user,omitempty"`
}

// BeforeCreate will set a UUID rather than numeric ID.
func (et *EmailToken) BeforeCreate(tx *gorm.DB) error {
	if et.ID == uuid.Nil {
		et.ID = uuid.New()
	}
	return nil
}

// TableName specifies the table name for the EmailToken model
func (EmailToken) TableName() string {
	return "email_tokens"
}

// IsExpired checks if the email token is expired
func (et *EmailToken) IsExpired() bool {
	return time.Now().After(et.ExpiresAt)
}

// IsValid checks if the email token is valid (not used and not expired)
func (et *EmailToken) IsValid() bool {
	return !et.Used && !et.IsExpired()
}
