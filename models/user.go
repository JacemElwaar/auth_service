package models

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

type User struct {
	ID            uuid.UUID      `gorm:"type:uuid;primary_key" json:"id"`
	Email         string         `gorm:"uniqueIndex;not null" json:"email" validate:"required,email"`
	PasswordHash  string         `gorm:"not null" json:"-"`
	EmailVerified bool           `gorm:"default:false" json:"email_verified"`
	MFAEnabled    bool           `gorm:"default:false" json:"mfa_enabled"`
	MFASecret     string         `gorm:"type:text" json:"-"`
	ProfileData   string         `gorm:"type:jsonb" json:"profile_data,omitempty"`
	CreatedAt     time.Time      `json:"created_at"`
	UpdatedAt     time.Time      `json:"updated_at"`
	DeletedAt     gorm.DeletedAt `gorm:"index" json:"-"`

	// Relationships
	SocialProviders []SocialProvider `gorm:"foreignKey:UserID" json:"social_providers,omitempty"`
	RefreshTokens   []RefreshToken   `gorm:"foreignKey:UserID" json:"-"`
	EmailTokens     []EmailToken     `gorm:"foreignKey:UserID" json:"-"`
}

// BeforeCreate will set a UUID rather than numeric ID.
func (u *User) BeforeCreate(tx *gorm.DB) error {
	if u.ID == uuid.Nil {
		u.ID = uuid.New()
	}
	return nil
}

// TableName specifies the table name for the User model
func (User) TableName() string {
	return "users"
}

// ProfileDataStruct represents the structure of profile data JSON
type ProfileDataStruct struct {
	FirstName   string `json:"first_name,omitempty"`
	LastName    string `json:"last_name,omitempty"`
	DisplayName string `json:"display_name,omitempty"`
	Avatar      string `json:"avatar,omitempty"`
	Location    string `json:"location,omitempty"`
	Website     string `json:"website,omitempty"`
}
