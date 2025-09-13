package models

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

type OAuthClient struct {
	ID           uuid.UUID      `gorm:"type:uuid;primary_key" json:"id"`
	ClientName   string         `gorm:"not null" json:"client_name"`
	ClientSecret string         `gorm:"not null" json:"-"`
	RedirectURIs string         `gorm:"type:text;not null" json:"redirect_uris"` // JSON array of URIs
	Scopes       string         `gorm:"type:text;not null" json:"scopes"`        // JSON array of scopes
	CreatedAt    time.Time      `json:"created_at"`
	UpdatedAt    time.Time      `json:"updated_at"`
	DeletedAt    gorm.DeletedAt `gorm:"index" json:"-"`
}

// BeforeCreate will set a UUID rather than numeric ID.
func (oc *OAuthClient) BeforeCreate(tx *gorm.DB) error {
	if oc.ID == uuid.Nil {
		oc.ID = uuid.New()
	}
	return nil
}

// TableName specifies the table name for the OAuthClient model
func (OAuthClient) TableName() string {
	return "oauth_clients"
}

// DefaultScopes defines the default OAuth2 scopes
var DefaultScopes = []string{
	"openid",
	"profile",
	"email",
	"offline_access",
}
