package database

import (
	"fmt"

	"auth-service/config"
	"auth-service/models"

	"gorm.io/driver/postgres"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

func Initialize(cfg *config.Config) (*gorm.DB, error) {
	var db *gorm.DB
	var err error

	// Configure GORM logger
	gormConfig := &gorm.Config{
		Logger: logger.Default.LogMode(logger.Info),
	}

	// Connect to database based on driver
	switch cfg.DatabaseDriver {
	case "postgres":
		db, err = gorm.Open(postgres.Open(cfg.DatabaseURL), gormConfig)
	case "sqlite":
		db, err = gorm.Open(sqlite.Open(cfg.DatabaseURL), gormConfig)
	default:
		return nil, fmt.Errorf("unsupported database driver: %s", cfg.DatabaseDriver)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to connect to database: %w", err)
	}

	// Run migrations if enabled
	if cfg.MigrateOnStartup {
		if err := runMigrations(db); err != nil {
			return nil, fmt.Errorf("failed to run migrations: %w", err)
		}
	}

	return db, nil
}

func runMigrations(db *gorm.DB) error {
	// Auto-migrate all models
	return db.AutoMigrate(
		&models.User{},
		&models.SocialProvider{},
		&models.OAuthClient{},
		&models.RefreshToken{},
		&models.EmailToken{},
	)
}

// CreateIndexes creates additional database indexes for performance
func CreateIndexes(db *gorm.DB) error {
	// Create composite indexes for better query performance
	if err := db.Exec("CREATE INDEX IF NOT EXISTS idx_social_providers_provider_user ON social_providers(provider, provider_user_id)").Error; err != nil {
		return err
	}

	if err := db.Exec("CREATE INDEX IF NOT EXISTS idx_email_tokens_type_expires ON email_tokens(type, expires_at)").Error; err != nil {
		return err
	}

	if err := db.Exec("CREATE INDEX IF NOT EXISTS idx_refresh_tokens_user_expires ON refresh_tokens(user_id, expires_at)").Error; err != nil {
		return err
	}

	return nil
}
