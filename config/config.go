package config

import (
	"os"
	"strconv"
	"time"
)

type Config struct {
	// Database
	DatabaseURL      string
	DatabaseDriver   string
	MigrateOnStartup bool

	// JWT
	JWTSecret           string
	AccessTokenExpiry   time.Duration
	RefreshTokenExpiry  time.Duration

	// Email
	SMTPHost     string
	SMTPPort     int
	SMTPUsername string
	SMTPPassword string
	SMTPFrom     string

	// OAuth Providers
	GoogleClientID     string
	GoogleClientSecret string
	LinkedInClientID   string
	LinkedInClientSecret string
	TwitterClientID    string
	TwitterClientSecret string

	// Server
	Port        string
	Environment string
	BaseURL     string

	// ORY Integration
	HydraAdminURL  string
	HydraPublicURL string
	KratosAdminURL string
	KratosPublicURL string

	// Security
	BCryptCost int
}

func Load() *Config {
	return &Config{
		// Database
		DatabaseURL:      getEnv("DATABASE_URL", "auth_service.db"),
		DatabaseDriver:   getEnv("DATABASE_DRIVER", "sqlite"),
		MigrateOnStartup: getEnvBool("MIGRATE_ON_STARTUP", true),

		// JWT
		JWTSecret:          getEnv("JWT_SECRET", "your-super-secret-jwt-key-change-in-production"),
		AccessTokenExpiry:  getEnvDuration("ACCESS_TOKEN_EXPIRY", 15*time.Minute),
		RefreshTokenExpiry: getEnvDuration("REFRESH_TOKEN_EXPIRY", 7*24*time.Hour),

		// Email
		SMTPHost:     getEnv("SMTP_HOST", "localhost"),
		SMTPPort:     getEnvInt("SMTP_PORT", 1025), // MailHog default
		SMTPUsername: getEnv("SMTP_USERNAME", ""),
		SMTPPassword: getEnv("SMTP_PASSWORD", ""),
		SMTPFrom:     getEnv("SMTP_FROM", "noreply@auth-service.local"),

		// OAuth Providers
		GoogleClientID:       getEnv("GOOGLE_CLIENT_ID", ""),
		GoogleClientSecret:   getEnv("GOOGLE_CLIENT_SECRET", ""),
		LinkedInClientID:     getEnv("LINKEDIN_CLIENT_ID", ""),
		LinkedInClientSecret: getEnv("LINKEDIN_CLIENT_SECRET", ""),
		TwitterClientID:      getEnv("TWITTER_CLIENT_ID", ""),
		TwitterClientSecret:  getEnv("TWITTER_CLIENT_SECRET", ""),

		// Server
		Port:        getEnv("PORT", "8080"),
		Environment: getEnv("ENVIRONMENT", "development"),
		BaseURL:     getEnv("BASE_URL", "http://localhost:8080"),

		// ORY Integration
		HydraAdminURL:   getEnv("HYDRA_ADMIN_URL", "http://localhost:4445"),
		HydraPublicURL:  getEnv("HYDRA_PUBLIC_URL", "http://localhost:4444"),
		KratosAdminURL:  getEnv("KRATOS_ADMIN_URL", "http://localhost:4434"),
		KratosPublicURL: getEnv("KRATOS_PUBLIC_URL", "http://localhost:4433"),

		// Security
		BCryptCost: getEnvInt("BCRYPT_COST", 12),
	}
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func getEnvInt(key string, defaultValue int) int {
	if value := os.Getenv(key); value != "" {
		if intValue, err := strconv.Atoi(value); err == nil {
			return intValue
		}
	}
	return defaultValue
}

func getEnvBool(key string, defaultValue bool) bool {
	if value := os.Getenv(key); value != "" {
		if boolValue, err := strconv.ParseBool(value); err == nil {
			return boolValue
		}
	}
	return defaultValue
}

func getEnvDuration(key string, defaultValue time.Duration) time.Duration {
	if value := os.Getenv(key); value != "" {
		if duration, err := time.ParseDuration(value); err == nil {
			return duration
		}
	}
	return defaultValue
}
