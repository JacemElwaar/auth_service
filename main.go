package main

import (
	"log"
	"os"

	"auth-service/config"
	"auth-service/database"
	"auth-service/handlers"
	"auth-service/middleware"
	"auth-service/services"

	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
	"github.com/sirupsen/logrus"
)

func main() {
	// Load environment variables
	if err := godotenv.Load(); err != nil {
		logrus.Warn("No .env file found")
	}

	// Initialize configuration
	cfg := config.Load()

	// Initialize database
	db, err := database.Initialize(cfg)
	if err != nil {
		log.Fatal("Failed to initialize database:", err)
	}

	// Initialize services
	emailService := services.NewEmailService(cfg)
	authService := services.NewAuthService(db, cfg)
	mfaService := services.NewMFAService()
	socialAuthService, err := services.NewSocialAuthService(cfg)
	if err != nil {
		log.Fatal("Failed to initialize social auth service:", err)
	}

	// Initialize handlers
	authHandler := handlers.NewAuthHandler(authService, emailService, mfaService)
	healthHandler := handlers.NewHealthHandler(db)
	socialAuthHandler := handlers.NewSocialAuthHandler(socialAuthService, authService)

	// Setup router
	router := gin.New()
	router.Use(gin.Logger())
	router.Use(gin.Recovery())
	router.Use(middleware.CORS())
	router.Use(middleware.Metrics())

	// Inject auth service into context for middleware
	router.Use(func(c *gin.Context) {
		c.Set("authService", authService)
		c.Next()
	})

	// Health endpoints
	router.GET("/health", healthHandler.Health)
	router.GET("/metrics", gin.WrapH(middleware.PrometheusHandler()))

	// API routes
	v1 := router.Group("/api/v1")
	{
		// Authentication routes
		v1.POST("/register", authHandler.Register)
		v1.POST("/login", authHandler.Login)
		v1.POST("/forgot-password", authHandler.ForgotPassword)
		v1.POST("/reset-password", authHandler.ResetPassword)
		v1.POST("/verify-email", authHandler.VerifyEmail)
		v1.POST("/resend-verification", authHandler.ResendVerification)
		v1.POST("/refresh-token", authHandler.RefreshToken)
		v1.POST("/logout", authHandler.Logout)

		// Social Login routes
		v1.GET("/social/login/:provider", socialAuthHandler.SocialLoginRedirect)
		v1.GET("/social/callback/:provider", socialAuthHandler.SocialLoginCallback)

		// MFA routes
		v1.POST("/mfa/setup", middleware.RequireAuth(), authHandler.SetupMFA)
		v1.POST("/mfa/verify", middleware.RequireAuth(), authHandler.VerifyMFA)
		v1.POST("/mfa/disable", middleware.RequireAuth(), authHandler.DisableMFA)

		// Profile routes
		v1.GET("/profile", middleware.RequireAuth(), authHandler.GetProfile)
		v1.PUT("/profile", middleware.RequireAuth(), authHandler.UpdateProfile)
		v1.DELETE("/profile", middleware.RequireAuth(), authHandler.DeleteProfile)
	}

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	logrus.Infof("Starting server on port %s", port)
	if err := router.Run(":" + port); err != nil {
		log.Fatal("Failed to start server:", err)
	}
}
