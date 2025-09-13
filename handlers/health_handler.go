package handlers

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

type HealthHandler struct {
	db *gorm.DB
}

func NewHealthHandler(db *gorm.DB) *HealthHandler {
	return &HealthHandler{
		db: db,
	}
}

// Health performs health checks and returns system status
func (h *HealthHandler) Health(c *gin.Context) {
	status := gin.H{
		"status":    "healthy",
		"timestamp": time.Now().UTC(),
		"service":   "auth-service",
		"version":   "1.0.0",
	}

	// Check database connection
	sqlDB, err := h.db.DB()
	if err != nil {
		status["status"] = "unhealthy"
		status["database"] = "connection error"
		c.JSON(http.StatusServiceUnavailable, status)
		return
	}

	if err := sqlDB.Ping(); err != nil {
		status["status"] = "unhealthy"
		status["database"] = "ping failed"
		c.JSON(http.StatusServiceUnavailable, status)
		return
	}

	status["database"] = "healthy"

	// Check database stats
	stats := sqlDB.Stats()
	status["database_stats"] = gin.H{
		"open_connections": stats.OpenConnections,
		"in_use":          stats.InUse,
		"idle":            stats.Idle,
	}

	c.JSON(http.StatusOK, status)
}
