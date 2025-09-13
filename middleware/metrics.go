package middleware

import (
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
	httpRequestsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "http_requests_total",
			Help: "Total number of HTTP requests",
		},
		[]string{"method", "endpoint", "status_code"},
	)

	httpRequestDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "http_request_duration_seconds",
			Help:    "Duration of HTTP requests in seconds",
			Buckets: prometheus.DefBuckets,
		},
		[]string{"method", "endpoint"},
	)

	authAttempts = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "auth_attempts_total",
			Help: "Total number of authentication attempts",
		},
		[]string{"type", "status"},
	)

	emailsSent = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "emails_sent_total",
			Help: "Total number of emails sent",
		},
		[]string{"type", "status"},
	)

	activeTokens = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "active_tokens_count",
			Help: "Number of active refresh tokens",
		},
	)
)

func init() {
	prometheus.MustRegister(httpRequestsTotal)
	prometheus.MustRegister(httpRequestDuration)
	prometheus.MustRegister(authAttempts)
	prometheus.MustRegister(emailsSent)
	prometheus.MustRegister(activeTokens)
}

func Metrics() gin.HandlerFunc {
	return gin.HandlerFunc(func(c *gin.Context) {
		start := time.Now()

		c.Next()

		duration := time.Since(start).Seconds()
		statusCode := strconv.Itoa(c.Writer.Status())

		httpRequestsTotal.WithLabelValues(
			c.Request.Method,
			c.FullPath(),
			statusCode,
		).Inc()

		httpRequestDuration.WithLabelValues(
			c.Request.Method,
			c.FullPath(),
		).Observe(duration)
	})
}

func PrometheusHandler() http.Handler {
	return promhttp.Handler()
}

// RecordAuthAttempt records authentication attempt metrics
func RecordAuthAttempt(authType, status string) {
	authAttempts.WithLabelValues(authType, status).Inc()
}

// RecordEmailSent records email sending metrics
func RecordEmailSent(emailType, status string) {
	emailsSent.WithLabelValues(emailType, status).Inc()
}

// UpdateActiveTokens updates the active tokens gauge
func UpdateActiveTokens(count float64) {
	activeTokens.Set(count)
}
