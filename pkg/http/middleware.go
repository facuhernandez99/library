package http

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/facuhernandez99/library/pkg/logging"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// RequestIDMiddleware adds a unique request ID to each request for correlation
func RequestIDMiddleware() gin.HandlerFunc {
	return gin.HandlerFunc(func(c *gin.Context) {
		requestID := c.GetHeader("X-Request-ID")
		if requestID == "" {
			requestID = uuid.New().String()
		}

		// Set the request ID in the response header
		c.Header("X-Request-ID", requestID)

		// Store in context for use in handlers
		c.Set("request_id", requestID)

		// Add to Gin context
		ctx := context.WithValue(c.Request.Context(), "request_id", requestID)
		c.Request = c.Request.WithContext(ctx)

		c.Next()
	})
}

// GetRequestID extracts the request ID from the Gin context
func GetRequestID(c *gin.Context) string {
	if requestID, exists := c.Get("request_id"); exists {
		if id, ok := requestID.(string); ok {
			return id
		}
	}
	return ""
}

// RateLimiter holds rate limiting configuration and state
type RateLimiter struct {
	requests        map[string]*clientLimitInfo
	mutex           sync.RWMutex
	limit           int           // requests per window
	window          time.Duration // time window
	cleanupInterval time.Duration // cleanup interval
}

type clientLimitInfo struct {
	count     int
	lastReset time.Time
	mutex     sync.Mutex
}

// NewRateLimiter creates a new rate limiter
func NewRateLimiter(requestsPerWindow int, window time.Duration) *RateLimiter {
	rl := &RateLimiter{
		requests:        make(map[string]*clientLimitInfo),
		limit:           requestsPerWindow,
		window:          window,
		cleanupInterval: window * 2, // cleanup every 2 windows
	}

	// Start cleanup goroutine
	go rl.cleanupExpiredEntries()

	return rl
}

// RateLimitMiddleware returns a middleware that enforces rate limiting
func (rl *RateLimiter) RateLimitMiddleware() gin.HandlerFunc {
	return gin.HandlerFunc(func(c *gin.Context) {
		clientIP := c.ClientIP()

		if !rl.allowRequest(clientIP) {
			c.Header("X-Rate-Limit-Limit", fmt.Sprintf("%d", rl.limit))
			c.Header("X-Rate-Limit-Window", rl.window.String())
			RespondWithError(c, http.StatusTooManyRequests, "Rate limit exceeded")
			c.Abort()
			return
		}

		c.Header("X-Rate-Limit-Limit", fmt.Sprintf("%d", rl.limit))
		c.Next()
	})
}

// allowRequest checks if a request should be allowed based on rate limiting
func (rl *RateLimiter) allowRequest(clientID string) bool {
	rl.mutex.RLock()
	clientInfo, exists := rl.requests[clientID]
	rl.mutex.RUnlock()

	if !exists {
		rl.mutex.Lock()
		rl.requests[clientID] = &clientLimitInfo{
			count:     1,
			lastReset: time.Now(),
		}
		rl.mutex.Unlock()
		return true
	}

	clientInfo.mutex.Lock()
	defer clientInfo.mutex.Unlock()

	now := time.Now()
	if now.Sub(clientInfo.lastReset) > rl.window {
		clientInfo.count = 1
		clientInfo.lastReset = now
		return true
	}

	if clientInfo.count >= rl.limit {
		return false
	}

	clientInfo.count++
	return true
}

// cleanupExpiredEntries removes old entries from the rate limiter
func (rl *RateLimiter) cleanupExpiredEntries() {
	ticker := time.NewTicker(rl.cleanupInterval)
	defer ticker.Stop()

	for range ticker.C {
		rl.mutex.Lock()
		now := time.Now()
		for clientID, info := range rl.requests {
			info.mutex.Lock()
			if now.Sub(info.lastReset) > rl.cleanupInterval {
				delete(rl.requests, clientID)
			}
			info.mutex.Unlock()
		}
		rl.mutex.Unlock()
	}
}

// CORSConfig holds CORS configuration
type CORSConfig struct {
	AllowOrigins     []string
	AllowMethods     []string
	AllowHeaders     []string
	ExposeHeaders    []string
	AllowCredentials bool
	MaxAge           time.Duration
}

// DefaultCORSConfig returns a secure default CORS configuration
func DefaultCORSConfig() *CORSConfig {
	return &CORSConfig{
		AllowOrigins: []string{"*"},
		AllowMethods: []string{"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"},
		AllowHeaders: []string{
			"Origin",
			"Content-Length",
			"Content-Type",
			"Authorization",
			"X-Requested-With",
			"X-Request-ID",
		},
		ExposeHeaders: []string{
			"X-Request-ID",
			"X-Rate-Limit-Limit",
			"X-Rate-Limit-Window",
		},
		AllowCredentials: false,
		MaxAge:           12 * time.Hour,
	}
}

// CORSMiddleware returns a CORS middleware with security improvements
func CORSMiddleware(config *CORSConfig) gin.HandlerFunc {
	if config == nil {
		config = DefaultCORSConfig()
	}

	return gin.HandlerFunc(func(c *gin.Context) {
		origin := c.GetHeader("Origin")

		// Check if origin is allowed
		if len(config.AllowOrigins) > 0 && !isOriginAllowed(origin, config.AllowOrigins) {
			c.AbortWithStatus(http.StatusForbidden)
			return
		}

		// Set CORS headers
		if len(config.AllowOrigins) == 1 && config.AllowOrigins[0] == "*" {
			c.Header("Access-Control-Allow-Origin", "*")
		} else if origin != "" {
			c.Header("Access-Control-Allow-Origin", origin)
		}

		c.Header("Access-Control-Allow-Methods", strings.Join(config.AllowMethods, ", "))
		c.Header("Access-Control-Allow-Headers", strings.Join(config.AllowHeaders, ", "))

		if len(config.ExposeHeaders) > 0 {
			c.Header("Access-Control-Expose-Headers", strings.Join(config.ExposeHeaders, ", "))
		}

		if config.AllowCredentials {
			c.Header("Access-Control-Allow-Credentials", "true")
		}

		if config.MaxAge > 0 {
			c.Header("Access-Control-Max-Age", fmt.Sprintf("%.0f", config.MaxAge.Seconds()))
		}

		// Handle preflight requests
		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(http.StatusNoContent)
			return
		}

		c.Next()
	})
}

// isOriginAllowed checks if an origin is in the allowed list
func isOriginAllowed(origin string, allowedOrigins []string) bool {
	// Extract hostname from the full origin URL (e.g., "https://api.example.com" -> "api.example.com")
	hostname := origin
	if strings.Contains(origin, "://") {
		parts := strings.Split(origin, "://")
		if len(parts) > 1 {
			hostname = parts[1]
		}
	}

	for _, allowed := range allowedOrigins {
		if allowed == "*" || allowed == origin {
			return true
		}
		// Support wildcard subdomains (e.g., *.example.com)
		if strings.HasPrefix(allowed, "*.") {
			domain := strings.TrimPrefix(allowed, "*.")
			// Check both the full origin and the hostname for wildcard matches
			if strings.HasSuffix(hostname, "."+domain) || hostname == domain ||
				strings.HasSuffix(origin, "."+domain) || origin == domain {
				return true
			}
		}
	}
	return false
}

// SecurityHeadersMiddleware adds common security headers
func SecurityHeadersMiddleware() gin.HandlerFunc {
	return gin.HandlerFunc(func(c *gin.Context) {
		// Prevent MIME type sniffing
		c.Header("X-Content-Type-Options", "nosniff")

		// Prevent clickjacking
		c.Header("X-Frame-Options", "DENY")

		// Enable XSS protection
		c.Header("X-XSS-Protection", "1; mode=block")

		// Control referrer information
		c.Header("Referrer-Policy", "strict-origin-when-cross-origin")

		// Prevent browsers from loading HTTP content when HTTPS is used
		c.Header("Content-Security-Policy", "upgrade-insecure-requests")

		// Enforce HTTPS (uncomment in production with HTTPS)
		// c.Header("Strict-Transport-Security", "max-age=31536000; includeSubDomains")

		c.Next()
	})
}

// TimeoutMiddleware adds request timeout handling
func TimeoutMiddleware(timeout time.Duration) gin.HandlerFunc {
	return gin.HandlerFunc(func(c *gin.Context) {
		ctx, cancel := context.WithTimeout(c.Request.Context(), timeout)
		defer cancel()

		c.Request = c.Request.WithContext(ctx)

		// Use a buffered channel to avoid goroutine leaks
		done := make(chan bool, 1)

		go func() {
			c.Next()
			select {
			case done <- true:
			default:
				// Channel already closed or filled, request timed out
			}
		}()

		select {
		case <-ctx.Done():
			if ctx.Err() == context.DeadlineExceeded {
				RespondWithError(c, http.StatusRequestTimeout, "Request timeout")
				c.Abort()
				return
			}
		case <-done:
			// Request completed normally
			return
		}
	})
}

// LoggingMiddleware adds request logging with structured logging
// Deprecated: Use logging.HTTPLoggingMiddleware for enhanced structured logging
func LoggingMiddleware() gin.HandlerFunc {
	logger := logging.GetDefault()
	return gin.HandlerFunc(func(c *gin.Context) {
		start := time.Now()
		path := c.Request.URL.Path
		raw := c.Request.URL.RawQuery

		// Extract request ID and user ID for context
		requestID := GetRequestID(c)
		userID := ""
		if uid, exists := c.Get("user_id"); exists {
			if id, ok := uid.(string); ok {
				userID = id
			}
		}

		// Create enriched context
		ctx := logging.WithRequestAndUserID(c.Request.Context(), requestID, userID)
		c.Request = c.Request.WithContext(ctx)

		// Process request
		c.Next()

		// Log request details with structured logging
		latency := time.Since(start)
		clientIP := c.ClientIP()
		method := c.Request.Method
		statusCode := c.Writer.Status()

		if raw != "" {
			path = path + "?" + raw
		}

		fields := map[string]interface{}{
			"method":      method,
			"path":        path,
			"status_code": statusCode,
			"latency_ms":  float64(latency.Nanoseconds()) / 1e6,
			"client_ip":   clientIP,
			"user_agent":  c.Request.UserAgent(),
		}

		message := fmt.Sprintf("%s %s %d %v", method, path, statusCode, latency)

		// Log with appropriate level based on status code
		if statusCode >= 500 {
			logger.WithFields(fields).Error(ctx, message, nil)
		} else if statusCode >= 400 {
			logger.WithFields(fields).Warn(ctx, message)
		} else {
			logger.WithFields(fields).Info(ctx, message)
		}
	})
}

// StructuredLoggingMiddleware provides enhanced structured logging with full configuration
func StructuredLoggingMiddleware(config *logging.HTTPLoggingConfig) gin.HandlerFunc {
	return logging.HTTPLoggingMiddleware(config)
}

// DefaultStructuredLoggingMiddleware provides structured logging with default configuration
func DefaultStructuredLoggingMiddleware() gin.HandlerFunc {
	return logging.HTTPLoggingMiddleware(nil)
}

// RecoveryMiddleware provides panic recovery with structured logging
func RecoveryMiddleware() gin.HandlerFunc {
	logger := logging.GetDefault()
	return gin.HandlerFunc(func(c *gin.Context) {
		defer func() {
			if err := recover(); err != nil {
				requestID := GetRequestID(c)

				// Create context with request ID for logging
				ctx := logging.WithRequestAndUserID(c.Request.Context(), requestID, "")

				// Create error from panic value
				var panicErr error
				if e, ok := err.(error); ok {
					panicErr = e
				} else {
					panicErr = fmt.Errorf("panic: %v", err)
				}

				fields := map[string]interface{}{
					"method":      c.Request.Method,
					"path":        c.Request.URL.Path,
					"client_ip":   c.ClientIP(),
					"user_agent":  c.Request.UserAgent(),
					"panic_value": err,
				}

				logger.WithFields(fields).Error(ctx, "Request panic recovered", panicErr)
				RespondWithInternalError(c, "Internal server error occurred")
				c.Abort()
			}
		}()
		c.Next()
	})
}
