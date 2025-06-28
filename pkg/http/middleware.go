package http

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

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
	for _, allowed := range allowedOrigins {
		if allowed == "*" || allowed == origin {
			return true
		}
		// Support wildcard subdomains (e.g., *.example.com)
		if strings.HasPrefix(allowed, "*.") {
			domain := strings.TrimPrefix(allowed, "*.")
			if strings.HasSuffix(origin, "."+domain) || origin == domain {
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

		finished := make(chan struct{})
		go func() {
			defer close(finished)
			c.Next()
		}()

		select {
		case <-ctx.Done():
			if ctx.Err() == context.DeadlineExceeded {
				RespondWithError(c, http.StatusRequestTimeout, "Request timeout")
				c.Abort()
			}
		case <-finished:
		}
	})
}

// LoggingMiddleware adds request logging with request ID correlation
func LoggingMiddleware() gin.HandlerFunc {
	return gin.HandlerFunc(func(c *gin.Context) {
		start := time.Now()
		path := c.Request.URL.Path
		raw := c.Request.URL.RawQuery

		// Process request
		c.Next()

		// Log request details
		latency := time.Since(start)
		clientIP := c.ClientIP()
		method := c.Request.Method
		statusCode := c.Writer.Status()
		requestID := GetRequestID(c)

		if raw != "" {
			path = path + "?" + raw
		}

		// Format: [RequestID] ClientIP - Method Path Status Latency
		fmt.Printf("[%s] %s - %s %s %d %v\n",
			requestID, clientIP, method, path, statusCode, latency)
	})
}

// RecoveryMiddleware provides panic recovery with request ID correlation
func RecoveryMiddleware() gin.HandlerFunc {
	return gin.HandlerFunc(func(c *gin.Context) {
		defer func() {
			if err := recover(); err != nil {
				requestID := GetRequestID(c)
				fmt.Printf("[%s] PANIC: %v\n", requestID, err)
				RespondWithInternalError(c, "Internal server error occurred")
				c.Abort()
			}
		}()
		c.Next()
	})
}
