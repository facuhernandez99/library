package logging

import (
	"bytes"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// HTTPLoggingConfig holds configuration for HTTP logging middleware
type HTTPLoggingConfig struct {
	Logger             *Logger
	SkipPaths          []string
	LogRequestBody     bool
	LogResponseBody    bool
	MaxBodySize        int64
	SanitizeHeaders    bool
	SkipSuccessfulGETs bool
	RequestIDHeader    string
	UserIDExtractor    func(*gin.Context) string
}

// DefaultHTTPLoggingConfig returns a default HTTP logging configuration
func DefaultHTTPLoggingConfig() *HTTPLoggingConfig {
	return &HTTPLoggingConfig{
		Logger:             GetDefault(),
		SkipPaths:          []string{"/health", "/metrics", "/ready"},
		LogRequestBody:     false,
		LogResponseBody:    false,
		MaxBodySize:        1024 * 1024, // 1MB
		SanitizeHeaders:    true,
		SkipSuccessfulGETs: true,
		RequestIDHeader:    "X-Request-ID",
		UserIDExtractor:    DefaultUserIDExtractor,
	}
}

// DefaultUserIDExtractor extracts user ID from JWT claims or context
func DefaultUserIDExtractor(c *gin.Context) string {
	// Try to get from JWT claims (if auth middleware has processed it)
	if userID, exists := c.Get("user_id"); exists {
		if id, ok := userID.(string); ok {
			return id
		}
	}

	// Try to get from custom header
	if userID := c.GetHeader("X-User-ID"); userID != "" {
		return userID
	}

	return ""
}

// responseWriter wraps gin's ResponseWriter to capture response data
type responseWriter struct {
	gin.ResponseWriter
	body       *bytes.Buffer
	statusCode int
}

func newResponseWriter(w gin.ResponseWriter) *responseWriter {
	return &responseWriter{
		ResponseWriter: w,
		body:           bytes.NewBuffer(nil),
		statusCode:     200,
	}
}

func (w *responseWriter) Write(data []byte) (int, error) {
	w.body.Write(data)
	return w.ResponseWriter.Write(data)
}

func (w *responseWriter) WriteHeader(statusCode int) {
	w.statusCode = statusCode
	w.ResponseWriter.WriteHeader(statusCode)
}

// HTTPLoggingMiddleware returns a gin middleware for comprehensive HTTP logging
func HTTPLoggingMiddleware(config *HTTPLoggingConfig) gin.HandlerFunc {
	if config == nil {
		config = DefaultHTTPLoggingConfig()
	}

	// Set defaults for any missing fields
	if config.Logger == nil {
		config.Logger = GetDefault()
	}
	if config.RequestIDHeader == "" {
		config.RequestIDHeader = "X-Request-ID"
	}
	if config.UserIDExtractor == nil {
		config.UserIDExtractor = DefaultUserIDExtractor
	}
	if config.MaxBodySize == 0 {
		config.MaxBodySize = 1024 * 1024 // 1MB default
	}

	return gin.HandlerFunc(func(c *gin.Context) {
		start := time.Now()
		path := c.Request.URL.Path

		// Skip logging for specified paths
		for _, skipPath := range config.SkipPaths {
			if path == skipPath {
				c.Next()
				return
			}
		}

		// Generate or extract request ID
		requestID := c.GetHeader(config.RequestIDHeader)
		if requestID == "" {
			requestID = uuid.New().String()
			c.Header(config.RequestIDHeader, requestID)
		}

		// Extract user ID
		userID := config.UserIDExtractor(c)

		// Create enriched context
		ctx := WithRequestAndUserID(c.Request.Context(), requestID, userID)
		c.Request = c.Request.WithContext(ctx)

		// Store in Gin context for other middleware/handlers
		c.Set("request_id", requestID)
		if userID != "" {
			c.Set("user_id", userID)
		}

		// Capture request body if configured
		var requestBody string
		if config.LogRequestBody && c.Request.Body != nil {
			bodyBytes, err := io.ReadAll(io.LimitReader(c.Request.Body, config.MaxBodySize))
			if err == nil {
				requestBody = string(bodyBytes)
				// Restore the body for the actual handler
				c.Request.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
			}
		}

		// Wrap response writer to capture response data
		var responseWriter *responseWriter
		if config.LogResponseBody {
			responseWriter = newResponseWriter(c.Writer)
			c.Writer = responseWriter
		}

		// Process request
		c.Next()

		// Calculate duration
		latency := time.Since(start)
		statusCode := c.Writer.Status()
		method := c.Request.Method
		clientIP := c.ClientIP()
		userAgent := c.Request.UserAgent()

		// Check if we should skip successful GET requests
		if config.SkipSuccessfulGETs && method == "GET" && statusCode < 400 {
			return
		}

		// Build query string
		rawQuery := c.Request.URL.RawQuery
		if rawQuery != "" {
			path = path + "?" + rawQuery
		}

		// Prepare log fields
		fields := map[string]interface{}{
			"method":      method,
			"path":        path,
			"status_code": statusCode,
			"latency_ms":  float64(latency.Nanoseconds()) / 1e6,
			"client_ip":   clientIP,
			"user_agent":  userAgent,
		}

		// Add request headers (sanitized)
		if config.SanitizeHeaders {
			headers := make(map[string]string)
			for key, values := range c.Request.Header {
				if len(values) > 0 {
					headers[key] = sanitizeHeaderValue(key, values[0])
				}
			}
			fields["request_headers"] = headers
		}

		// Add request body if captured and not empty
		if config.LogRequestBody && requestBody != "" {
			if config.Logger.sanitizer != nil {
				fields["request_body"] = config.Logger.sanitizer.sanitizeString(requestBody)
			} else {
				fields["request_body"] = requestBody
			}
		}

		// Add response body if captured
		if config.LogResponseBody && responseWriter != nil {
			responseBody := responseWriter.body.String()
			if responseBody != "" {
				if config.Logger.sanitizer != nil {
					fields["response_body"] = config.Logger.sanitizer.sanitizeString(responseBody)
				} else {
					fields["response_body"] = responseBody
				}
			}
		}

		// Add error information if present
		if len(c.Errors) > 0 {
			var errorMessages []string
			for _, err := range c.Errors {
				if config.Logger.sanitizer != nil {
					sanitizedErr := config.Logger.sanitizer.Sanitize(err.Err)
					errorMessages = append(errorMessages, sanitizedErr.Error())
				} else {
					errorMessages = append(errorMessages, err.Err.Error())
				}
			}
			fields["errors"] = errorMessages
		}

		// Log with appropriate level based on status code
		contextLogger := config.Logger.WithFields(fields)
		message := formatHTTPLogMessage(method, path, statusCode, latency)

		switch {
		case statusCode >= 500:
			var err error
			if len(c.Errors) > 0 {
				err = c.Errors.Last().Err
			}
			contextLogger.Error(ctx, message, err)
		case statusCode >= 400:
			contextLogger.Warn(ctx, message)
		default:
			contextLogger.Info(ctx, message)
		}
	})
}

// formatHTTPLogMessage creates a standardized HTTP log message
func formatHTTPLogMessage(method, path string, statusCode int, latency time.Duration) string {
	return fmt.Sprintf("%s %s - %d (%v)", method, path, statusCode, latency)
}

// sanitizeHeaderValue sanitizes header values to remove sensitive information
func sanitizeHeaderValue(key, value string) string {
	keyLower := strings.ToLower(key)

	// Sensitive headers to redact
	sensitiveHeaders := []string{
		"authorization",
		"cookie",
		"set-cookie",
		"x-api-key",
		"x-auth-token",
		"x-access-token",
		"x-csrf-token",
		"x-xsrf-token",
		"proxy-authorization",
	}

	for _, sensitive := range sensitiveHeaders {
		if keyLower == sensitive || strings.Contains(keyLower, sensitive) {
			if len(value) > 8 {
				return value[:4] + "..." + "[REDACTED]"
			}
			return "[REDACTED]"
		}
	}

	return value
}

// RequestLoggingMiddleware is a simpler alternative that focuses on request correlation
func RequestLoggingMiddleware(logger *Logger) gin.HandlerFunc {
	if logger == nil {
		logger = GetDefault()
	}

	return gin.HandlerFunc(func(c *gin.Context) {
		start := time.Now()

		// Generate or extract request ID
		requestID := c.GetHeader("X-Request-ID")
		if requestID == "" {
			requestID = uuid.New().String()
			c.Header("X-Request-ID", requestID)
		}

		// Create enriched context
		ctx := WithRequestID(c.Request.Context(), requestID)
		c.Request = c.Request.WithContext(ctx)
		c.Set("request_id", requestID)

		// Log request start
		logger.WithFields(map[string]interface{}{
			"method":    c.Request.Method,
			"path":      c.Request.URL.Path,
			"client_ip": c.ClientIP(),
		}).Info(ctx, "Request started")

		// Process request
		c.Next()

		// Log request completion
		latency := time.Since(start)
		statusCode := c.Writer.Status()

		logLevel := LevelInfo
		if statusCode >= 500 {
			logLevel = LevelError
		} else if statusCode >= 400 {
			logLevel = LevelWarn
		}

		fields := map[string]interface{}{
			"method":      c.Request.Method,
			"path":        c.Request.URL.Path,
			"status_code": statusCode,
			"latency_ms":  float64(latency.Nanoseconds()) / 1e6,
			"client_ip":   c.ClientIP(),
		}

		message := formatHTTPLogMessage(c.Request.Method, c.Request.URL.Path, statusCode, latency)

		switch logLevel {
		case LevelError:
			var err error
			if len(c.Errors) > 0 {
				err = c.Errors.Last().Err
			}
			logger.WithFields(fields).Error(ctx, message, err)
		case LevelWarn:
			logger.WithFields(fields).Warn(ctx, message)
		default:
			logger.WithFields(fields).Info(ctx, message)
		}
	})
}

// RecoveryLoggingMiddleware provides panic recovery with structured logging
func RecoveryLoggingMiddleware(logger *Logger) gin.HandlerFunc {
	if logger == nil {
		logger = GetDefault()
	}

	return gin.HandlerFunc(func(c *gin.Context) {
		defer func() {
			if err := recover(); err != nil {
				// Get request context with request ID
				ctx := c.Request.Context()

				logger.WithFields(map[string]interface{}{
					"method":    c.Request.Method,
					"path":      c.Request.URL.Path,
					"client_ip": c.ClientIP(),
					"panic":     err,
				}).Error(ctx, "Panic recovered", nil)

				c.JSON(500, gin.H{"error": "Internal server error"})
				c.Abort()
			}
		}()
		c.Next()
	})
}
