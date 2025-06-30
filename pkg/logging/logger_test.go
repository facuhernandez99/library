package logging

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	apperrors "github.com/facuhernandez99/library/pkg/errors"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLogLevel_String(t *testing.T) {
	tests := []struct {
		level    LogLevel
		expected string
	}{
		{LevelDebug, "DEBUG"},
		{LevelInfo, "INFO"},
		{LevelWarn, "WARN"},
		{LevelError, "ERROR"},
		{LevelFatal, "FATAL"},
		{LogLevel(999), "UNKNOWN"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.level.String())
		})
	}
}

func TestDefaultConfig(t *testing.T) {
	config := DefaultConfig()
	assert.Equal(t, LevelInfo, config.Level)
	assert.Equal(t, "library-service", config.Service)
	assert.Equal(t, "1.0.0", config.Version)
	assert.False(t, config.Production)
	assert.NotNil(t, config.Output)
}

func TestNewLogger(t *testing.T) {
	var buf bytes.Buffer
	config := &Config{
		Level:      LevelDebug,
		Output:     &buf,
		Service:    "test-service",
		Version:    "1.0.0",
		Production: false,
	}

	logger := NewLogger(config)
	assert.Equal(t, LevelDebug, logger.GetLevel())
	assert.Equal(t, "test-service", logger.service)
	assert.Equal(t, "1.0.0", logger.version)
	assert.False(t, logger.production)
	assert.NotNil(t, logger.sanitizer)
}

func TestNewLogger_NilConfig(t *testing.T) {
	logger := NewLogger(nil)
	assert.Equal(t, LevelInfo, logger.GetLevel())
	assert.Equal(t, "library-service", logger.service)
}

func TestLogger_SetLevel(t *testing.T) {
	logger := NewLogger(nil)

	logger.SetLevel(LevelError)
	assert.Equal(t, LevelError, logger.GetLevel())

	logger.SetLevel(LevelDebug)
	assert.Equal(t, LevelDebug, logger.GetLevel())
}

func TestLogger_ShouldLog(t *testing.T) {
	logger := NewLogger(&Config{Level: LevelWarn})

	assert.False(t, logger.shouldLog(LevelDebug))
	assert.False(t, logger.shouldLog(LevelInfo))
	assert.True(t, logger.shouldLog(LevelWarn))
	assert.True(t, logger.shouldLog(LevelError))
	assert.True(t, logger.shouldLog(LevelFatal))
}

func TestLogger_BasicLogging(t *testing.T) {
	var buf bytes.Buffer
	logger := NewLogger(&Config{
		Level:  LevelDebug,
		Output: &buf,
	})

	ctx := context.Background()

	logger.Debug(ctx, "debug message")
	logger.Info(ctx, "info message")
	logger.Warn(ctx, "warn message")
	logger.Error(ctx, "error message", errors.New("test error"))

	output := buf.String()
	lines := strings.Split(strings.TrimSpace(output), "\n")
	assert.Len(t, lines, 4)

	// Test debug log
	var debugEntry LogEntry
	err := json.Unmarshal([]byte(lines[0]), &debugEntry)
	require.NoError(t, err)
	assert.Equal(t, "DEBUG", debugEntry.Level)
	assert.Equal(t, "debug message", debugEntry.Message)

	// Test error log
	var errorEntry LogEntry
	err = json.Unmarshal([]byte(lines[3]), &errorEntry)
	require.NoError(t, err)
	assert.Equal(t, "ERROR", errorEntry.Level)
	assert.Equal(t, "error message", errorEntry.Message)
	assert.Equal(t, "test error", errorEntry.Error)
}

func TestLogger_FormattedLogging(t *testing.T) {
	var buf bytes.Buffer
	logger := NewLogger(&Config{
		Level:  LevelDebug,
		Output: &buf,
	})

	ctx := context.Background()

	logger.Debugf(ctx, "debug %s %d", "test", 123)
	logger.Infof(ctx, "info %s", "message")
	logger.Warnf(ctx, "warn %d", 456)
	logger.Errorf(ctx, errors.New("test error"), "error %s", "formatted")

	output := buf.String()
	lines := strings.Split(strings.TrimSpace(output), "\n")
	assert.Len(t, lines, 4)

	var debugEntry LogEntry
	err := json.Unmarshal([]byte(lines[0]), &debugEntry)
	require.NoError(t, err)
	assert.Equal(t, "debug test 123", debugEntry.Message)

	var errorEntry LogEntry
	err = json.Unmarshal([]byte(lines[3]), &errorEntry)
	require.NoError(t, err)
	assert.Equal(t, "error formatted", errorEntry.Message)
}

func TestLogger_ContextPropagation(t *testing.T) {
	var buf bytes.Buffer
	logger := NewLogger(&Config{
		Level:  LevelInfo,
		Output: &buf,
	})

	// Create context with request ID and user ID
	ctx := WithRequestAndUserID(context.Background(), "req-123", "user-456")

	logger.Info(ctx, "test message")

	output := buf.String()
	var entry LogEntry
	err := json.Unmarshal([]byte(strings.TrimSpace(output)), &entry)
	require.NoError(t, err)

	assert.Equal(t, "req-123", entry.RequestID)
	assert.Equal(t, "user-456", entry.UserID)
}

func TestLogger_WithFields(t *testing.T) {
	var buf bytes.Buffer
	logger := NewLogger(&Config{
		Level:  LevelInfo,
		Output: &buf,
	})

	ctx := context.Background()
	fields := map[string]interface{}{
		"component": "test",
		"action":    "validation",
		"count":     42,
	}

	contextLogger := logger.WithFields(fields)
	contextLogger.Info(ctx, "test message")

	output := buf.String()
	var entry LogEntry
	err := json.Unmarshal([]byte(strings.TrimSpace(output)), &entry)
	require.NoError(t, err)

	assert.Equal(t, "test", entry.Fields["component"])
	assert.Equal(t, "validation", entry.Fields["action"])
	assert.Equal(t, float64(42), entry.Fields["count"]) // JSON unmarshaling converts to float64
}

func TestContextLogger_WithField(t *testing.T) {
	var buf bytes.Buffer
	logger := NewLogger(&Config{
		Level:  LevelInfo,
		Output: &buf,
	})

	ctx := context.Background()

	contextLogger := logger.WithField("component", "test").WithField("action", "validation")
	contextLogger.Info(ctx, "test message")

	output := buf.String()
	var entry LogEntry
	err := json.Unmarshal([]byte(strings.TrimSpace(output)), &entry)
	require.NoError(t, err)

	assert.Equal(t, "test", entry.Fields["component"])
	assert.Equal(t, "validation", entry.Fields["action"])
}

func TestLogger_ProductionMode(t *testing.T) {
	var buf bytes.Buffer
	logger := NewLogger(&Config{
		Level:      LevelInfo,
		Output:     &buf,
		Production: true,
	})

	ctx := context.Background()
	appErr := apperrors.ErrInternal.WithDetails("sensitive database connection details")

	logger.Error(ctx, "database error", appErr)

	output := buf.String()
	var entry LogEntry
	err := json.Unmarshal([]byte(strings.TrimSpace(output)), &entry)
	require.NoError(t, err)

	// In production mode, internal errors should be sanitized
	assert.Contains(t, entry.Error, "Internal server error")
	assert.NotContains(t, entry.Error, "sensitive database connection details")
}

func TestLogger_LevelFiltering(t *testing.T) {
	var buf bytes.Buffer
	logger := NewLogger(&Config{
		Level:  LevelWarn,
		Output: &buf,
	})

	ctx := context.Background()

	logger.Debug(ctx, "debug message")
	logger.Info(ctx, "info message")
	logger.Warn(ctx, "warn message")
	logger.Error(ctx, "error message", nil)

	output := buf.String()
	lines := strings.Split(strings.TrimSpace(output), "\n")

	// Only warn and error should be logged
	assert.Len(t, lines, 2)
	assert.Contains(t, lines[0], "warn message")
	assert.Contains(t, lines[1], "error message")
}

func TestPackageLevelFunctions(t *testing.T) {
	// Test the functions work without errors - the exact output capture is tricky with globals
	ctx := context.Background()

	// These should not panic or error
	assert.NotPanics(t, func() {
		Debug(ctx, "debug message")
		Info(ctx, "info message")
		Warn(ctx, "warn message")
		Error(ctx, "error message", errors.New("test error"))
	})
}

func TestPackageLevelWithFields(t *testing.T) {
	var buf bytes.Buffer

	customLogger := NewLogger(&Config{
		Level:  LevelInfo,
		Output: &buf,
	})
	SetDefault(customLogger)

	ctx := context.Background()

	WithField("test", "value").Info(ctx, "message with field")
	WithFields(map[string]interface{}{
		"key1": "value1",
		"key2": 42,
	}).Info(ctx, "message with fields")

	output := buf.String()
	lines := strings.Split(strings.TrimSpace(output), "\n")
	assert.Len(t, lines, 2)
}

// Context tests
func TestWithRequestID(t *testing.T) {
	ctx := WithRequestID(context.Background(), "test-request-id")

	requestID := GetRequestIDFromContext(ctx)
	assert.Equal(t, "test-request-id", requestID)
}

func TestWithUserID(t *testing.T) {
	ctx := WithUserID(context.Background(), "test-user-id")

	userID := GetUserIDFromContext(ctx)
	assert.Equal(t, "test-user-id", userID)
}

func TestWithRequestAndUserID(t *testing.T) {
	ctx := WithRequestAndUserID(context.Background(), "req-123", "user-456")

	requestID := GetRequestIDFromContext(ctx)
	userID := GetUserIDFromContext(ctx)

	assert.Equal(t, "req-123", requestID)
	assert.Equal(t, "user-456", userID)
}

func TestGetFromNilContext(t *testing.T) {
	requestID := GetRequestIDFromContext(nil)
	userID := GetUserIDFromContext(nil)

	assert.Empty(t, requestID)
	assert.Empty(t, userID)
}

func TestGetFromEmptyContext(t *testing.T) {
	ctx := context.Background()

	requestID := GetRequestIDFromContext(ctx)
	userID := GetUserIDFromContext(ctx)

	assert.Empty(t, requestID)
	assert.Empty(t, userID)
}

// HTTP Middleware tests
func TestHTTPLoggingMiddleware(t *testing.T) {
	var buf bytes.Buffer
	logger := NewLogger(&Config{
		Level:  LevelInfo,
		Output: &buf,
	})

	config := &HTTPLoggingConfig{
		Logger:             logger,
		SkipPaths:          []string{"/health"},
		LogRequestBody:     false,
		LogResponseBody:    false,
		SanitizeHeaders:    true,
		SkipSuccessfulGETs: false,
		RequestIDHeader:    "X-Request-ID",
		UserIDExtractor:    DefaultUserIDExtractor,
	}

	middleware := HTTPLoggingMiddleware(config)

	// Test normal request
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(middleware)
	router.GET("/test", func(c *gin.Context) {
		c.JSON(200, gin.H{"status": "ok"})
	})

	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("User-Agent", "test-agent")

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, 200, w.Code)
	assert.NotEmpty(t, w.Header().Get("X-Request-ID"))

	// Check log output
	output := buf.String()
	assert.Contains(t, output, "GET")
	assert.Contains(t, output, "/test")
	assert.Contains(t, output, "200")
}

func TestHTTPLoggingMiddleware_SkipPaths(t *testing.T) {
	var buf bytes.Buffer
	logger := NewLogger(&Config{
		Level:  LevelInfo,
		Output: &buf,
	})

	config := &HTTPLoggingConfig{
		Logger:    logger,
		SkipPaths: []string{"/health"},
	}

	middleware := HTTPLoggingMiddleware(config)

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(middleware)
	router.GET("/health", func(c *gin.Context) {
		c.JSON(200, gin.H{"status": "ok"})
	})

	req := httptest.NewRequest("GET", "/health", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, 200, w.Code)

	// No log output should be generated for skipped paths
	output := buf.String()
	assert.Empty(t, strings.TrimSpace(output))
}

func TestHTTPLoggingMiddleware_ErrorResponse(t *testing.T) {
	var buf bytes.Buffer
	logger := NewLogger(&Config{
		Level:  LevelInfo,
		Output: &buf,
	})

	config := &HTTPLoggingConfig{
		Logger:          logger,
		UserIDExtractor: DefaultUserIDExtractor, // Add this to prevent nil pointer
	}

	middleware := HTTPLoggingMiddleware(config)

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(middleware)
	router.GET("/error", func(c *gin.Context) {
		c.Error(errors.New("test error"))
		c.JSON(500, gin.H{"error": "internal error"})
	})

	req := httptest.NewRequest("GET", "/error", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, 500, w.Code)

	// Check that error is logged at ERROR level
	output := buf.String()
	var entry LogEntry
	err := json.Unmarshal([]byte(strings.TrimSpace(output)), &entry)
	require.NoError(t, err)

	assert.Equal(t, "ERROR", entry.Level)
	assert.Contains(t, entry.Message, "500")
}

func TestRequestLoggingMiddleware(t *testing.T) {
	var buf bytes.Buffer
	logger := NewLogger(&Config{
		Level:  LevelInfo,
		Output: &buf,
	})

	middleware := RequestLoggingMiddleware(logger)

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(middleware)
	router.GET("/test", func(c *gin.Context) {
		c.JSON(200, gin.H{"status": "ok"})
	})

	req := httptest.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, 200, w.Code)

	// Should generate multiple log entries (start and completion)
	output := buf.String()
	lines := strings.Split(strings.TrimSpace(output), "\n")
	assert.GreaterOrEqual(t, len(lines), 2)
}

func TestRecoveryLoggingMiddleware(t *testing.T) {
	var buf bytes.Buffer
	logger := NewLogger(&Config{
		Level:  LevelInfo,
		Output: &buf,
	})

	middleware := RecoveryLoggingMiddleware(logger)

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(middleware)
	router.GET("/panic", func(c *gin.Context) {
		panic("test panic")
	})

	req := httptest.NewRequest("GET", "/panic", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, 500, w.Code)

	// Check that panic is logged
	output := buf.String()
	assert.Contains(t, output, "Panic recovered")
	assert.Contains(t, output, "test panic")
}

func TestDefaultUserIDExtractor(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tests := []struct {
		name     string
		setupCtx func(*gin.Context)
		expected string
	}{
		{
			name: "from gin context",
			setupCtx: func(c *gin.Context) {
				c.Set("user_id", "user-123")
			},
			expected: "user-123",
		},
		{
			name: "from header",
			setupCtx: func(c *gin.Context) {
				c.Request.Header.Set("X-User-ID", "user-456")
			},
			expected: "user-456",
		},
		{
			name: "priority: gin context over header",
			setupCtx: func(c *gin.Context) {
				c.Set("user_id", "user-123")
				c.Request.Header.Set("X-User-ID", "user-456")
			},
			expected: "user-123",
		},
		{
			name:     "no user ID",
			setupCtx: func(c *gin.Context) {},
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, _ := gin.CreateTestContext(httptest.NewRecorder())
			c.Request = httptest.NewRequest("GET", "/", nil)
			tt.setupCtx(c)

			result := DefaultUserIDExtractor(c)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestFormatHTTPLogMessage(t *testing.T) {
	message := formatHTTPLogMessage("GET", "/api/users", 200, 150*time.Millisecond)
	expected := "GET /api/users - 200 (150ms)"
	assert.Equal(t, expected, message)
}

func TestSanitizeHeaderValue(t *testing.T) {
	tests := []struct {
		key      string
		value    string
		expected string
	}{
		{"Authorization", "Bearer token123456789", "Bear...[REDACTED]"},
		{"Cookie", "session=abc123", "sess...[REDACTED]"},
		{"User-Agent", "Mozilla/5.0", "Mozilla/5.0"},
		{"Content-Type", "application/json", "application/json"},
		{"X-API-Key", "secret-key-12345", "secr...[REDACTED]"},
	}

	for _, tt := range tests {
		t.Run(tt.key, func(t *testing.T) {
			result := sanitizeHeaderValue(tt.key, tt.value)
			assert.Equal(t, tt.expected, result)
		})
	}
}
