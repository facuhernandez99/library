package http

import (
	"bytes"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/facuhernandez99/library/pkg/logging"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

func TestRequestIDMiddleware(t *testing.T) {
	gin.SetMode(gin.TestMode)

	t.Run("generates new request ID when none provided", func(t *testing.T) {
		router := gin.New()
		router.Use(RequestIDMiddleware())
		router.GET("/test", func(c *gin.Context) {
			requestID := GetRequestID(c)
			assert.NotEmpty(t, requestID)
			c.JSON(200, gin.H{"request_id": requestID})
		})

		w := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "/test", nil)
		router.ServeHTTP(w, req)

		assert.Equal(t, 200, w.Code)
		assert.NotEmpty(t, w.Header().Get("X-Request-ID"))
	})

	t.Run("uses provided request ID", func(t *testing.T) {
		router := gin.New()
		router.Use(RequestIDMiddleware())
		router.GET("/test", func(c *gin.Context) {
			requestID := GetRequestID(c)
			c.JSON(200, gin.H{"request_id": requestID})
		})

		w := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "/test", nil)
		req.Header.Set("X-Request-ID", "test-request-id")
		router.ServeHTTP(w, req)

		assert.Equal(t, 200, w.Code)
		assert.Equal(t, "test-request-id", w.Header().Get("X-Request-ID"))
	})
}

func TestRateLimiter(t *testing.T) {
	gin.SetMode(gin.TestMode)

	t.Run("allows requests within limit", func(t *testing.T) {
		limiter := NewRateLimiter(5, time.Minute)
		router := gin.New()
		router.Use(limiter.RateLimitMiddleware())
		router.GET("/test", func(c *gin.Context) {
			c.JSON(200, gin.H{"status": "ok"})
		})

		// Make 5 requests (should all succeed)
		for i := 0; i < 5; i++ {
			w := httptest.NewRecorder()
			req := httptest.NewRequest("GET", "/test", nil)
			router.ServeHTTP(w, req)
			assert.Equal(t, 200, w.Code)
		}
	})

	t.Run("blocks requests exceeding limit", func(t *testing.T) {
		limiter := NewRateLimiter(2, time.Minute)
		router := gin.New()
		router.Use(limiter.RateLimitMiddleware())
		router.GET("/test", func(c *gin.Context) {
			c.JSON(200, gin.H{"status": "ok"})
		})

		// Make 2 requests (should succeed)
		for i := 0; i < 2; i++ {
			w := httptest.NewRecorder()
			req := httptest.NewRequest("GET", "/test", nil)
			router.ServeHTTP(w, req)
			assert.Equal(t, 200, w.Code)
		}

		// Third request should be rate limited
		w := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "/test", nil)
		router.ServeHTTP(w, req)
		assert.Equal(t, 429, w.Code)
	})

	t.Run("resets after time window", func(t *testing.T) {
		limiter := NewRateLimiter(1, 100*time.Millisecond)
		router := gin.New()
		router.Use(limiter.RateLimitMiddleware())
		router.GET("/test", func(c *gin.Context) {
			c.JSON(200, gin.H{"status": "ok"})
		})

		// First request should succeed
		w := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "/test", nil)
		router.ServeHTTP(w, req)
		assert.Equal(t, 200, w.Code)

		// Second request should be rate limited
		w = httptest.NewRecorder()
		req = httptest.NewRequest("GET", "/test", nil)
		router.ServeHTTP(w, req)
		assert.Equal(t, 429, w.Code)

		// Wait for time window to pass
		time.Sleep(150 * time.Millisecond)

		// Third request should succeed
		w = httptest.NewRecorder()
		req = httptest.NewRequest("GET", "/test", nil)
		router.ServeHTTP(w, req)
		assert.Equal(t, 200, w.Code)
	})
}

func TestCORSMiddleware(t *testing.T) {
	gin.SetMode(gin.TestMode)

	t.Run("sets default CORS headers", func(t *testing.T) {
		router := gin.New()
		router.Use(CORSMiddleware(nil))
		router.GET("/test", func(c *gin.Context) {
			c.JSON(200, gin.H{"status": "ok"})
		})

		w := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "/test", nil)
		req.Header.Set("Origin", "https://example.com")
		router.ServeHTTP(w, req)

		assert.Equal(t, 200, w.Code)
		assert.Equal(t, "*", w.Header().Get("Access-Control-Allow-Origin"))
		assert.Contains(t, w.Header().Get("Access-Control-Allow-Methods"), "GET")
		assert.Contains(t, w.Header().Get("Access-Control-Allow-Headers"), "Content-Type")
	})

	t.Run("handles preflight requests", func(t *testing.T) {
		router := gin.New()
		router.Use(CORSMiddleware(nil))
		router.OPTIONS("/test", func(c *gin.Context) {
			c.JSON(200, gin.H{"status": "ok"})
		})

		w := httptest.NewRecorder()
		req := httptest.NewRequest("OPTIONS", "/test", nil)
		req.Header.Set("Origin", "https://example.com")
		router.ServeHTTP(w, req)

		assert.Equal(t, 204, w.Code)
	})

	t.Run("restricts origins when configured", func(t *testing.T) {
		config := &CORSConfig{
			AllowOrigins: []string{"https://allowed.com"},
			AllowMethods: []string{"GET", "POST"},
			AllowHeaders: []string{"Content-Type"},
		}

		router := gin.New()
		router.Use(CORSMiddleware(config))
		router.GET("/test", func(c *gin.Context) {
			c.JSON(200, gin.H{"status": "ok"})
		})

		// Allowed origin should work
		w := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "/test", nil)
		req.Header.Set("Origin", "https://allowed.com")
		router.ServeHTTP(w, req)
		assert.Equal(t, 200, w.Code)

		// Disallowed origin should be blocked
		w = httptest.NewRecorder()
		req = httptest.NewRequest("GET", "/test", nil)
		req.Header.Set("Origin", "https://evil.com")
		router.ServeHTTP(w, req)
		assert.Equal(t, 403, w.Code)
	})

	t.Run("supports wildcard subdomains", func(t *testing.T) {
		config := &CORSConfig{
			AllowOrigins: []string{"*.example.com"},
			AllowMethods: []string{"GET"},
			AllowHeaders: []string{"Content-Type"},
		}

		router := gin.New()
		router.Use(CORSMiddleware(config))
		router.GET("/test", func(c *gin.Context) {
			c.JSON(200, gin.H{"status": "ok"})
		})

		// Subdomain should work
		w := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "/test", nil)
		req.Header.Set("Origin", "https://api.example.com")
		router.ServeHTTP(w, req)
		assert.Equal(t, 200, w.Code)

		// Root domain should work
		w = httptest.NewRecorder()
		req = httptest.NewRequest("GET", "/test", nil)
		req.Header.Set("Origin", "https://example.com")
		router.ServeHTTP(w, req)
		assert.Equal(t, 200, w.Code)

		// Different domain should be blocked
		w = httptest.NewRecorder()
		req = httptest.NewRequest("GET", "/test", nil)
		req.Header.Set("Origin", "https://evil.com")
		router.ServeHTTP(w, req)
		assert.Equal(t, 403, w.Code)
	})
}

func TestSecurityHeadersMiddleware(t *testing.T) {
	gin.SetMode(gin.TestMode)

	router := gin.New()
	router.Use(SecurityHeadersMiddleware())
	router.GET("/test", func(c *gin.Context) {
		c.JSON(200, gin.H{"status": "ok"})
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/test", nil)
	router.ServeHTTP(w, req)

	assert.Equal(t, 200, w.Code)
	assert.Equal(t, "nosniff", w.Header().Get("X-Content-Type-Options"))
	assert.Equal(t, "DENY", w.Header().Get("X-Frame-Options"))
	assert.Equal(t, "1; mode=block", w.Header().Get("X-XSS-Protection"))
	assert.Equal(t, "strict-origin-when-cross-origin", w.Header().Get("Referrer-Policy"))
	assert.Equal(t, "upgrade-insecure-requests", w.Header().Get("Content-Security-Policy"))
}

func TestTimeoutMiddleware(t *testing.T) {
	gin.SetMode(gin.TestMode)

	t.Run("allows fast requests", func(t *testing.T) {
		router := gin.New()
		router.Use(TimeoutMiddleware(100 * time.Millisecond))
		router.GET("/test", func(c *gin.Context) {
			c.JSON(200, gin.H{"status": "ok"})
		})

		w := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "/test", nil)
		router.ServeHTTP(w, req)

		assert.Equal(t, 200, w.Code)
	})

	t.Run("times out slow requests", func(t *testing.T) {
		router := gin.New()
		router.Use(TimeoutMiddleware(50 * time.Millisecond))
		router.GET("/test", func(c *gin.Context) {
			time.Sleep(100 * time.Millisecond)
			c.JSON(200, gin.H{"status": "ok"})
		})

		w := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "/test", nil)
		router.ServeHTTP(w, req)

		assert.Equal(t, 408, w.Code)
	})
}

func TestLoggingMiddleware(t *testing.T) {
	gin.SetMode(gin.TestMode)

	t.Run("logs request with structured logging", func(t *testing.T) {
		// Capture log output
		var logBuffer bytes.Buffer
		logger := logging.NewLogger(&logging.Config{
			Level:      logging.LevelInfo,
			Output:     &logBuffer,
			Service:    "test-service",
			Version:    "1.0.0",
			Production: false,
		})
		logging.SetDefault(logger)

		router := gin.New()
		router.Use(RequestIDMiddleware())
		router.Use(LoggingMiddleware())
		router.GET("/test", func(c *gin.Context) {
			c.JSON(200, gin.H{"status": "ok"})
		})

		w := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "/test", nil)
		router.ServeHTTP(w, req)

		assert.Equal(t, 200, w.Code)

		// Check that structured logging was used
		logOutput := logBuffer.String()
		assert.Contains(t, logOutput, "GET")
		assert.Contains(t, logOutput, "/test")
		assert.Contains(t, logOutput, "200")
		assert.Contains(t, logOutput, "status_code")
		assert.Contains(t, logOutput, "latency_ms")
	})

	t.Run("logs different levels based on status code", func(t *testing.T) {
		var logBuffer bytes.Buffer
		logger := logging.NewLogger(&logging.Config{
			Level:      logging.LevelInfo,
			Output:     &logBuffer,
			Service:    "test-service",
			Version:    "1.0.0",
			Production: false,
		})
		logging.SetDefault(logger)

		router := gin.New()
		router.Use(RequestIDMiddleware())
		router.Use(LoggingMiddleware())
		router.GET("/error", func(c *gin.Context) {
			c.JSON(500, gin.H{"error": "server error"})
		})

		w := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "/error", nil)
		router.ServeHTTP(w, req)

		assert.Equal(t, 500, w.Code)

		logOutput := logBuffer.String()
		assert.Contains(t, logOutput, "ERROR")
		assert.Contains(t, logOutput, "500")
	})

	t.Run("includes user context when available", func(t *testing.T) {
		var logBuffer bytes.Buffer
		logger := logging.NewLogger(&logging.Config{
			Level:      logging.LevelInfo,
			Output:     &logBuffer,
			Service:    "test-service",
			Version:    "1.0.0",
			Production: false,
		})
		logging.SetDefault(logger)

		router := gin.New()
		router.Use(RequestIDMiddleware())
		router.Use(func(c *gin.Context) {
			c.Set("user_id", "123")
			c.Next()
		})
		router.Use(LoggingMiddleware())
		router.GET("/test", func(c *gin.Context) {
			c.JSON(200, gin.H{"status": "ok"})
		})

		w := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "/test", nil)
		router.ServeHTTP(w, req)

		assert.Equal(t, 200, w.Code)

		logOutput := logBuffer.String()
		assert.Contains(t, logOutput, "user_id")
		assert.Contains(t, logOutput, "123")
	})
}

func TestStructuredLoggingMiddleware(t *testing.T) {
	gin.SetMode(gin.TestMode)

	t.Run("uses enhanced structured logging", func(t *testing.T) {
		var logBuffer bytes.Buffer
		logger := logging.NewLogger(&logging.Config{
			Level:      logging.LevelInfo,
			Output:     &logBuffer,
			Service:    "test-service",
			Version:    "1.0.0",
			Production: false,
		})

		config := &logging.HTTPLoggingConfig{
			Logger:          logger,
			SkipPaths:       []string{},
			LogRequestBody:  true,
			LogResponseBody: true,
			MaxBodySize:     1024,
		}

		router := gin.New()
		router.Use(RequestIDMiddleware())
		router.Use(StructuredLoggingMiddleware(config))
		router.POST("/test", func(c *gin.Context) {
			c.JSON(200, gin.H{"status": "ok"})
		})

		w := httptest.NewRecorder()
		req := httptest.NewRequest("POST", "/test", bytes.NewBufferString(`{"test": "data"}`))
		req.Header.Set("Content-Type", "application/json")
		router.ServeHTTP(w, req)

		assert.Equal(t, 200, w.Code)

		logOutput := logBuffer.String()
		assert.Contains(t, logOutput, "POST")
		assert.Contains(t, logOutput, "/test")
		assert.Contains(t, logOutput, "200")
	})

	t.Run("uses default configuration when nil", func(t *testing.T) {
		router := gin.New()
		router.Use(RequestIDMiddleware())
		router.Use(DefaultStructuredLoggingMiddleware())
		router.GET("/test", func(c *gin.Context) {
			c.JSON(200, gin.H{"status": "ok"})
		})

		w := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "/test", nil)
		router.ServeHTTP(w, req)

		assert.Equal(t, 200, w.Code)
	})
}

func TestRecoveryMiddleware(t *testing.T) {
	gin.SetMode(gin.TestMode)

	t.Run("recovers from panic with structured logging", func(t *testing.T) {
		var logBuffer bytes.Buffer
		logger := logging.NewLogger(&logging.Config{
			Level:      logging.LevelInfo,
			Output:     &logBuffer,
			Service:    "test-service",
			Version:    "1.0.0",
			Production: false,
		})
		logging.SetDefault(logger)

		router := gin.New()
		router.Use(RequestIDMiddleware())
		router.Use(RecoveryMiddleware())
		router.GET("/panic", func(c *gin.Context) {
			panic("test panic")
		})

		w := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "/panic", nil)
		router.ServeHTTP(w, req)

		assert.Equal(t, 500, w.Code)

		logOutput := logBuffer.String()
		assert.Contains(t, logOutput, "ERROR")
		assert.Contains(t, logOutput, "Request panic recovered")
		assert.Contains(t, logOutput, "test panic")
		assert.Contains(t, logOutput, "client_ip")
		assert.Contains(t, logOutput, "method")
	})

	t.Run("includes request context in panic logs", func(t *testing.T) {
		var logBuffer bytes.Buffer
		logger := logging.NewLogger(&logging.Config{
			Level:      logging.LevelInfo,
			Output:     &logBuffer,
			Service:    "test-service",
			Version:    "1.0.0",
			Production: false,
		})
		logging.SetDefault(logger)

		router := gin.New()
		router.Use(RequestIDMiddleware())
		router.Use(RecoveryMiddleware())
		router.POST("/panic", func(c *gin.Context) {
			panic("test panic with context")
		})

		w := httptest.NewRecorder()
		req := httptest.NewRequest("POST", "/panic", nil)
		req.Header.Set("User-Agent", "test-agent")
		router.ServeHTTP(w, req)

		assert.Equal(t, 500, w.Code)

		logOutput := logBuffer.String()
		assert.Contains(t, logOutput, "POST")
		assert.Contains(t, logOutput, "/panic")
		assert.Contains(t, logOutput, "test-agent")
		assert.Contains(t, logOutput, "panic_value")
	})
}

func TestGetRequestID(t *testing.T) {
	gin.SetMode(gin.TestMode)

	t.Run("returns request ID when present", func(t *testing.T) {
		c, _ := gin.CreateTestContext(httptest.NewRecorder())
		c.Set("request_id", "test-id")

		id := GetRequestID(c)
		assert.Equal(t, "test-id", id)
	})

	t.Run("returns empty string when not present", func(t *testing.T) {
		c, _ := gin.CreateTestContext(httptest.NewRecorder())

		id := GetRequestID(c)
		assert.Equal(t, "", id)
	})

	t.Run("returns empty string when wrong type", func(t *testing.T) {
		c, _ := gin.CreateTestContext(httptest.NewRecorder())
		c.Set("request_id", 123)

		id := GetRequestID(c)
		assert.Equal(t, "", id)
	})
}

func TestIsOriginAllowed(t *testing.T) {
	tests := []struct {
		name           string
		origin         string
		allowedOrigins []string
		expected       bool
	}{
		{
			name:           "wildcard allows all",
			origin:         "https://example.com",
			allowedOrigins: []string{"*"},
			expected:       true,
		},
		{
			name:           "exact match",
			origin:         "https://example.com",
			allowedOrigins: []string{"https://example.com"},
			expected:       true,
		},
		{
			name:           "no match",
			origin:         "https://evil.com",
			allowedOrigins: []string{"https://example.com"},
			expected:       false,
		},
		{
			name:           "wildcard subdomain match",
			origin:         "https://api.example.com",
			allowedOrigins: []string{"*.example.com"},
			expected:       true,
		},
		{
			name:           "wildcard root domain match",
			origin:         "https://example.com",
			allowedOrigins: []string{"*.example.com"},
			expected:       true,
		},
		{
			name:           "wildcard no match",
			origin:         "https://evil.com",
			allowedOrigins: []string{"*.example.com"},
			expected:       false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isOriginAllowed(tt.origin, tt.allowedOrigins)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestDefaultCORSConfig(t *testing.T) {
	config := DefaultCORSConfig()

	assert.NotNil(t, config)
	assert.Equal(t, []string{"*"}, config.AllowOrigins)
	assert.Contains(t, config.AllowMethods, "GET")
	assert.Contains(t, config.AllowMethods, "POST")
	assert.Contains(t, config.AllowHeaders, "Content-Type")
	assert.Equal(t, false, config.AllowCredentials)
	assert.Equal(t, 12*time.Hour, config.MaxAge)
}

// Benchmark tests
func BenchmarkRequestIDMiddleware(b *testing.B) {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(RequestIDMiddleware())
	router.GET("/test", func(c *gin.Context) {
		c.Status(200)
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/test", nil)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		router.ServeHTTP(w, req)
	}
}

func BenchmarkRateLimiter(b *testing.B) {
	gin.SetMode(gin.TestMode)
	limiter := NewRateLimiter(1000, time.Minute)
	router := gin.New()
	router.Use(limiter.RateLimitMiddleware())
	router.GET("/test", func(c *gin.Context) {
		c.Status(200)
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/test", nil)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		router.ServeHTTP(w, req)
	}
}
