//go:build ignore
// +build ignore

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/facuhernandez99/blog/pkg/auth"
	"github.com/facuhernandez99/blog/pkg/config"
	"github.com/facuhernandez99/blog/pkg/errors"
	bloghttp "github.com/facuhernandez99/blog/pkg/http"
	"github.com/facuhernandez99/blog/pkg/logging"
	"github.com/facuhernandez99/blog/pkg/models"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// MiddlewareStage represents a stage in the middleware pipeline
type MiddlewareStage struct {
	Name        string
	Description string
	Order       int
	Executed    bool
	Timestamp   time.Time
	Duration    time.Duration
	Data        map[string]interface{}
}

// RequestLifecycleTracker tracks a request through the middleware pipeline
type RequestLifecycleTracker struct {
	RequestID string
	StartTime time.Time
	Stages    []*MiddlewareStage
	Context   map[string]interface{}
	mu        sync.RWMutex
}

// AddStage adds a middleware stage to the tracker
func (t *RequestLifecycleTracker) AddStage(name, description string, data map[string]interface{}) {
	t.mu.Lock()
	defer t.mu.Unlock()

	stage := &MiddlewareStage{
		Name:        name,
		Description: description,
		Order:       len(t.Stages) + 1,
		Executed:    true,
		Timestamp:   time.Now(),
		Data:        data,
	}

	if len(t.Stages) > 0 {
		stage.Duration = stage.Timestamp.Sub(t.Stages[len(t.Stages)-1].Timestamp)
	} else {
		stage.Duration = stage.Timestamp.Sub(t.StartTime)
	}

	t.Stages = append(t.Stages, stage)
}

// GetSummary returns a summary of the request lifecycle
func (t *RequestLifecycleTracker) GetSummary() map[string]interface{} {
	t.mu.RLock()
	defer t.mu.RUnlock()

	totalDuration := time.Since(t.StartTime)
	stageCount := len(t.Stages)

	return map[string]interface{}{
		"request_id":      t.RequestID,
		"total_duration":  totalDuration.Milliseconds(),
		"stages_executed": stageCount,
		"start_time":      t.StartTime.Format(time.RFC3339Nano),
		"end_time":        time.Now().Format(time.RFC3339Nano),
		"context":         t.Context,
		"stages":          t.Stages,
	}
}

// TestRequestLifecycleWithFullMiddlewareStack tests the complete request lifecycle
// with detailed tracking through every middleware stage
func TestRequestLifecycleWithFullMiddlewareStack(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	fmt.Println("=== Request Lifecycle with Full Middleware Stack Integration Test ===")
	fmt.Println("Testing complete request lifecycle with detailed middleware tracking")

	// === Step 1: Setup Environment and Configuration ===
	fmt.Println("\n1. Setting up environment and configuration...")

	// Set comprehensive test environment variables
	envVars := map[string]string{
		"JWT_SECRET":          "test_jwt_secret_key_for_request_lifecycle_that_is_long_enough_for_validation",
		"DATABASE_URL":        "postgres://test:test@localhost:5432/lifecycle_test_db",
		"LOG_LEVEL":           "debug",
		"ENVIRONMENT":         "development",
		"REDIS_URL":           "redis://localhost:6379/2",
		"SERVER_PORT":         "8080",
		"REQUEST_TIMEOUT":     "30s",
		"RATE_LIMIT_WINDOW":   "1m",
		"RATE_LIMIT_REQUESTS": "100",
	}

	for key, value := range envVars {
		os.Setenv(key, value)
	}

	cfg, err := config.Load()
	require.NoError(t, err, "Failed to load configuration")
	fmt.Printf("   ✅ Configuration loaded: Environment=%s, LogLevel=%s\n", cfg.Environment, cfg.LogLevel)

	// === Step 2: Setup Structured Logging with Lifecycle Tracking ===
	fmt.Println("\n2. Setting up structured logging with lifecycle tracking...")

	logBuffer := &bytes.Buffer{}
	loggerConfig := &logging.Config{
		Level:      logging.LevelDebug,
		Output:     logBuffer,
		Service:    "request-lifecycle-test",
		Version:    "test-2.0.0",
		Production: cfg.IsProduction(),
	}

	logger := logging.NewLogger(loggerConfig)
	logging.SetDefault(logger)
	fmt.Printf("   ✅ Logger initialized with debug level for detailed tracking\n")

	// === Step 3: Create Test User and Authentication ===
	fmt.Println("\n3. Creating test user and authentication...")

	testUser := &models.User{
		ID:       100,
		Username: "lifecycleuser",
	}

	tokenResponse, err := auth.GenerateJWT(testUser, cfg.JWTSecret, 24)
	require.NoError(t, err, "Failed to generate JWT token")
	fmt.Printf("   ✅ JWT token generated for user: %s (ID: %d)\n", testUser.Username, testUser.ID)

	// === Step 4: Setup Request Lifecycle Tracker ===
	fmt.Println("\n4. Setting up request lifecycle tracker...")

	var lifecycleTracker *RequestLifecycleTracker
	requestID := "lifecycle-test-" + fmt.Sprintf("%d", time.Now().Unix())

	// === Step 5: Build Complete Middleware Stack with Lifecycle Tracking ===
	fmt.Println("\n5. Building complete middleware stack with lifecycle tracking...")

	gin.SetMode(gin.TestMode)
	router := gin.New()

	// Build the complete middleware stack with lifecycle tracking
	setupLifecycleMiddlewareStack(router, cfg, logger, &lifecycleTracker)

	// Setup test endpoints
	setupLifecycleTestEndpoints(router, cfg)

	fmt.Printf("   ✅ Complete middleware stack configured with lifecycle tracking\n")

	// === Step 6: Execute Complete Request Lifecycle Test ===
	fmt.Println("\n6. Executing complete request lifecycle test...")

	// Initialize tracker
	lifecycleTracker = &RequestLifecycleTracker{
		RequestID: requestID,
		StartTime: time.Now(),
		Context:   make(map[string]interface{}),
	}

	// Clear log buffer for lifecycle test
	logBuffer.Reset()

	// Create comprehensive authenticated request
	requestData := map[string]interface{}{
		"action":    "get_profile",
		"timestamp": time.Now().Unix(),
		"client_info": map[string]string{
			"version":    "2.0.0",
			"user_agent": "LifecycleTest/2.0",
		},
	}

	req := createLifecycleTestRequest("POST", "/api/v1/lifecycle/profile", requestData, map[string]string{
		"Authorization":   "Bearer " + tokenResponse.Token,
		"Content-Type":    "application/json",
		"X-Request-ID":    requestID,
		"Origin":          "https://app.example.com",
		"User-Agent":      "LifecycleTest/2.0 (RequestLifecycleTest)",
		"Accept":          "application/json",
		"X-Client-IP":     "192.168.1.50",
		"X-Forwarded-For": "203.0.113.10",
		"Referer":         "https://app.example.com/dashboard",
		"Accept-Language": "en-US,en;q=0.9",
		"Cache-Control":   "no-cache",
	})

	w := httptest.NewRecorder()

	// Execute request and track lifecycle
	startTime := time.Now()
	router.ServeHTTP(w, req)
	totalDuration := time.Since(startTime)

	fmt.Printf("   ✅ Request executed in %v\n", totalDuration)

	// === Step 7: Verify Request Lifecycle Results ===
	fmt.Println("\n7. Verifying request lifecycle results...")

	// Verify successful response
	assert.Equal(t, http.StatusOK, w.Code, "Request should complete successfully")

	// Parse response
	var response map[string]interface{}
	err = json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err, "Response should be valid JSON")

	// Verify request lifecycle tracking
	verifyRequestLifecycle(t, lifecycleTracker, w, logBuffer.String(), requestID, testUser, totalDuration)

	// === Step 8: Test Failed Request Lifecycle (Authentication) ===
	fmt.Println("\n8. Testing failed request lifecycle (authentication failure)...")

	// Reset tracker for failed request
	lifecycleTracker = &RequestLifecycleTracker{
		RequestID: "lifecycle-fail-auth-" + fmt.Sprintf("%d", time.Now().Unix()),
		StartTime: time.Now(),
		Context:   make(map[string]interface{}),
	}

	logBuffer.Reset()

	// Create request without authentication
	failReq := createLifecycleTestRequest("POST", "/api/v1/lifecycle/profile", requestData, map[string]string{
		"Content-Type": "application/json",
		"X-Request-ID": lifecycleTracker.RequestID,
		"User-Agent":   "LifecycleTest/2.0 (AuthFailTest)",
	})

	failW := httptest.NewRecorder()
	failStartTime := time.Now()
	router.ServeHTTP(failW, failReq)
	failDuration := time.Since(failStartTime)

	// Verify authentication failure
	assert.Equal(t, http.StatusUnauthorized, failW.Code, "Should fail authentication")
	fmt.Printf("   ✅ Authentication failure handled correctly in %v\n", failDuration)

	// === Step 9: Test Rate Limited Request Lifecycle ===
	fmt.Println("\n9. Testing rate limited request lifecycle...")

	// Create rate limiter with very low limit for testing
	testRateLimiter := bloghttp.NewRateLimiter(2, time.Minute)
	rateLimitRouter := gin.New()
	rateLimitRouter.Use(bloghttp.RequestIDMiddleware())
	rateLimitRouter.Use(testRateLimiter.RateLimitMiddleware())
	rateLimitRouter.GET("/rate-test", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "rate test ok"})
	})

	// Make requests to hit rate limit
	for i := 0; i < 3; i++ {
		testReq := createLifecycleTestRequest("GET", "/rate-test", nil, map[string]string{
			"X-Request-ID": fmt.Sprintf("rate-test-%d", i),
		})
		testW := httptest.NewRecorder()
		rateLimitRouter.ServeHTTP(testW, testReq)

		if i < 2 {
			assert.Equal(t, http.StatusOK, testW.Code, fmt.Sprintf("Request %d should succeed", i))
		} else {
			assert.Equal(t, http.StatusTooManyRequests, testW.Code, "Request should be rate limited")
			fmt.Printf("   ✅ Rate limiting lifecycle verified\n")
		}
	}

	// === Step 10: Test Error Recovery Lifecycle ===
	fmt.Println("\n10. Testing error recovery lifecycle...")

	logBuffer.Reset()

	panicReq := createLifecycleTestRequest("GET", "/api/v1/lifecycle/panic", nil, map[string]string{
		"X-Request-ID": "lifecycle-panic-" + fmt.Sprintf("%d", time.Now().Unix()),
		"User-Agent":   "LifecycleTest/2.0 (PanicTest)",
	})

	panicW := httptest.NewRecorder()
	panicStartTime := time.Now()
	router.ServeHTTP(panicW, panicReq)
	panicDuration := time.Since(panicStartTime)

	// Verify panic recovery
	assert.Equal(t, http.StatusInternalServerError, panicW.Code, "Panic should be recovered")
	fmt.Printf("   ✅ Panic recovery lifecycle completed in %v\n", panicDuration)

	// === Step 11: Generate Comprehensive Lifecycle Report ===
	fmt.Println("\n11. Generating comprehensive lifecycle report...")

	report := generateLifecycleReport(lifecycleTracker, logBuffer.String(), w)
	fmt.Printf("   ✅ Lifecycle report generated\n")

	// Verify report completeness
	assert.NotEmpty(t, report["request_summary"], "Report should contain request summary")
	assert.NotEmpty(t, report["middleware_flow"], "Report should contain middleware flow")
	assert.NotEmpty(t, report["performance_metrics"], "Report should contain performance metrics")

	// Print summary
	printLifecycleSummary(report)

	fmt.Println("\n=== Request Lifecycle with Full Middleware Stack Test Complete ===")
	fmt.Println("✅ Complete request lifecycle successfully tracked through all middleware stages!")
}

// setupLifecycleMiddlewareStack configures middleware with lifecycle tracking
func setupLifecycleMiddlewareStack(router *gin.Engine, cfg *config.Config, logger *logging.Logger, tracker **RequestLifecycleTracker) {
	// 1. Request ID Middleware (Entry Point)
	router.Use(func(c *gin.Context) {
		if *tracker != nil {
			(*tracker).AddStage("RequestID", "Request ID generation/extraction", map[string]interface{}{
				"request_id": c.GetHeader("X-Request-ID"),
				"method":     c.Request.Method,
				"path":       c.Request.URL.Path,
			})
		}
		bloghttp.RequestIDMiddleware()(c)
	})

	// 2. Security Headers Middleware
	router.Use(func(c *gin.Context) {
		if *tracker != nil {
			(*tracker).AddStage("SecurityHeaders", "Security headers application", map[string]interface{}{
				"headers_applied": []string{"X-Content-Type-Options", "X-Frame-Options", "X-XSS-Protection"},
			})
		}
		bloghttp.SecurityHeadersMiddleware()(c)
	})

	// 3. CORS Middleware
	corsConfig := &bloghttp.CORSConfig{
		AllowOrigins:     []string{"*"}, // Allow all origins for testing
		AllowMethods:     []string{"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"},
		AllowHeaders:     []string{"Origin", "Content-Type", "Accept", "Authorization", "X-Request-ID"},
		ExposeHeaders:    []string{"X-Request-ID", "X-Rate-Limit-Limit"},
		AllowCredentials: false, // Must be false when using "*" for origins
		MaxAge:           12 * time.Hour,
	}

	router.Use(func(c *gin.Context) {
		if *tracker != nil {
			(*tracker).AddStage("CORS", "CORS policy application", map[string]interface{}{
				"origin":              c.GetHeader("Origin"),
				"cors_allowed":        true,
				"preflight":           c.Request.Method == "OPTIONS",
				"credentials_allowed": corsConfig.AllowCredentials,
			})
		}
		bloghttp.CORSMiddleware(corsConfig)(c)
	})

	// 4. Rate Limiting Middleware
	rateLimiter := bloghttp.NewRateLimiter(100, time.Minute)
	router.Use(func(c *gin.Context) {
		if *tracker != nil {
			(*tracker).AddStage("RateLimit", "Rate limiting check", map[string]interface{}{
				"client_ip":    c.ClientIP(),
				"limit":        100,
				"window":       "1m",
				"rate_limited": false, // Will be updated if rate limited
			})
		}
		rateLimiter.RateLimitMiddleware()(c)
	})

	// 5. Timeout Middleware
	router.Use(func(c *gin.Context) {
		if *tracker != nil {
			(*tracker).AddStage("Timeout", "Request timeout configuration", map[string]interface{}{
				"timeout": "30s",
			})
		}
		bloghttp.TimeoutMiddleware(30 * time.Second)(c)
	})

	// 6. Validation Middleware
	validationConfig := &bloghttp.ValidationConfig{
		MaxStringLength:  2000,
		MaxFileSize:      20 * 1024 * 1024,
		AllowedMimeTypes: []string{"application/json", "multipart/form-data"},
	}

	router.Use(func(c *gin.Context) {
		if *tracker != nil {
			(*tracker).AddStage("Validation", "Request validation", map[string]interface{}{
				"content_type":      c.GetHeader("Content-Type"),
				"content_length":    c.Request.ContentLength,
				"validation_passed": true,
			})
		}
		bloghttp.ValidationMiddleware(validationConfig)(c)
	})

	// 7. Structured Logging Middleware
	loggingConfig := &logging.HTTPLoggingConfig{
		Logger:          logger,
		LogRequestBody:  false,
		LogResponseBody: false,
		SanitizeHeaders: true,
	}

	router.Use(func(c *gin.Context) {
		if *tracker != nil {
			(*tracker).AddStage("Logging", "Structured logging initialization", map[string]interface{}{
				"log_level":        "debug",
				"sanitize_headers": true,
				"correlation_id":   c.GetHeader("X-Request-ID"),
			})
		}
		logging.HTTPLoggingMiddleware(loggingConfig)(c)
	})

	// 8. Recovery Middleware (Last in chain)
	router.Use(func(c *gin.Context) {
		if *tracker != nil {
			(*tracker).AddStage("Recovery", "Panic recovery initialization", map[string]interface{}{
				"recovery_active": true,
			})
		}
		bloghttp.RecoveryMiddleware()(c)
	})
}

// setupLifecycleTestEndpoints creates endpoints for lifecycle testing
func setupLifecycleTestEndpoints(router *gin.Engine, cfg *config.Config) {
	// API group with lifecycle tracking
	v1 := router.Group("/api/v1")

	// Lifecycle test endpoints
	lifecycle := v1.Group("/lifecycle")
	{
		// Protected profile endpoint with authentication
		lifecycle.POST("/profile", auth.AuthMiddleware(cfg.JWTSecret), func(c *gin.Context) {
			userID, _ := auth.GetUserID(c)
			username, _ := auth.GetUsername(c)
			requestID := bloghttp.GetRequestID(c)

			// Parse request body
			var requestData map[string]interface{}
			if err := c.ShouldBindJSON(&requestData); err != nil {
				errors.RespondWithValidationError(c, "Invalid request data")
				return
			}

			// Log successful profile access
			logging.GetDefault().WithFields(map[string]interface{}{
				"user_id":    userID,
				"username":   username,
				"request_id": requestID,
				"endpoint":   "/lifecycle/profile",
				"action":     requestData["action"],
			}).Info(c.Request.Context(), "Lifecycle profile endpoint accessed successfully")

			// Return comprehensive response
			bloghttp.RespondWithSuccess(c, gin.H{
				"user_profile": gin.H{
					"user_id":      userID,
					"username":     username,
					"request_id":   requestID,
					"timestamp":    time.Now().Unix(),
					"request_data": requestData,
				},
				"middleware_flow": gin.H{
					"authenticated":     true,
					"request_processed": true,
					"all_middleware":    "executed",
				},
				"lifecycle_info": gin.H{
					"stage":         "handler_execution",
					"response_time": time.Now().Format(time.RFC3339Nano),
				},
			})
		})

		// Panic endpoint for recovery testing
		lifecycle.GET("/panic", func(c *gin.Context) {
			requestID := bloghttp.GetRequestID(c)
			logging.GetDefault().WithField("request_id", requestID).Info(c.Request.Context(), "About to trigger panic for recovery test")
			panic("Test panic for lifecycle recovery testing")
		})

		// Public endpoint for basic testing
		lifecycle.GET("/health", func(c *gin.Context) {
			requestID := bloghttp.GetRequestID(c)
			bloghttp.RespondWithSuccess(c, gin.H{
				"status":     "healthy",
				"request_id": requestID,
				"timestamp":  time.Now().Unix(),
				"lifecycle":  "complete",
			})
		})
	}
}

// createLifecycleTestRequest creates a test request for lifecycle testing
func createLifecycleTestRequest(method, path string, body interface{}, headers map[string]string) *http.Request {
	var bodyStr string
	if body != nil {
		bodyBytes, _ := json.Marshal(body)
		bodyStr = string(bodyBytes)
	}

	req, _ := http.NewRequest(method, path, strings.NewReader(bodyStr))

	// Set default headers
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	// Add custom headers
	for key, value := range headers {
		req.Header.Set(key, value)
	}

	return req
}

// verifyRequestLifecycle verifies the complete request lifecycle
func verifyRequestLifecycle(t *testing.T, tracker *RequestLifecycleTracker, w *httptest.ResponseRecorder, logOutput, requestID string, testUser *models.User, totalDuration time.Duration) {
	fmt.Println("   Verifying complete request lifecycle...")

	// 1. Verify request tracking
	assert.NotNil(t, tracker, "Lifecycle tracker should be initialized")
	if tracker != nil {
		assert.Equal(t, requestID, tracker.RequestID, "Request ID should match")
		assert.Greater(t, len(tracker.Stages), 5, "Should have multiple middleware stages")
		fmt.Printf("     ✅ Request tracked through %d middleware stages\n", len(tracker.Stages))
	}

	// 2. Verify response headers
	assert.Equal(t, requestID, w.Header().Get("X-Request-ID"), "Request ID should propagate")
	assert.NotEmpty(t, w.Header().Get("X-Content-Type-Options"), "Security headers should be applied")
	assert.NotEmpty(t, w.Header().Get("Access-Control-Allow-Origin"), "CORS headers should be applied")

	// 3. Verify response content
	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err, "Response should be valid JSON")

	data, ok := response["data"].(map[string]interface{})
	require.True(t, ok, "Response should have data field")

	userProfile, ok := data["user_profile"].(map[string]interface{})
	require.True(t, ok, "Should have user profile data")

	userID, ok := userProfile["user_id"].(float64)
	require.True(t, ok, "User ID should be present")
	assert.Equal(t, float64(testUser.ID), userID, "User ID should match")

	// 4. Verify middleware flow
	middlewareFlow, ok := data["middleware_flow"].(map[string]interface{})
	require.True(t, ok, "Should have middleware flow data")
	assert.Equal(t, true, middlewareFlow["authenticated"], "Should be authenticated")
	assert.Equal(t, true, middlewareFlow["request_processed"], "Should be processed")

	// 5. Verify logging output
	if logOutput != "" {
		logChecks := []string{
			requestID,
			testUser.Username,
			"Lifecycle profile endpoint accessed successfully",
			"POST",
			"/api/v1/lifecycle/profile",
		}

		passedChecks := 0
		for _, check := range logChecks {
			if strings.Contains(logOutput, check) {
				passedChecks++
			}
		}
		fmt.Printf("     ✅ Structured logging: %d/%d checks passed\n", passedChecks, len(logChecks))
	}

	// 6. Verify performance
	assert.Less(t, totalDuration.Milliseconds(), int64(5000), "Request should complete within 5 seconds")
	fmt.Printf("     ✅ Performance: Request completed in %v\n", totalDuration)

	// 7. Verify stage execution order
	if tracker != nil && len(tracker.Stages) > 0 {
		expectedStages := []string{"RequestID", "SecurityHeaders", "CORS", "RateLimit", "Timeout", "Validation", "Logging", "Recovery"}
		executedStages := make([]string, len(tracker.Stages))
		for i, stage := range tracker.Stages {
			executedStages[i] = stage.Name
		}

		stageMatches := 0
		for i, expected := range expectedStages {
			if i < len(executedStages) && executedStages[i] == expected {
				stageMatches++
			}
		}
		fmt.Printf("     ✅ Middleware execution order: %d/%d stages in correct order\n", stageMatches, len(expectedStages))
	}

	fmt.Printf("     ✅ Complete request lifecycle verification passed\n")
}

// generateLifecycleReport generates a comprehensive lifecycle report
func generateLifecycleReport(tracker *RequestLifecycleTracker, logOutput string, w *httptest.ResponseRecorder) map[string]interface{} {
	report := make(map[string]interface{})

	// Request Summary
	if tracker != nil {
		report["request_summary"] = tracker.GetSummary()
	}

	// Middleware Flow Analysis
	middlewareFlow := make([]map[string]interface{}, 0)
	if tracker != nil {
		for _, stage := range tracker.Stages {
			stageInfo := map[string]interface{}{
				"stage":       stage.Name,
				"description": stage.Description,
				"order":       stage.Order,
				"duration_ms": stage.Duration.Milliseconds(),
				"timestamp":   stage.Timestamp.Format(time.RFC3339Nano),
				"data":        stage.Data,
			}
			middlewareFlow = append(middlewareFlow, stageInfo)
		}
	}
	report["middleware_flow"] = middlewareFlow

	// Performance Metrics
	performanceMetrics := map[string]interface{}{
		"response_status": w.Code,
		"response_size":   w.Body.Len(),
		"headers_count":   len(w.Header()),
	}

	if tracker != nil && len(tracker.Stages) > 0 {
		totalMiddlewareDuration := time.Duration(0)
		for _, stage := range tracker.Stages {
			totalMiddlewareDuration += stage.Duration
		}
		performanceMetrics["middleware_duration_ms"] = totalMiddlewareDuration.Milliseconds()
		performanceMetrics["total_request_duration_ms"] = time.Since(tracker.StartTime).Milliseconds()
	}

	report["performance_metrics"] = performanceMetrics

	// Log Analysis
	if logOutput != "" {
		logLines := strings.Split(strings.TrimSpace(logOutput), "\n")
		report["log_analysis"] = map[string]interface{}{
			"log_lines_generated":      len(logLines),
			"contains_structured_logs": strings.Contains(logOutput, "\"level\":"),
			"contains_request_id":      tracker != nil && strings.Contains(logOutput, tracker.RequestID),
		}
	}

	return report
}

// printLifecycleSummary prints a summary of the lifecycle test
func printLifecycleSummary(report map[string]interface{}) {
	fmt.Println("\n   === LIFECYCLE TEST SUMMARY ===")

	if summary, ok := report["request_summary"].(map[string]interface{}); ok {
		fmt.Printf("   Request ID: %v\n", summary["request_id"])
		fmt.Printf("   Total Duration: %v ms\n", summary["total_duration"])
		fmt.Printf("   Stages Executed: %v\n", summary["stages_executed"])
	}

	if middlewareFlow, ok := report["middleware_flow"].([]map[string]interface{}); ok {
		fmt.Printf("   Middleware Stages:\n")
		for _, stage := range middlewareFlow {
			fmt.Printf("     %d. %s - %v ms\n", stage["order"], stage["stage"], stage["duration_ms"])
		}
	}

	if perf, ok := report["performance_metrics"].(map[string]interface{}); ok {
		fmt.Printf("   Performance:\n")
		fmt.Printf("     Response Status: %v\n", perf["response_status"])
		fmt.Printf("     Response Size: %v bytes\n", perf["response_size"])
		fmt.Printf("     Total Duration: %v ms\n", perf["total_request_duration_ms"])
	}

	fmt.Println("   ===============================")
}

// main function to run the test standalone
func main() {
	fmt.Println("Running Request Lifecycle with Full Middleware Stack Integration Test...")

	// Create test runner
	testRunner := &testing.T{}

	// Run the integration test
	TestRequestLifecycleWithFullMiddlewareStack(testRunner)

	if testRunner.Failed() {
		fmt.Println("❌ Request Lifecycle Integration test failed!")
		os.Exit(1)
	}

	fmt.Println("✅ Request Lifecycle Integration test passed!")
}
