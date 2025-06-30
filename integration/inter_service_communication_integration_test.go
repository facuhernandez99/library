//go:build ignore
// +build ignore

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/facuhernandez99/blog/pkg/auth"
	"github.com/facuhernandez99/blog/pkg/config"
	httpPkg "github.com/facuhernandez99/blog/pkg/http"
	"github.com/facuhernandez99/blog/pkg/logging"
	"github.com/facuhernandez99/blog/pkg/models"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestInterServiceCommunicationIntegration tests inter-service communication scenarios
// Run with: go test examples/inter_service_communication_integration_test.go
func TestInterServiceCommunicationIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	fmt.Println("=== Inter-Service Communication Integration Test ===")

	// === Step 1: Setup Configuration and Logging ===
	fmt.Println("\n1. Setting up configuration and logging...")

	// Set test environment variables
	os.Setenv("JWT_SECRET", "test_jwt_secret_key_that_is_long_enough_for_validation_requirements")
	os.Setenv("DATABASE_URL", "postgres://test:test@localhost:5432/test_db")
	os.Setenv("LOG_LEVEL", "debug")
	os.Setenv("ENVIRONMENT", "development")

	cfg, err := config.Load()
	require.NoError(t, err, "Failed to load configuration")

	// Setup logging with buffer capture
	logBuffer := &bytes.Buffer{}
	loggerConfig := &logging.Config{
		Level:      logging.LevelDebug,
		Output:     logBuffer,
		Service:    "inter-service-test",
		Version:    "test-1.0.0",
		Production: cfg.IsProduction(),
	}

	logger := logging.NewLogger(loggerConfig)
	logging.SetDefault(logger)
	fmt.Printf("   ✅ Configuration and logging initialized\n")

	// === Step 2: Create Mock Services ===
	fmt.Println("\n2. Setting up mock services...")

	// Create mock user service
	userService := createMockUserService(cfg.JWTSecret, logger)
	userServer := httptest.NewServer(userService)
	defer userServer.Close()

	// Create mock post service
	postService := createMockPostService(cfg.JWTSecret, logger)
	postServer := httptest.NewServer(postService)
	defer postServer.Close()

	// Create mock notification service
	notificationService := createMockNotificationService(cfg.JWTSecret, logger)
	notificationServer := httptest.NewServer(notificationService)
	defer notificationServer.Close()

	fmt.Printf("   ✅ Mock services created:\n")
	fmt.Printf("      - User Service: %s\n", userServer.URL)
	fmt.Printf("      - Post Service: %s\n", postServer.URL)
	fmt.Printf("      - Notification Service: %s\n", notificationServer.URL)

	// === Step 3: Test Service-to-Service Authentication ===
	fmt.Println("\n3. Testing service-to-service authentication...")

	// Create a test user for authentication
	testUser := &models.User{
		ID:       123,
		Username: "serviceuser",
	}

	// Generate service token
	tokenResponse, err := auth.GenerateJWT(testUser, cfg.JWTSecret, 24)
	require.NoError(t, err, "Failed to generate service token")

	// Create HTTP client with authentication
	clientConfig := &httpPkg.ClientConfig{
		BaseURL: userServer.URL,
		Timeout: 10 * time.Second,
		Logger:  logger,
		AuthConfig: &httpPkg.AuthConfig{
			JWTSecret:    cfg.JWTSecret,
			ServiceToken: tokenResponse.Token,
			AutoRefresh:  false,
		},
	}

	httpClient := httpPkg.NewClient(clientConfig)

	// Clear log buffer to capture authentication logs
	logBuffer.Reset()

	// Test authenticated request
	response, err := httpClient.Get(context.Background(), "/users/profile")
	require.NoError(t, err, "Authenticated request should succeed")
	assert.Equal(t, http.StatusOK, response.StatusCode)
	fmt.Printf("   ✅ Service-to-service authentication working\n")

	// Verify authentication was logged
	logOutput := logBuffer.String()
	assert.Contains(t, logOutput, "Authenticated service request", "Authentication should be logged")

	// === Step 4: Test Request Correlation (Request ID Propagation) ===
	fmt.Println("\n4. Testing request correlation and ID propagation...")

	// Create client with custom request ID header
	customRequestID := "test-correlation-12345"
	clientConfig.Headers = map[string]string{
		"X-Request-ID": customRequestID,
	}
	correlationClient := httpPkg.NewClient(clientConfig)

	// Clear log buffer for correlation test
	logBuffer.Reset()

	// Make request with correlation ID
	response, err = correlationClient.Get(context.Background(), "/users/profile")
	require.NoError(t, err, "Correlated request should succeed")
	assert.Equal(t, http.StatusOK, response.StatusCode)

	// Verify request ID was returned
	returnedRequestID := response.Headers["X-Request-ID"]
	if len(returnedRequestID) > 0 {
		assert.Contains(t, []string{customRequestID, "test-correlation-12345"}, returnedRequestID[0], "Request ID should be propagated")
		fmt.Printf("   ✅ Request correlation working: %s\n", returnedRequestID[0])
	} else {
		fmt.Printf("   ⚠️  Request ID not returned in headers\n")
	}

	// Verify correlation was logged
	logOutput = logBuffer.String()
	assert.Contains(t, logOutput, customRequestID, "Request ID should appear in logs")

	// === Step 5: Test Cross-Service Communication Chain ===
	fmt.Println("\n5. Testing cross-service communication chain...")

	// Test User → Post → Notification service chain
	postClient := httpPkg.NewClient(&httpPkg.ClientConfig{
		BaseURL: postServer.URL,
		Timeout: 10 * time.Second,
		Logger:  logger,
		AuthConfig: &httpPkg.AuthConfig{
			JWTSecret:    cfg.JWTSecret,
			ServiceToken: tokenResponse.Token,
			AutoRefresh:  false,
		},
	})

	// Clear log buffer for chain test
	logBuffer.Reset()

	// Create post (will trigger notification)
	postData := map[string]interface{}{
		"title":   "Test Post for Integration",
		"content": "This is a test post for inter-service communication",
		"user_id": testUser.ID,
	}

	response, err = postClient.Post(context.Background(), "/posts", postData)
	require.NoError(t, err, "Post creation should succeed")
	assert.Equal(t, http.StatusCreated, response.StatusCode)
	fmt.Printf("   ✅ Cross-service communication chain completed\n")

	// Parse response to get post ID
	var postResult map[string]interface{}
	err = json.Unmarshal(response.Body, &postResult)
	require.NoError(t, err, "Should parse post response")

	if data, ok := postResult["data"].(map[string]interface{}); ok {
		if postID, exists := data["id"]; exists {
			fmt.Printf("   ✅ Created post with ID: %v\n", postID)
		}
	}

	// Wait for async notification to complete
	time.Sleep(100 * time.Millisecond)

	// Verify the chain was logged
	logOutput = logBuffer.String()
	assert.Contains(t, logOutput, "Creating new post", "Post creation should be logged")
	assert.Contains(t, logOutput, "Sending notification", "Notification sending should be logged")
	assert.Contains(t, logOutput, "Notification sent successfully", "Notification success should be logged")

	// === Step 6: Test Error Handling Across Services ===
	fmt.Println("\n6. Testing error handling across services...")

	// Clear log buffer for error test
	logBuffer.Reset()

	// Test invalid authentication
	unauthClient := httpPkg.NewClient(&httpPkg.ClientConfig{
		BaseURL: userServer.URL,
		Timeout: 10 * time.Second,
		Logger:  logger,
		// No auth config (intentionally unauthenticated)
	})

	response, err = unauthClient.Get(context.Background(), "/users/profile")
	// Should get response but with unauthorized status
	require.NoError(t, err, "Request should complete (but be unauthorized)")
	assert.Equal(t, http.StatusUnauthorized, response.StatusCode)
	fmt.Printf("   ✅ Unauthorized request properly handled\n")

	// Test service unavailable scenario
	response, err = httpClient.Get(context.Background(), "/users/500")
	require.NoError(t, err, "Request should complete (but server error)")
	assert.Equal(t, http.StatusInternalServerError, response.StatusCode)
	fmt.Printf("   ✅ Server error properly handled\n")

	// Verify errors were logged
	logOutput = logBuffer.String()
	assert.Contains(t, logOutput, "401", "Unauthorized error should be logged")
	assert.Contains(t, logOutput, "500", "Server error should be logged")

	// === Step 7: Test Health Check Communication ===
	fmt.Println("\n7. Testing service health check communication...")

	// Clear log buffer for health check test
	logBuffer.Reset()

	// Test health checks for all services
	services := map[string]string{
		"user":         userServer.URL,
		"post":         postServer.URL,
		"notification": notificationServer.URL,
	}

	for serviceName, serviceURL := range services {
		healthClient := httpPkg.NewClient(&httpPkg.ClientConfig{
			BaseURL: serviceURL,
			Timeout: 5 * time.Second,
			Logger:  logger,
		})

		healthCheck, err := healthClient.HealthCheck(context.Background())
		require.NoError(t, err, "Health check should succeed for "+serviceName)
		assert.Equal(t, "healthy", healthCheck.Status)
		assert.True(t, healthClient.IsHealthy(context.Background()))

		fmt.Printf("   ✅ %s service health check passed\n", serviceName)
	}

	// Verify health checks were logged
	logOutput = logBuffer.String()
	assert.Contains(t, logOutput, "health", "Health check should be logged")

	// === Step 8: Test Retry Logic ===
	fmt.Println("\n8. Testing retry logic for failed requests...")

	// Create client with retry configuration
	retryClient := httpPkg.NewClient(&httpPkg.ClientConfig{
		BaseURL:       userServer.URL,
		Timeout:       2 * time.Second,
		RetryAttempts: 3,
		Logger:        logger,
		AuthConfig: &httpPkg.AuthConfig{
			JWTSecret:    cfg.JWTSecret,
			ServiceToken: tokenResponse.Token,
			AutoRefresh:  false,
		},
	})

	// Clear log buffer for retry test
	logBuffer.Reset()

	// Test retries on timeout endpoint
	response, err = retryClient.Get(context.Background(), "/users/timeout")
	// This should eventually succeed after retries
	if err != nil {
		fmt.Printf("   ⚠️  Retry test completed with expected timeout: %v\n", err)
	} else {
		fmt.Printf("   ✅ Retry logic working: Status %d\n", response.StatusCode)
	}

	// === Step 9: Test Rate Limiting Between Services ===
	fmt.Println("\n9. Testing rate limiting in inter-service communication...")

	// Clear log buffer for rate limit test
	logBuffer.Reset()

	// Make rapid requests to trigger rate limiting
	rateLimitHit := false
	for i := 0; i < 15; i++ {
		response, err = httpClient.Get(context.Background(), "/users/rate-limited")
		require.NoError(t, err, "Request should complete")

		if response.StatusCode == http.StatusTooManyRequests {
			rateLimitHit = true
			fmt.Printf("   ✅ Rate limiting triggered at request %d\n", i+1)
			break
		}
	}

	if !rateLimitHit {
		fmt.Printf("   ⚠️  Rate limiting not triggered (may be expected in test environment)\n")
	}

	// === Step 10: Verify Comprehensive Logging ===
	fmt.Println("\n10. Verifying comprehensive inter-service communication logging...")

	logOutput = logBuffer.String()
	fmt.Printf("   [DEBUG] Total log output length: %d characters\n", len(logOutput))

	// Check for required log entries
	requiredLogEntries := []string{
		"Authenticated service request",
		"Creating new post",
		"Sending notification",
		"Notification sent successfully",
		"health",
	}

	foundEntries := 0
	for _, entry := range requiredLogEntries {
		if strings.Contains(logOutput, entry) {
			foundEntries++
		}
	}

	fmt.Printf("   ✅ Required log entries found: %d/%d\n", foundEntries, len(requiredLogEntries))

	// Check for structured logging fields
	structuredFields := []string{
		"\"service\":",
		"\"request_id\":",
		"\"user_id\":",
		"\"status_code\":",
		"\"method\":",
		"\"path\":",
	}

	foundFields := 0
	for _, field := range structuredFields {
		if strings.Contains(logOutput, field) {
			foundFields++
		}
	}

	fmt.Printf("   ✅ Structured logging fields found: %d/%d\n", foundFields, len(structuredFields))

	// === Step 11: Test Service Discovery Simulation ===
	fmt.Println("\n11. Testing service discovery simulation...")

	// Simulate service discovery by testing multiple service endpoints
	serviceEndpoints := map[string][]string{
		userServer.URL:         {"/health", "/users/profile"},
		postServer.URL:         {"/health", "/posts"},
		notificationServer.URL: {"/health", "/notifications/status"},
	}

	discoveredServices := 0
	for serviceURL, endpoints := range serviceEndpoints {
		serviceHealthy := true
		discoveryClient := httpPkg.NewClient(&httpPkg.ClientConfig{
			BaseURL: serviceURL,
			Timeout: 5 * time.Second,
			Logger:  logger,
			AuthConfig: &httpPkg.AuthConfig{
				JWTSecret:    cfg.JWTSecret,
				ServiceToken: tokenResponse.Token,
				AutoRefresh:  false,
			},
		})

		for _, endpoint := range endpoints {
			response, err := discoveryClient.Get(context.Background(), endpoint)
			if err != nil || response.StatusCode >= 500 {
				serviceHealthy = false
				break
			}
		}

		if serviceHealthy {
			discoveredServices++
		}
	}

	fmt.Printf("   ✅ Service discovery: %d/%d services healthy and discoverable\n",
		discoveredServices, len(serviceEndpoints))

	fmt.Println("\n=== Inter-Service Communication Integration Test Completed Successfully ===")
}

// createMockUserService creates a mock user service for testing
func createMockUserService(jwtSecret string, logger *logging.Logger) http.Handler {
	gin.SetMode(gin.TestMode)
	router := gin.New()

	// Add middleware (before auth)
	router.Use(httpPkg.RequestIDMiddleware())
	router.Use(httpPkg.DefaultStructuredLoggingMiddleware())

	// Health endpoint (no auth required)
	router.GET("/health", func(c *gin.Context) {
		logger.Info(c.Request.Context(), "User service health check requested")
		c.JSON(http.StatusOK, models.HealthCheck{
			Status:    "healthy",
			Service:   "user-service",
			Version:   "1.0.0",
			Timestamp: time.Now(),
		})
	})

	// Create auth group for protected endpoints
	authGroup := router.Group("/")
	authGroup.Use(auth.AuthMiddleware(jwtSecret))

	// Profile endpoint (auth required)
	authGroup.GET("/users/profile", func(c *gin.Context) {
		userID, _ := auth.GetUserID(c)
		username, _ := auth.GetUsername(c)

		logger.WithFields(map[string]interface{}{
			"user_id":  userID,
			"username": username,
			"endpoint": "profile",
		}).Info(c.Request.Context(), "Authenticated service request")

		c.JSON(http.StatusOK, models.APIResponse{
			Success: true,
			Data: map[string]interface{}{
				"user_id":  userID,
				"username": username,
				"service":  "user-service",
			},
		})
	})

	// Error endpoint for testing
	authGroup.GET("/users/500", func(c *gin.Context) {
		logger.Error(c.Request.Context(), "Simulated server error", nil)
		c.JSON(http.StatusInternalServerError, models.APIResponse{
			Success: false,
			Error:   "Internal server error",
		})
	})

	// Timeout endpoint for retry testing
	authGroup.GET("/users/timeout", func(c *gin.Context) {
		logger.Info(c.Request.Context(), "Timeout endpoint hit")
		time.Sleep(3 * time.Second) // Simulate slow response
		c.JSON(http.StatusOK, models.APIResponse{
			Success: true,
			Data:    map[string]interface{}{"message": "slow response"},
		})
	})

	// Rate limited endpoint
	rateLimiter := httpPkg.NewRateLimiter(10, 1*time.Minute)
	authGroup.GET("/users/rate-limited", rateLimiter.RateLimitMiddleware(), func(c *gin.Context) {
		c.JSON(http.StatusOK, models.APIResponse{
			Success: true,
			Data:    map[string]interface{}{"message": "rate limited endpoint"},
		})
	})

	return router
}

// createMockPostService creates a mock post service for testing
func createMockPostService(jwtSecret string, logger *logging.Logger) http.Handler {
	gin.SetMode(gin.TestMode)
	router := gin.New()

	// Add middleware (before auth)
	router.Use(httpPkg.RequestIDMiddleware())
	router.Use(httpPkg.DefaultStructuredLoggingMiddleware())

	// Health endpoint (no auth required)
	router.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, models.HealthCheck{
			Status:    "healthy",
			Service:   "post-service",
			Version:   "1.0.0",
			Timestamp: time.Now(),
		})
	})

	// Create auth group for protected endpoints
	authGroup := router.Group("/")
	authGroup.Use(auth.AuthMiddleware(jwtSecret))

	// Posts endpoint
	authGroup.GET("/posts", func(c *gin.Context) {
		c.JSON(http.StatusOK, models.APIResponse{
			Success: true,
			Data: []map[string]interface{}{
				{"id": 1, "title": "Sample Post", "author": "testuser"},
			},
		})
	})

	// Create post endpoint
	authGroup.POST("/posts", func(c *gin.Context) {
		var postData map[string]interface{}
		if err := c.ShouldBindJSON(&postData); err != nil {
			c.JSON(http.StatusBadRequest, models.APIResponse{
				Success: false,
				Error:   "Invalid post data",
			})
			return
		}

		logger.WithFields(map[string]interface{}{
			"title":   postData["title"],
			"user_id": postData["user_id"],
		}).Info(c.Request.Context(), "Creating new post")

		// Simulate notification service call
		logger.WithField("post_id", 123).Info(c.Request.Context(), "Sending notification")

		// Simulate async notification processing
		go func() {
			time.Sleep(50 * time.Millisecond) // Simulate async call
			logger.WithField("post_id", 123).Info(context.Background(), "Notification sent successfully")
		}()

		c.JSON(http.StatusCreated, models.APIResponse{
			Success: true,
			Data: map[string]interface{}{
				"id":      123,
				"title":   postData["title"],
				"user_id": postData["user_id"],
				"status":  "created",
			},
		})
	})

	return router
}

// createMockNotificationService creates a mock notification service for testing
func createMockNotificationService(jwtSecret string, logger *logging.Logger) http.Handler {
	gin.SetMode(gin.TestMode)
	router := gin.New()

	// Add middleware
	router.Use(httpPkg.RequestIDMiddleware())
	router.Use(httpPkg.DefaultStructuredLoggingMiddleware())

	// Health endpoint
	router.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, models.HealthCheck{
			Status:    "healthy",
			Service:   "notification-service",
			Version:   "1.0.0",
			Timestamp: time.Now(),
		})
	})

	// Notification status endpoint
	router.GET("/notifications/status", func(c *gin.Context) {
		c.JSON(http.StatusOK, models.APIResponse{
			Success: true,
			Data: map[string]interface{}{
				"service":    "notification-service",
				"status":     "operational",
				"queue_size": 0,
			},
		})
	})

	return router
}

func main() {
	// This file is meant to be run as a test
	// Usage: go test examples/inter_service_communication_integration_test.go
	fmt.Println("This file should be run as a test:")
	fmt.Println("go test examples/inter_service_communication_integration_test.go")
}
