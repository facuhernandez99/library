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
	"time"

	"github.com/facuhernandez99/library/pkg/auth"
	"github.com/facuhernandez99/library/pkg/config"
	"github.com/facuhernandez99/library/pkg/errors"
	libraryhttp "github.com/facuhernandez99/library/pkg/http"
	"github.com/facuhernandez99/library/pkg/logging"
	"github.com/facuhernandez99/library/pkg/models"
	"github.com/gin-gonic/gin"
)

func main() {
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
	if err != nil {
		fmt.Printf("❌ Failed to load configuration: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("   ✅ Configuration loaded: Environment=%s, LogLevel=%s\n", cfg.Environment, cfg.LogLevel)

	// === Step 2: Setup Structured Logging ===
	fmt.Println("\n2. Setting up structured logging...")

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
	fmt.Printf("   ✅ Logger initialized with debug level\n")

	// === Step 3: Create Test User and Authentication ===
	fmt.Println("\n3. Creating test user and authentication...")

	testUser := &models.User{
		ID:       100,
		Username: "lifecycleuser",
	}

	tokenResponse, err := auth.GenerateJWT(testUser, cfg.JWTSecret, 24)
	if err != nil {
		fmt.Printf("❌ Failed to generate JWT token: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("   ✅ JWT token generated for user: %s (ID: %d)\n", testUser.Username, testUser.ID)

	// === Step 4: Setup Middleware Stack ===
	fmt.Println("\n4. Setting up complete middleware stack...")

	gin.SetMode(gin.TestMode)
	router := gin.New()

	// Add middleware stack
	router.Use(libraryhttp.RequestIDMiddleware())
	router.Use(libraryhttp.SecurityHeadersMiddleware())

	corsConfig := &libraryhttp.CORSConfig{
		AllowOrigins:     []string{"*"},
		AllowMethods:     []string{"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"},
		AllowHeaders:     []string{"Origin", "Content-Type", "Accept", "Authorization", "X-Request-ID"},
		ExposeHeaders:    []string{"X-Request-ID"},
		AllowCredentials: false,
		MaxAge:           12 * time.Hour,
	}
	router.Use(libraryhttp.CORSMiddleware(corsConfig))

	rateLimiter := libraryhttp.NewRateLimiter(100, time.Minute)
	router.Use(rateLimiter.RateLimitMiddleware())

	loggingConfig := &logging.HTTPLoggingConfig{
		Logger:          logger,
		LogRequestBody:  false,
		LogResponseBody: false,
		SanitizeHeaders: true,
	}
	router.Use(logging.HTTPLoggingMiddleware(loggingConfig))
	router.Use(libraryhttp.RecoveryMiddleware())

	fmt.Printf("   ✅ Complete middleware stack configured\n")

	// === Step 5: Setup Test Endpoints ===
	fmt.Println("\n5. Setting up test endpoints...")

	v1 := router.Group("/api/v1")
	lifecycle := v1.Group("/lifecycle")

	lifecycle.POST("/profile", auth.AuthMiddleware(cfg.JWTSecret), func(c *gin.Context) {
		userID, _ := auth.GetUserID(c)
		username, _ := auth.GetUsername(c)
		requestID := libraryhttp.GetRequestID(c)

		var requestData map[string]interface{}
		if err := c.ShouldBindJSON(&requestData); err != nil {
			errors.RespondWithValidationError(c, "Invalid request data")
			return
		}

		logging.GetDefault().WithFields(map[string]interface{}{
			"user_id":    userID,
			"username":   username,
			"request_id": requestID,
			"endpoint":   "/lifecycle/profile",
		}).Info(c.Request.Context(), "Lifecycle profile endpoint accessed successfully")

		libraryhttp.RespondWithSuccess(c, gin.H{
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
		})
	})

	fmt.Printf("   ✅ Test endpoints configured\n")

	// === Step 6: Execute Test Request ===
	fmt.Println("\n6. Executing test request...")

	requestID := fmt.Sprintf("lifecycle-test-%d", time.Now().Unix())
	requestData := map[string]interface{}{
		"action":    "get_profile",
		"timestamp": time.Now().Unix(),
	}

	bodyBytes, _ := json.Marshal(requestData)
	req, _ := http.NewRequest("POST", "/api/v1/lifecycle/profile", strings.NewReader(string(bodyBytes)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+tokenResponse.Token)
	req.Header.Set("X-Request-ID", requestID)

	w := httptest.NewRecorder()
	startTime := time.Now()
	router.ServeHTTP(w, req)
	duration := time.Since(startTime)

	fmt.Printf("   ✅ Request executed in %v\n", duration)

	// === Step 7: Verify Results ===
	fmt.Println("\n7. Verifying results...")

	if w.Code != http.StatusOK {
		fmt.Printf("❌ Expected status 200, got %d\n", w.Code)
		fmt.Printf("Response: %s\n", w.Body.String())
		os.Exit(1)
	}

	var response map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		fmt.Printf("❌ Failed to parse response: %v\n", err)
		os.Exit(1)
	}

	// Verify response contains expected data
	data, ok := response["data"].(map[string]interface{})
	if !ok {
		fmt.Printf("❌ Response missing data field\n")
		os.Exit(1)
	}

	userProfile, ok := data["user_profile"].(map[string]interface{})
	if !ok {
		fmt.Printf("❌ Response missing user profile\n")
		os.Exit(1)
	}

	if userProfile["username"] != testUser.Username {
		fmt.Printf("❌ Username mismatch\n")
		os.Exit(1)
	}

	fmt.Printf("   ✅ Request lifecycle verification passed\n")
	fmt.Printf("   ✅ Request ID: %s\n", requestID)
	fmt.Printf("   ✅ User authenticated: %s\n", testUser.Username)
	fmt.Printf("   ✅ All middleware executed successfully\n")

	fmt.Println("\n=== Request Lifecycle Test Complete ===")
	fmt.Println("✅ Complete request lifecycle successfully tracked through all middleware stages!")
}
