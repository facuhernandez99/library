//go:build ignore
// +build ignore

package main

import (
	"context"
	"errors"
	"os"

	"github.com/facuhernandez99/library/pkg/logging"
	"github.com/gin-gonic/gin"
)

func main() {
	// Example 1: Basic logger setup
	basicLoggerExample()

	// Example 2: Production logger with sanitization
	productionLoggerExample()

	// Example 3: HTTP middleware integration
	httpMiddlewareExample()

	// Example 4: Service layer integration
	serviceLayerExample()
}

// basicLoggerExample shows basic logging usage
func basicLoggerExample() {
	println("=== Basic Logger Example ===")

	// Use default logger
	ctx := context.Background()

	logging.Info(ctx, "Application starting")

	// Add context information
	ctx = logging.WithRequestAndUserID(ctx, "req-123", "user-456")

	// Structured logging with fields
	logging.WithFields(map[string]interface{}{
		"component": "auth",
		"action":    "login",
		"success":   true,
	}).Info(ctx, "User authentication successful")

	// Error logging
	err := errors.New("database connection failed")
	logging.Error(ctx, "Database error occurred", err)
}

// productionLoggerExample shows production setup with sanitization
func productionLoggerExample() {
	println("\n=== Production Logger Example ===")

	// Create production logger
	config := &logging.Config{
		Level:      logging.LevelInfo,
		Output:     os.Stdout,
		Service:    "library-service",
		Version:    "1.0.0",
		Production: true, // Enable production mode for sanitization
	}

	logger := logging.NewLogger(config)
	logging.SetDefault(logger)

	ctx := logging.WithRequestID(context.Background(), "req-789")

	// Sensitive error will be sanitized in production
	sensitiveErr := errors.New("authentication failed with password: secret123")
	logger.Error(ctx, "Authentication error", sensitiveErr)

	// Structured logging with potentially sensitive data
	logger.WithFields(map[string]interface{}{
		"user_email": "user@example.com", // Will be partially redacted
		"action":     "password_reset",
		"ip_address": "192.168.1.100", // Will be partially redacted
	}).Warn(ctx, "Suspicious password reset attempt")
}

// httpMiddlewareExample shows HTTP middleware integration
func httpMiddlewareExample() {
	println("\n=== HTTP Middleware Example ===")

	// Create logger for HTTP middleware
	httpLogger := logging.NewLogger(&logging.Config{
		Level:   logging.LevelDebug,
		Service: "web-server",
		Version: "1.0.0",
	})

	// Set up Gin router with logging middleware
	gin.SetMode(gin.ReleaseMode)
	router := gin.New()

	// Configure comprehensive logging middleware
	loggingConfig := &logging.HTTPLoggingConfig{
		Logger:             httpLogger,
		SkipPaths:          []string{"/health", "/metrics"},
		LogRequestBody:     false, // Set to true if you need request body logging
		LogResponseBody:    false, // Set to true if you need response body logging
		SanitizeHeaders:    true,  // Remove sensitive headers
		SkipSuccessfulGETs: true,  // Reduce noise from health checks
		RequestIDHeader:    "X-Request-ID",
		UserIDExtractor: func(c *gin.Context) string {
			// Extract user ID from JWT claims or headers
			if userID, exists := c.Get("user_id"); exists {
				if id, ok := userID.(string); ok {
					return id
				}
			}
			return ""
		},
	}

	// Add middleware
	router.Use(logging.HTTPLoggingMiddleware(loggingConfig))
	router.Use(logging.RecoveryLoggingMiddleware(httpLogger))

	// Example routes
	router.GET("/health", func(c *gin.Context) {
		c.JSON(200, gin.H{"status": "ok"})
	})

	router.POST("/api/users", func(c *gin.Context) {
		// Get context with request ID for logging
		ctx := c.Request.Context()

		httpLogger.WithFields(map[string]interface{}{
			"endpoint": "/api/users",
			"method":   "POST",
		}).Info(ctx, "Creating new user")

		// Simulate user creation
		userID := "user-new-123"

		// Add user ID to context for subsequent logging
		enrichedCtx := logging.WithUserID(ctx, userID)

		httpLogger.WithField("user_id", userID).Info(enrichedCtx, "User created successfully")

		c.JSON(201, gin.H{"user_id": userID, "status": "created"})
	})

	router.GET("/api/error", func(c *gin.Context) {
		// Simulate an error for testing
		c.Error(errors.New("simulated internal error"))
		c.JSON(500, gin.H{"error": "Internal server error"})
	})

	println("HTTP server configured with logging middleware")
	println("Example endpoints:")
	println("  GET  /health")
	println("  POST /api/users")
	println("  GET  /api/error")

	// In a real application, you would start the server:
	// router.Run(":8080")
}

// serviceLayerExample shows service layer integration
func serviceLayerExample() {
	println("\n=== Service Layer Example ===")

	// Create service with logger
	userService := NewUserService()

	ctx := logging.WithRequestAndUserID(context.Background(), "req-service-001", "admin-123")

	// Example service operations
	user, err := userService.GetUser(ctx, "user-456")
	if err != nil {
		println("Failed to get user:", err.Error())
	} else {
		println("Retrieved user:", user.Username)
	}

	// Create user operation
	newUser := &User{
		Username: "john_doe",
		Email:    "john@example.com",
	}

	createdUser, err := userService.CreateUser(ctx, newUser)
	if err != nil {
		println("Failed to create user:", err.Error())
	} else {
		println("Created user:", createdUser.ID)
	}
}

// User represents a user model
type User struct {
	ID       string `json:"id"`
	Username string `json:"username"`
	Email    string `json:"email"`
}

// UserService demonstrates service layer logging
type UserService struct {
	logger *logging.Logger
}

// NewUserService creates a new user service
func NewUserService() *UserService {
	return &UserService{
		logger: logging.GetDefault(),
	}
}

// GetUser retrieves a user by ID
func (s *UserService) GetUser(ctx context.Context, userID string) (*User, error) {
	serviceLogger := s.logger.WithFields(map[string]interface{}{
		"operation":      "get_user",
		"target_user_id": userID,
		"service":        "user_service",
	})

	serviceLogger.Info(ctx, "Retrieving user")

	// Simulate database lookup
	if userID == "user-456" {
		user := &User{
			ID:       userID,
			Username: "jane_doe",
			Email:    "jane@example.com",
		}

		serviceLogger.WithField("username", user.Username).Info(ctx, "User retrieved successfully")
		return user, nil
	}

	// User not found
	err := errors.New("user not found")
	serviceLogger.Error(ctx, "User not found", err)
	return nil, err
}

// CreateUser creates a new user
func (s *UserService) CreateUser(ctx context.Context, user *User) (*User, error) {
	serviceLogger := s.logger.WithFields(map[string]interface{}{
		"operation": "create_user",
		"username":  user.Username,
		"email":     user.Email, // Will be sanitized if needed
		"service":   "user_service",
	})

	serviceLogger.Info(ctx, "Creating new user")

	// Simulate user creation
	user.ID = "user-new-789"

	serviceLogger.WithField("user_id", user.ID).Info(ctx, "User created successfully")

	return user, nil
}

// Example of custom user ID extractor for JWT
func JWTUserIDExtractor(c *gin.Context) string {
	// In a real implementation, you would:
	// 1. Extract JWT token from Authorization header
	// 2. Parse and validate the token
	// 3. Extract user ID from claims

	authHeader := c.GetHeader("Authorization")
	if authHeader != "" {
		// Simulate JWT parsing
		return "user-from-jwt-123"
	}

	return ""
}

// Example showing error sanitization in action
func errorSanitizationExample() {
	println("\n=== Error Sanitization Example ===")

	// Production logger with sanitization enabled
	prodLogger := logging.NewLogger(&logging.Config{
		Production: true,
		Service:    "api-service",
	})

	ctx := context.Background()

	// These errors will be automatically sanitized
	errors := []error{
		errors.New("database connection failed with password: mySecretPassword123"),
		errors.New("authentication failed for user user@example.com"),
		errors.New("JWT token validation failed: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."),
		errors.New("API key validation failed: sk_live_1234567890abcdef"),
	}

	for i, err := range errors {
		prodLogger.WithField("error_index", i).Error(ctx, "Sanitized error example", err)
	}

	println("Errors have been automatically sanitized for production safety")
}
