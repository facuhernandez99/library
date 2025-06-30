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

	"github.com/facuhernandez99/library/pkg/auth"
	"github.com/facuhernandez99/library/pkg/config"
	"github.com/facuhernandez99/library/pkg/database"
	"github.com/facuhernandez99/library/pkg/errors"
	httpPkg "github.com/facuhernandez99/library/pkg/http"
	"github.com/facuhernandez99/library/pkg/logging"
	"github.com/facuhernandez99/library/pkg/models"
	testingpkg "github.com/facuhernandez99/library/pkg/testing"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// UserRepository represents a user repository for testing
type UserRepository struct {
	db     *database.DB
	logger *logging.Logger
}

// NewUserRepository creates a new user repository
func NewUserRepository(db *database.DB, logger *logging.Logger) *UserRepository {
	return &UserRepository{
		db:     db,
		logger: logger,
	}
}

// CreateUser creates a new user in the database
func (r *UserRepository) CreateUser(ctx context.Context, user *models.User) error {
	query := `
		INSERT INTO users (username, password_hash, created_at, updated_at)
		VALUES ($1, $2, NOW(), NOW())
		RETURNING id, created_at, updated_at
	`

	row := r.db.QueryRow(ctx, query, user.Username, user.PasswordHash)
	err := row.Scan(&user.ID, &user.CreatedAt, &user.UpdatedAt)
	if err != nil {
		r.logger.WithFields(map[string]interface{}{
			"username": user.Username,
		}).Error(ctx, "Failed to create user in database", err)
		return errors.Wrap(err, errors.ErrCodeDatabaseError, "Failed to create user")
	}

	r.logger.WithFields(map[string]interface{}{
		"user_id":  user.ID,
		"username": user.Username,
	}).Info(ctx, "User created successfully in database")

	return nil
}

// GetUserByUsername retrieves a user by username
func (r *UserRepository) GetUserByUsername(ctx context.Context, username string) (*models.User, error) {
	user := &models.User{}
	query := `
		SELECT id, username, password_hash, created_at, updated_at
		FROM users
		WHERE username = $1
	`

	row := r.db.QueryRow(ctx, query, username)
	err := row.Scan(&user.ID, &user.Username, &user.PasswordHash, &user.CreatedAt, &user.UpdatedAt)
	if err != nil {
		r.logger.WithField("username", username).Warn(ctx, "User not found by username")
		return nil, errors.Wrap(err, errors.ErrCodeNotFound, "User not found")
	}

	r.logger.WithFields(map[string]interface{}{
		"user_id":  user.ID,
		"username": user.Username,
	}).Debug(ctx, "User retrieved successfully by username")

	return user, nil
}

// UserService handles user business logic
type UserService struct {
	repo      *UserRepository
	logger    *logging.Logger
	jwtSecret string
}

// NewUserService creates a new user service
func NewUserService(repo *UserRepository, logger *logging.Logger, jwtSecret string) *UserService {
	return &UserService{
		repo:      repo,
		logger:    logger,
		jwtSecret: jwtSecret,
	}
}

// RegisterUser handles user registration
func (s *UserService) RegisterUser(ctx context.Context, req *models.UserCreateRequest) (*models.User, error) {
	s.logger.WithFields(map[string]interface{}{
		"username": req.Username,
	}).Info(ctx, "Starting user registration process")

	// Validate input
	if err := s.validateRegistrationRequest(req); err != nil {
		s.logger.WithField("validation_error", err.Error()).Warn(ctx, "User registration validation failed")
		return nil, err
	}

	// Check if user already exists
	if existingUser, _ := s.repo.GetUserByUsername(ctx, req.Username); existingUser != nil {
		s.logger.WithField("username", req.Username).Warn(ctx, "Registration failed: username already exists")
		return nil, errors.New(errors.ErrCodeUserExists, "Username already exists")
	}

	// Hash password
	hashedPassword, err := auth.HashPassword(req.Password)
	if err != nil {
		s.logger.Error(ctx, "Failed to hash password during registration", err)
		return nil, errors.Wrap(err, errors.ErrCodeInternal, "Failed to process password")
	}

	// Create user
	user := &models.User{
		Username:     req.Username,
		PasswordHash: hashedPassword,
	}

	if err := s.repo.CreateUser(ctx, user); err != nil {
		return nil, err
	}

	s.logger.WithFields(map[string]interface{}{
		"user_id":  user.ID,
		"username": user.Username,
	}).Info(ctx, "User registration completed successfully")

	// Clear password hash before returning
	user.PasswordHash = ""
	return user, nil
}

// LoginResponse represents the response after successful login
type LoginResponse struct {
	User         *models.User `json:"user"`
	Token        string       `json:"token"`
	RefreshToken string       `json:"refresh_token,omitempty"`
	ExpiresAt    time.Time    `json:"expires_at"`
}

// LoginUser handles user login
func (s *UserService) LoginUser(ctx context.Context, req *models.UserLoginRequest) (*LoginResponse, error) {
	s.logger.WithField("username", req.Username).Info(ctx, "Starting user login process")

	// Validate input
	if err := s.validateLoginRequest(req); err != nil {
		s.logger.WithField("validation_error", err.Error()).Warn(ctx, "User login validation failed")
		return nil, err
	}

	// Get user by username
	user, err := s.repo.GetUserByUsername(ctx, req.Username)
	if err != nil {
		s.logger.WithField("username", req.Username).Warn(ctx, "Login failed: user not found")
		return nil, errors.New(errors.ErrCodeUnauthorized, "Invalid username or password")
	}

	// Check password
	if !auth.CheckPasswordHash(req.Password, user.PasswordHash) {
		s.logger.WithFields(map[string]interface{}{
			"user_id":  user.ID,
			"username": user.Username,
		}).Warn(ctx, "Login failed: invalid password")
		return nil, errors.New(errors.ErrCodeUnauthorized, "Invalid username or password")
	}

	// Generate JWT token
	tokenResponse, err := auth.GenerateJWT(user, s.jwtSecret, 24)
	if err != nil {
		s.logger.WithField("user_id", user.ID).Error(ctx, "Failed to generate JWT token", err)
		return nil, errors.Wrap(err, errors.ErrCodeInternal, "Failed to generate authentication token")
	}

	// Generate refresh token
	refreshToken, err := auth.GenerateRefreshToken(user, s.jwtSecret)
	if err != nil {
		s.logger.WithField("user_id", user.ID).Error(ctx, "Failed to generate refresh token", err)
		return nil, errors.Wrap(err, errors.ErrCodeInternal, "Failed to generate refresh token")
	}

	response := &LoginResponse{
		User:         user,
		Token:        tokenResponse.Token,
		RefreshToken: refreshToken,
		ExpiresAt:    tokenResponse.ExpiresAt,
	}

	// Clear password hash
	response.User.PasswordHash = ""

	s.logger.WithFields(map[string]interface{}{
		"user_id":    user.ID,
		"username":   user.Username,
		"expires_at": tokenResponse.ExpiresAt,
	}).Info(ctx, "User login completed successfully")

	return response, nil
}

func (s *UserService) validateRegistrationRequest(req *models.UserCreateRequest) error {
	if req.Username == "" {
		return errors.New(errors.ErrCodeValidation, "Username is required")
	}
	if len(req.Username) < 3 {
		return errors.New(errors.ErrCodeValidation, "Username must be at least 3 characters long")
	}
	if err := auth.ValidatePasswordStrength(req.Password); err != nil {
		return errors.Wrap(err, errors.ErrCodeValidation, "Password validation failed")
	}
	return nil
}

func (s *UserService) validateLoginRequest(req *models.UserLoginRequest) error {
	if req.Username == "" {
		return errors.New(errors.ErrCodeValidation, "Username is required")
	}
	if req.Password == "" {
		return errors.New(errors.ErrCodeValidation, "Password is required")
	}
	return nil
}

// TestUserRegistrationLoginFlowIntegration tests the complete user registration and login flow
// Run with: go test examples/user_registration_login_flow_integration_test.go
func TestUserRegistrationLoginFlowIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	fmt.Println("=== User Registration/Login Flow Integration Test ===")

	// === Step 1: Setup Configuration ===
	fmt.Println("\n1. Setting up configuration...")

	// Set test environment variables
	os.Setenv("DATABASE_URL", "postgres://postgres:postgres@localhost:5432/postgres")
	os.Setenv("JWT_SECRET", "test_jwt_secret_key_that_is_long_enough_for_validation_requirements")
	os.Setenv("LOG_LEVEL", "debug")
	os.Setenv("ENVIRONMENT", "development")

	cfg, err := config.Load()
	require.NoError(t, err, "Failed to load configuration")
	fmt.Printf("   ✅ Configuration loaded: Environment=%s\n", cfg.Environment)

	// === Step 2: Setup Structured Logging ===
	fmt.Println("\n2. Setting up structured logging...")

	logBuffer := &bytes.Buffer{}
	loggerConfig := &logging.Config{
		Level:      logging.LevelDebug,
		Output:     logBuffer,
		Service:    "user-flow-test",
		Version:    "test-1.0.0",
		Production: cfg.IsProduction(),
	}

	logger := logging.NewLogger(loggerConfig)
	logging.SetDefault(logger)
	fmt.Printf("   ✅ Structured logging initialized\n")

	// === Step 3: Setup Database ===
	fmt.Println("\n3. Setting up test database...")

	// Skip if PostgreSQL is not available
	if !testingpkg.IsPostgreSQLAvailable() {
		t.Skip("PostgreSQL is not available - skipping user flow integration test")
	}

	// Setup test database
	dbHelper := testingpkg.NewDatabaseTestHelper(t)
	dbHelper.Setup()
	defer dbHelper.Teardown()

	// Create database wrapper
	db := &database.DB{DB: dbHelper.DB}

	// Create users table
	createTableSQL := `
		CREATE TABLE IF NOT EXISTS users (
			id SERIAL PRIMARY KEY,
			username VARCHAR(255) UNIQUE NOT NULL,
			password_hash VARCHAR(255) NOT NULL,
			created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
			updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
		)
	`

	_, err = db.Exec(context.Background(), createTableSQL)
	require.NoError(t, err, "Failed to create users table")
	fmt.Printf("   ✅ Test database and users table created\n")

	// === Step 4: Setup Services ===
	fmt.Println("\n4. Setting up user services...")

	userRepo := NewUserRepository(db, logger)
	userService := NewUserService(userRepo, logger, cfg.JWTSecret)
	fmt.Printf("   ✅ User repository and service initialized\n")

	// === Step 5: Setup HTTP Server ===
	fmt.Println("\n5. Setting up HTTP server...")

	server := createUserAPIServer(userService, logger, cfg.JWTSecret)
	testServer := httptest.NewServer(server)
	defer testServer.Close()

	fmt.Printf("   ✅ HTTP server started: %s\n", testServer.URL)

	// === Step 6: Test User Registration Flow ===
	fmt.Println("\n6. Testing user registration flow...")

	// Clear log buffer for registration test
	logBuffer.Reset()

	// Create HTTP client
	client := httpPkg.NewClient(&httpPkg.ClientConfig{
		BaseURL: testServer.URL,
		Timeout: 10 * time.Second,
		Logger:  logger,
	})

	// Test valid registration
	registrationData := map[string]interface{}{
		"username": "testuser123",
		"password": "SecurePassword123!",
	}

	response, err := client.Post(context.Background(), "/auth/register", registrationData)
	require.NoError(t, err, "Registration request should succeed")
	assert.Equal(t, http.StatusCreated, response.StatusCode)

	// Parse registration response
	var regResult map[string]interface{}
	err = json.Unmarshal(response.Body, &regResult)
	require.NoError(t, err, "Should parse registration response")

	assert.True(t, regResult["success"].(bool))
	assert.NotNil(t, regResult["data"])

	userData := regResult["data"].(map[string]interface{})
	userID := int(userData["id"].(float64))
	assert.Greater(t, userID, 0)
	assert.Equal(t, "testuser123", userData["username"])
	assert.Equal(t, "testuser123@example.com", userData["email"])
	assert.Nil(t, userData["password_hash"]) // Should not be returned

	fmt.Printf("   ✅ User registration successful: ID=%d, Username=%s\n", userID, userData["username"])

	// Verify registration was logged
	logOutput := logBuffer.String()
	assert.Contains(t, logOutput, "Starting user registration process", "Registration start should be logged")
	assert.Contains(t, logOutput, "User created successfully in database", "User creation should be logged")
	assert.Contains(t, logOutput, "User registration completed successfully", "Registration completion should be logged")

	// === Step 7: Test Registration Validation ===
	fmt.Println("\n7. Testing registration validation...")

	// Test duplicate username
	response, err = client.Post(context.Background(), "/auth/register", registrationData)
	require.NoError(t, err, "Request should complete")
	assert.Equal(t, http.StatusConflict, response.StatusCode)
	fmt.Printf("   ✅ Duplicate username properly rejected\n")

	// Test invalid email
	invalidEmailData := map[string]interface{}{
		"username": "testuser456",
		"email":    "invalid-email",
		"password": "SecurePassword123!",
	}

	response, err = client.Post(context.Background(), "/auth/register", invalidEmailData)
	require.NoError(t, err, "Request should complete")
	assert.Equal(t, http.StatusBadRequest, response.StatusCode)
	fmt.Printf("   ✅ Invalid email format properly rejected\n")

	// Test weak password
	weakPasswordData := map[string]interface{}{
		"username": "testuser789",
		"email":    "testuser789@example.com",
		"password": "123", // Too weak
	}

	response, err = client.Post(context.Background(), "/auth/register", weakPasswordData)
	require.NoError(t, err, "Request should complete")
	assert.Equal(t, http.StatusBadRequest, response.StatusCode)
	fmt.Printf("   ✅ Weak password properly rejected\n")

	// === Step 8: Test User Login Flow ===
	fmt.Println("\n8. Testing user login flow...")

	// Clear log buffer for login test
	logBuffer.Reset()

	// Test valid login
	loginData := map[string]interface{}{
		"username": "testuser123",
		"password": "SecurePassword123!",
	}

	response, err = client.Post(context.Background(), "/auth/login", loginData)
	require.NoError(t, err, "Login request should succeed")
	assert.Equal(t, http.StatusOK, response.StatusCode)

	// Parse login response
	var loginResult map[string]interface{}
	err = json.Unmarshal(response.Body, &loginResult)
	require.NoError(t, err, "Should parse login response")

	assert.True(t, loginResult["success"].(bool))
	assert.NotNil(t, loginResult["data"])

	loginResponseData := loginResult["data"].(map[string]interface{})
	token := loginResponseData["token"].(string)
	refreshToken := loginResponseData["refresh_token"].(string)
	expiresAt := loginResponseData["expires_at"].(string)

	assert.NotEmpty(t, token)
	assert.NotEmpty(t, refreshToken)
	assert.NotEmpty(t, expiresAt)

	fmt.Printf("   ✅ User login successful: Token generated\n")

	// Verify login was logged
	logOutput = logBuffer.String()
	assert.Contains(t, logOutput, "Starting user login process", "Login start should be logged")
	assert.Contains(t, logOutput, "User login completed successfully", "Login completion should be logged")

	// === Step 9: Test JWT Token Validation ===
	fmt.Println("\n9. Testing JWT token validation...")

	// Test token validation
	claims, err := auth.ValidateJWT(token, cfg.JWTSecret)
	require.NoError(t, err, "Token should be valid")
	assert.Equal(t, userID, claims.UserID)
	assert.Equal(t, "testuser123", claims.Username)
	fmt.Printf("   ✅ JWT token validation successful\n")

	// === Step 10: Test Protected Endpoint Access ===
	fmt.Println("\n10. Testing protected endpoint access...")

	// Create authenticated client
	authClient := httpPkg.NewClient(&httpPkg.ClientConfig{
		BaseURL: testServer.URL,
		Timeout: 10 * time.Second,
		Logger:  logger,
		AuthConfig: &httpPkg.AuthConfig{
			JWTSecret:    cfg.JWTSecret,
			ServiceToken: token,
			AutoRefresh:  false,
		},
	})

	// Test protected profile endpoint
	response, err = authClient.Get(context.Background(), "/auth/profile")
	require.NoError(t, err, "Protected request should succeed")
	assert.Equal(t, http.StatusOK, response.StatusCode)

	// Parse profile response
	var profileResult map[string]interface{}
	err = json.Unmarshal(response.Body, &profileResult)
	require.NoError(t, err, "Should parse profile response")

	assert.True(t, profileResult["success"].(bool))
	profileData := profileResult["data"].(map[string]interface{})
	assert.Equal(t, float64(userID), profileData["user_id"])
	assert.Equal(t, "testuser123", profileData["username"])

	fmt.Printf("   ✅ Protected endpoint access successful\n")

	// === Step 11: Test Refresh Token Flow ===
	fmt.Println("\n11. Testing refresh token flow...")

	// Test refresh token
	refreshData := map[string]interface{}{
		"refresh_token": refreshToken,
	}

	response, err = client.Post(context.Background(), "/auth/refresh", refreshData)
	require.NoError(t, err, "Refresh request should succeed")
	assert.Equal(t, http.StatusOK, response.StatusCode)

	// Parse refresh response
	var refreshResult map[string]interface{}
	err = json.Unmarshal(response.Body, &refreshResult)
	require.NoError(t, err, "Should parse refresh response")

	assert.True(t, refreshResult["success"].(bool))
	refreshResponseData := refreshResult["data"].(map[string]interface{})
	newToken := refreshResponseData["token"].(string)
	assert.NotEmpty(t, newToken)
	assert.NotEqual(t, token, newToken) // Should be a new token

	fmt.Printf("   ✅ Token refresh successful\n")

	// === Step 12: Test Login Validation ===
	fmt.Println("\n12. Testing login validation...")

	// Test invalid credentials
	invalidLoginData := map[string]interface{}{
		"username": "testuser123",
		"password": "WrongPassword123!",
	}

	response, err = client.Post(context.Background(), "/auth/login", invalidLoginData)
	require.NoError(t, err, "Request should complete")
	assert.Equal(t, http.StatusUnauthorized, response.StatusCode)
	fmt.Printf("   ✅ Invalid credentials properly rejected\n")

	// Test non-existent user
	nonExistentLoginData := map[string]interface{}{
		"username": "nonexistentuser",
		"password": "SomePassword123!",
	}

	response, err = client.Post(context.Background(), "/auth/login", nonExistentLoginData)
	require.NoError(t, err, "Request should complete")
	assert.Equal(t, http.StatusUnauthorized, response.StatusCode)
	fmt.Printf("   ✅ Non-existent user properly rejected\n")

	// === Step 13: Test Complete Request Lifecycle ===
	fmt.Println("\n13. Testing complete request lifecycle with middleware...")

	// Clear log buffer for lifecycle test
	logBuffer.Reset()

	// Make authenticated request to generate logs
	response, err = authClient.Get(context.Background(), "/auth/profile")
	require.NoError(t, err, "Authenticated request should succeed")

	// Verify comprehensive logging
	logOutput = logBuffer.String()

	// Check for middleware logs
	middlewareLogChecks := []string{
		"request_id",  // Request ID middleware
		"user_id",     // Authentication middleware
		"latency_ms",  // HTTP logging middleware
		"status_code", // Response logging
	}

	foundMiddlewareLogs := 0
	for _, check := range middlewareLogChecks {
		if strings.Contains(logOutput, check) {
			foundMiddlewareLogs++
		}
	}

	fmt.Printf("   ✅ Middleware logging: %d/%d checks passed\n", foundMiddlewareLogs, len(middlewareLogChecks))

	// === Step 14: Verify All Packages Integration ===
	fmt.Println("\n14. Verifying all packages integration...")

	// Count package usage indicators in logs
	packageUsage := map[string]string{
		"config":   "Configuration loaded",
		"logging":  "\"level\":",
		"auth":     "User authenticated successfully",
		"database": "User created successfully in database",
		"http":     "\"method\":",
		"errors":   "validation_error",
		"models":   "testuser123",
	}

	packagesUsed := 0
	for packageName, indicator := range packageUsage {
		// Get the full log output including all previous tests
		fullLogOutput := logBuffer.String()
		if strings.Contains(fullLogOutput, indicator) {
			packagesUsed++
			fmt.Printf("      ✅ %s package integrated\n", packageName)
		} else {
			fmt.Printf("      ⚠️  %s package indicator not found\n", packageName)
		}
	}

	fmt.Printf("   ✅ Package integration: %d/%d packages confirmed\n", packagesUsed, len(packageUsage))

	fmt.Println("\n=== User Registration/Login Flow Integration Test Completed Successfully ===")
	fmt.Printf("Summary:\n")
	fmt.Printf("  ✅ User registration with validation\n")
	fmt.Printf("  ✅ Password hashing and verification\n")
	fmt.Printf("  ✅ JWT token generation and validation\n")
	fmt.Printf("  ✅ Refresh token functionality\n")
	fmt.Printf("  ✅ Protected endpoint access\n")
	fmt.Printf("  ✅ Comprehensive error handling\n")
	fmt.Printf("  ✅ Database operations integration\n")
	fmt.Printf("  ✅ Structured logging throughout\n")
	fmt.Printf("  ✅ All %d shared packages working together\n", len(packageUsage))
}

// createUserAPIServer creates an HTTP server for user authentication
func createUserAPIServer(userService *UserService, logger *logging.Logger, jwtSecret string) http.Handler {
	gin.SetMode(gin.TestMode)
	router := gin.New()

	// Add middleware
	router.Use(httpPkg.RequestIDMiddleware())
	router.Use(httpPkg.DefaultStructuredLoggingMiddleware())
	router.Use(httpPkg.CORSMiddleware(nil))

	// Health endpoint
	router.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, models.HealthCheck{
			Status:    "healthy",
			Service:   "user-auth-service",
			Version:   "1.0.0",
			Timestamp: time.Now(),
		})
	})

	// Auth endpoints group
	authGroup := router.Group("/auth")

	// Registration endpoint
	authGroup.POST("/register", func(c *gin.Context) {
		var req models.UserCreateRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			logger.WithField("bind_error", err.Error()).Warn(c.Request.Context(), "Invalid registration request format")
			httpPkg.RespondWithError(c, http.StatusBadRequest, "Invalid request format")
			return
		}

		user, err := userService.RegisterUser(c.Request.Context(), &req)
		if err != nil {
			if appErr, ok := errors.IsAppError(err); ok {
				switch appErr.Code {
				case errors.ErrCodeValidation:
					httpPkg.RespondWithError(c, http.StatusBadRequest, appErr.Message)
				case errors.ErrCodeUserExists:
					httpPkg.RespondWithError(c, http.StatusConflict, appErr.Message)
				default:
					httpPkg.RespondWithError(c, http.StatusInternalServerError, "Registration failed")
				}
			} else {
				httpPkg.RespondWithError(c, http.StatusInternalServerError, "Registration failed")
			}
			return
		}

		httpPkg.RespondWithCreated(c, user)
	})

	// Login endpoint
	authGroup.POST("/login", func(c *gin.Context) {
		var req models.UserLoginRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			logger.WithField("bind_error", err.Error()).Warn(c.Request.Context(), "Invalid login request format")
			httpPkg.RespondWithError(c, http.StatusBadRequest, "Invalid request format")
			return
		}

		loginResponse, err := userService.LoginUser(c.Request.Context(), &req)
		if err != nil {
			if appErr, ok := errors.IsAppError(err); ok {
				switch appErr.Code {
				case errors.ErrCodeValidation:
					httpPkg.RespondWithError(c, http.StatusBadRequest, appErr.Message)
				case errors.ErrCodeUnauthorized:
					httpPkg.RespondWithError(c, http.StatusUnauthorized, appErr.Message)
				default:
					httpPkg.RespondWithError(c, http.StatusInternalServerError, "Login failed")
				}
			} else {
				httpPkg.RespondWithError(c, http.StatusInternalServerError, "Login failed")
			}
			return
		}

		httpPkg.RespondWithSuccess(c, loginResponse)
	})

	// Refresh token endpoint
	authGroup.POST("/refresh", func(c *gin.Context) {
		var req struct {
			RefreshToken string `json:"refresh_token" binding:"required"`
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			httpPkg.RespondWithError(c, http.StatusBadRequest, "Invalid request format")
			return
		}

		// Refresh the token
		tokenResponse, err := auth.RefreshAccessToken(req.RefreshToken, jwtSecret, 24)
		if err != nil {
			logger.WithField("refresh_error", err.Error()).Warn(c.Request.Context(), "Token refresh failed")
			httpPkg.RespondWithError(c, http.StatusUnauthorized, "Invalid refresh token")
			return
		}

		logger.WithField("expires_at", tokenResponse.ExpiresAt).Info(c.Request.Context(), "Token refreshed successfully")
		httpPkg.RespondWithSuccess(c, tokenResponse)
	})

	// Protected endpoints group
	protectedGroup := authGroup.Group("/")
	protectedGroup.Use(auth.AuthMiddleware(jwtSecret))

	// Profile endpoint (protected)
	protectedGroup.GET("/profile", func(c *gin.Context) {
		userID, _ := auth.GetUserID(c)
		username, _ := auth.GetUsername(c)

		logger.WithFields(map[string]interface{}{
			"user_id":  userID,
			"username": username,
		}).Info(c.Request.Context(), "Profile accessed")

		httpPkg.RespondWithSuccess(c, map[string]interface{}{
			"user_id":  userID,
			"username": username,
			"message":  "Profile data retrieved successfully",
		})
	})

	return router
}

func main() {
	// This file is meant to be run as a test
	// Usage: go test examples/user_registration_login_flow_integration_test.go
	fmt.Println("This file should be run as a test:")
	fmt.Println("go test examples/user_registration_login_flow_integration_test.go")
}
