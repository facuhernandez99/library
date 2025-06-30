//go:build ignore
// +build ignore

package main

import (
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/facuhernandez99/library/pkg/errors"
	libraryhttp "github.com/facuhernandez99/library/pkg/http"
	"github.com/gin-gonic/gin"
)

// UserCreateRequest represents a user creation request
type UserCreateRequest struct {
	Username string `json:"username" validate:"required,min=3,max=50"`
	Email    string `json:"email" validate:"required,email"`
	Password string `json:"password" validate:"required"`
	Phone    string `json:"phone,omitempty" validate:"omitempty"`
}

// UserResponse represents a user response
type UserResponse struct {
	ID       int    `json:"id"`
	Username string `json:"username"`
	Email    string `json:"email"`
	Phone    string `json:"phone,omitempty"`
}

func main() {
	// Create Gin router
	router := gin.New()

	// Set up comprehensive middleware stack
	setupMiddleware(router)

	// Set up routes
	setupRoutes(router)

	// Start server
	router.Run(":8080")
}

// setupMiddleware configures all HTTP middleware
func setupMiddleware(router *gin.Engine) {
	// 1. Request ID middleware (should be first for correlation)
	router.Use(libraryhttp.RequestIDMiddleware())

	// 2. Security headers middleware
	router.Use(libraryhttp.SecurityHeadersMiddleware())

	// 3. CORS middleware with custom configuration
	corsConfig := &libraryhttp.CORSConfig{
		AllowOrigins: []string{
			"https://localhost:3000",
			"https://app.example.com",
			"*.example.com", // Wildcard subdomain support
		},
		AllowMethods: []string{"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"},
		AllowHeaders: []string{
			"Origin",
			"Content-Type",
			"Accept",
			"Authorization",
			"X-Requested-With",
			"X-Request-ID",
		},
		ExposeHeaders: []string{
			"X-Request-ID",
			"X-Rate-Limit-Limit",
			"X-Rate-Limit-Window",
		},
		AllowCredentials: true,
		MaxAge:           12 * time.Hour,
	}
	router.Use(libraryhttp.CORSMiddleware(corsConfig))

	// 4. Rate limiting middleware (100 requests per minute per IP)
	rateLimiter := libraryhttp.NewRateLimiter(100, time.Minute)
	router.Use(rateLimiter.RateLimitMiddleware())

	// 5. Request timeout middleware (30 seconds)
	router.Use(libraryhttp.TimeoutMiddleware(30 * time.Second))

	// 6. Validation middleware with custom config
	validationConfig := &libraryhttp.ValidationConfig{
		MaxStringLength: 2000,
		MaxFileSize:     20 * 1024 * 1024, // 20MB
		AllowedMimeTypes: []string{
			"application/json",
			"multipart/form-data",
			"application/x-www-form-urlencoded",
		},
	}
	router.Use(libraryhttp.ValidationMiddleware(validationConfig))

	// 7. Logging middleware (after request ID for correlation)
	router.Use(libraryhttp.LoggingMiddleware())

	// 8. Recovery middleware (should be last in the chain)
	router.Use(libraryhttp.RecoveryMiddleware())
}

// setupRoutes configures application routes
func setupRoutes(router *gin.Engine) {
	// Health check endpoint
	router.GET("/health", healthCheckHandler)

	// API routes group
	v1 := router.Group("/api/v1")
	{
		// User management routes
		users := v1.Group("/users")
		{
			users.POST("", createUserHandler)
			users.GET("/:id", getUserHandler)
			users.PUT("/:id", updateUserHandler)
			users.DELETE("/:id", deleteUserHandler)
		}

		// Authentication routes
		auth := v1.Group("/auth")
		{
			auth.POST("/login", loginHandler)
			auth.POST("/logout", logoutHandler)
			auth.POST("/refresh", refreshTokenHandler)
		}

		// Public routes (no authentication required)
		public := v1.Group("/public")
		{
			public.GET("/posts", listPostsHandler)
			public.GET("/posts/:slug", getPostBySlugHandler)
		}
	}
}

// healthCheckHandler handles health check requests
func healthCheckHandler(c *gin.Context) {
	libraryhttp.RespondWithSuccess(c, gin.H{
		"status":     "healthy",
		"request_id": libraryhttp.GetRequestID(c),
		"timestamp":  time.Now().UTC(),
	})
}

// createUserHandler demonstrates comprehensive input validation and sanitization
func createUserHandler(c *gin.Context) {
	var req UserCreateRequest

	// Bind and validate JSON request
	if err := c.ShouldBindJSON(&req); err != nil {
		errors.RespondWithValidationError(c, "Invalid request format")
		return
	}

	// Basic validation
	if req.Username == "" {
		errors.RespondWithValidationError(c, "Username is required")
		return
	}
	if req.Email == "" {
		errors.RespondWithValidationError(c, "Email is required")
		return
	}
	if req.Password == "" {
		errors.RespondWithValidationError(c, "Password is required")
		return
	}

	// Additional password strength validation (simplified)
	if len(req.Password) < 8 {
		errors.RespondWithValidationError(c, "Password must be at least 8 characters")
		return
	}

	// Simple sanitization
	req.Username = strings.TrimSpace(req.Username)
	req.Email = strings.TrimSpace(req.Email)
	if req.Phone != "" {
		req.Phone = strings.TrimSpace(req.Phone)
		// Basic phone validation
		if len(req.Phone) < 10 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid phone number format"})
			return
		}
	}

	// Business logic simulation
	user := UserResponse{
		ID:       123,
		Username: req.Username,
		Email:    req.Email,
		Phone:    req.Phone,
	}

	c.JSON(http.StatusCreated, gin.H{"data": user})
}

// getUserHandler demonstrates parameter validation
func getUserHandler(c *gin.Context) {
	userID := c.Param("id")

	// Validate user ID parameter
	if userID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "User ID is required"})
		return
	}

	// Simple numeric validation
	if _, err := strconv.Atoi(userID); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid user ID format"})
		return
	}

	// Business logic simulation
	user := UserResponse{
		ID:       123,
		Username: "johndoe",
		Email:    "john@example.com",
		Phone:    "+1234567890",
	}

	libraryhttp.RespondWithSuccess(c, user)
}

// updateUserHandler demonstrates partial update validation
func updateUserHandler(c *gin.Context) {
	userID := c.Param("id")

	// Validate user ID
	if userID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid user ID"})
		return
	}
	if _, err := strconv.Atoi(userID); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid user ID format"})
		return
	}

	// Parse raw JSON for partial updates
	var updateData map[string]interface{}
	if err := c.ShouldBindJSON(&updateData); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid JSON format"})
		return
	}

	// Basic validation for update fields
	if username, exists := updateData["username"]; exists {
		if usernameStr, ok := username.(string); !ok || usernameStr == "" {
			errors.RespondWithValidationError(c, "Invalid username")
			return
		}
	}

	if email, exists := updateData["email"]; exists {
		if emailStr, ok := email.(string); !ok || !strings.Contains(emailStr, "@") {
			errors.RespondWithValidationError(c, "Invalid email format")
			return
		}
	}

	// Additional validation for password if provided
	if password, exists := updateData["password"]; exists {
		if passwordStr, ok := password.(string); ok {
			if len(passwordStr) < 8 {
				errors.RespondWithValidationError(c, "Password must be at least 8 characters")
				return
			}
		}
	}

	// Business logic simulation
	user := UserResponse{
		ID:       123,
		Username: "johndoe_updated",
		Email:    "john.updated@example.com",
	}

	libraryhttp.RespondWithSuccess(c, user)
}

// deleteUserHandler demonstrates simple parameter validation
func deleteUserHandler(c *gin.Context) {
	userID := c.Param("id")

	if userID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid user ID"})
		return
	}
	if _, err := strconv.Atoi(userID); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid user ID format"})
		return
	}

	// Business logic simulation
	c.Status(http.StatusNoContent)
}

// loginHandler demonstrates authentication validation
func loginHandler(c *gin.Context) {
	type LoginRequest struct {
		Email    string `json:"email" validate:"required,email"`
		Password string `json:"password" validate:"required"`
	}

	var req LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		errors.RespondWithValidationError(c, "Invalid request format")
		return
	}

	// Basic validation
	if req.Email == "" || req.Password == "" {
		errors.RespondWithValidationError(c, "Email and password are required")
		return
	}

	// Sanitize inputs
	req.Email = strings.TrimSpace(req.Email)

	// Business logic simulation
	libraryhttp.RespondWithSuccess(c, gin.H{
		"token":      "jwt-token-here",
		"expires_at": time.Now().Add(24 * time.Hour),
		"user": UserResponse{
			ID:       123,
			Username: "johndoe",
			Email:    req.Email,
		},
	})
}

// logoutHandler demonstrates simple authenticated endpoints
func logoutHandler(c *gin.Context) {
	// In a real application, you would invalidate the token here
	libraryhttp.RespondWithSuccess(c, gin.H{
		"message": "Successfully logged out",
	})
}

// refreshTokenHandler demonstrates token refresh validation
func refreshTokenHandler(c *gin.Context) {
	type RefreshRequest struct {
		RefreshToken string `json:"refresh_token" validate:"required"`
	}

	var req RefreshRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		errors.RespondWithValidationError(c, "Invalid request format")
		return
	}

	if req.RefreshToken == "" {
		errors.RespondWithValidationError(c, "Refresh token is required")
		return
	}

	// Business logic simulation
	libraryhttp.RespondWithSuccess(c, gin.H{
		"access_token":  "new-jwt-token",
		"refresh_token": "new-refresh-token",
		"expires_at":    time.Now().Add(24 * time.Hour),
	})
}

// listPostsHandler demonstrates query parameter validation
func listPostsHandler(c *gin.Context) {
	// Get pagination parameters with basic validation
	page := 1
	limit := 10

	if pageStr := c.Query("page"); pageStr != "" {
		if p, err := strconv.Atoi(pageStr); err == nil && p > 0 {
			page = p
		}
	}

	if limitStr := c.Query("limit"); limitStr != "" {
		if l, err := strconv.Atoi(limitStr); err == nil && l > 0 && l <= 100 {
			limit = l
		}
	}

	// Additional query parameter validation
	category := strings.TrimSpace(c.Query("category"))
	search := strings.TrimSpace(c.Query("search"))

	if search != "" && len(search) > 100 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Search query must be between 1 and 100 characters"})
		return
	}

	// Business logic simulation
	posts := []gin.H{
		{
			"id":       1,
			"title":    "Sample Post 1",
			"slug":     "sample-post-1",
			"category": category,
		},
		{
			"id":       2,
			"title":    "Sample Post 2",
			"slug":     "sample-post-2",
			"category": category,
		},
	}

	// Response with pagination info
	c.JSON(http.StatusOK, gin.H{
		"data": posts,
		"pagination": gin.H{
			"page":        page,
			"limit":       limit,
			"total":       50,
			"total_pages": 5,
		},
	})
}

// getPostBySlugHandler demonstrates slug validation
func getPostBySlugHandler(c *gin.Context) {
	slug := c.Param("slug")

	// Validate slug format
	if slug == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Post slug is required"})
		return
	}

	// Basic slug validation (alphanumeric + hyphens)
	if !isValidSlug(slug) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid post slug format"})
		return
	}

	// Business logic simulation
	post := gin.H{
		"id":      1,
		"title":   "Sample Post",
		"slug":    slug,
		"content": "This is the post content...",
	}

	libraryhttp.RespondWithSuccess(c, post)
}

// Helper function for slug validation
func isValidSlug(slug string) bool {
	if len(slug) == 0 || len(slug) > 100 {
		return false
	}

	for _, char := range slug {
		if !((char >= 'a' && char <= 'z') || (char >= '0' && char <= '9') || char == '-') {
			return false
		}
	}
	return true
}

/*
Example usage with curl commands:

1. Health check:
curl -X GET http://localhost:8080/health

2. Create user with validation:
curl -X POST http://localhost:8080/api/v1/users \
  -H "Content-Type: application/json" \
  -d '{"username": "johndoe", "email": "john@example.com", "password": "StrongP@ssw0rd123", "phone": "+1234567890"}'

3. Create user with validation errors:
curl -X POST http://localhost:8080/api/v1/users \
  -H "Content-Type: application/json" \
  -d '{"username": "", "email": "invalid-email", "password": "weak"}'

4. Get user:
curl -X GET http://localhost:8080/api/v1/users/123

5. Update user:
curl -X PUT http://localhost:8080/api/v1/users/123 \
  -H "Content-Type: application/json" \
  -d '{"email": "newemail@example.com"}'

6. List posts with pagination:
curl -X GET "http://localhost:8080/api/v1/public/posts?page=1&limit=10&category=tech&search=golang"

7. Test rate limiting (run multiple times quickly):
for i in {1..10}; do curl -X GET http://localhost:8080/health; done

8. Test CORS preflight:
curl -X OPTIONS http://localhost:8080/api/v1/users \
  -H "Origin: https://app.example.com" \
  -H "Access-Control-Request-Method: POST" \
  -H "Access-Control-Request-Headers: Content-Type"
*/
