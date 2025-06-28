package main

import (
	"net/http"
	"time"

	bloghttp "github.com/facuhernandez99/blog/pkg/http"
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
	router.Use(bloghttp.RequestIDMiddleware())

	// 2. Security headers middleware
	router.Use(bloghttp.SecurityHeadersMiddleware())

	// 3. CORS middleware with custom configuration
	corsConfig := &bloghttp.CORSConfig{
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
	router.Use(bloghttp.CORSMiddleware(corsConfig))

	// 4. Rate limiting middleware (100 requests per minute per IP)
	rateLimiter := bloghttp.NewRateLimiter(100, time.Minute)
	router.Use(rateLimiter.RateLimitMiddleware())

	// 5. Request timeout middleware (30 seconds)
	router.Use(bloghttp.TimeoutMiddleware(30 * time.Second))

	// 6. Validation middleware with custom config
	validationConfig := &bloghttp.ValidationConfig{
		MaxStringLength: 2000,
		MaxFileSize:     20 * 1024 * 1024, // 20MB
		AllowedMimeTypes: []string{
			"application/json",
			"multipart/form-data",
			"application/x-www-form-urlencoded",
		},
	}
	router.Use(bloghttp.ValidationMiddleware(validationConfig))

	// 7. Logging middleware (after request ID for correlation)
	router.Use(bloghttp.LoggingMiddleware())

	// 8. Recovery middleware (should be last in the chain)
	router.Use(bloghttp.RecoveryMiddleware())
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
	bloghttp.RespondWithSuccess(c, gin.H{
		"status":     "healthy",
		"request_id": bloghttp.GetRequestID(c),
		"timestamp":  time.Now().UTC(),
	})
}

// createUserHandler demonstrates comprehensive input validation and sanitization
func createUserHandler(c *gin.Context) {
	var req UserCreateRequest

	// Bind and validate JSON request
	if errors := http.BindAndValidate(c, &req); errors.HasErrors() {
		http.RespondWithValidationErrors(c, convertValidationErrors(errors))
		return
	}

	// Additional password strength validation
	if passwordErrors := http.ValidatePasswordStrength(req.Password); passwordErrors.HasErrors() {
		http.RespondWithValidationErrors(c, convertValidationErrors(passwordErrors))
		return
	}

	// Sanitize input data
	req.Username = http.SanitizeString(req.Username)
	req.Email = http.SanitizeString(req.Email)
	if req.Phone != "" {
		req.Phone = http.SanitizeString(req.Phone)
		if !http.ValidatePhone(req.Phone) {
			http.RespondWithBadRequest(c, "Invalid phone number format")
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

	http.RespondWithCreated(c, user)
}

// getUserHandler demonstrates parameter validation
func getUserHandler(c *gin.Context) {
	userID := c.Param("id")

	// Validate user ID parameter
	if !http.ValidateRequired(userID) {
		http.RespondWithBadRequest(c, "User ID is required")
		return
	}

	if !http.ValidateAlphanumeric(userID) {
		http.RespondWithBadRequest(c, "Invalid user ID format")
		return
	}

	// Business logic simulation
	user := UserResponse{
		ID:       123,
		Username: "johndoe",
		Email:    "john@example.com",
		Phone:    "+1234567890",
	}

	http.RespondWithSuccess(c, user)
}

// updateUserHandler demonstrates partial update validation
func updateUserHandler(c *gin.Context) {
	userID := c.Param("id")

	// Validate user ID
	if !http.ValidateRequired(userID) || !http.ValidateAlphanumeric(userID) {
		http.RespondWithBadRequest(c, "Invalid user ID")
		return
	}

	// Parse raw JSON for partial updates
	var updateData map[string]interface{}
	if err := c.ShouldBindJSON(&updateData); err != nil {
		http.RespondWithBadRequest(c, "Invalid JSON format")
		return
	}

	// Define validation rules for update fields
	validationRules := map[string][]string{
		"username": {"alphanumeric"},
		"email":    {"email"},
		"phone":    {"phone"},
	}

	// Sanitize and validate input
	sanitizedData, errors := http.SanitizeAndValidateInput(updateData, validationRules)
	if errors.HasErrors() {
		http.RespondWithValidationErrors(c, convertValidationErrors(errors))
		return
	}

	// Additional validation for password if provided
	if password, exists := (*sanitizedData)["password"]; exists {
		if passwordStr, ok := password.(string); ok {
			if passwordErrors := http.ValidatePasswordStrength(passwordStr); passwordErrors.HasErrors() {
				http.RespondWithValidationErrors(c, convertValidationErrors(passwordErrors))
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

	http.RespondWithSuccess(c, user)
}

// deleteUserHandler demonstrates simple parameter validation
func deleteUserHandler(c *gin.Context) {
	userID := c.Param("id")

	if !http.ValidateRequired(userID) || !http.ValidateAlphanumeric(userID) {
		http.RespondWithBadRequest(c, "Invalid user ID")
		return
	}

	// Business logic simulation
	http.RespondWithNoContent(c)
}

// loginHandler demonstrates authentication validation
func loginHandler(c *gin.Context) {
	type LoginRequest struct {
		Email    string `json:"email" validate:"required,email"`
		Password string `json:"password" validate:"required"`
	}

	var req LoginRequest
	if errors := http.BindAndValidate(c, &req); errors.HasErrors() {
		http.RespondWithValidationErrors(c, convertValidationErrors(errors))
		return
	}

	// Sanitize inputs
	req.Email = http.SanitizeString(req.Email)

	// Business logic simulation
	http.RespondWithSuccess(c, gin.H{
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
	http.RespondWithSuccess(c, gin.H{
		"message": "Successfully logged out",
	})
}

// refreshTokenHandler demonstrates token refresh validation
func refreshTokenHandler(c *gin.Context) {
	type RefreshRequest struct {
		RefreshToken string `json:"refresh_token" validate:"required"`
	}

	var req RefreshRequest
	if errors := http.BindAndValidate(c, &req); errors.HasErrors() {
		http.RespondWithValidationErrors(c, convertValidationErrors(errors))
		return
	}

	// Business logic simulation
	http.RespondWithSuccess(c, gin.H{
		"access_token":  "new-jwt-token",
		"refresh_token": "new-refresh-token",
		"expires_at":    time.Now().Add(24 * time.Hour),
	})
}

// listPostsHandler demonstrates query parameter validation
func listPostsHandler(c *gin.Context) {
	// Get pagination parameters with validation
	pagination := http.GetPaginationFromQuery(c)

	// Additional query parameter validation
	category := http.SanitizeString(c.Query("category"))
	if category != "" && !http.ValidateSlug(category) {
		http.RespondWithBadRequest(c, "Invalid category format")
		return
	}

	search := http.SanitizeString(c.Query("search"))
	if search != "" && !http.ValidateStringLength(search, 1, 100) {
		http.RespondWithBadRequest(c, "Search query must be between 1 and 100 characters")
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

	// Set total count for pagination
	http.SetTotalCount(&pagination, 50)

	http.RespondWithPagination(c, posts, pagination)
}

// getPostBySlugHandler demonstrates slug validation
func getPostBySlugHandler(c *gin.Context) {
	slug := c.Param("slug")

	// Validate slug format
	if !http.ValidateRequired(slug) {
		http.RespondWithBadRequest(c, "Post slug is required")
		return
	}

	if !http.ValidateSlug(slug) {
		http.RespondWithBadRequest(c, "Invalid post slug format")
		return
	}

	// Business logic simulation
	post := gin.H{
		"id":      1,
		"title":   "Sample Post",
		"slug":    slug,
		"content": "This is the post content...",
	}

	http.RespondWithSuccess(c, post)
}

// convertValidationErrors converts ValidationErrors to the format expected by RespondWithValidationErrors
func convertValidationErrors(errors *http.ValidationErrors) map[string]string {
	errorMap := make(map[string]string)
	for _, err := range errors.Errors {
		errorMap[err.Field] = err.Message
	}
	return errorMap
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
