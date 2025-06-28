package auth

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/facuhernandez99/blog/pkg/models"
	"github.com/gin-gonic/gin"
)

// Context keys for storing user information
const (
	UserIDKey   = "user_id"
	UsernameKey = "username"
	ClaimsKey   = "claims"
)

// AuthMiddleware creates a middleware that requires valid JWT authentication.
func AuthMiddleware(jwtSecret string) gin.HandlerFunc {
	return gin.HandlerFunc(func(c *gin.Context) {
		token, err := extractToken(c)
		if err != nil {
			c.JSON(http.StatusUnauthorized, models.APIResponse{
				Success: false,
				Error:   "Authorization token required",
			})
			c.Abort()
			return
		}

		claims, err := ValidateJWT(token, jwtSecret)
		if err != nil {
			var statusCode int
			var message string

			switch err {
			case ErrTokenExpired:
				statusCode = http.StatusUnauthorized
				message = "Token has expired"
			case ErrTokenMalformed:
				statusCode = http.StatusBadRequest
				message = "Malformed token"
			case ErrInvalidSignature:
				statusCode = http.StatusUnauthorized
				message = "Invalid token signature"
			default:
				statusCode = http.StatusUnauthorized
				message = "Invalid token"
			}

			c.JSON(statusCode, models.APIResponse{
				Success: false,
				Error:   message,
			})
			c.Abort()
			return
		}

		// Set user information in context
		c.Set(UserIDKey, claims.UserID)
		c.Set(UsernameKey, claims.Username)
		c.Set(ClaimsKey, claims)

		c.Next()
	})
}

// OptionalAuthMiddleware creates a middleware that extracts JWT info if present but doesn't require it.
func OptionalAuthMiddleware(jwtSecret string) gin.HandlerFunc {
	return gin.HandlerFunc(func(c *gin.Context) {
		token, err := extractToken(c)
		if err != nil {
			// No token found, continue without authentication
			c.Next()
			return
		}

		claims, err := ValidateJWT(token, jwtSecret)
		if err != nil {
			// Invalid token, continue without authentication
			c.Next()
			return
		}

		// Set user information in context if token is valid
		c.Set(UserIDKey, claims.UserID)
		c.Set(UsernameKey, claims.Username)
		c.Set(ClaimsKey, claims)

		c.Next()
	})
}

// extractToken extracts the JWT token from the Authorization header.
func extractToken(c *gin.Context) (string, error) {
	authHeader := c.GetHeader("Authorization")
	if authHeader == "" {
		return "", ErrInvalidToken
	}

	// Check if it's a Bearer token
	tokenParts := strings.SplitN(authHeader, " ", 2)
	if len(tokenParts) != 2 || strings.ToLower(tokenParts[0]) != "bearer" {
		return "", ErrInvalidToken
	}

	return tokenParts[1], nil
}

// GetUserID extracts the user ID from the request context.
func GetUserID(c *gin.Context) (int64, bool) {
	if userID, exists := c.Get(UserIDKey); exists {
		if id, ok := userID.(int64); ok {
			return id, true
		}
	}
	return 0, false
}

// GetUsername extracts the username from the request context.
func GetUsername(c *gin.Context) (string, bool) {
	if username, exists := c.Get(UsernameKey); exists {
		if name, ok := username.(string); ok {
			return name, true
		}
	}
	return "", false
}

// GetClaims extracts the JWT claims from the request context.
func GetClaims(c *gin.Context) (*Claims, bool) {
	if claims, exists := c.Get(ClaimsKey); exists {
		if c, ok := claims.(*Claims); ok {
			return c, true
		}
	}
	return nil, false
}

// IsAuthenticated checks if the current request is authenticated.
func IsAuthenticated(c *gin.Context) bool {
	_, exists := GetUserID(c)
	return exists
}

// RequireUserID middleware ensures the authenticated user matches the requested user ID.
// Useful for protecting user-specific resources.
func RequireUserID(paramName string) gin.HandlerFunc {
	return gin.HandlerFunc(func(c *gin.Context) {
		// Get authenticated user ID
		userID, exists := GetUserID(c)
		if !exists {
			c.JSON(http.StatusUnauthorized, models.APIResponse{
				Success: false,
				Error:   "Authentication required",
			})
			c.Abort()
			return
		}

		// Get requested user ID from URL parameter
		requestedIDStr := c.Param(paramName)
		if requestedIDStr == "" {
			c.JSON(http.StatusBadRequest, models.APIResponse{
				Success: false,
				Error:   "User ID parameter required",
			})
			c.Abort()
			return
		}

		requestedID, err := strconv.ParseInt(requestedIDStr, 10, 64)
		if err != nil {
			c.JSON(http.StatusBadRequest, models.APIResponse{
				Success: false,
				Error:   "Invalid user ID format",
			})
			c.Abort()
			return
		}

		// Check if authenticated user matches requested user
		if userID != requestedID {
			c.JSON(http.StatusForbidden, models.APIResponse{
				Success: false,
				Error:   "Access denied: cannot access other user's resources",
			})
			c.Abort()
			return
		}

		c.Next()
	})
}

// CORSMiddleware adds CORS headers for cross-origin requests.
func CORSMiddleware() gin.HandlerFunc {
	return gin.HandlerFunc(func(c *gin.Context) {
		c.Header("Access-Control-Allow-Origin", "*")
		c.Header("Access-Control-Allow-Credentials", "true")
		c.Header("Access-Control-Allow-Headers", "Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization, accept, origin, Cache-Control, X-Requested-With")
		c.Header("Access-Control-Allow-Methods", "POST, OPTIONS, GET, PUT, DELETE")

		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(204)
			return
		}

		c.Next()
	})
}
