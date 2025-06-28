package http

import (
	"fmt"
	"net/http"

	"github.com/facuhernandez99/blog/pkg/models"
	"github.com/gin-gonic/gin"
)

// RespondWithSuccess sends a success response with data
func RespondWithSuccess(c *gin.Context, data interface{}) {
	c.JSON(http.StatusOK, models.APIResponse{
		Success: true,
		Data:    data,
	})
}

// RespondWithSuccessAndStatus sends a success response with custom status code
func RespondWithSuccessAndStatus(c *gin.Context, statusCode int, data interface{}) {
	c.JSON(statusCode, models.APIResponse{
		Success: true,
		Data:    data,
	})
}

// RespondWithCreated sends a 201 Created response
func RespondWithCreated(c *gin.Context, data interface{}) {
	c.JSON(http.StatusCreated, models.APIResponse{
		Success: true,
		Data:    data,
	})
}

// RespondWithNoContent sends a 204 No Content response
func RespondWithNoContent(c *gin.Context) {
	c.JSON(http.StatusNoContent, models.APIResponse{
		Success: true,
	})
}

// RespondWithPagination sends a paginated response
func RespondWithPagination(c *gin.Context, data interface{}, pagination models.Pagination) {
	response := models.PaginatedResponse{
		Data:       data,
		Pagination: pagination,
	}
	c.JSON(http.StatusOK, response)
}

// RespondWithError sends an error response
func RespondWithError(c *gin.Context, statusCode int, message string) {
	c.JSON(statusCode, models.APIResponse{
		Success: false,
		Error:   message,
	})
}

// RespondWithErrorAndData sends an error response with additional data
func RespondWithErrorAndData(c *gin.Context, statusCode int, message string, data interface{}) {
	c.JSON(statusCode, models.APIResponse{
		Success: false,
		Error:   message,
		Data:    data,
	})
}

// RespondWithValidationErrors sends a validation error response
func RespondWithValidationErrors(c *gin.Context, errors map[string]string) {
	c.JSON(http.StatusBadRequest, models.APIResponse{
		Success: false,
		Error:   "Validation failed",
		Data: map[string]interface{}{
			"validation_errors": errors,
		},
	})
}

// RespondWithBadRequest sends a 400 Bad Request response
func RespondWithBadRequest(c *gin.Context, message string) {
	RespondWithError(c, http.StatusBadRequest, message)
}

// RespondWithUnauthorized sends a 401 Unauthorized response
func RespondWithUnauthorized(c *gin.Context, message string) {
	if message == "" {
		message = "Unauthorized"
	}
	RespondWithError(c, http.StatusUnauthorized, message)
}

// RespondWithForbidden sends a 403 Forbidden response
func RespondWithForbidden(c *gin.Context, message string) {
	if message == "" {
		message = "Forbidden"
	}
	RespondWithError(c, http.StatusForbidden, message)
}

// RespondWithNotFound sends a 404 Not Found response
func RespondWithNotFound(c *gin.Context, message string) {
	if message == "" {
		message = "Resource not found"
	}
	RespondWithError(c, http.StatusNotFound, message)
}

// RespondWithConflict sends a 409 Conflict response
func RespondWithConflict(c *gin.Context, message string) {
	RespondWithError(c, http.StatusConflict, message)
}

// RespondWithInternalError sends a 500 Internal Server Error response
func RespondWithInternalError(c *gin.Context, message string) {
	if message == "" {
		message = "Internal server error"
	}
	RespondWithError(c, http.StatusInternalServerError, message)
}

// RespondWithHealthCheck sends a health check response
func RespondWithHealthCheck(c *gin.Context, health models.HealthCheck) {
	statusCode := http.StatusOK
	if health.Status != "healthy" {
		statusCode = http.StatusServiceUnavailable
	}

	c.JSON(statusCode, health)
}

// Helper functions for common response patterns

// GetPaginationFromQuery extracts pagination parameters from query string
func GetPaginationFromQuery(c *gin.Context) models.Pagination {
	page := getIntQueryParam(c, "page", 1)
	limit := getIntQueryParam(c, "limit", 20)

	// Set reasonable limits
	if page < 1 {
		page = 1
	}
	if limit < 1 {
		limit = 20
	}
	if limit > 100 {
		limit = 100
	}

	return models.Pagination{
		Page:  page,
		Limit: limit,
	}
}

// getIntQueryParam extracts integer parameter from query with default value
func getIntQueryParam(c *gin.Context, key string, defaultValue int) int {
	if value := c.Query(key); value != "" {
		if intValue := parseIntWithDefault(value, defaultValue); intValue > 0 {
			return intValue
		}
	}
	return defaultValue
}

// parseIntWithDefault parses string to int with fallback to default
func parseIntWithDefault(s string, defaultValue int) int {
	for _, char := range s {
		if char < '0' || char > '9' {
			return defaultValue
		}
	}

	result := 0
	for _, char := range s {
		result = result*10 + int(char-'0')
	}

	return result
}

// SetTotalCount updates pagination with total count and calculates total pages
func SetTotalCount(pagination *models.Pagination, totalCount int) {
	pagination.Total = totalCount
	if pagination.Limit > 0 {
		pagination.TotalPages = (totalCount + pagination.Limit - 1) / pagination.Limit
	}
}

// ValidateContentType checks if request has valid content type
func ValidateContentType(c *gin.Context, expectedType string) bool {
	contentType := c.GetHeader("Content-Type")
	return contentType == expectedType
}

// ValidateJSONContentType checks if request has JSON content type
func ValidateJSONContentType(c *gin.Context) bool {
	return ValidateContentType(c, "application/json")
}

// SetSecurityHeaders sets common security headers
func SetSecurityHeaders(c *gin.Context) {
	c.Header("X-Content-Type-Options", "nosniff")
	c.Header("X-Frame-Options", "DENY")
	c.Header("X-XSS-Protection", "1; mode=block")
	c.Header("Referrer-Policy", "strict-origin-when-cross-origin")
}

// AddCacheHeaders adds cache control headers
func AddCacheHeaders(c *gin.Context, maxAge int) {
	if maxAge > 0 {
		c.Header("Cache-Control", fmt.Sprintf("public, max-age=%d", maxAge))
	} else {
		c.Header("Cache-Control", "no-cache, no-store, must-revalidate")
		c.Header("Pragma", "no-cache")
		c.Header("Expires", "0")
	}
}

// AddNoCacheHeaders disables caching
func AddNoCacheHeaders(c *gin.Context) {
	AddCacheHeaders(c, 0)
}
