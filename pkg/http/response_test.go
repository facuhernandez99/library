package http

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/facuhernandez99/blog/pkg/models"
	"github.com/gin-gonic/gin"
)

func init() {
	// Set Gin to test mode
	gin.SetMode(gin.TestMode)
}

func TestSuccessResponseHelpers(t *testing.T) {
	t.Run("RespondWithSuccess", func(t *testing.T) {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)

		testData := map[string]interface{}{
			"message": "test data",
			"id":      123,
		}

		RespondWithSuccess(c, testData)

		// Check status code
		if w.Code != http.StatusOK {
			t.Errorf("Expected status %d, got %d", http.StatusOK, w.Code)
		}

		// Check response structure
		var response models.APIResponse
		err := json.Unmarshal(w.Body.Bytes(), &response)
		if err != nil {
			t.Errorf("Failed to unmarshal response: %v", err)
			return
		}

		if !response.Success {
			t.Error("Expected success=true")
		}

		if response.Error != "" {
			t.Errorf("Expected empty error, got %s", response.Error)
		}

		if response.Data == nil {
			t.Error("Expected data to be present")
		}
	})

	t.Run("RespondWithSuccessAndStatus", func(t *testing.T) {
		tests := []struct {
			name       string
			statusCode int
			data       interface{}
		}{
			{
				name:       "status_202",
				statusCode: http.StatusAccepted,
				data:       "accepted",
			},
			{
				name:       "status_201",
				statusCode: http.StatusCreated,
				data:       map[string]string{"id": "created"},
			},
			{
				name:       "status_200_with_nil_data",
				statusCode: http.StatusOK,
				data:       nil,
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				w := httptest.NewRecorder()
				c, _ := gin.CreateTestContext(w)

				RespondWithSuccessAndStatus(c, tt.statusCode, tt.data)

				if w.Code != tt.statusCode {
					t.Errorf("Expected status %d, got %d", tt.statusCode, w.Code)
				}

				var response models.APIResponse
				err := json.Unmarshal(w.Body.Bytes(), &response)
				if err != nil {
					t.Errorf("Failed to unmarshal response: %v", err)
					return
				}

				if !response.Success {
					t.Error("Expected success=true")
				}
			})
		}
	})

	t.Run("RespondWithCreated", func(t *testing.T) {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)

		createdData := map[string]interface{}{
			"id":   1,
			"name": "new resource",
		}

		RespondWithCreated(c, createdData)

		if w.Code != http.StatusCreated {
			t.Errorf("Expected status %d, got %d", http.StatusCreated, w.Code)
		}

		var response models.APIResponse
		err := json.Unmarshal(w.Body.Bytes(), &response)
		if err != nil {
			t.Errorf("Failed to unmarshal response: %v", err)
			return
		}

		if !response.Success {
			t.Error("Expected success=true")
		}

		if response.Data == nil {
			t.Error("Expected data to be present")
		}
	})

	t.Run("RespondWithNoContent", func(t *testing.T) {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)

		RespondWithNoContent(c)

		if w.Code != http.StatusNoContent {
			t.Errorf("Expected status %d, got %d", http.StatusNoContent, w.Code)
		}

		// For 204 No Content, Gin doesn't send a body, so we should check that the body is empty
		if w.Body.Len() != 0 {
			t.Errorf("Expected empty body for 204 No Content, got %d bytes", w.Body.Len())
		}
	})

	t.Run("RespondWithPagination", func(t *testing.T) {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)

		testData := []map[string]interface{}{
			{"id": 1, "name": "item1"},
			{"id": 2, "name": "item2"},
		}

		pagination := models.Pagination{
			Page:       1,
			Limit:      20,
			Total:      50,
			TotalPages: 3,
		}

		RespondWithPagination(c, testData, pagination)

		if w.Code != http.StatusOK {
			t.Errorf("Expected status %d, got %d", http.StatusOK, w.Code)
		}

		var response models.PaginatedResponse
		err := json.Unmarshal(w.Body.Bytes(), &response)
		if err != nil {
			t.Errorf("Failed to unmarshal response: %v", err)
			return
		}

		if response.Data == nil {
			t.Error("Expected data to be present")
		}

		if response.Pagination.Page != pagination.Page {
			t.Errorf("Expected page %d, got %d", pagination.Page, response.Pagination.Page)
		}

		if response.Pagination.Total != pagination.Total {
			t.Errorf("Expected total %d, got %d", pagination.Total, response.Pagination.Total)
		}
	})
}

func TestErrorResponseHelpers(t *testing.T) {
	t.Run("RespondWithError", func(t *testing.T) {
		tests := []struct {
			name       string
			statusCode int
			message    string
		}{
			{
				name:       "bad_request",
				statusCode: http.StatusBadRequest,
				message:    "Invalid input",
			},
			{
				name:       "internal_error",
				statusCode: http.StatusInternalServerError,
				message:    "Something went wrong",
			},
			{
				name:       "empty_message",
				statusCode: http.StatusBadRequest,
				message:    "",
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				w := httptest.NewRecorder()
				c, _ := gin.CreateTestContext(w)

				RespondWithError(c, tt.statusCode, tt.message)

				if w.Code != tt.statusCode {
					t.Errorf("Expected status %d, got %d", tt.statusCode, w.Code)
				}

				var response models.APIResponse
				err := json.Unmarshal(w.Body.Bytes(), &response)
				if err != nil {
					t.Errorf("Failed to unmarshal response: %v", err)
					return
				}

				if response.Success {
					t.Error("Expected success=false")
				}

				if response.Error != tt.message {
					t.Errorf("Expected error message %s, got %s", tt.message, response.Error)
				}
			})
		}
	})

	t.Run("RespondWithErrorAndData", func(t *testing.T) {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)

		errorData := map[string]interface{}{
			"field": "username",
			"issue": "already exists",
		}

		RespondWithErrorAndData(c, http.StatusConflict, "User already exists", errorData)

		if w.Code != http.StatusConflict {
			t.Errorf("Expected status %d, got %d", http.StatusConflict, w.Code)
		}

		var response models.APIResponse
		err := json.Unmarshal(w.Body.Bytes(), &response)
		if err != nil {
			t.Errorf("Failed to unmarshal response: %v", err)
			return
		}

		if response.Success {
			t.Error("Expected success=false")
		}

		if response.Error != "User already exists" {
			t.Errorf("Expected error message 'User already exists', got %s", response.Error)
		}

		if response.Data == nil {
			t.Error("Expected data to be present")
		}
	})

	t.Run("RespondWithValidationErrors", func(t *testing.T) {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)

		validationErrors := map[string]string{
			"username": "Username is required",
			"email":    "Invalid email format",
			"password": "Password too weak",
		}

		RespondWithValidationErrors(c, validationErrors)

		if w.Code != http.StatusBadRequest {
			t.Errorf("Expected status %d, got %d", http.StatusBadRequest, w.Code)
		}

		var response models.APIResponse
		err := json.Unmarshal(w.Body.Bytes(), &response)
		if err != nil {
			t.Errorf("Failed to unmarshal response: %v", err)
			return
		}

		if response.Success {
			t.Error("Expected success=false")
		}

		if response.Error != "Validation failed" {
			t.Errorf("Expected error message 'Validation failed', got %s", response.Error)
		}

		// Check that validation errors are in data
		data, ok := response.Data.(map[string]interface{})
		if !ok {
			t.Error("Expected data to be a map")
			return
		}

		if data["validation_errors"] == nil {
			t.Error("Expected validation_errors in data")
		}
	})

	t.Run("SpecificErrorResponses", func(t *testing.T) {
		tests := []struct {
			name           string
			function       func(*gin.Context, string)
			expectedStatus int
			message        string
			expectedMsg    string
		}{
			{
				name:           "RespondWithBadRequest",
				function:       RespondWithBadRequest,
				expectedStatus: http.StatusBadRequest,
				message:        "Invalid request",
				expectedMsg:    "Invalid request",
			},
			{
				name:           "RespondWithUnauthorized_with_message",
				function:       RespondWithUnauthorized,
				expectedStatus: http.StatusUnauthorized,
				message:        "Invalid token",
				expectedMsg:    "Invalid token",
			},
			{
				name:           "RespondWithUnauthorized_empty_message",
				function:       RespondWithUnauthorized,
				expectedStatus: http.StatusUnauthorized,
				message:        "",
				expectedMsg:    "Unauthorized",
			},
			{
				name:           "RespondWithForbidden_with_message",
				function:       RespondWithForbidden,
				expectedStatus: http.StatusForbidden,
				message:        "Access denied",
				expectedMsg:    "Access denied",
			},
			{
				name:           "RespondWithForbidden_empty_message",
				function:       RespondWithForbidden,
				expectedStatus: http.StatusForbidden,
				message:        "",
				expectedMsg:    "Forbidden",
			},
			{
				name:           "RespondWithNotFound_with_message",
				function:       RespondWithNotFound,
				expectedStatus: http.StatusNotFound,
				message:        "User not found",
				expectedMsg:    "User not found",
			},
			{
				name:           "RespondWithNotFound_empty_message",
				function:       RespondWithNotFound,
				expectedStatus: http.StatusNotFound,
				message:        "",
				expectedMsg:    "Resource not found",
			},
			{
				name:           "RespondWithConflict",
				function:       RespondWithConflict,
				expectedStatus: http.StatusConflict,
				message:        "Resource already exists",
				expectedMsg:    "Resource already exists",
			},
			{
				name:           "RespondWithInternalError_with_message",
				function:       RespondWithInternalError,
				expectedStatus: http.StatusInternalServerError,
				message:        "Database error",
				expectedMsg:    "Database error",
			},
			{
				name:           "RespondWithInternalError_empty_message",
				function:       RespondWithInternalError,
				expectedStatus: http.StatusInternalServerError,
				message:        "",
				expectedMsg:    "Internal server error",
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				w := httptest.NewRecorder()
				c, _ := gin.CreateTestContext(w)

				tt.function(c, tt.message)

				if w.Code != tt.expectedStatus {
					t.Errorf("Expected status %d, got %d", tt.expectedStatus, w.Code)
				}

				var response models.APIResponse
				err := json.Unmarshal(w.Body.Bytes(), &response)
				if err != nil {
					t.Errorf("Failed to unmarshal response: %v", err)
					return
				}

				if response.Success {
					t.Error("Expected success=false")
				}

				if response.Error != tt.expectedMsg {
					t.Errorf("Expected error message %s, got %s", tt.expectedMsg, response.Error)
				}
			})
		}
	})
}

func TestHealthCheckResponse(t *testing.T) {
	t.Run("RespondWithHealthCheck", func(t *testing.T) {
		tests := []struct {
			name           string
			health         models.HealthCheck
			expectedStatus int
		}{
			{
				name: "healthy_status",
				health: models.HealthCheck{
					Status:    "healthy",
					Service:   "test-service",
					Version:   "1.0.0",
					Timestamp: time.Now(),
				},
				expectedStatus: http.StatusOK,
			},
			{
				name: "unhealthy_status",
				health: models.HealthCheck{
					Status:    "unhealthy",
					Service:   "test-service",
					Version:   "1.0.0",
					Timestamp: time.Now(),
				},
				expectedStatus: http.StatusServiceUnavailable,
			},
			{
				name: "degraded_status",
				health: models.HealthCheck{
					Status:    "degraded",
					Service:   "test-service",
					Version:   "1.0.0",
					Timestamp: time.Now(),
				},
				expectedStatus: http.StatusServiceUnavailable,
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				w := httptest.NewRecorder()
				c, _ := gin.CreateTestContext(w)

				RespondWithHealthCheck(c, tt.health)

				if w.Code != tt.expectedStatus {
					t.Errorf("Expected status %d, got %d", tt.expectedStatus, w.Code)
				}

				var response models.HealthCheck
				err := json.Unmarshal(w.Body.Bytes(), &response)
				if err != nil {
					t.Errorf("Failed to unmarshal response: %v", err)
					return
				}

				if response.Status != tt.health.Status {
					t.Errorf("Expected status %s, got %s", tt.health.Status, response.Status)
				}

				if response.Service != tt.health.Service {
					t.Errorf("Expected service %s, got %s", tt.health.Service, response.Service)
				}
			})
		}
	})
}

func TestPaginationHelpers(t *testing.T) {
	t.Run("GetPaginationFromQuery", func(t *testing.T) {
		tests := []struct {
			name          string
			queryParams   map[string]string
			expectedPage  int
			expectedLimit int
			description   string
		}{
			{
				name:          "default_values",
				queryParams:   map[string]string{},
				expectedPage:  1,
				expectedLimit: 20,
				description:   "Should use default values when no params provided",
			},
			{
				name: "valid_params",
				queryParams: map[string]string{
					"page":  "2",
					"limit": "50",
				},
				expectedPage:  2,
				expectedLimit: 50,
				description:   "Should use provided valid parameters",
			},
			{
				name: "invalid_page",
				queryParams: map[string]string{
					"page":  "0",
					"limit": "10",
				},
				expectedPage:  1,
				expectedLimit: 10,
				description:   "Should default page to 1 when provided value is invalid",
			},
			{
				name: "invalid_limit",
				queryParams: map[string]string{
					"page":  "1",
					"limit": "0",
				},
				expectedPage:  1,
				expectedLimit: 20,
				description:   "Should default limit to 20 when provided value is invalid",
			},
			{
				name: "limit_too_high",
				queryParams: map[string]string{
					"page":  "1",
					"limit": "150",
				},
				expectedPage:  1,
				expectedLimit: 100,
				description:   "Should cap limit at 100",
			},
			{
				name: "negative_values",
				queryParams: map[string]string{
					"page":  "-1",
					"limit": "-10",
				},
				expectedPage:  1,
				expectedLimit: 20,
				description:   "Should use defaults for negative values",
			},
			{
				name: "non_numeric_values",
				queryParams: map[string]string{
					"page":  "abc",
					"limit": "xyz",
				},
				expectedPage:  1,
				expectedLimit: 20,
				description:   "Should use defaults for non-numeric values",
			},
			{
				name: "mixed_valid_invalid",
				queryParams: map[string]string{
					"page":  "3",
					"limit": "abc",
				},
				expectedPage:  3,
				expectedLimit: 20,
				description:   "Should use valid page and default limit",
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				w := httptest.NewRecorder()
				c, _ := gin.CreateTestContext(w)

				// Set query parameters
				c.Request, _ = http.NewRequest("GET", "/test", nil)
				q := c.Request.URL.Query()
				for key, value := range tt.queryParams {
					q.Add(key, value)
				}
				c.Request.URL.RawQuery = q.Encode()

				pagination := GetPaginationFromQuery(c)

				if pagination.Page != tt.expectedPage {
					t.Errorf("%s: expected page %d, got %d", tt.description, tt.expectedPage, pagination.Page)
				}

				if pagination.Limit != tt.expectedLimit {
					t.Errorf("%s: expected limit %d, got %d", tt.description, tt.expectedLimit, pagination.Limit)
				}
			})
		}
	})

	t.Run("SetTotalCount", func(t *testing.T) {
		tests := []struct {
			name               string
			pagination         models.Pagination
			totalCount         int
			expectedTotal      int
			expectedTotalPages int
			description        string
		}{
			{
				name: "normal_calculation",
				pagination: models.Pagination{
					Page:  1,
					Limit: 10,
				},
				totalCount:         25,
				expectedTotal:      25,
				expectedTotalPages: 3,
				description:        "Should calculate total pages correctly",
			},
			{
				name: "exact_division",
				pagination: models.Pagination{
					Page:  1,
					Limit: 5,
				},
				totalCount:         20,
				expectedTotal:      20,
				expectedTotalPages: 4,
				description:        "Should handle exact division",
			},
			{
				name: "zero_total",
				pagination: models.Pagination{
					Page:  1,
					Limit: 10,
				},
				totalCount:         0,
				expectedTotal:      0,
				expectedTotalPages: 0,
				description:        "Should handle zero total count",
			},
			{
				name: "zero_limit",
				pagination: models.Pagination{
					Page:  1,
					Limit: 0,
				},
				totalCount:         10,
				expectedTotal:      10,
				expectedTotalPages: 0,
				description:        "Should handle zero limit",
			},
			{
				name: "single_item",
				pagination: models.Pagination{
					Page:  1,
					Limit: 10,
				},
				totalCount:         1,
				expectedTotal:      1,
				expectedTotalPages: 1,
				description:        "Should handle single item",
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				pagination := tt.pagination

				SetTotalCount(&pagination, tt.totalCount)

				if pagination.Total != tt.expectedTotal {
					t.Errorf("%s: expected total %d, got %d", tt.description, tt.expectedTotal, pagination.Total)
				}

				if pagination.TotalPages != tt.expectedTotalPages {
					t.Errorf("%s: expected total pages %d, got %d", tt.description, tt.expectedTotalPages, pagination.TotalPages)
				}
			})
		}
	})
}

func TestValidationHelpers(t *testing.T) {
	t.Run("ValidateContentType", func(t *testing.T) {
		tests := []struct {
			name         string
			contentType  string
			expectedType string
			expected     bool
			description  string
		}{
			{
				name:         "matching_content_type",
				contentType:  "application/json",
				expectedType: "application/json",
				expected:     true,
				description:  "Should return true for matching content types",
			},
			{
				name:         "non_matching_content_type",
				contentType:  "text/html",
				expectedType: "application/json",
				expected:     false,
				description:  "Should return false for non-matching content types",
			},
			{
				name:         "empty_content_type",
				contentType:  "",
				expectedType: "application/json",
				expected:     false,
				description:  "Should return false for empty content type",
			},
			{
				name:         "case_sensitive",
				contentType:  "Application/JSON",
				expectedType: "application/json",
				expected:     false,
				description:  "Should be case sensitive",
			},
			{
				name:         "xml_content_type",
				contentType:  "application/xml",
				expectedType: "application/xml",
				expected:     true,
				description:  "Should work with other content types",
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				w := httptest.NewRecorder()
				c, _ := gin.CreateTestContext(w)

				// Set content type header
				c.Request, _ = http.NewRequest("POST", "/test", nil)
				c.Request.Header.Set("Content-Type", tt.contentType)

				result := ValidateContentType(c, tt.expectedType)

				if result != tt.expected {
					t.Errorf("%s: expected %t, got %t", tt.description, tt.expected, result)
				}
			})
		}
	})

	t.Run("ValidateJSONContentType", func(t *testing.T) {
		tests := []struct {
			name        string
			contentType string
			expected    bool
			description string
		}{
			{
				name:        "valid_json",
				contentType: "application/json",
				expected:    true,
				description: "Should return true for application/json",
			},
			{
				name:        "invalid_content_type",
				contentType: "text/html",
				expected:    false,
				description: "Should return false for non-JSON content type",
			},
			{
				name:        "empty_content_type",
				contentType: "",
				expected:    false,
				description: "Should return false for empty content type",
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				w := httptest.NewRecorder()
				c, _ := gin.CreateTestContext(w)

				// Set content type header
				c.Request, _ = http.NewRequest("POST", "/test", nil)
				c.Request.Header.Set("Content-Type", tt.contentType)

				result := ValidateJSONContentType(c)

				if result != tt.expected {
					t.Errorf("%s: expected %t, got %t", tt.description, tt.expected, result)
				}
			})
		}
	})
}

func TestSecurityAndCacheHeaders(t *testing.T) {
	t.Run("SetSecurityHeaders", func(t *testing.T) {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)

		SetSecurityHeaders(c)

		expectedHeaders := map[string]string{
			"X-Content-Type-Options": "nosniff",
			"X-Frame-Options":        "DENY",
			"X-XSS-Protection":       "1; mode=block",
			"Referrer-Policy":        "strict-origin-when-cross-origin",
		}

		for header, expectedValue := range expectedHeaders {
			actualValue := w.Header().Get(header)
			if actualValue != expectedValue {
				t.Errorf("Expected header %s to be %s, got %s", header, expectedValue, actualValue)
			}
		}
	})

	t.Run("AddCacheHeaders", func(t *testing.T) {
		tests := []struct {
			name            string
			maxAge          int
			expectedHeaders map[string]string
			description     string
		}{
			{
				name:   "positive_max_age",
				maxAge: 3600,
				expectedHeaders: map[string]string{
					"Cache-Control": "public, max-age=3600",
				},
				description: "Should set cache headers for positive max age",
			},
			{
				name:   "zero_max_age",
				maxAge: 0,
				expectedHeaders: map[string]string{
					"Cache-Control": "no-cache, no-store, must-revalidate",
					"Pragma":        "no-cache",
					"Expires":       "0",
				},
				description: "Should set no-cache headers for zero max age",
			},
			{
				name:   "negative_max_age",
				maxAge: -1,
				expectedHeaders: map[string]string{
					"Cache-Control": "no-cache, no-store, must-revalidate",
					"Pragma":        "no-cache",
					"Expires":       "0",
				},
				description: "Should set no-cache headers for negative max age",
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				w := httptest.NewRecorder()
				c, _ := gin.CreateTestContext(w)

				AddCacheHeaders(c, tt.maxAge)

				for header, expectedValue := range tt.expectedHeaders {
					actualValue := w.Header().Get(header)
					if actualValue != expectedValue {
						t.Errorf("%s: expected header %s to be %s, got %s", tt.description, header, expectedValue, actualValue)
					}
				}
			})
		}
	})

	t.Run("AddNoCacheHeaders", func(t *testing.T) {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)

		AddNoCacheHeaders(c)

		expectedHeaders := map[string]string{
			"Cache-Control": "no-cache, no-store, must-revalidate",
			"Pragma":        "no-cache",
			"Expires":       "0",
		}

		for header, expectedValue := range expectedHeaders {
			actualValue := w.Header().Get(header)
			if actualValue != expectedValue {
				t.Errorf("Expected header %s to be %s, got %s", header, expectedValue, actualValue)
			}
		}
	})
}

func TestPaginationHelperFunctions(t *testing.T) {
	t.Run("parseIntWithDefault", func(t *testing.T) {
		tests := []struct {
			name         string
			input        string
			defaultValue int
			expected     int
			description  string
		}{
			{
				name:         "valid_number",
				input:        "123",
				defaultValue: 10,
				expected:     123,
				description:  "Should parse valid number string",
			},
			{
				name:         "zero_value",
				input:        "0",
				defaultValue: 10,
				expected:     0,
				description:  "Should parse zero correctly",
			},
			{
				name:         "invalid_string",
				input:        "abc",
				defaultValue: 10,
				expected:     10,
				description:  "Should return default for invalid string",
			},
			{
				name:         "mixed_string",
				input:        "12a3",
				defaultValue: 10,
				expected:     10,
				description:  "Should return default for mixed string",
			},
			{
				name:         "empty_string",
				input:        "",
				defaultValue: 10,
				expected:     0,
				description:  "Should return 0 for empty string",
			},
			{
				name:         "large_number",
				input:        "999999",
				defaultValue: 10,
				expected:     999999,
				description:  "Should handle large numbers",
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				result := parseIntWithDefault(tt.input, tt.defaultValue)
				if result != tt.expected {
					t.Errorf("%s: expected %d, got %d", tt.description, tt.expected, result)
				}
			})
		}
	})
}

// Benchmark tests
func BenchmarkRespondWithSuccess(b *testing.B) {
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	data := map[string]string{"test": "data"}

	for i := 0; i < b.N; i++ {
		w.Body.Reset()
		RespondWithSuccess(c, data)
	}
}

func BenchmarkGetPaginationFromQuery(b *testing.B) {
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request, _ = http.NewRequest("GET", "/test?page=2&limit=50", nil)

	for i := 0; i < b.N; i++ {
		_ = GetPaginationFromQuery(c)
	}
}

func BenchmarkParseIntWithDefault(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_ = parseIntWithDefault("123", 10)
	}
}

func BenchmarkSetSecurityHeaders(b *testing.B) {
	for i := 0; i < b.N; i++ {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		SetSecurityHeaders(c)
	}
}
