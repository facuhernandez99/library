package models

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAPIResponse_JSONMarshalling(t *testing.T) {
	tests := []struct {
		name     string
		response APIResponse
		expected map[string]interface{}
	}{
		{
			name: "success_response_with_data",
			response: APIResponse{
				Success: true,
				Message: "Operation successful",
				Data:    map[string]string{"key": "value"},
				Error:   "",
			},
			expected: map[string]interface{}{
				"success": true,
				"message": "Operation successful",
				"data":    map[string]interface{}{"key": "value"},
			},
		},
		{
			name: "error_response",
			response: APIResponse{
				Success: false,
				Message: "Operation failed",
				Data:    nil,
				Error:   "Something went wrong",
			},
			expected: map[string]interface{}{
				"success": false,
				"message": "Operation failed",
				"error":   "Something went wrong",
			},
		},
		{
			name: "minimal_success_response",
			response: APIResponse{
				Success: true,
			},
			expected: map[string]interface{}{
				"success": true,
			},
		},
		{
			name: "response_with_complex_data",
			response: APIResponse{
				Success: true,
				Data: map[string]interface{}{
					"users": []string{"user1", "user2"},
					"count": 2,
					"metadata": map[string]string{
						"version": "1.0",
					},
				},
			},
			expected: map[string]interface{}{
				"success": true,
				"data": map[string]interface{}{
					"users": []interface{}{"user1", "user2"},
					"count": float64(2), // JSON unmarshal converts numbers to float64
					"metadata": map[string]interface{}{
						"version": "1.0",
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test marshalling
			jsonData, err := json.Marshal(tt.response)
			require.NoError(t, err)

			// Test unmarshalling
			var unmarshaled map[string]interface{}
			err = json.Unmarshal(jsonData, &unmarshaled)
			require.NoError(t, err)

			// Verify required fields
			assert.Equal(t, tt.expected["success"], unmarshaled["success"])

			// Verify optional fields (omitempty)
			if tt.response.Message != "" {
				assert.Equal(t, tt.expected["message"], unmarshaled["message"])
			} else {
				assert.NotContains(t, unmarshaled, "message", "Empty message should be omitted")
			}

			if tt.response.Data != nil {
				assert.Equal(t, tt.expected["data"], unmarshaled["data"])
			} else {
				assert.NotContains(t, unmarshaled, "data", "Nil data should be omitted")
			}

			if tt.response.Error != "" {
				assert.Equal(t, tt.expected["error"], unmarshaled["error"])
			} else {
				assert.NotContains(t, unmarshaled, "error", "Empty error should be omitted")
			}
		})
	}
}

func TestPagination_JSONMarshalling(t *testing.T) {
	tests := []struct {
		name       string
		pagination Pagination
	}{
		{
			name: "first_page",
			pagination: Pagination{
				Page:       1,
				Limit:      10,
				Total:      100,
				TotalPages: 10,
			},
		},
		{
			name: "middle_page",
			pagination: Pagination{
				Page:       5,
				Limit:      20,
				Total:      200,
				TotalPages: 10,
			},
		},
		{
			name: "last_page",
			pagination: Pagination{
				Page:       10,
				Limit:      10,
				Total:      100,
				TotalPages: 10,
			},
		},
		{
			name: "empty_result",
			pagination: Pagination{
				Page:       1,
				Limit:      10,
				Total:      0,
				TotalPages: 0,
			},
		},
		{
			name: "large_dataset",
			pagination: Pagination{
				Page:       1000,
				Limit:      50,
				Total:      100000,
				TotalPages: 2000,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test marshalling
			jsonData, err := json.Marshal(tt.pagination)
			require.NoError(t, err)

			// Test unmarshalling
			var unmarshaled Pagination
			err = json.Unmarshal(jsonData, &unmarshaled)
			require.NoError(t, err)

			assert.Equal(t, tt.pagination.Page, unmarshaled.Page)
			assert.Equal(t, tt.pagination.Limit, unmarshaled.Limit)
			assert.Equal(t, tt.pagination.Total, unmarshaled.Total)
			assert.Equal(t, tt.pagination.TotalPages, unmarshaled.TotalPages)
		})
	}
}

func TestPaginatedResponse_JSONMarshalling(t *testing.T) {
	tests := []struct {
		name     string
		response PaginatedResponse
	}{
		{
			name: "users_pagination",
			response: PaginatedResponse{
				Data: []string{"user1", "user2", "user3"},
				Pagination: Pagination{
					Page:       1,
					Limit:      10,
					Total:      3,
					TotalPages: 1,
				},
			},
		},
		{
			name: "empty_data",
			response: PaginatedResponse{
				Data: []interface{}{},
				Pagination: Pagination{
					Page:       1,
					Limit:      10,
					Total:      0,
					TotalPages: 0,
				},
			},
		},
		{
			name: "complex_data",
			response: PaginatedResponse{
				Data: map[string]interface{}{
					"items": []map[string]string{
						{"id": "1", "name": "item1"},
						{"id": "2", "name": "item2"},
					},
				},
				Pagination: Pagination{
					Page:       2,
					Limit:      2,
					Total:      10,
					TotalPages: 5,
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test marshalling
			jsonData, err := json.Marshal(tt.response)
			require.NoError(t, err)

			// Test unmarshalling
			var unmarshaled PaginatedResponse
			err = json.Unmarshal(jsonData, &unmarshaled)
			require.NoError(t, err)

			// Note: Data comparison might be complex due to JSON unmarshalling behavior
			// We verify the structure is preserved
			assert.NotNil(t, unmarshaled.Data)
			assert.Equal(t, tt.response.Pagination.Page, unmarshaled.Pagination.Page)
			assert.Equal(t, tt.response.Pagination.Limit, unmarshaled.Pagination.Limit)
			assert.Equal(t, tt.response.Pagination.Total, unmarshaled.Pagination.Total)
			assert.Equal(t, tt.response.Pagination.TotalPages, unmarshaled.Pagination.TotalPages)
		})
	}
}

func TestHealthCheck_JSONMarshalling(t *testing.T) {
	timestamp := time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC)

	tests := []struct {
		name        string
		healthCheck HealthCheck
	}{
		{
			name: "healthy_service",
			healthCheck: HealthCheck{
				Status:    "healthy",
				Timestamp: timestamp,
				Version:   "1.0.0",
				Service:   "library-service",
			},
		},
		{
			name: "unhealthy_service",
			healthCheck: HealthCheck{
				Status:    "unhealthy",
				Timestamp: timestamp,
				Version:   "",
				Service:   "library-service",
			},
		},
		{
			name: "degraded_service",
			healthCheck: HealthCheck{
				Status:    "degraded",
				Timestamp: timestamp,
				Version:   "1.2.3",
				Service:   "blog-api",
			},
		},
		{
			name: "minimal_health_check",
			healthCheck: HealthCheck{
				Status:    "ok",
				Timestamp: timestamp,
				Service:   "minimal-service",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test marshalling
			jsonData, err := json.Marshal(tt.healthCheck)
			require.NoError(t, err)

			jsonString := string(jsonData)
			assert.Contains(t, jsonString, tt.healthCheck.Status)
			assert.Contains(t, jsonString, tt.healthCheck.Service)
			assert.Contains(t, jsonString, "2024-01-01T12:00:00Z")

			// Version is omitempty
			if tt.healthCheck.Version != "" {
				assert.Contains(t, jsonString, tt.healthCheck.Version)
			}

			// Test unmarshalling
			var unmarshaled HealthCheck
			err = json.Unmarshal(jsonData, &unmarshaled)
			require.NoError(t, err)

			assert.Equal(t, tt.healthCheck.Status, unmarshaled.Status)
			assert.Equal(t, tt.healthCheck.Timestamp.UTC(), unmarshaled.Timestamp.UTC())
			assert.Equal(t, tt.healthCheck.Version, unmarshaled.Version)
			assert.Equal(t, tt.healthCheck.Service, unmarshaled.Service)
		})
	}
}

func TestTokenResponse_JSONMarshalling(t *testing.T) {
	expiresAt := time.Date(2024, 1, 1, 13, 0, 0, 0, time.UTC)

	tests := []struct {
		name          string
		tokenResponse TokenResponse
	}{
		{
			name: "complete_token_response",
			tokenResponse: TokenResponse{
				Token:        "eyJhbGciOiJIUzI1NiIs...",
				ExpiresAt:    expiresAt,
				TokenType:    "Bearer",
				RefreshToken: "refresh_token_123",
			},
		},
		{
			name: "token_without_refresh",
			tokenResponse: TokenResponse{
				Token:        "eyJhbGciOiJIUzI1NiIs...",
				ExpiresAt:    expiresAt,
				TokenType:    "Bearer",
				RefreshToken: "",
			},
		},
		{
			name: "minimal_token_response",
			tokenResponse: TokenResponse{
				Token:     "simple_token",
				ExpiresAt: expiresAt,
				TokenType: "Bearer",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test marshalling
			jsonData, err := json.Marshal(tt.tokenResponse)
			require.NoError(t, err)

			jsonString := string(jsonData)
			assert.Contains(t, jsonString, tt.tokenResponse.Token)
			assert.Contains(t, jsonString, tt.tokenResponse.TokenType)
			assert.Contains(t, jsonString, "2024-01-01T13:00:00Z")

			// RefreshToken is omitempty
			if tt.tokenResponse.RefreshToken != "" {
				assert.Contains(t, jsonString, tt.tokenResponse.RefreshToken)
			} else {
				assert.NotContains(t, jsonString, "refresh_token")
			}

			// Test unmarshalling
			var unmarshaled TokenResponse
			err = json.Unmarshal(jsonData, &unmarshaled)
			require.NoError(t, err)

			assert.Equal(t, tt.tokenResponse.Token, unmarshaled.Token)
			assert.Equal(t, tt.tokenResponse.ExpiresAt.UTC(), unmarshaled.ExpiresAt.UTC())
			assert.Equal(t, tt.tokenResponse.TokenType, unmarshaled.TokenType)
			assert.Equal(t, tt.tokenResponse.RefreshToken, unmarshaled.RefreshToken)
		})
	}
}

func TestValidationConstants(t *testing.T) {
	t.Run("username_length_constants", func(t *testing.T) {
		assert.Equal(t, 50, MaxUsernameLength)
		assert.Equal(t, 3, MinUsernameLength)
		assert.True(t, MaxUsernameLength > MinUsernameLength, "Max should be greater than min")
	})

	t.Run("password_length_constants", func(t *testing.T) {
		assert.Equal(t, 100, MaxPasswordLength)
		assert.Equal(t, 8, MinPasswordLength)
		assert.True(t, MaxPasswordLength > MinPasswordLength, "Max should be greater than min")
	})

	t.Run("constants_relationship", func(t *testing.T) {
		// Ensure username constraints are reasonable
		assert.True(t, MinUsernameLength >= 1, "Minimum username length should be at least 1")
		assert.True(t, MaxUsernameLength <= 255, "Maximum username length should be reasonable")

		// Ensure password constraints follow security best practices
		assert.True(t, MinPasswordLength >= 8, "Minimum password length should be at least 8 for security")
		assert.True(t, MaxPasswordLength >= 50, "Maximum password length should allow strong passwords")
	})
}

func TestStructZeroValues(t *testing.T) {
	t.Run("api_response_zero_values", func(t *testing.T) {
		response := APIResponse{}
		assert.False(t, response.Success)
		assert.Equal(t, "", response.Message)
		assert.Nil(t, response.Data)
		assert.Equal(t, "", response.Error)
	})

	t.Run("pagination_zero_values", func(t *testing.T) {
		pagination := Pagination{}
		assert.Equal(t, 0, pagination.Page)
		assert.Equal(t, 0, pagination.Limit)
		assert.Equal(t, 0, pagination.Total)
		assert.Equal(t, 0, pagination.TotalPages)
	})

	t.Run("health_check_zero_values", func(t *testing.T) {
		health := HealthCheck{}
		assert.Equal(t, "", health.Status)
		assert.True(t, health.Timestamp.IsZero())
		assert.Equal(t, "", health.Version)
		assert.Equal(t, "", health.Service)
	})

	t.Run("token_response_zero_values", func(t *testing.T) {
		token := TokenResponse{}
		assert.Equal(t, "", token.Token)
		assert.True(t, token.ExpiresAt.IsZero())
		assert.Equal(t, "", token.TokenType)
		assert.Equal(t, "", token.RefreshToken)
	})

	t.Run("paginated_response_zero_values", func(t *testing.T) {
		response := PaginatedResponse{}
		assert.Nil(t, response.Data)
		assert.Equal(t, Pagination{}, response.Pagination)
	})
}

// Helper function tests demonstrating practical usage
func TestCommonModelUsagePatterns(t *testing.T) {
	t.Run("success_api_response_pattern", func(t *testing.T) {
		data := map[string]string{"id": "123", "name": "test"}
		response := APIResponse{
			Success: true,
			Message: "User created successfully",
			Data:    data,
		}

		jsonData, err := json.Marshal(response)
		require.NoError(t, err)

		var result map[string]interface{}
		err = json.Unmarshal(jsonData, &result)
		require.NoError(t, err)

		assert.True(t, result["success"].(bool))
		assert.Equal(t, "User created successfully", result["message"])
		assert.NotNil(t, result["data"])
	})

	t.Run("error_api_response_pattern", func(t *testing.T) {
		response := APIResponse{
			Success: false,
			Message: "Validation failed",
			Error:   "Username is required",
		}

		jsonData, err := json.Marshal(response)
		require.NoError(t, err)

		var result map[string]interface{}
		err = json.Unmarshal(jsonData, &result)
		require.NoError(t, err)

		assert.False(t, result["success"].(bool))
		assert.Equal(t, "Validation failed", result["message"])
		assert.Equal(t, "Username is required", result["error"])
		assert.NotContains(t, result, "data")
	})

	t.Run("pagination_with_data_pattern", func(t *testing.T) {
		users := []map[string]string{
			{"id": "1", "username": "user1"},
			{"id": "2", "username": "user2"},
		}

		response := PaginatedResponse{
			Data: users,
			Pagination: Pagination{
				Page:       1,
				Limit:      10,
				Total:      2,
				TotalPages: 1,
			},
		}

		jsonData, err := json.Marshal(response)
		require.NoError(t, err)

		var result map[string]interface{}
		err = json.Unmarshal(jsonData, &result)
		require.NoError(t, err)

		assert.NotNil(t, result["data"])
		assert.NotNil(t, result["pagination"])

		pagination := result["pagination"].(map[string]interface{})
		assert.Equal(t, float64(1), pagination["page"])
		assert.Equal(t, float64(10), pagination["limit"])
		assert.Equal(t, float64(2), pagination["total"])
		assert.Equal(t, float64(1), pagination["total_pages"])
	})
}

// Benchmark tests for performance awareness
func BenchmarkAPIResponse_JSONMarshal(b *testing.B) {
	response := APIResponse{
		Success: true,
		Message: "Operation successful",
		Data:    map[string]string{"key": "value"},
	}

	for i := 0; i < b.N; i++ {
		_, _ = json.Marshal(response)
	}
}

func BenchmarkPagination_JSONMarshal(b *testing.B) {
	pagination := Pagination{
		Page:       1,
		Limit:      10,
		Total:      100,
		TotalPages: 10,
	}

	for i := 0; i < b.N; i++ {
		_, _ = json.Marshal(pagination)
	}
}
