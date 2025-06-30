package models

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestUser_ToResponse(t *testing.T) {
	tests := []struct {
		name     string
		user     User
		expected UserResponse
	}{
		{
			name: "complete_user_data",
			user: User{
				ID:           123,
				Username:     "testuser",
				PasswordHash: "hashed_password_should_not_appear",
				CreatedAt:    time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC),
				UpdatedAt:    time.Date(2024, 1, 2, 12, 0, 0, 0, time.UTC),
			},
			expected: UserResponse{
				ID:        123,
				Username:  "testuser",
				CreatedAt: time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC),
				UpdatedAt: time.Date(2024, 1, 2, 12, 0, 0, 0, time.UTC),
			},
		},
		{
			name: "minimal_user_data",
			user: User{
				ID:           1,
				Username:     "user",
				PasswordHash: "secret",
				CreatedAt:    time.Time{},
				UpdatedAt:    time.Time{},
			},
			expected: UserResponse{
				ID:        1,
				Username:  "user",
				CreatedAt: time.Time{},
				UpdatedAt: time.Time{},
			},
		},
		{
			name: "empty_username",
			user: User{
				ID:           0,
				Username:     "",
				PasswordHash: "still_secret",
				CreatedAt:    time.Time{},
				UpdatedAt:    time.Time{},
			},
			expected: UserResponse{
				ID:        0,
				Username:  "",
				CreatedAt: time.Time{},
				UpdatedAt: time.Time{},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.user.ToResponse()

			assert.Equal(t, tt.expected.ID, result.ID)
			assert.Equal(t, tt.expected.Username, result.Username)
			assert.Equal(t, tt.expected.CreatedAt, result.CreatedAt)
			assert.Equal(t, tt.expected.UpdatedAt, result.UpdatedAt)

			// Critical security test: ensure UserResponse doesn't have password hash field at all
			// This is validated by the struct definition itself - no PasswordHash field exists
		})
	}
}

func TestUser_JSONMarshalling(t *testing.T) {
	user := User{
		ID:           456,
		Username:     "jsonuser",
		PasswordHash: "super_secret_hash",
		CreatedAt:    time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC),
		UpdatedAt:    time.Date(2024, 1, 2, 12, 0, 0, 0, time.UTC),
	}

	t.Run("user_json_marshal_excludes_password", func(t *testing.T) {
		jsonData, err := json.Marshal(user)
		require.NoError(t, err)

		jsonString := string(jsonData)

		// Verify password hash is never exposed in JSON
		assert.NotContains(t, jsonString, "super_secret_hash", "Password hash should never appear in JSON")
		assert.NotContains(t, jsonString, "password_hash", "Password hash field should not be in JSON")

		// Verify other fields are present
		assert.Contains(t, jsonString, "456")
		assert.Contains(t, jsonString, "jsonuser")
		assert.Contains(t, jsonString, "id")
		assert.Contains(t, jsonString, "username")
	})

	t.Run("user_json_unmarshal", func(t *testing.T) {
		jsonData := `{
			"id": 789,
			"username": "unmarshaled",
			"created_at": "2024-01-01T12:00:00Z",
			"updated_at": "2024-01-02T12:00:00Z"
		}`

		var unmarshaled User
		err := json.Unmarshal([]byte(jsonData), &unmarshaled)
		require.NoError(t, err)

		assert.Equal(t, int64(789), unmarshaled.ID)
		assert.Equal(t, "unmarshaled", unmarshaled.Username)
		assert.Equal(t, time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC), unmarshaled.CreatedAt)
		assert.Equal(t, time.Date(2024, 1, 2, 12, 0, 0, 0, time.UTC), unmarshaled.UpdatedAt)
		assert.Empty(t, unmarshaled.PasswordHash, "Password hash should not be set from JSON")
	})
}

func TestUserResponse_JSONMarshalling(t *testing.T) {
	response := UserResponse{
		ID:        123,
		Username:  "responseuser",
		CreatedAt: time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC),
		UpdatedAt: time.Date(2024, 1, 2, 12, 0, 0, 0, time.UTC),
	}

	t.Run("user_response_json_marshal", func(t *testing.T) {
		jsonData, err := json.Marshal(response)
		require.NoError(t, err)

		jsonString := string(jsonData)

		// Verify all fields are present
		assert.Contains(t, jsonString, "123")
		assert.Contains(t, jsonString, "responseuser")
		assert.Contains(t, jsonString, "2024-01-01T12:00:00Z")
		assert.Contains(t, jsonString, "2024-01-02T12:00:00Z")
	})

	t.Run("user_response_json_unmarshal", func(t *testing.T) {
		jsonData := `{
			"id": 456,
			"username": "unmarshaled_response",
			"created_at": "2024-01-01T12:00:00Z",
			"updated_at": "2024-01-02T12:00:00Z"
		}`

		var unmarshaled UserResponse
		err := json.Unmarshal([]byte(jsonData), &unmarshaled)
		require.NoError(t, err)

		assert.Equal(t, int64(456), unmarshaled.ID)
		assert.Equal(t, "unmarshaled_response", unmarshaled.Username)
		assert.Equal(t, time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC), unmarshaled.CreatedAt)
		assert.Equal(t, time.Date(2024, 1, 2, 12, 0, 0, 0, time.UTC), unmarshaled.UpdatedAt)
	})
}

func TestUserCreateRequest_JSONMarshalling(t *testing.T) {
	tests := []struct {
		name        string
		request     UserCreateRequest
		expectValid bool
	}{
		{
			name: "valid_request",
			request: UserCreateRequest{
				Username: "validuser",
				Password: "validpassword123",
			},
			expectValid: true,
		},
		{
			name: "empty_username",
			request: UserCreateRequest{
				Username: "",
				Password: "validpassword123",
			},
			expectValid: false,
		},
		{
			name: "empty_password",
			request: UserCreateRequest{
				Username: "validuser",
				Password: "",
			},
			expectValid: false,
		},
		{
			name: "short_username",
			request: UserCreateRequest{
				Username: "ab", // Less than min length of 3
				Password: "validpassword123",
			},
			expectValid: false,
		},
		{
			name: "short_password",
			request: UserCreateRequest{
				Username: "validuser",
				Password: "1234567", // Less than min length of 8
			},
			expectValid: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test JSON marshalling
			jsonData, err := json.Marshal(tt.request)
			require.NoError(t, err)

			jsonString := string(jsonData)
			assert.Contains(t, jsonString, tt.request.Username)

			// Verify password is included in request (unlike User struct)
			if tt.request.Password != "" {
				assert.Contains(t, jsonString, tt.request.Password)
			}

			// Test JSON unmarshalling
			var unmarshaled UserCreateRequest
			err = json.Unmarshal(jsonData, &unmarshaled)
			require.NoError(t, err)

			assert.Equal(t, tt.request.Username, unmarshaled.Username)
			assert.Equal(t, tt.request.Password, unmarshaled.Password)
		})
	}
}

func TestUserLoginRequest_JSONMarshalling(t *testing.T) {
	tests := []struct {
		name    string
		request UserLoginRequest
	}{
		{
			name: "valid_login_request",
			request: UserLoginRequest{
				Username: "loginuser",
				Password: "loginpassword",
			},
		},
		{
			name: "empty_fields",
			request: UserLoginRequest{
				Username: "",
				Password: "",
			},
		},
		{
			name: "special_characters",
			request: UserLoginRequest{
				Username: "user@domain.com",
				Password: "P@ssw0rd!",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test JSON marshalling
			jsonData, err := json.Marshal(tt.request)
			require.NoError(t, err)

			// Test JSON unmarshalling
			var unmarshaled UserLoginRequest
			err = json.Unmarshal(jsonData, &unmarshaled)
			require.NoError(t, err)

			assert.Equal(t, tt.request.Username, unmarshaled.Username)
			assert.Equal(t, tt.request.Password, unmarshaled.Password)
		})
	}
}

func TestUserStructs_FieldValidation(t *testing.T) {
	t.Run("user_struct_fields", func(t *testing.T) {
		user := User{}

		// Test zero values
		assert.Equal(t, int64(0), user.ID)
		assert.Equal(t, "", user.Username)
		assert.Equal(t, "", user.PasswordHash)
		assert.True(t, user.CreatedAt.IsZero())
		assert.True(t, user.UpdatedAt.IsZero())
	})

	t.Run("user_response_struct_fields", func(t *testing.T) {
		response := UserResponse{}

		// Test zero values
		assert.Equal(t, int64(0), response.ID)
		assert.Equal(t, "", response.Username)
		assert.True(t, response.CreatedAt.IsZero())
		assert.True(t, response.UpdatedAt.IsZero())
	})

	t.Run("user_create_request_struct_fields", func(t *testing.T) {
		request := UserCreateRequest{}

		// Test zero values
		assert.Equal(t, "", request.Username)
		assert.Equal(t, "", request.Password)
	})

	t.Run("user_login_request_struct_fields", func(t *testing.T) {
		request := UserLoginRequest{}

		// Test zero values
		assert.Equal(t, "", request.Username)
		assert.Equal(t, "", request.Password)
	})
}

// Benchmark tests for performance awareness
func BenchmarkUser_ToResponse(b *testing.B) {
	user := User{
		ID:           123,
		Username:     "benchmarkuser",
		PasswordHash: "hashed_password",
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}

	for i := 0; i < b.N; i++ {
		_ = user.ToResponse()
	}
}

func BenchmarkUser_JSONMarshal(b *testing.B) {
	user := User{
		ID:           123,
		Username:     "benchmarkuser",
		PasswordHash: "hashed_password",
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}

	for i := 0; i < b.N; i++ {
		_, _ = json.Marshal(user)
	}
}
