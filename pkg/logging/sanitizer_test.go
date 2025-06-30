package logging

import (
	"errors"
	"testing"

	apperrors "github.com/facuhernandez99/library/pkg/errors"
	"github.com/stretchr/testify/assert"
)

func TestNewErrorSanitizer(t *testing.T) {
	// Test development mode
	devSanitizer := NewErrorSanitizer(false)
	assert.False(t, devSanitizer.production)
	assert.NotNil(t, devSanitizer.replacements)
	assert.Len(t, devSanitizer.sensitivePatterns, 0) // No patterns in dev mode

	// Test production mode
	prodSanitizer := NewErrorSanitizer(true)
	assert.True(t, prodSanitizer.production)
	assert.NotNil(t, prodSanitizer.replacements)
	assert.Greater(t, len(prodSanitizer.sensitivePatterns), 0) // Patterns in prod mode
}

func TestErrorSanitizer_Sanitize_NilError(t *testing.T) {
	sanitizer := NewErrorSanitizer(false)

	result := sanitizer.Sanitize(nil)
	assert.Nil(t, result)
}

func TestErrorSanitizer_Sanitize_RegularError(t *testing.T) {
	sanitizer := NewErrorSanitizer(false)

	originalErr := errors.New("simple error message")
	result := sanitizer.Sanitize(originalErr)

	assert.Equal(t, originalErr, result) // Should remain unchanged in dev mode
}

func TestErrorSanitizer_Sanitize_SensitiveRegularError(t *testing.T) {
	sanitizer := NewErrorSanitizer(false)

	originalErr := errors.New("failed to connect with password: secret123")
	result := sanitizer.Sanitize(originalErr)

	assert.Contains(t, result.Error(), "password: [REDACTED]")
	assert.NotContains(t, result.Error(), "secret123")
}

func TestErrorSanitizer_SanitizeAppError_Development(t *testing.T) {
	sanitizer := NewErrorSanitizer(false)

	appErr := apperrors.ErrInternal.WithDetails("sensitive database connection details")
	result := sanitizer.Sanitize(appErr)

	appResult, ok := apperrors.IsAppError(result)
	assert.True(t, ok)
	assert.Equal(t, apperrors.ErrCodeInternal, appResult.Code)
	// In dev mode, details should be preserved (unless they contain sensitive keywords)
	assert.NotEmpty(t, appResult.Details)
}

func TestErrorSanitizer_SanitizeAppError_Production(t *testing.T) {
	sanitizer := NewErrorSanitizer(true)

	// Test internal error sanitization
	appErr := apperrors.ErrInternal.WithDetails("sensitive database connection details")
	result := sanitizer.Sanitize(appErr)

	appResult, ok := apperrors.IsAppError(result)
	assert.True(t, ok)
	assert.Equal(t, apperrors.ErrCodeInternal, appResult.Code)
	assert.Equal(t, "Internal server error", appResult.Message)
	assert.Empty(t, appResult.Details) // Details should be removed in production
}

func TestErrorSanitizer_SanitizeAppError_ProductionAuth(t *testing.T) {
	sanitizer := NewErrorSanitizer(true)

	// Test auth error sanitization
	appErr := apperrors.ErrInvalidToken.WithDetails("JWT token validation failed")
	result := sanitizer.Sanitize(appErr)

	appResult, ok := apperrors.IsAppError(result)
	assert.True(t, ok)
	assert.Equal(t, apperrors.ErrCodeInvalidToken, appResult.Code)
	assert.Equal(t, "Authentication failed", appResult.Message)
}

func TestErrorSanitizer_SanitizeAppError_ProductionUserError(t *testing.T) {
	sanitizer := NewErrorSanitizer(true)

	// Test user error - these should not be over-sanitized
	appErr := apperrors.ErrUserNotFound
	result := sanitizer.Sanitize(appErr)

	appResult, ok := apperrors.IsAppError(result)
	assert.True(t, ok)
	assert.Equal(t, apperrors.ErrCodeUserNotFound, appResult.Code)
	assert.Equal(t, "User not found", appResult.Message) // Should preserve original message
}

func TestErrorSanitizer_SanitizeString(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "empty string",
			input:    "",
			expected: "",
		},
		{
			name:     "no sensitive data",
			input:    "normal error message",
			expected: "normal error message",
		},
		{
			name:     "password in string",
			input:    "failed to authenticate with password: secret123",
			expected: "failed to auth: [REDACTED] password: [REDACTED]",
		},
		{
			name:     "token in string",
			input:    "invalid token: abc123xyz",
			expected: "invalid token: [REDACTED]",
		},
		{
			name:     "api key in string",
			input:    "authentication failed for key sk_test_12345",
			expected: "auth: [REDACTED] for key: [REDACTED]",
		},
		{
			name:     "multiple sensitive keywords",
			input:    "password: secret123 and token: abc456",
			expected: "password: [REDACTED] and token: [REDACTED]",
		},
	}

	sanitizer := NewErrorSanitizer(false)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := sanitizer.sanitizeString(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestErrorSanitizer_SanitizeString_ProductionPatterns(t *testing.T) {
	sanitizer := NewErrorSanitizer(true)

	tests := []struct {
		name        string
		input       string
		contains    []string
		notContains []string
	}{
		{
			name:        "email address",
			input:       "failed to send email to user@example.com",
			contains:    []string{"us***@example.com"},
			notContains: []string{"user@example.com"},
		},
		{
			name:        "credit card",
			input:       "payment failed for card 4532-1234-5678-9012",
			contains:    []string{"[REDACTED]"},
			notContains: []string{"4532-1234-5678-9012"},
		},
		{
			name:        "IP address",
			input:       "connection failed to 192.168.1.100",
			contains:    []string{"192.***.***.***"},
			notContains: []string{"192.168.1.100"},
		},
		{
			name:        "JWT token",
			input:       "invalid JWT: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
			contains:    []string{"[REDACTED]"},
			notContains: []string{"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := sanitizer.sanitizeString(tt.input)

			for _, contains := range tt.contains {
				assert.Contains(t, result, contains)
			}

			for _, notContains := range tt.notContains {
				assert.NotContains(t, result, notContains)
			}
		})
	}
}

func TestErrorSanitizer_SanitizeMap(t *testing.T) {
	sanitizer := NewErrorSanitizer(false)

	tests := []struct {
		name     string
		input    map[string]interface{}
		expected map[string]interface{}
	}{
		{
			name:     "nil map",
			input:    nil,
			expected: nil,
		},
		{
			name:     "empty map",
			input:    map[string]interface{}{},
			expected: map[string]interface{}{},
		},
		{
			name: "normal data",
			input: map[string]interface{}{
				"user_id": "123",
				"action":  "login",
				"count":   42,
			},
			expected: map[string]interface{}{
				"user_id": "123",
				"action":  "login",
				"count":   42,
			},
		},
		{
			name: "sensitive keys",
			input: map[string]interface{}{
				"user_password": "secret123",
				"api_token":     "token456",
				"username":      "john",
			},
			expected: map[string]interface{}{
				"user_password": "[REDACTED]",
				"api_token":     "[REDACTED]",
				"username":      "john",
			},
		},
		{
			name: "nested map",
			input: map[string]interface{}{
				"user": map[string]interface{}{
					"name":     "john",
					"password": "secret",
				},
				"meta": map[string]interface{}{
					"request_id": "req-123",
				},
			},
			expected: map[string]interface{}{
				"user": map[string]interface{}{
					"name":     "john",
					"password": "[REDACTED]",
				},
				"meta": map[string]interface{}{
					"request_id": "req-123",
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := sanitizer.SanitizeMap(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestErrorSanitizer_SanitizeValue(t *testing.T) {
	sanitizer := NewErrorSanitizer(false)

	tests := []struct {
		name     string
		key      string
		value    interface{}
		expected interface{}
	}{
		{
			name:     "normal string",
			key:      "message",
			value:    "hello world",
			expected: "hello world",
		},
		{
			name:     "sensitive key",
			key:      "password",
			value:    "secret123",
			expected: "[REDACTED]",
		},
		{
			name:     "sensitive string content",
			key:      "error",
			value:    "authentication failed with password: secret",
			expected: "auth: [REDACTED] with password: [REDACTED]",
		},
		{
			name:     "number value",
			key:      "count",
			value:    42,
			expected: 42,
		},
		{
			name: "slice value",
			key:  "items",
			value: []interface{}{
				"item1",
				map[string]interface{}{"password": "secret"},
			},
			expected: []interface{}{
				"item1",
				map[string]interface{}{"password": "[REDACTED]"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := sanitizer.sanitizeValue(tt.key, tt.value)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestErrorSanitizer_IsSensitiveError(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected bool
	}{
		{
			name:     "nil error",
			err:      nil,
			expected: false,
		},
		{
			name:     "normal error",
			err:      errors.New("something went wrong"),
			expected: false,
		},
		{
			name:     "password in error",
			err:      errors.New("failed with password abc123"),
			expected: true,
		},
		{
			name:     "token in error",
			err:      errors.New("invalid token provided"),
			expected: true,
		},
		{
			name:     "secret in error",
			err:      errors.New("secret key validation failed"),
			expected: true,
		},
		{
			name:     "credential in error",
			err:      errors.New("credential verification failed"),
			expected: true,
		},
	}

	sanitizer := NewErrorSanitizer(false)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := sanitizer.IsSensitiveError(tt.err)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestErrorSanitizer_IsSensitiveError_ProductionPatterns(t *testing.T) {
	sanitizer := NewErrorSanitizer(true)

	tests := []struct {
		name     string
		err      error
		expected bool
	}{
		{
			name:     "email in error",
			err:      errors.New("failed to notify user@example.com"),
			expected: true,
		},
		{
			name:     "JWT token in error",
			err:      errors.New("invalid JWT eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"),
			expected: true,
		},
		{
			name:     "API key in error",
			err:      errors.New("invalid API key sk_live_abcdef1234567890"),
			expected: true,
		},
		{
			name:     "IP address in error",
			err:      errors.New("connection failed to 10.0.0.1"),
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := sanitizer.IsSensitiveError(tt.err)
			assert.Equal(t, tt.expected, result)
		})
	}
}
