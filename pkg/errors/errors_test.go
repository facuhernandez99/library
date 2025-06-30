package errors

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/facuhernandez99/library/pkg/models"
	"github.com/gin-gonic/gin"
)

func init() {
	// Set Gin to test mode
	gin.SetMode(gin.TestMode)
}

func TestAppErrorCreation(t *testing.T) {
	t.Run("New", func(t *testing.T) {
		tests := []struct {
			name           string
			code           ErrorCode
			message        string
			expectedStatus int
			description    string
		}{
			{
				name:           "basic_error",
				code:           ErrCodeValidation,
				message:        "Test validation error",
				expectedStatus: http.StatusBadRequest,
				description:    "Should create basic AppError with correct status code",
			},
			{
				name:           "not_found_error",
				code:           ErrCodeNotFound,
				message:        "Resource not found",
				expectedStatus: http.StatusNotFound,
				description:    "Should create not found error with 404 status",
			},
			{
				name:           "internal_error",
				code:           ErrCodeInternal,
				message:        "Something went wrong",
				expectedStatus: http.StatusInternalServerError,
				description:    "Should create internal error with 500 status",
			},
			{
				name:           "unauthorized_error",
				code:           ErrCodeUnauthorized,
				message:        "Access denied",
				expectedStatus: http.StatusUnauthorized,
				description:    "Should create unauthorized error with 401 status",
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				err := New(tt.code, tt.message)

				if err.Code != tt.code {
					t.Errorf("%s: expected code %s, got %s", tt.description, tt.code, err.Code)
				}

				if err.Message != tt.message {
					t.Errorf("%s: expected message %s, got %s", tt.description, tt.message, err.Message)
				}

				if err.StatusCode != tt.expectedStatus {
					t.Errorf("%s: expected status %d, got %d", tt.description, tt.expectedStatus, err.StatusCode)
				}

				if err.Err != nil {
					t.Errorf("%s: expected no underlying error, got %v", tt.description, err.Err)
				}

				if err.Details != "" {
					t.Errorf("%s: expected empty details, got %s", tt.description, err.Details)
				}
			})
		}
	})

	t.Run("Newf", func(t *testing.T) {
		tests := []struct {
			name            string
			code            ErrorCode
			format          string
			args            []interface{}
			expectedMessage string
			description     string
		}{
			{
				name:            "formatted_message_string",
				code:            ErrCodeValidation,
				format:          "Field %s is required",
				args:            []interface{}{"username"},
				expectedMessage: "Field username is required",
				description:     "Should format message with string argument",
			},
			{
				name:            "formatted_message_multiple_args",
				code:            ErrCodeValidation,
				format:          "Value %s must be between %d and %d characters",
				args:            []interface{}{"password", 8, 100},
				expectedMessage: "Value password must be between 8 and 100 characters",
				description:     "Should format message with multiple arguments",
			},
			{
				name:            "no_format_args",
				code:            ErrCodeInternal,
				format:          "Simple error message",
				args:            []interface{}{},
				expectedMessage: "Simple error message",
				description:     "Should handle format string without arguments",
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				err := Newf(tt.code, tt.format, tt.args...)

				if err.Code != tt.code {
					t.Errorf("%s: expected code %s, got %s", tt.description, tt.code, err.Code)
				}

				if err.Message != tt.expectedMessage {
					t.Errorf("%s: expected message %s, got %s", tt.description, tt.expectedMessage, err.Message)
				}
			})
		}
	})

	t.Run("Wrap", func(t *testing.T) {
		originalErr := errors.New("database connection timeout")

		tests := []struct {
			name        string
			err         error
			code        ErrorCode
			message     string
			description string
		}{
			{
				name:        "wrap_database_error",
				err:         originalErr,
				code:        ErrCodeDatabaseError,
				message:     "Failed to connect to database",
				description: "Should wrap original error with AppError",
			},
			{
				name:        "wrap_nil_error",
				err:         nil,
				code:        ErrCodeInternal,
				message:     "Unexpected error",
				description: "Should handle nil error wrapping",
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				err := Wrap(tt.err, tt.code, tt.message)

				if err.Code != tt.code {
					t.Errorf("%s: expected code %s, got %s", tt.description, tt.code, err.Code)
				}

				if err.Message != tt.message {
					t.Errorf("%s: expected message %s, got %s", tt.description, tt.message, err.Message)
				}

				if err.Err != tt.err {
					t.Errorf("%s: expected wrapped error %v, got %v", tt.description, tt.err, err.Err)
				}

				// Test Error() method includes original error
				if tt.err != nil {
					expectedErrorString := fmt.Sprintf("%s: %s (%v)", tt.code, tt.message, tt.err)
					if err.Error() != expectedErrorString {
						t.Errorf("%s: expected error string %s, got %s", tt.description, expectedErrorString, err.Error())
					}
				}

				// Test Unwrap() method
				if err.Unwrap() != tt.err {
					t.Errorf("%s: expected unwrapped error %v, got %v", tt.description, tt.err, err.Unwrap())
				}
			})
		}
	})

	t.Run("Wrapf", func(t *testing.T) {
		originalErr := errors.New("connection refused")

		err := Wrapf(originalErr, ErrCodeConnectionFailed, "Failed to connect to %s on port %d", "localhost", 5432)

		expectedMessage := "Failed to connect to localhost on port 5432"
		if err.Message != expectedMessage {
			t.Errorf("Expected message %s, got %s", expectedMessage, err.Message)
		}

		if err.Err != originalErr {
			t.Errorf("Expected wrapped error %v, got %v", originalErr, err.Err)
		}

		if err.Code != ErrCodeConnectionFailed {
			t.Errorf("Expected code %s, got %s", ErrCodeConnectionFailed, err.Code)
		}
	})

	t.Run("WithDetails", func(t *testing.T) {
		err := New(ErrCodeValidation, "Validation failed")
		details := "Field 'email' must be a valid email address"

		err = err.WithDetails(details)

		if err.Details != details {
			t.Errorf("Expected details %s, got %s", details, err.Details)
		}
	})

	t.Run("WithStatusCode", func(t *testing.T) {
		err := New(ErrCodeValidation, "Custom error")
		customStatus := http.StatusTeapot

		err = err.WithStatusCode(customStatus)

		if err.StatusCode != customStatus {
			t.Errorf("Expected status code %d, got %d", customStatus, err.StatusCode)
		}
	})
}

func TestHTTPStatusCodeMapping(t *testing.T) {
	tests := []struct {
		code           ErrorCode
		expectedStatus int
		description    string
	}{
		// 404 Not Found
		{ErrCodeNotFound, http.StatusNotFound, "Generic not found"},
		{ErrCodeUserNotFound, http.StatusNotFound, "User not found"},
		{ErrCodePostNotFound, http.StatusNotFound, "Post not found"},

		// 400 Bad Request
		{ErrCodeValidation, http.StatusBadRequest, "Validation error"},
		{ErrCodeBadRequest, http.StatusBadRequest, "Bad request"},
		{ErrCodeWeakPassword, http.StatusBadRequest, "Weak password"},
		{ErrCodeInvalidUsername, http.StatusBadRequest, "Invalid username"},
		{ErrCodeInvalidPostData, http.StatusBadRequest, "Invalid post data"},
		{ErrCodeTokenMalformed, http.StatusBadRequest, "Malformed token"},

		// 401 Unauthorized
		{ErrCodeUnauthorized, http.StatusUnauthorized, "Unauthorized"},
		{ErrCodeInvalidPassword, http.StatusUnauthorized, "Invalid password"},
		{ErrCodeInvalidToken, http.StatusUnauthorized, "Invalid token"},
		{ErrCodeTokenExpired, http.StatusUnauthorized, "Token expired"},
		{ErrCodeInvalidSignature, http.StatusUnauthorized, "Invalid signature"},
		{ErrCodeMissingToken, http.StatusUnauthorized, "Missing token"},

		// 403 Forbidden
		{ErrCodeForbidden, http.StatusForbidden, "Forbidden"},

		// 409 Conflict
		{ErrCodeConflict, http.StatusConflict, "Conflict"},
		{ErrCodeUserExists, http.StatusConflict, "User exists"},
		{ErrCodeEmailExists, http.StatusConflict, "Email exists"},
		{ErrCodeUsernameExists, http.StatusConflict, "Username exists"},
		{ErrCodePostExists, http.StatusConflict, "Post exists"},

		// 500 Internal Server Error
		{ErrCodeInternal, http.StatusInternalServerError, "Internal error"},
		{ErrCodeDatabaseError, http.StatusInternalServerError, "Database error"},
		{ErrCodeConnectionFailed, http.StatusInternalServerError, "Connection failed"},
		{ErrCodeQueryFailed, http.StatusInternalServerError, "Query failed"},

		// Unknown code should default to 500
		{ErrorCode("UNKNOWN_ERROR"), http.StatusInternalServerError, "Unknown error code"},
	}

	for _, tt := range tests {
		t.Run(string(tt.code), func(t *testing.T) {
			err := New(tt.code, "Test message")
			if err.StatusCode != tt.expectedStatus {
				t.Errorf("%s: expected status %d, got %d", tt.description, tt.expectedStatus, err.StatusCode)
			}
		})
	}
}

func TestErrorResponseHelpers(t *testing.T) {
	t.Run("RespondWithError", func(t *testing.T) {
		tests := []struct {
			name        string
			appError    *AppError
			description string
		}{
			{
				name:        "basic_error",
				appError:    New(ErrCodeValidation, "Test validation error"),
				description: "Should respond with basic AppError",
			},
			{
				name:        "error_with_details",
				appError:    New(ErrCodeValidation, "Validation failed").WithDetails("Email is required"),
				description: "Should respond with AppError including details",
			},
			{
				name:        "custom_status_code",
				appError:    New(ErrCodeValidation, "Custom error").WithStatusCode(http.StatusTeapot),
				description: "Should respond with custom status code",
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				w := httptest.NewRecorder()
				c, _ := gin.CreateTestContext(w)

				RespondWithError(c, tt.appError)

				// Check status code
				if w.Code != tt.appError.StatusCode {
					t.Errorf("%s: expected status %d, got %d", tt.description, tt.appError.StatusCode, w.Code)
				}

				// Check response body
				var response models.APIResponse
				err := json.Unmarshal(w.Body.Bytes(), &response)
				if err != nil {
					t.Errorf("%s: failed to unmarshal response: %v", tt.description, err)
					return
				}

				if response.Success {
					t.Errorf("%s: expected success=false, got true", tt.description)
				}

				if response.Error != tt.appError.Message {
					t.Errorf("%s: expected error message %s, got %s", tt.description, tt.appError.Message, response.Error)
				}

				// Check data field contains code and details
				data, ok := response.Data.(map[string]interface{})
				if !ok {
					t.Errorf("%s: expected data to be map[string]interface{}", tt.description)
					return
				}

				if data["code"] != string(tt.appError.Code) {
					t.Errorf("%s: expected code %s, got %v", tt.description, tt.appError.Code, data["code"])
				}

				if data["details"] != tt.appError.Details {
					t.Errorf("%s: expected details %s, got %v", tt.description, tt.appError.Details, data["details"])
				}
			})
		}
	})

	t.Run("RespondWithErrorCode", func(t *testing.T) {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)

		code := ErrCodeNotFound
		message := "User not found"

		RespondWithErrorCode(c, code, message)

		if w.Code != http.StatusNotFound {
			t.Errorf("Expected status %d, got %d", http.StatusNotFound, w.Code)
		}

		var response models.APIResponse
		err := json.Unmarshal(w.Body.Bytes(), &response)
		if err != nil {
			t.Errorf("Failed to unmarshal response: %v", err)
			return
		}

		if response.Error != message {
			t.Errorf("Expected error message %s, got %s", message, response.Error)
		}
	})

	t.Run("RespondWithInternalError", func(t *testing.T) {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)

		RespondWithInternalError(c)

		if w.Code != http.StatusInternalServerError {
			t.Errorf("Expected status %d, got %d", http.StatusInternalServerError, w.Code)
		}

		var response models.APIResponse
		err := json.Unmarshal(w.Body.Bytes(), &response)
		if err != nil {
			t.Errorf("Failed to unmarshal response: %v", err)
			return
		}

		if response.Error != ErrInternal.Message {
			t.Errorf("Expected error message %s, got %s", ErrInternal.Message, response.Error)
		}
	})

	t.Run("RespondWithValidationError", func(t *testing.T) {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)

		details := "Email is required"
		RespondWithValidationError(c, details)

		if w.Code != http.StatusBadRequest {
			t.Errorf("Expected status %d, got %d", http.StatusBadRequest, w.Code)
		}

		var response models.APIResponse
		err := json.Unmarshal(w.Body.Bytes(), &response)
		if err != nil {
			t.Errorf("Failed to unmarshal response: %v", err)
			return
		}

		data, ok := response.Data.(map[string]interface{})
		if !ok {
			t.Error("Expected data to be map[string]interface{}")
			return
		}

		if data["details"] != details {
			t.Errorf("Expected details %s, got %v", details, data["details"])
		}
	})

	t.Run("RespondWithNotFound", func(t *testing.T) {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)

		resource := "User"
		RespondWithNotFound(c, resource)

		if w.Code != http.StatusNotFound {
			t.Errorf("Expected status %d, got %d", http.StatusNotFound, w.Code)
		}

		var response models.APIResponse
		err := json.Unmarshal(w.Body.Bytes(), &response)
		if err != nil {
			t.Errorf("Failed to unmarshal response: %v", err)
			return
		}

		expectedMessage := "User not found"
		if response.Error != expectedMessage {
			t.Errorf("Expected error message %s, got %s", expectedMessage, response.Error)
		}
	})

	t.Run("RespondWithUnauthorized", func(t *testing.T) {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)

		message := "Invalid credentials"
		RespondWithUnauthorized(c, message)

		if w.Code != http.StatusUnauthorized {
			t.Errorf("Expected status %d, got %d", http.StatusUnauthorized, w.Code)
		}

		var response models.APIResponse
		err := json.Unmarshal(w.Body.Bytes(), &response)
		if err != nil {
			t.Errorf("Failed to unmarshal response: %v", err)
			return
		}

		if response.Error != message {
			t.Errorf("Expected error message %s, got %s", message, response.Error)
		}
	})

	t.Run("RespondWithConflict", func(t *testing.T) {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)

		message := "Username already exists"
		RespondWithConflict(c, message)

		if w.Code != http.StatusConflict {
			t.Errorf("Expected status %d, got %d", http.StatusConflict, w.Code)
		}

		var response models.APIResponse
		err := json.Unmarshal(w.Body.Bytes(), &response)
		if err != nil {
			t.Errorf("Failed to unmarshal response: %v", err)
			return
		}

		if response.Error != message {
			t.Errorf("Expected error message %s, got %s", message, response.Error)
		}
	})
}

func TestValidationHelpers(t *testing.T) {
	t.Run("ValidateRequired", func(t *testing.T) {
		tests := []struct {
			name        string
			value       interface{}
			fieldName   string
			shouldError bool
			description string
		}{
			{
				name:        "valid_string",
				value:       "test",
				fieldName:   "username",
				shouldError: false,
				description: "Should pass for non-empty string",
			},
			{
				name:        "empty_string",
				value:       "",
				fieldName:   "email",
				shouldError: true,
				description: "Should fail for empty string",
			},
			{
				name:        "nil_value",
				value:       nil,
				fieldName:   "password",
				shouldError: true,
				description: "Should fail for nil value",
			},
			{
				name:        "non_string_value",
				value:       123,
				fieldName:   "number",
				shouldError: false,
				description: "Should pass for non-string, non-nil value",
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				err := ValidateRequired(tt.value, tt.fieldName)

				if tt.shouldError {
					if err == nil {
						t.Errorf("%s: expected error but got none", tt.description)
						return
					}

					if err.Code != ErrCodeValidation {
						t.Errorf("%s: expected error code %s, got %s", tt.description, ErrCodeValidation, err.Code)
					}

					expectedMessage := fmt.Sprintf("%s is required", tt.fieldName)
					if err.Message != expectedMessage {
						t.Errorf("%s: expected error message %s, got %s", tt.description, expectedMessage, err.Message)
					}
				} else {
					if err != nil {
						t.Errorf("%s: expected no error but got %v", tt.description, err)
					}
				}
			})
		}
	})

	t.Run("ValidateLength", func(t *testing.T) {
		tests := []struct {
			name        string
			value       string
			fieldName   string
			minLen      int
			maxLen      int
			shouldError bool
			expectedMsg string
			description string
		}{
			{
				name:        "valid_length",
				value:       "testuser",
				fieldName:   "username",
				minLen:      3,
				maxLen:      20,
				shouldError: false,
				description: "Should pass for valid length",
			},
			{
				name:        "too_short",
				value:       "ab",
				fieldName:   "username",
				minLen:      3,
				maxLen:      20,
				shouldError: true,
				expectedMsg: "username must be at least 3 characters long",
				description: "Should fail for too short value",
			},
			{
				name:        "too_long",
				value:       "verylongusernamethatexceedslimit",
				fieldName:   "username",
				minLen:      3,
				maxLen:      20,
				shouldError: true,
				expectedMsg: "username must not exceed 20 characters",
				description: "Should fail for too long value",
			},
			{
				name:        "no_max_limit",
				value:       "verylongusernamethatwouldnormallyexceedlimits",
				fieldName:   "description",
				minLen:      5,
				maxLen:      0, // No max limit
				shouldError: false,
				description: "Should pass when maxLen is 0 (no limit)",
			},
			{
				name:        "exactly_min_length",
				value:       "abc",
				fieldName:   "code",
				minLen:      3,
				maxLen:      10,
				shouldError: false,
				description: "Should pass for exactly minimum length",
			},
			{
				name:        "exactly_max_length",
				value:       "abcdefghij",
				fieldName:   "code",
				minLen:      3,
				maxLen:      10,
				shouldError: false,
				description: "Should pass for exactly maximum length",
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				err := ValidateLength(tt.value, tt.fieldName, tt.minLen, tt.maxLen)

				if tt.shouldError {
					if err == nil {
						t.Errorf("%s: expected error but got none", tt.description)
						return
					}

					if err.Code != ErrCodeValidation {
						t.Errorf("%s: expected error code %s, got %s", tt.description, ErrCodeValidation, err.Code)
					}

					if err.Message != tt.expectedMsg {
						t.Errorf("%s: expected error message %s, got %s", tt.description, tt.expectedMsg, err.Message)
					}
				} else {
					if err != nil {
						t.Errorf("%s: expected no error but got %v", tt.description, err)
					}
				}
			})
		}
	})

	t.Run("ValidateUsernameFormat", func(t *testing.T) {
		tests := []struct {
			name        string
			username    string
			shouldError bool
			expectedErr ErrorCode
			description string
		}{
			{
				name:        "valid_username",
				username:    "testuser123",
				shouldError: false,
				description: "Should pass for valid username",
			},
			{
				name:        "valid_with_underscore",
				username:    "test_user_123",
				shouldError: false,
				description: "Should pass for username with underscores",
			},
			{
				name:        "empty_username",
				username:    "",
				shouldError: true,
				expectedErr: ErrCodeValidation,
				description: "Should fail for empty username",
			},
			{
				name:        "too_short_username",
				username:    "ab",
				shouldError: true,
				expectedErr: ErrCodeValidation,
				description: "Should fail for too short username",
			},
			{
				name:        "too_long_username",
				username:    "verylongusernamethatexceedsthirtychars",
				shouldError: true,
				expectedErr: ErrCodeValidation,
				description: "Should fail for too long username",
			},
			{
				name:        "invalid_chars_hyphen",
				username:    "test-user",
				shouldError: true,
				expectedErr: ErrCodeInvalidUsername,
				description: "Should fail for username with hyphen",
			},
			{
				name:        "invalid_chars_space",
				username:    "test user",
				shouldError: true,
				expectedErr: ErrCodeInvalidUsername,
				description: "Should fail for username with space",
			},
			{
				name:        "invalid_chars_special",
				username:    "test@user",
				shouldError: true,
				expectedErr: ErrCodeInvalidUsername,
				description: "Should fail for username with special characters",
			},
			{
				name:        "uppercase_letters",
				username:    "TestUser123",
				shouldError: false,
				description: "Should pass for username with uppercase letters",
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				err := ValidateUsernameFormat(tt.username)

				if tt.shouldError {
					if err == nil {
						t.Errorf("%s: expected error but got none", tt.description)
						return
					}

					if err.Code != tt.expectedErr {
						t.Errorf("%s: expected error code %s, got %s", tt.description, tt.expectedErr, err.Code)
					}
				} else {
					if err != nil {
						t.Errorf("%s: expected no error but got %v", tt.description, err)
					}
				}
			})
		}
	})
}

func TestIsAppError(t *testing.T) {
	tests := []struct {
		name        string
		err         error
		expectApp   bool
		description string
	}{
		{
			name:        "app_error",
			err:         New(ErrCodeValidation, "Test error"),
			expectApp:   true,
			description: "Should identify AppError correctly",
		},
		{
			name:        "standard_error",
			err:         errors.New("standard error"),
			expectApp:   false,
			description: "Should not identify standard error as AppError",
		},
		{
			name:        "nil_error",
			err:         nil,
			expectApp:   false,
			description: "Should handle nil error",
		},
		{
			name:        "wrapped_app_error",
			err:         Wrap(errors.New("original"), ErrCodeInternal, "wrapped error"),
			expectApp:   true,
			description: "Should identify wrapped AppError correctly",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			appErr, isApp := IsAppError(tt.err)

			if isApp != tt.expectApp {
				t.Errorf("%s: expected isApp=%v, got %v", tt.description, tt.expectApp, isApp)
			}

			if tt.expectApp {
				if appErr == nil {
					t.Errorf("%s: expected non-nil AppError when isApp=true", tt.description)
				} else if appErr != tt.err {
					t.Errorf("%s: expected AppError to be the same instance", tt.description)
				}
			} else {
				if appErr != nil {
					t.Errorf("%s: expected nil AppError when isApp=false", tt.description)
				}
			}
		})
	}
}

func TestHandleError(t *testing.T) {
	t.Run("handle_app_error", func(t *testing.T) {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)

		appErr := New(ErrCodeValidation, "Validation failed")
		HandleError(c, appErr)

		if w.Code != http.StatusBadRequest {
			t.Errorf("Expected status %d, got %d", http.StatusBadRequest, w.Code)
		}

		var response models.APIResponse
		err := json.Unmarshal(w.Body.Bytes(), &response)
		if err != nil {
			t.Errorf("Failed to unmarshal response: %v", err)
			return
		}

		if response.Error != appErr.Message {
			t.Errorf("Expected error message %s, got %s", appErr.Message, response.Error)
		}
	})

	t.Run("handle_standard_error", func(t *testing.T) {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)

		stdErr := errors.New("database connection failed")
		HandleError(c, stdErr)

		if w.Code != http.StatusInternalServerError {
			t.Errorf("Expected status %d, got %d", http.StatusInternalServerError, w.Code)
		}

		var response models.APIResponse
		err := json.Unmarshal(w.Body.Bytes(), &response)
		if err != nil {
			t.Errorf("Failed to unmarshal response: %v", err)
			return
		}

		expectedMessage := "An unexpected error occurred"
		if response.Error != expectedMessage {
			t.Errorf("Expected error message %s, got %s", expectedMessage, response.Error)
		}

		// Check that the original error is wrapped
		data, ok := response.Data.(map[string]interface{})
		if !ok {
			t.Error("Expected data to be map[string]interface{}")
			return
		}

		if data["code"] != string(ErrCodeInternal) {
			t.Errorf("Expected code %s, got %v", ErrCodeInternal, data["code"])
		}
	})
}

func TestPredefinedErrors(t *testing.T) {
	tests := []struct {
		name         string
		err          *AppError
		expectCode   ErrorCode
		expectStatus int
		description  string
	}{
		{"ErrInternal", ErrInternal, ErrCodeInternal, http.StatusInternalServerError, "Internal error"},
		{"ErrNotFound", ErrNotFound, ErrCodeNotFound, http.StatusNotFound, "Not found error"},
		{"ErrUnauthorized", ErrUnauthorized, ErrCodeUnauthorized, http.StatusUnauthorized, "Unauthorized error"},
		{"ErrForbidden", ErrForbidden, ErrCodeForbidden, http.StatusForbidden, "Forbidden error"},
		{"ErrValidation", ErrValidation, ErrCodeValidation, http.StatusBadRequest, "Validation error"},
		{"ErrUserNotFound", ErrUserNotFound, ErrCodeUserNotFound, http.StatusNotFound, "User not found error"},
		{"ErrUserExists", ErrUserExists, ErrCodeUserExists, http.StatusConflict, "User exists error"},
		{"ErrInvalidPassword", ErrInvalidPassword, ErrCodeInvalidPassword, http.StatusUnauthorized, "Invalid password error"},
		{"ErrInvalidToken", ErrInvalidToken, ErrCodeInvalidToken, http.StatusUnauthorized, "Invalid token error"},
		{"ErrDatabaseError", ErrDatabaseError, ErrCodeDatabaseError, http.StatusInternalServerError, "Database error"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.err.Code != tt.expectCode {
				t.Errorf("%s: expected code %s, got %s", tt.description, tt.expectCode, tt.err.Code)
			}

			if tt.err.StatusCode != tt.expectStatus {
				t.Errorf("%s: expected status %d, got %d", tt.description, tt.expectStatus, tt.err.StatusCode)
			}

			if tt.err.Message == "" {
				t.Errorf("%s: expected non-empty message", tt.description)
			}
		})
	}
}

// Benchmark tests
func BenchmarkNewAppError(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_ = New(ErrCodeValidation, "Test error")
	}
}

func BenchmarkNewfAppError(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_ = Newf(ErrCodeValidation, "Error %d occurred", i)
	}
}

func BenchmarkWrapError(b *testing.B) {
	originalErr := errors.New("original error")
	for i := 0; i < b.N; i++ {
		_ = Wrap(originalErr, ErrCodeInternal, "Wrapped error")
	}
}

func BenchmarkValidateRequired(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_ = ValidateRequired("test", "field")
	}
}

func BenchmarkValidateLength(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_ = ValidateLength("testuser", "username", 3, 20)
	}
}
