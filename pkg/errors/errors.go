package errors

import (
	"fmt"
	"net/http"

	"github.com/facuhernandez99/blog/pkg/models"
	"github.com/gin-gonic/gin"
)

// ErrorCode represents a unique error code for application errors
type ErrorCode string

// Application error codes
const (
	// General errors
	ErrCodeInternal     ErrorCode = "INTERNAL_ERROR"
	ErrCodeNotFound     ErrorCode = "NOT_FOUND"
	ErrCodeValidation   ErrorCode = "VALIDATION_ERROR"
	ErrCodeUnauthorized ErrorCode = "UNAUTHORIZED"
	ErrCodeForbidden    ErrorCode = "FORBIDDEN"
	ErrCodeConflict     ErrorCode = "CONFLICT"
	ErrCodeBadRequest   ErrorCode = "BAD_REQUEST"

	// User-related errors
	ErrCodeUserNotFound    ErrorCode = "USER_NOT_FOUND"
	ErrCodeUserExists      ErrorCode = "USER_ALREADY_EXISTS"
	ErrCodeInvalidPassword ErrorCode = "INVALID_PASSWORD"
	ErrCodeWeakPassword    ErrorCode = "WEAK_PASSWORD"
	ErrCodeInvalidUsername ErrorCode = "INVALID_USERNAME"
	ErrCodeEmailExists     ErrorCode = "EMAIL_ALREADY_EXISTS"
	ErrCodeUsernameExists  ErrorCode = "USERNAME_ALREADY_EXISTS"

	// Authentication errors
	ErrCodeInvalidToken     ErrorCode = "INVALID_TOKEN"
	ErrCodeTokenExpired     ErrorCode = "TOKEN_EXPIRED"
	ErrCodeTokenMalformed   ErrorCode = "TOKEN_MALFORMED"
	ErrCodeInvalidSignature ErrorCode = "INVALID_SIGNATURE"
	ErrCodeMissingToken     ErrorCode = "MISSING_TOKEN"

	// Database errors
	ErrCodeDatabaseError    ErrorCode = "DATABASE_ERROR"
	ErrCodeConnectionFailed ErrorCode = "CONNECTION_FAILED"
	ErrCodeQueryFailed      ErrorCode = "QUERY_FAILED"

	// Post-related errors (future use)
	ErrCodePostNotFound    ErrorCode = "POST_NOT_FOUND"
	ErrCodeInvalidPostData ErrorCode = "INVALID_POST_DATA"
	ErrCodePostExists      ErrorCode = "POST_ALREADY_EXISTS"
)

// AppError represents a custom application error
type AppError struct {
	Code       ErrorCode `json:"code"`
	Message    string    `json:"message"`
	Details    string    `json:"details,omitempty"`
	StatusCode int       `json:"-"`
	Err        error     `json:"-"`
}

// Error implements the error interface
func (e *AppError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("%s: %s (%v)", e.Code, e.Message, e.Err)
	}
	return fmt.Sprintf("%s: %s", e.Code, e.Message)
}

// Unwrap returns the underlying error
func (e *AppError) Unwrap() error {
	return e.Err
}

// New creates a new AppError
func New(code ErrorCode, message string) *AppError {
	return &AppError{
		Code:       code,
		Message:    message,
		StatusCode: getDefaultStatusCode(code),
	}
}

// Newf creates a new AppError with formatted message
func Newf(code ErrorCode, format string, args ...interface{}) *AppError {
	return New(code, fmt.Sprintf(format, args...))
}

// Wrap creates a new AppError wrapping an existing error
func Wrap(err error, code ErrorCode, message string) *AppError {
	return &AppError{
		Code:       code,
		Message:    message,
		StatusCode: getDefaultStatusCode(code),
		Err:        err,
	}
}

// Wrapf creates a new AppError wrapping an existing error with formatted message
func Wrapf(err error, code ErrorCode, format string, args ...interface{}) *AppError {
	return Wrap(err, code, fmt.Sprintf(format, args...))
}

// WithDetails adds details to an existing AppError
func (e *AppError) WithDetails(details string) *AppError {
	e.Details = details
	return e
}

// WithStatusCode overrides the default status code
func (e *AppError) WithStatusCode(statusCode int) *AppError {
	e.StatusCode = statusCode
	return e
}

// getDefaultStatusCode returns the default HTTP status code for an error code
func getDefaultStatusCode(code ErrorCode) int {
	switch code {
	case ErrCodeNotFound, ErrCodeUserNotFound, ErrCodePostNotFound:
		return http.StatusNotFound
	case ErrCodeValidation, ErrCodeBadRequest, ErrCodeWeakPassword,
		ErrCodeInvalidUsername, ErrCodeInvalidPostData, ErrCodeTokenMalformed:
		return http.StatusBadRequest
	case ErrCodeUnauthorized, ErrCodeInvalidPassword, ErrCodeInvalidToken,
		ErrCodeTokenExpired, ErrCodeInvalidSignature, ErrCodeMissingToken:
		return http.StatusUnauthorized
	case ErrCodeForbidden:
		return http.StatusForbidden
	case ErrCodeConflict, ErrCodeUserExists, ErrCodeEmailExists,
		ErrCodeUsernameExists, ErrCodePostExists:
		return http.StatusConflict
	case ErrCodeDatabaseError, ErrCodeConnectionFailed, ErrCodeQueryFailed, ErrCodeInternal:
		return http.StatusInternalServerError
	default:
		return http.StatusInternalServerError
	}
}

// Predefined common errors
var (
	// General errors
	ErrInternal     = New(ErrCodeInternal, "Internal server error")
	ErrNotFound     = New(ErrCodeNotFound, "Resource not found")
	ErrUnauthorized = New(ErrCodeUnauthorized, "Unauthorized access")
	ErrForbidden    = New(ErrCodeForbidden, "Access forbidden")
	ErrValidation   = New(ErrCodeValidation, "Validation failed")
	ErrBadRequest   = New(ErrCodeBadRequest, "Bad request")

	// User errors
	ErrUserNotFound    = New(ErrCodeUserNotFound, "User not found")
	ErrUserExists      = New(ErrCodeUserExists, "User already exists")
	ErrInvalidPassword = New(ErrCodeInvalidPassword, "Invalid password")
	ErrWeakPassword    = New(ErrCodeWeakPassword, "Password does not meet strength requirements")
	ErrInvalidUsername = New(ErrCodeInvalidUsername, "Invalid username format")
	ErrEmailExists     = New(ErrCodeEmailExists, "Email address already in use")
	ErrUsernameExists  = New(ErrCodeUsernameExists, "Username already taken")

	// Auth errors
	ErrInvalidToken     = New(ErrCodeInvalidToken, "Invalid authentication token")
	ErrTokenExpired     = New(ErrCodeTokenExpired, "Authentication token has expired")
	ErrTokenMalformed   = New(ErrCodeTokenMalformed, "Malformed authentication token")
	ErrInvalidSignature = New(ErrCodeInvalidSignature, "Invalid token signature")
	ErrMissingToken     = New(ErrCodeMissingToken, "Authentication token required")

	// Database errors
	ErrDatabaseError    = New(ErrCodeDatabaseError, "Database operation failed")
	ErrConnectionFailed = New(ErrCodeConnectionFailed, "Database connection failed")
	ErrQueryFailed      = New(ErrCodeQueryFailed, "Database query failed")
)

// Response helpers

// RespondWithError sends an error response using the AppError
func RespondWithError(c *gin.Context, err *AppError) {
	c.JSON(err.StatusCode, models.APIResponse{
		Success: false,
		Error:   err.Message,
		Data: map[string]interface{}{
			"code":    err.Code,
			"details": err.Details,
		},
	})
}

// RespondWithErrorCode sends an error response using an error code and message
func RespondWithErrorCode(c *gin.Context, code ErrorCode, message string) {
	err := New(code, message)
	RespondWithError(c, err)
}

// RespondWithInternalError sends a generic internal server error response
func RespondWithInternalError(c *gin.Context) {
	RespondWithError(c, ErrInternal)
}

// RespondWithValidationError sends a validation error response with details
func RespondWithValidationError(c *gin.Context, details string) {
	err := ErrValidation.WithDetails(details)
	RespondWithError(c, err)
}

// RespondWithNotFound sends a not found error response
func RespondWithNotFound(c *gin.Context, resource string) {
	err := Newf(ErrCodeNotFound, "%s not found", resource)
	RespondWithError(c, err)
}

// RespondWithUnauthorized sends an unauthorized error response
func RespondWithUnauthorized(c *gin.Context, message string) {
	err := New(ErrCodeUnauthorized, message)
	RespondWithError(c, err)
}

// RespondWithConflict sends a conflict error response
func RespondWithConflict(c *gin.Context, message string) {
	err := New(ErrCodeConflict, message)
	RespondWithError(c, err)
}

// Helper functions for converting standard errors to AppErrors

// IsAppError checks if an error is an AppError
func IsAppError(err error) (*AppError, bool) {
	if appErr, ok := err.(*AppError); ok {
		return appErr, true
	}
	return nil, false
}

// HandleError converts any error to an AppError and responds with it
func HandleError(c *gin.Context, err error) {
	if appErr, ok := IsAppError(err); ok {
		RespondWithError(c, appErr)
		return
	}

	// For non-AppError errors, wrap them as internal errors
	appErr := Wrap(err, ErrCodeInternal, "An unexpected error occurred")
	RespondWithError(c, appErr)
}

// Validation helpers

// ValidateRequired checks if a value is present and returns an AppError if not
func ValidateRequired(value interface{}, fieldName string) *AppError {
	switch v := value.(type) {
	case string:
		if v == "" {
			return Newf(ErrCodeValidation, "%s is required", fieldName)
		}
	case nil:
		return Newf(ErrCodeValidation, "%s is required", fieldName)
	}
	return nil
}

// ValidateLength checks string length constraints
func ValidateLength(value string, fieldName string, minLen, maxLen int) *AppError {
	if len(value) < minLen {
		return Newf(ErrCodeValidation, "%s must be at least %d characters long", fieldName, minLen)
	}
	if maxLen > 0 && len(value) > maxLen {
		return Newf(ErrCodeValidation, "%s must not exceed %d characters", fieldName, maxLen)
	}
	return nil
}

// ValidateUsernameFormat validates username format
func ValidateUsernameFormat(username string) *AppError {
	if err := ValidateRequired(username, "username"); err != nil {
		return err
	}

	if err := ValidateLength(username, "username", 3, 30); err != nil {
		return err
	}

	// Add more specific username validation as needed
	// For example: alphanumeric + underscore only
	for _, char := range username {
		if !((char >= 'a' && char <= 'z') ||
			(char >= 'A' && char <= 'Z') ||
			(char >= '0' && char <= '9') ||
			char == '_') {
			return New(ErrCodeInvalidUsername, "Username can only contain letters, numbers, and underscores")
		}
	}

	return nil
}
