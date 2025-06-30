package logging

import (
	"errors"
	"fmt"
	"regexp"
	"strings"

	apperrors "github.com/facuhernandez99/blog/pkg/errors"
)

// ErrorSanitizer handles sanitization of sensitive information in errors
type ErrorSanitizer struct {
	production        bool
	sensitivePatterns []*regexp.Regexp
	replacements      map[string]string
}

// NewErrorSanitizer creates a new error sanitizer
func NewErrorSanitizer(production bool) *ErrorSanitizer {
	sanitizer := &ErrorSanitizer{
		production: production,
		replacements: map[string]string{
			"password":   "[REDACTED]",
			"secret":     "[REDACTED]",
			"token":      "[REDACTED]",
			"key":        "[REDACTED]",
			"credential": "[REDACTED]",
			"auth":       "[REDACTED]",
		},
	}

	// Compile sensitive data patterns
	if production {
		patterns := []string{
			// Credit card numbers
			`\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b`,
			// Social security numbers
			`\b\d{3}-\d{2}-\d{4}\b`,
			// Email addresses (partial redaction)
			`\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b`,
			// Phone numbers
			`\b\d{3}[-.]?\d{3}[-.]?\d{4}\b`,
			// IP addresses (partial redaction)
			`\b(?:\d{1,3}\.){3}\d{1,3}\b`,
			// URLs with potential sensitive query params
			`\b(?:https?|ftp)://[^\s/$.?#].[^\s]*[?&](?:password|token|key|secret|auth)[^&\s]*`,
			// JWT tokens
			`\beyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*\b`,
			// API keys (common patterns)
			`\b[a-zA-Z0-9]{32,}\b`,
			// SQL injection attempts
			`(?i)\b(?:union|select|insert|update|delete|drop|create|alter)\s+`,
		}

		for _, pattern := range patterns {
			if compiled, err := regexp.Compile(pattern); err == nil {
				sanitizer.sensitivePatterns = append(sanitizer.sensitivePatterns, compiled)
			}
		}
	}

	return sanitizer
}

// Sanitize sanitizes an error for safe logging
func (s *ErrorSanitizer) Sanitize(err error) error {
	if err == nil {
		return nil
	}

	// Handle application errors specially
	if appErr, ok := apperrors.IsAppError(err); ok {
		return s.sanitizeAppError(appErr)
	}

	// For regular errors, sanitize the message
	message := err.Error()
	sanitizedMessage := s.sanitizeString(message)

	if sanitizedMessage != message {
		return errors.New(sanitizedMessage)
	}

	return err
}

// sanitizeAppError sanitizes application-specific errors
func (s *ErrorSanitizer) sanitizeAppError(appErr *apperrors.AppError) error {
	// In production, don't expose internal error details
	if s.production {
		switch appErr.Code {
		case apperrors.ErrCodeInternal,
			apperrors.ErrCodeDatabaseError,
			apperrors.ErrCodeConnectionFailed,
			apperrors.ErrCodeQueryFailed:
			return apperrors.New(appErr.Code, "Internal server error")
		case apperrors.ErrCodeInvalidToken,
			apperrors.ErrCodeTokenExpired,
			apperrors.ErrCodeTokenMalformed,
			apperrors.ErrCodeInvalidSignature:
			return apperrors.New(appErr.Code, "Authentication failed")
		}
	}

	// Sanitize the error message and details
	sanitizedMessage := s.sanitizeString(appErr.Message)
	sanitizedDetails := s.sanitizeString(appErr.Details)

	newErr := apperrors.New(appErr.Code, sanitizedMessage)
	if sanitizedDetails != "" && sanitizedDetails != appErr.Details {
		newErr = newErr.WithDetails(sanitizedDetails)
	} else if !s.production && appErr.Details != "" {
		newErr = newErr.WithDetails(appErr.Details)
	}

	return newErr.WithStatusCode(appErr.StatusCode)
}

// sanitizeString removes sensitive information from a string
func (s *ErrorSanitizer) sanitizeString(input string) string {
	if input == "" {
		return input
	}

	result := input

	// First, normalize authentication-related words
	authPattern := `(?i)\bauthenticat[a-z]*\b`
	if re, err := regexp.Compile(authPattern); err == nil {
		result = re.ReplaceAllString(result, "auth")
	}

	// Then handle sensitive keyword patterns
	for keyword, replacement := range s.replacements {
		// Pattern 1: Match "keyword: value" format
		pattern1 := fmt.Sprintf(`(?i)\b%s\s*:\s*[^\s,;)}\]]+`, keyword)
		if re, err := regexp.Compile(pattern1); err == nil {
			result = re.ReplaceAllString(result, keyword+": "+replacement)
		}

		// Pattern 2: Match standalone keywords followed by sensitive data (for key/password)
		if keyword == "password" || keyword == "key" {
			// Match patterns like "password secret123" or "key sk_test_12345"
			pattern2 := fmt.Sprintf(`(?i)\b%s\s+[a-zA-Z0-9_\-]+`, keyword)
			if re, err := regexp.Compile(pattern2); err == nil {
				result = re.ReplaceAllString(result, keyword+": "+replacement)
			}
		}
	}

	// Special case: Handle "auth WORD" pattern (after normalization)
	authWordPattern := `(?i)\bauth\s+[a-zA-Z]+`
	if re, err := regexp.Compile(authWordPattern); err == nil {
		result = re.ReplaceAllString(result, "auth: [REDACTED]")
	}

	// Apply regex patterns for production
	if s.production {
		for _, pattern := range s.sensitivePatterns {
			result = pattern.ReplaceAllStringFunc(result, func(match string) string {
				switch {
				case strings.Contains(strings.ToLower(match), "@"):
					// Email: show first 2 chars and domain
					parts := strings.Split(match, "@")
					if len(parts) == 2 && len(parts[0]) > 2 {
						return parts[0][:2] + "***@" + parts[1]
					}
					return "***@" + parts[1]
				case strings.Contains(match, "."):
					// IP address: show first octet only
					parts := strings.Split(match, ".")
					if len(parts) == 4 {
						return parts[0] + ".***.***.***"
					}
					return "[REDACTED]"
				case len(match) > 8:
					// Long strings (API keys, tokens): show first 4 chars
					return match[:4] + "..." + "[REDACTED]"
				default:
					return "[REDACTED]"
				}
			})
		}
	}

	return result
}

// SanitizeMap sanitizes a map of values (useful for request/response logging)
func (s *ErrorSanitizer) SanitizeMap(data map[string]interface{}) map[string]interface{} {
	if data == nil {
		return nil
	}

	sanitized := make(map[string]interface{})
	for key, value := range data {
		sanitized[key] = s.sanitizeValue(key, value)
	}

	return sanitized
}

// sanitizeValue sanitizes a single value based on its key and content
func (s *ErrorSanitizer) sanitizeValue(key string, value interface{}) interface{} {
	keyLower := strings.ToLower(key)

	// Check if key contains sensitive keywords
	for keyword := range s.replacements {
		if strings.Contains(keyLower, keyword) {
			return s.replacements[keyword]
		}
	}

	// Sanitize string values
	if str, ok := value.(string); ok {
		return s.sanitizeString(str)
	}

	// Recursively sanitize nested maps
	if mapValue, ok := value.(map[string]interface{}); ok {
		return s.SanitizeMap(mapValue)
	}

	// Recursively sanitize slices
	if slice, ok := value.([]interface{}); ok {
		sanitized := make([]interface{}, len(slice))
		for i, item := range slice {
			sanitized[i] = s.sanitizeValue(fmt.Sprintf("%s[%d]", key, i), item)
		}
		return sanitized
	}

	return value
}

// IsSensitiveError checks if an error contains sensitive information
func (s *ErrorSanitizer) IsSensitiveError(err error) bool {
	if err == nil {
		return false
	}

	message := strings.ToLower(err.Error())
	for keyword := range s.replacements {
		if strings.Contains(message, keyword) {
			return true
		}
	}

	// Check against regex patterns
	if s.production {
		for _, pattern := range s.sensitivePatterns {
			if pattern.MatchString(err.Error()) {
				return true
			}
		}
	}

	return false
}
