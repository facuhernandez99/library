package http

import (
	"net/mail"
	"regexp"
	"strings"
	"unicode"

	"github.com/gin-gonic/gin"
	"github.com/go-playground/validator/v10"
)

var (
	// Common validation patterns
	alphanumericRegex = regexp.MustCompile(`^[a-zA-Z0-9]+$`)
	phoneRegex        = regexp.MustCompile(`^\+?[1-9]\d{1,14}$`)
	urlRegex          = regexp.MustCompile(`^https?://[^\s]+$`)
	slugRegex         = regexp.MustCompile(`^[a-z0-9]+(?:-[a-z0-9]+)*$`)
)

// ValidationConfig holds validation configuration
type ValidationConfig struct {
	MaxStringLength  int
	MaxFileSize      int64
	AllowedMimeTypes []string
}

// DefaultValidationConfig returns default validation configuration
func DefaultValidationConfig() *ValidationConfig {
	return &ValidationConfig{
		MaxStringLength: 1000,
		MaxFileSize:     10 * 1024 * 1024, // 10MB
		AllowedMimeTypes: []string{
			"image/jpeg",
			"image/png",
			"image/gif",
			"application/pdf",
			"text/plain",
		},
	}
}

// ValidationError represents a validation error
type ValidationError struct {
	Field   string `json:"field"`
	Message string `json:"message"`
	Code    string `json:"code"`
}

// ValidationErrors holds multiple validation errors
type ValidationErrors struct {
	Errors []ValidationError `json:"errors"`
}

// Error implements the error interface
func (ve ValidationErrors) Error() string {
	if len(ve.Errors) == 0 {
		return "validation failed"
	}
	return ve.Errors[0].Message
}

// AddError adds a new validation error
func (ve *ValidationErrors) AddError(field, message, code string) {
	ve.Errors = append(ve.Errors, ValidationError{
		Field:   field,
		Message: message,
		Code:    code,
	})
}

// HasErrors returns true if there are validation errors
func (ve *ValidationErrors) HasErrors() bool {
	return len(ve.Errors) > 0
}

// SanitizeString performs basic string sanitization
func SanitizeString(input string) string {
	// Remove leading/trailing whitespace
	sanitized := strings.TrimSpace(input)

	// Remove null bytes
	sanitized = strings.ReplaceAll(sanitized, "\x00", "")

	// Normalize unicode
	sanitized = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) && r != '\n' && r != '\r' && r != '\t' {
			return -1
		}
		return r
	}, sanitized)

	return sanitized
}

// SanitizeHTML performs basic HTML sanitization (removes tags)
func SanitizeHTML(input string) string {
	// Remove HTML tags using regex
	htmlTagRegex := regexp.MustCompile(`<[^>]*>`)
	return htmlTagRegex.ReplaceAllString(input, "")
}

// ValidateEmail validates email format
func ValidateEmail(email string) bool {
	email = SanitizeString(email)
	_, err := mail.ParseAddress(email)
	return err == nil
}

// ValidatePhone validates phone number format
func ValidatePhone(phone string) bool {
	phone = SanitizeString(phone)
	return phoneRegex.MatchString(phone)
}

// ValidateURL validates URL format
func ValidateURL(url string) bool {
	url = SanitizeString(url)
	return urlRegex.MatchString(url)
}

// ValidateAlphanumeric validates alphanumeric strings
func ValidateAlphanumeric(input string) bool {
	input = SanitizeString(input)
	return alphanumericRegex.MatchString(input)
}

// ValidateSlug validates URL-friendly slugs
func ValidateSlug(slug string) bool {
	slug = SanitizeString(strings.ToLower(slug))
	return slugRegex.MatchString(slug)
}

// ValidateStringLength validates string length
func ValidateStringLength(input string, min, max int) bool {
	length := len(strings.TrimSpace(input))
	return length >= min && length <= max
}

// ValidateRequired checks if a field is not empty
func ValidateRequired(input string) bool {
	return strings.TrimSpace(input) != ""
}

// ValidatePasswordStrength validates password strength
func ValidatePasswordStrength(password string) *ValidationErrors {
	errors := &ValidationErrors{}

	if len(password) < 8 {
		errors.AddError("password", "Password must be at least 8 characters long", "min_length")
	}

	if len(password) > 128 {
		errors.AddError("password", "Password must be at most 128 characters long", "max_length")
	}

	hasUpper := false
	hasLower := false
	hasDigit := false
	hasSpecial := false

	for _, char := range password {
		switch {
		case unicode.IsUpper(char):
			hasUpper = true
		case unicode.IsLower(char):
			hasLower = true
		case unicode.IsDigit(char):
			hasDigit = true
		case unicode.IsPunct(char) || unicode.IsSymbol(char):
			hasSpecial = true
		}
	}

	if !hasUpper {
		errors.AddError("password", "Password must contain at least one uppercase letter", "missing_uppercase")
	}

	if !hasLower {
		errors.AddError("password", "Password must contain at least one lowercase letter", "missing_lowercase")
	}

	if !hasDigit {
		errors.AddError("password", "Password must contain at least one digit", "missing_digit")
	}

	if !hasSpecial {
		errors.AddError("password", "Password must contain at least one special character", "missing_special")
	}

	return errors
}

// ValidationMiddleware provides request validation middleware
func ValidationMiddleware(config *ValidationConfig) gin.HandlerFunc {
	if config == nil {
		config = DefaultValidationConfig()
	}

	return gin.HandlerFunc(func(c *gin.Context) {
		// Validate content length
		if c.Request.ContentLength > config.MaxFileSize {
			RespondWithError(c, 413, "Request body too large")
			c.Abort()
			return
		}

		// Validate content type for POST/PUT/PATCH requests
		if c.Request.Method == "POST" || c.Request.Method == "PUT" || c.Request.Method == "PATCH" {
			contentType := c.GetHeader("Content-Type")
			if contentType == "" {
				RespondWithError(c, 400, "Content-Type header is required")
				c.Abort()
				return
			}
		}

		c.Next()
	})
}

// ValidateStruct validates a struct using the validator package
func ValidateStruct(s interface{}) *ValidationErrors {
	validate := validator.New()
	errors := &ValidationErrors{}

	err := validate.Struct(s)
	if err != nil {
		for _, err := range err.(validator.ValidationErrors) {
			errors.AddError(
				strings.ToLower(err.Field()),
				formatValidationMessage(err),
				err.Tag(),
			)
		}
	}

	return errors
}

// formatValidationMessage formats validation error messages
func formatValidationMessage(err validator.FieldError) string {
	switch err.Tag() {
	case "required":
		return err.Field() + " is required"
	case "email":
		return err.Field() + " must be a valid email address"
	case "min":
		return err.Field() + " must be at least " + err.Param() + " characters"
	case "max":
		return err.Field() + " must be at most " + err.Param() + " characters"
	case "len":
		return err.Field() + " must be exactly " + err.Param() + " characters"
	case "gt":
		return err.Field() + " must be greater than " + err.Param()
	case "gte":
		return err.Field() + " must be greater than or equal to " + err.Param()
	case "lt":
		return err.Field() + " must be less than " + err.Param()
	case "lte":
		return err.Field() + " must be less than or equal to " + err.Param()
	case "alphanum":
		return err.Field() + " must contain only alphanumeric characters"
	case "url":
		return err.Field() + " must be a valid URL"
	default:
		return err.Field() + " is invalid"
	}
}

// SanitizeAndValidateInput combines sanitization and validation
func SanitizeAndValidateInput(input map[string]interface{}, rules map[string][]string) (*map[string]interface{}, *ValidationErrors) {
	sanitized := make(map[string]interface{})
	errors := &ValidationErrors{}

	for field, value := range input {
		stringValue, ok := value.(string)
		if !ok {
			sanitized[field] = value
			continue
		}

		// Sanitize the string value
		sanitizedValue := SanitizeString(stringValue)

		// Apply validation rules
		fieldRules, hasRules := rules[field]
		if hasRules {
			for _, rule := range fieldRules {
				if !applyValidationRule(sanitizedValue, rule) {
					errors.AddError(field, "Field "+field+" failed validation rule: "+rule, rule)
				}
			}
		}

		sanitized[field] = sanitizedValue
	}

	return &sanitized, errors
}

// applyValidationRule applies a single validation rule
func applyValidationRule(value string, rule string) bool {
	switch rule {
	case "required":
		return ValidateRequired(value)
	case "email":
		return ValidateEmail(value)
	case "phone":
		return ValidatePhone(value)
	case "url":
		return ValidateURL(value)
	case "alphanumeric":
		return ValidateAlphanumeric(value)
	case "slug":
		return ValidateSlug(value)
	default:
		return true // Unknown rule passes by default
	}
}

// BindAndValidate binds request data and validates it
func BindAndValidate(c *gin.Context, obj interface{}) *ValidationErrors {
	if err := c.ShouldBindJSON(obj); err != nil {
		errors := &ValidationErrors{}
		errors.AddError("request", "Invalid JSON format: "+err.Error(), "invalid_json")
		return errors
	}

	return ValidateStruct(obj)
}
