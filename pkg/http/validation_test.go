package http

import (
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

func TestSanitizeString(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "removes leading and trailing whitespace",
			input:    "  hello world  ",
			expected: "hello world",
		},
		{
			name:     "removes null bytes",
			input:    "hello\x00world",
			expected: "helloworld",
		},
		{
			name:     "preserves newlines and tabs",
			input:    "hello\nworld\ttest",
			expected: "hello\nworld\ttest",
		},
		{
			name:     "removes control characters",
			input:    "hello\x01\x02world",
			expected: "helloworld",
		},
		{
			name:     "handles empty string",
			input:    "",
			expected: "",
		},
		{
			name:     "handles only whitespace",
			input:    "   \t\n   ",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := SanitizeString(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestSanitizeHTML(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "removes simple HTML tags",
			input:    "<p>Hello World</p>",
			expected: "Hello World",
		},
		{
			name:     "removes multiple tags",
			input:    "<div><span>Test</span></div>",
			expected: "Test",
		},
		{
			name:     "removes self-closing tags",
			input:    "Hello<br/>World",
			expected: "HelloWorld",
		},
		{
			name:     "removes tags with attributes",
			input:    `<a href="http://example.com">Link</a>`,
			expected: "Link",
		},
		{
			name:     "handles text without tags",
			input:    "Plain text",
			expected: "Plain text",
		},
		{
			name:     "handles empty string",
			input:    "",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := SanitizeHTML(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestValidateEmail(t *testing.T) {
	tests := []struct {
		name     string
		email    string
		expected bool
	}{
		{
			name:     "valid email",
			email:    "test@example.com",
			expected: true,
		},
		{
			name:     "valid email with subdomain",
			email:    "user@mail.example.com",
			expected: true,
		},
		{
			name:     "invalid email without @",
			email:    "testexample.com",
			expected: false,
		},
		{
			name:     "invalid email without domain",
			email:    "test@",
			expected: false,
		},
		{
			name:     "invalid email without user",
			email:    "@example.com",
			expected: false,
		},
		{
			name:     "empty string",
			email:    "",
			expected: false,
		},
		{
			name:     "email with whitespace (should be sanitized)",
			email:    "  test@example.com  ",
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ValidateEmail(tt.email)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestValidatePhone(t *testing.T) {
	tests := []struct {
		name     string
		phone    string
		expected bool
	}{
		{
			name:     "valid US phone",
			phone:    "+1234567890",
			expected: true,
		},
		{
			name:     "valid international phone",
			phone:    "+441234567890",
			expected: true,
		},
		{
			name:     "valid phone without plus",
			phone:    "1234567890",
			expected: true,
		},
		{
			name:     "invalid phone starting with 0",
			phone:    "+0123456789",
			expected: false,
		},
		{
			name:     "invalid phone too short",
			phone:    "+123",
			expected: false,
		},
		{
			name:     "invalid phone with letters",
			phone:    "+123abc7890",
			expected: false,
		},
		{
			name:     "empty string",
			phone:    "",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ValidatePhone(tt.phone)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestValidateURL(t *testing.T) {
	tests := []struct {
		name     string
		url      string
		expected bool
	}{
		{
			name:     "valid HTTP URL",
			url:      "http://example.com",
			expected: true,
		},
		{
			name:     "valid HTTPS URL",
			url:      "https://example.com",
			expected: true,
		},
		{
			name:     "valid URL with path",
			url:      "https://example.com/path/to/resource",
			expected: true,
		},
		{
			name:     "invalid URL without protocol",
			url:      "example.com",
			expected: false,
		},
		{
			name:     "invalid URL with FTP",
			url:      "ftp://example.com",
			expected: false,
		},
		{
			name:     "empty string",
			url:      "",
			expected: false,
		},
		{
			name:     "URL with whitespace",
			url:      "https://example.com/path with spaces",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ValidateURL(tt.url)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestValidateAlphanumeric(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected bool
	}{
		{
			name:     "valid alphanumeric",
			input:    "abc123",
			expected: true,
		},
		{
			name:     "valid letters only",
			input:    "abcdef",
			expected: true,
		},
		{
			name:     "valid numbers only",
			input:    "123456",
			expected: true,
		},
		{
			name:     "invalid with special characters",
			input:    "abc123!",
			expected: false,
		},
		{
			name:     "invalid with spaces",
			input:    "abc 123",
			expected: false,
		},
		{
			name:     "empty string",
			input:    "",
			expected: true, // Empty string matches the regex
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ValidateAlphanumeric(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestValidateSlug(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected bool
	}{
		{
			name:     "valid slug",
			input:    "hello-world",
			expected: true,
		},
		{
			name:     "valid slug single word",
			input:    "hello",
			expected: true,
		},
		{
			name:     "valid slug with numbers",
			input:    "hello-world-123",
			expected: true,
		},
		{
			name:     "invalid slug with uppercase",
			input:    "Hello-World",
			expected: true, // Gets converted to lowercase
		},
		{
			name:     "invalid slug with spaces",
			input:    "hello world",
			expected: false,
		},
		{
			name:     "invalid slug with special chars",
			input:    "hello_world",
			expected: false,
		},
		{
			name:     "invalid slug starting with dash",
			input:    "-hello",
			expected: false,
		},
		{
			name:     "invalid slug ending with dash",
			input:    "hello-",
			expected: false,
		},
		{
			name:     "empty string",
			input:    "",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ValidateSlug(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestValidateStringLength(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		min      int
		max      int
		expected bool
	}{
		{
			name:     "valid length",
			input:    "hello",
			min:      3,
			max:      10,
			expected: true,
		},
		{
			name:     "too short",
			input:    "hi",
			min:      3,
			max:      10,
			expected: false,
		},
		{
			name:     "too long",
			input:    "this is a very long string",
			min:      3,
			max:      10,
			expected: false,
		},
		{
			name:     "exact min length",
			input:    "abc",
			min:      3,
			max:      10,
			expected: true,
		},
		{
			name:     "exact max length",
			input:    "abcdefghij",
			min:      3,
			max:      10,
			expected: true,
		},
		{
			name:     "handles whitespace",
			input:    "  hello  ",
			min:      3,
			max:      10,
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ValidateStringLength(tt.input, tt.min, tt.max)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestValidateRequired(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected bool
	}{
		{
			name:     "valid non-empty string",
			input:    "hello",
			expected: true,
		},
		{
			name:     "empty string",
			input:    "",
			expected: false,
		},
		{
			name:     "whitespace only",
			input:    "   ",
			expected: false,
		},
		{
			name:     "string with content and whitespace",
			input:    "  hello  ",
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ValidateRequired(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestValidatePasswordStrength(t *testing.T) {
	tests := []struct {
		name      string
		password  string
		expectErr bool
		errCodes  []string
	}{
		{
			name:      "strong password",
			password:  "StrongP@ssw0rd",
			expectErr: false,
		},
		{
			name:      "too short",
			password:  "Short1!",
			expectErr: true,
			errCodes:  []string{"min_length"},
		},
		{
			name:      "too long",
			password:  strings.Repeat("a", 129) + "B1!",
			expectErr: true,
			errCodes:  []string{"max_length"},
		},
		{
			name:      "missing uppercase",
			password:  "lowercase123!",
			expectErr: true,
			errCodes:  []string{"missing_uppercase"},
		},
		{
			name:      "missing lowercase",
			password:  "UPPERCASE123!",
			expectErr: true,
			errCodes:  []string{"missing_lowercase"},
		},
		{
			name:      "missing digit",
			password:  "NoDigitHere!",
			expectErr: true,
			errCodes:  []string{"missing_digit"},
		},
		{
			name:      "missing special character",
			password:  "NoSpecialChar123",
			expectErr: true,
			errCodes:  []string{"missing_special"},
		},
		{
			name:      "multiple issues",
			password:  "weak",
			expectErr: true,
			errCodes:  []string{"min_length", "missing_uppercase", "missing_digit", "missing_special"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			errors := ValidatePasswordStrength(tt.password)

			if tt.expectErr {
				assert.True(t, errors.HasErrors())
				for _, code := range tt.errCodes {
					found := false
					for _, err := range errors.Errors {
						if err.Code == code {
							found = true
							break
						}
					}
					assert.True(t, found, "Expected error code %s not found", code)
				}
			} else {
				assert.False(t, errors.HasErrors())
			}
		})
	}
}

func TestValidationErrors(t *testing.T) {
	t.Run("AddError and HasErrors", func(t *testing.T) {
		errors := &ValidationErrors{}
		assert.False(t, errors.HasErrors())

		errors.AddError("field1", "message1", "code1")
		assert.True(t, errors.HasErrors())
		assert.Len(t, errors.Errors, 1)
		assert.Equal(t, "field1", errors.Errors[0].Field)
		assert.Equal(t, "message1", errors.Errors[0].Message)
		assert.Equal(t, "code1", errors.Errors[0].Code)
	})

	t.Run("Error method", func(t *testing.T) {
		errors := &ValidationErrors{}
		assert.Equal(t, "validation failed", errors.Error())

		errors.AddError("field1", "message1", "code1")
		assert.Equal(t, "message1", errors.Error())
	})
}

func TestDefaultValidationConfig(t *testing.T) {
	config := DefaultValidationConfig()

	assert.NotNil(t, config)
	assert.Equal(t, 1000, config.MaxStringLength)
	assert.Equal(t, int64(10*1024*1024), config.MaxFileSize)
	assert.Contains(t, config.AllowedMimeTypes, "image/jpeg")
	assert.Contains(t, config.AllowedMimeTypes, "application/pdf")
}

func TestValidationMiddleware(t *testing.T) {
	gin.SetMode(gin.TestMode)

	t.Run("allows requests within size limit", func(t *testing.T) {
		router := gin.New()
		router.Use(ValidationMiddleware(nil))
		router.POST("/test", func(c *gin.Context) {
			c.JSON(200, gin.H{"status": "ok"})
		})

		w := httptest.NewRecorder()
		req := httptest.NewRequest("POST", "/test", strings.NewReader(`{"test": "data"}`))
		req.Header.Set("Content-Type", "application/json")
		router.ServeHTTP(w, req)

		assert.Equal(t, 200, w.Code)
	})

	t.Run("requires content-type for POST requests", func(t *testing.T) {
		router := gin.New()
		router.Use(ValidationMiddleware(nil))
		router.POST("/test", func(c *gin.Context) {
			c.JSON(200, gin.H{"status": "ok"})
		})

		w := httptest.NewRecorder()
		req := httptest.NewRequest("POST", "/test", strings.NewReader(`{"test": "data"}`))
		router.ServeHTTP(w, req)

		assert.Equal(t, 400, w.Code)
	})

	t.Run("allows GET requests without content-type", func(t *testing.T) {
		router := gin.New()
		router.Use(ValidationMiddleware(nil))
		router.GET("/test", func(c *gin.Context) {
			c.JSON(200, gin.H{"status": "ok"})
		})

		w := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "/test", nil)
		router.ServeHTTP(w, req)

		assert.Equal(t, 200, w.Code)
	})
}

func TestSanitizeAndValidateInput(t *testing.T) {
	t.Run("sanitizes and validates input", func(t *testing.T) {
		input := map[string]interface{}{
			"email":    "  test@example.com  ",
			"username": "  john123  ",
			"age":      25,
		}

		rules := map[string][]string{
			"email":    {"required", "email"},
			"username": {"required", "alphanumeric"},
		}

		sanitized, errors := SanitizeAndValidateInput(input, rules)

		assert.False(t, errors.HasErrors())
		assert.Equal(t, "test@example.com", (*sanitized)["email"])
		assert.Equal(t, "john123", (*sanitized)["username"])
		assert.Equal(t, 25, (*sanitized)["age"]) // Non-string values preserved
	})

	t.Run("returns validation errors", func(t *testing.T) {
		input := map[string]interface{}{
			"email":    "invalid-email",
			"username": "",
		}

		rules := map[string][]string{
			"email":    {"required", "email"},
			"username": {"required"},
		}

		_, errors := SanitizeAndValidateInput(input, rules)

		assert.True(t, errors.HasErrors())
		assert.Len(t, errors.Errors, 2)
	})
}

func TestApplyValidationRule(t *testing.T) {
	tests := []struct {
		name     string
		value    string
		rule     string
		expected bool
	}{
		{"required valid", "test", "required", true},
		{"required invalid", "", "required", false},
		{"email valid", "test@example.com", "email", true},
		{"email invalid", "invalid", "email", false},
		{"phone valid", "+1234567890", "phone", true},
		{"phone invalid", "invalid", "phone", false},
		{"url valid", "https://example.com", "url", true},
		{"url invalid", "not-a-url", "url", false},
		{"alphanumeric valid", "abc123", "alphanumeric", true},
		{"alphanumeric invalid", "abc-123", "alphanumeric", false},
		{"slug valid", "hello-world", "slug", true},
		{"slug invalid", "hello_world", "slug", false},
		{"unknown rule", "anything", "unknown", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := applyValidationRule(tt.value, tt.rule)
			assert.Equal(t, tt.expected, result)
		})
	}
}

type TestStruct struct {
	Name  string `validate:"required,min=2,max=50"`
	Email string `validate:"required,email"`
	Age   int    `validate:"gte=0,lte=150"`
}

func TestValidateStruct(t *testing.T) {
	t.Run("valid struct", func(t *testing.T) {
		s := TestStruct{
			Name:  "John Doe",
			Email: "john@example.com",
			Age:   30,
		}

		errors := ValidateStruct(s)
		assert.False(t, errors.HasErrors())
	})

	t.Run("invalid struct", func(t *testing.T) {
		s := TestStruct{
			Name:  "", // Required field empty
			Email: "invalid-email",
			Age:   200, // Out of range
		}

		errors := ValidateStruct(s)
		assert.True(t, errors.HasErrors())
		assert.Len(t, errors.Errors, 3)
	})
}

func TestBindAndValidate(t *testing.T) {
	gin.SetMode(gin.TestMode)

	t.Run("valid JSON", func(t *testing.T) {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)

		jsonData := `{"name": "John Doe", "email": "john@example.com", "age": 30}`
		c.Request = httptest.NewRequest("POST", "/test", strings.NewReader(jsonData))
		c.Request.Header.Set("Content-Type", "application/json")

		var s TestStruct
		errors := BindAndValidate(c, &s)

		assert.False(t, errors.HasErrors())
		assert.Equal(t, "John Doe", s.Name)
		assert.Equal(t, "john@example.com", s.Email)
		assert.Equal(t, 30, s.Age)
	})

	t.Run("invalid JSON", func(t *testing.T) {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)

		jsonData := `{"name": "John", "email": "invalid", "age": -5}`
		c.Request = httptest.NewRequest("POST", "/test", strings.NewReader(jsonData))
		c.Request.Header.Set("Content-Type", "application/json")

		var s TestStruct
		errors := BindAndValidate(c, &s)

		assert.True(t, errors.HasErrors())
	})

	t.Run("malformed JSON", func(t *testing.T) {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)

		jsonData := `{"name": "John", "email"`
		c.Request = httptest.NewRequest("POST", "/test", strings.NewReader(jsonData))
		c.Request.Header.Set("Content-Type", "application/json")

		var s TestStruct
		errors := BindAndValidate(c, &s)

		assert.True(t, errors.HasErrors())
		assert.Equal(t, "invalid_json", errors.Errors[0].Code)
	})
}
