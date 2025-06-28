package auth

import (
	"strings"
	"testing"
)

func TestHashPassword(t *testing.T) {
	tests := []struct {
		name        string
		password    string
		shouldError bool
		description string
	}{
		{
			name:        "valid_strong_password",
			password:    "MyPassword123!",
			shouldError: false,
			description: "Should successfully hash a valid strong password",
		},
		{
			name:        "valid_long_password",
			password:    "ThisIsAVeryLongAndSecurePassword123!@#",
			shouldError: false,
			description: "Should successfully hash a valid long password",
		},
		{
			name:        "password_with_unicode_upper",
			password:    "МойПароль123!",
			shouldError: false,
			description: "Should handle Unicode characters in password",
		},
		{
			name:        "password_with_spaces",
			password:    "My Secure Password 123!",
			shouldError: false,
			description: "Should handle passwords with spaces",
		},
		{
			name:        "empty_password",
			password:    "",
			shouldError: true, // HashPassword validates and rejects empty passwords
			description: "Should reject empty password",
		},
		{
			name:        "password_missing_uppercase",
			password:    "mypassword123!",
			shouldError: true,
			description: "Should reject password without uppercase letters",
		},
		{
			name:        "password_missing_lowercase",
			password:    "MYPASSWORD123!",
			shouldError: true,
			description: "Should reject password without lowercase letters",
		},
		{
			name:        "password_missing_digit",
			password:    "MyPassword!",
			shouldError: true,
			description: "Should reject password without digits",
		},
		{
			name:        "password_missing_special",
			password:    "MyPassword123",
			shouldError: true,
			description: "Should reject password without special characters",
		},
		{
			name:        "password_too_short",
			password:    "MyP1!",
			shouldError: true,
			description: "Should reject password shorter than 8 characters",
		},
		{
			name:        "password_too_long",
			password:    "MyPassword123!" + strings.Repeat("a", 100),
			shouldError: true,
			description: "Should reject password longer than 100 characters",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hash, err := HashPassword(tt.password)

			if tt.shouldError {
				if err == nil {
					t.Errorf("%s: expected error but got none", tt.description)
				}
				return
			}

			if err != nil {
				t.Errorf("%s: unexpected error: %v", tt.description, err)
				return
			}

			// Verify hash is not empty
			if hash == "" {
				t.Errorf("%s: hash should not be empty", tt.description)
			}

			// Verify hash is different from original password
			if hash == tt.password {
				t.Errorf("%s: hash should not equal original password", tt.description)
			}

			// Verify hash starts with bcrypt prefix
			if !strings.HasPrefix(hash, "$2a$") && !strings.HasPrefix(hash, "$2b$") && !strings.HasPrefix(hash, "$2y$") {
				t.Errorf("%s: hash should start with bcrypt prefix, got: %s", tt.description, hash[:10])
			}

			// Verify generated hash can be used to verify original password
			if !CheckPasswordHash(tt.password, hash) {
				t.Errorf("%s: generated hash should verify against original password", tt.description)
			}
		})
	}
}

func TestHashPasswordConsistency(t *testing.T) {
	password := "TestPassword123!"

	// Generate multiple hashes of the same password
	hash1, err1 := HashPassword(password)
	hash2, err2 := HashPassword(password)

	if err1 != nil || err2 != nil {
		t.Fatalf("Unexpected errors: %v, %v", err1, err2)
	}

	// Hashes should be different (due to salt)
	if hash1 == hash2 {
		t.Error("Multiple hashes of the same password should be different due to salt")
	}

	// Both hashes should verify the original password
	if !CheckPasswordHash(password, hash1) {
		t.Error("First hash should verify original password")
	}

	if !CheckPasswordHash(password, hash2) {
		t.Error("Second hash should verify original password")
	}
}

func TestCheckPasswordHash(t *testing.T) {
	// Generate a known hash for testing
	password := "TestPassword123!"
	hash, err := HashPassword(password)
	if err != nil {
		t.Fatalf("Failed to generate test hash: %v", err)
	}

	tests := []struct {
		name        string
		password    string
		hash        string
		expected    bool
		description string
	}{
		{
			name:        "correct_password",
			password:    password,
			hash:        hash,
			expected:    true,
			description: "Should return true for correct password",
		},
		{
			name:        "incorrect_password",
			password:    "wrong_password",
			hash:        hash,
			expected:    false,
			description: "Should return false for incorrect password",
		},
		{
			name:        "empty_password",
			password:    "",
			hash:        hash,
			expected:    false,
			description: "Should return false for empty password against valid hash",
		},
		{
			name:        "empty_hash",
			password:    password,
			hash:        "",
			expected:    false,
			description: "Should return false for valid password against empty hash",
		},
		{
			name:        "both_empty",
			password:    "",
			hash:        "",
			expected:    false,
			description: "Should return false when both password and hash are empty",
		},
		{
			name:        "invalid_hash_format",
			password:    password,
			hash:        "invalid_hash_format",
			expected:    false,
			description: "Should return false for invalid hash format",
		},
		{
			name:        "case_sensitive",
			password:    strings.ToUpper(password),
			hash:        hash,
			expected:    false,
			description: "Password comparison should be case sensitive",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := CheckPasswordHash(tt.password, tt.hash)

			if result != tt.expected {
				t.Errorf("%s: expected %v, got %v", tt.description, tt.expected, result)
			}
		})
	}
}

func TestValidatePasswordStrength(t *testing.T) {
	tests := []struct {
		name        string
		password    string
		shouldError bool
		description string
	}{
		// Valid strong passwords
		{
			name:        "strong_password_mixed_case",
			password:    "MyStrongPass123!",
			shouldError: false,
			description: "Should accept strong password with mixed case, numbers, and symbols",
		},
		{
			name:        "strong_password_long",
			password:    "ThisIsAVeryLongAndSecurePassword123!@#",
			shouldError: false,
			description: "Should accept long strong password",
		},
		{
			name:        "minimum_strong_password",
			password:    "MyPass1!",
			shouldError: false,
			description: "Should accept minimum requirements password (8 chars)",
		},

		// Length issues
		{
			name:        "too_short_with_requirements",
			password:    "MyP1!",
			shouldError: true,
			description: "Should reject password shorter than 8 characters even with all requirements",
		},
		{
			name:        "really_too_short",
			password:    "A1!",
			shouldError: true,
			description: "Should reject very short password",
		},
		{
			name:        "empty_password",
			password:    "",
			shouldError: true,
			description: "Should reject empty password",
		},

		// Missing character types
		{
			name:        "no_uppercase",
			password:    "mystrongpass123!",
			shouldError: true,
			description: "Should reject password without uppercase letters",
		},
		{
			name:        "no_lowercase",
			password:    "MYSTRONGPASS123!",
			shouldError: true,
			description: "Should reject password without lowercase letters",
		},
		{
			name:        "no_numbers",
			password:    "MyStrongPass!",
			shouldError: true,
			description: "Should reject password without numbers",
		},
		{
			name:        "no_special_chars",
			password:    "MyStrongPass123",
			shouldError: true,
			description: "Should reject password without special characters",
		},

		// Valid passwords with patterns (implementation doesn't check advanced patterns)
		{
			name:        "common_password_pattern",
			password:    "Password123!",
			shouldError: false,
			description: "Should accept password that meets basic requirements (no advanced pattern checking)",
		},
		{
			name:        "sequential_numbers",
			password:    "MyPass123456!",
			shouldError: false,
			description: "Should accept password with sequential numbers (no advanced pattern checking)",
		},
		{
			name:        "sequential_letters",
			password:    "MyPassABCD123!",
			shouldError: false,
			description: "Should accept password with sequential letters (no advanced pattern checking)",
		},
		{
			name:        "repeated_chars",
			password:    "MyPassaaa123!",
			shouldError: false,
			description: "Should accept password with repeated characters (no advanced pattern checking)",
		},

		// Edge cases
		{
			name:        "unicode_characters",
			password:    "МойПароль123!",
			shouldError: false,
			description: "Should accept password with Unicode characters",
		},
		{
			name:        "spaces_in_password",
			password:    "My Strong Pass 123!",
			shouldError: false,
			description: "Should accept password with spaces",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidatePasswordStrength(tt.password)

			if tt.shouldError {
				if err == nil {
					t.Errorf("%s: expected error but got none", tt.description)
				}
			} else {
				if err != nil {
					t.Errorf("%s: unexpected error: %v", tt.description, err)
				}
			}
		})
	}
}

func TestValidatePasswordBasic(t *testing.T) {
	tests := []struct {
		name        string
		password    string
		shouldError bool
		description string
	}{
		{
			name:        "valid_minimum_length",
			password:    "12345678", // 8 characters
			shouldError: false,
			description: "Should accept password of minimum length",
		},
		{
			name:        "valid_long_password",
			password:    strings.Repeat("a", 50),
			shouldError: false,
			description: "Should accept long password within limits",
		},
		{
			name:        "valid_maximum_length",
			password:    strings.Repeat("a", 100), // 100 characters
			shouldError: false,
			description: "Should accept password of maximum length",
		},
		{
			name:        "too_short",
			password:    "1234567", // 7 characters
			shouldError: true,
			description: "Should reject password shorter than minimum",
		},
		{
			name:        "empty_password",
			password:    "",
			shouldError: true,
			description: "Should reject empty password",
		},
		{
			name:        "too_long",
			password:    strings.Repeat("a", 101), // 101 characters
			shouldError: true,
			description: "Should reject password longer than maximum",
		},
		{
			name:        "unicode_minimum_length",
			password:    "密码密码密码密码", // 8 Unicode characters
			shouldError: false,
			description: "Should accept Unicode password of minimum length",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidatePasswordBasic(tt.password)

			if tt.shouldError {
				if err == nil {
					t.Errorf("%s: expected error but got none", tt.description)
				}
			} else {
				if err != nil {
					t.Errorf("%s: unexpected error: %v", tt.description, err)
				}
			}
		})
	}
}

func TestPasswordWorkflow(t *testing.T) {
	// Test complete workflow: validation -> hashing -> verification
	tests := []struct {
		name     string
		password string
	}{
		{"strong_password", "MySecurePass123!"},
		{"minimum_valid", "Pass123!"},
		{"with_spaces", "My Pass 123!"},
		{"unicode", "МойПароль123!"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Step 1: Validate password strength
			if err := ValidatePasswordStrength(tt.password); err != nil {
				t.Fatalf("Password validation failed: %v", err)
			}

			// Step 2: Hash the password
			hash, err := HashPassword(tt.password)
			if err != nil {
				t.Fatalf("Password hashing failed: %v", err)
			}

			// Step 3: Verify the password
			if !CheckPasswordHash(tt.password, hash) {
				t.Errorf("Password verification failed")
			}

			// Step 4: Verify wrong password fails
			if CheckPasswordHash("wrong_password", hash) {
				t.Errorf("Wrong password should not verify")
			}
		})
	}
}

// Benchmark tests to ensure performance
func BenchmarkHashPassword(b *testing.B) {
	password := "BenchmarkPassword123!"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := HashPassword(password)
		if err != nil {
			b.Fatalf("HashPassword failed: %v", err)
		}
	}
}

func BenchmarkCheckPasswordHash(b *testing.B) {
	password := "BenchmarkPassword123!"
	hash, err := HashPassword(password)
	if err != nil {
		b.Fatalf("Failed to generate test hash: %v", err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		CheckPasswordHash(password, hash)
	}
}

func BenchmarkValidatePasswordStrength(b *testing.B) {
	password := "BenchmarkPassword123!"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ValidatePasswordStrength(password)
	}
}
