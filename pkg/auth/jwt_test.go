package auth

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/facuhernandez99/blog/pkg/models"
	"github.com/golang-jwt/jwt/v5"
)

func TestGenerateJWT(t *testing.T) {
	tests := []struct {
		name            string
		user            *models.User
		secret          string
		expirationHours int
		shouldError     bool
		expectedErr     error
		description     string
	}{
		{
			name: "valid_token_generation",
			user: &models.User{
				ID:       123,
				Username: "testuser",
			},
			secret:          "test_secret_key",
			expirationHours: 24,
			shouldError:     false,
			description:     "Should generate valid JWT token with proper claims",
		},
		{
			name: "valid_token_long_username",
			user: &models.User{
				ID:       456,
				Username: "very_long_username_with_special_chars_123",
			},
			secret:          "test_secret_key",
			expirationHours: 48,
			shouldError:     false,
			description:     "Should handle long usernames",
		},
		{
			name: "valid_token_unicode_username",
			user: &models.User{
				ID:       789,
				Username: "пользователь",
			},
			secret:          "test_secret_key",
			expirationHours: 12,
			shouldError:     false,
			description:     "Should handle Unicode usernames",
		},
		{
			name: "zero_user_id",
			user: &models.User{
				ID:       0,
				Username: "testuser",
			},
			secret:          "test_secret_key",
			expirationHours: 24,
			shouldError:     false,
			description:     "Should handle zero user ID",
		},
		{
			name: "negative_user_id",
			user: &models.User{
				ID:       -1,
				Username: "testuser",
			},
			secret:          "test_secret_key",
			expirationHours: 24,
			shouldError:     false,
			description:     "Should handle negative user ID",
		},
		{
			name: "empty_username",
			user: &models.User{
				ID:       123,
				Username: "",
			},
			secret:          "test_secret_key",
			expirationHours: 24,
			shouldError:     false,
			description:     "Should handle empty username",
		},
		{
			name:            "nil_user",
			user:            nil,
			secret:          "test_secret_key",
			expirationHours: 24,
			shouldError:     true,
			expectedErr:     ErrUserEmpty,
			description:     "Should reject nil user",
		},
		{
			name: "empty_secret",
			user: &models.User{
				ID:       123,
				Username: "testuser",
			},
			secret:          "",
			expirationHours: 24,
			shouldError:     true,
			expectedErr:     ErrSecretEmpty,
			description:     "Should reject empty secret",
		},
		{
			name: "zero_expiration_hours",
			user: &models.User{
				ID:       123,
				Username: "testuser",
			},
			secret:          "test_secret_key",
			expirationHours: 0,
			shouldError:     false,
			description:     "Should use default expiration for zero hours",
		},
		{
			name: "negative_expiration_hours",
			user: &models.User{
				ID:       123,
				Username: "testuser",
			},
			secret:          "test_secret_key",
			expirationHours: -5,
			shouldError:     false,
			description:     "Should use default expiration for negative hours",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tokenResponse, err := GenerateJWT(tt.user, tt.secret, tt.expirationHours)

			if tt.shouldError {
				if err == nil {
					t.Errorf("%s: expected error but got none", tt.description)
					return
				}
				if tt.expectedErr != nil && err != tt.expectedErr {
					t.Errorf("%s: expected error %v, got %v", tt.description, tt.expectedErr, err)
				}
				return
			}

			if err != nil {
				t.Errorf("%s: unexpected error: %v", tt.description, err)
				return
			}

			// Verify token response is not nil
			if tokenResponse == nil {
				t.Errorf("%s: token response should not be nil", tt.description)
				return
			}

			// Verify token is not empty
			if tokenResponse.Token == "" {
				t.Errorf("%s: token should not be empty", tt.description)
			}

			// Verify token type
			if tokenResponse.TokenType != "Bearer" {
				t.Errorf("%s: expected token type 'Bearer', got %s", tt.description, tokenResponse.TokenType)
			}

			// Verify token has JWT structure (header.payload.signature)
			parts := strings.Split(tokenResponse.Token, ".")
			if len(parts) != 3 {
				t.Errorf("%s: token should have 3 parts separated by dots, got %d", tt.description, len(parts))
			}

			// Verify token can be validated with same secret
			claims, err := ValidateJWT(tokenResponse.Token, tt.secret)
			if err != nil {
				t.Errorf("%s: generated token should be valid: %v", tt.description, err)
				return
			}

			// Verify claims contain correct data
			if claims.UserID != tt.user.ID {
				t.Errorf("%s: expected UserID %d, got %d", tt.description, tt.user.ID, claims.UserID)
			}

			if claims.Username != tt.user.Username {
				t.Errorf("%s: expected Username %s, got %s", tt.description, tt.user.Username, claims.Username)
			}

			// Verify expiration time
			expectedHours := tt.expirationHours
			if expectedHours <= 0 {
				expectedHours = 72 // Default value
			}

			expectedExpiration := time.Now().Add(time.Duration(expectedHours) * time.Hour)
			actualExpiration := tokenResponse.ExpiresAt

			// Allow 1 minute tolerance for timing
			tolerance := time.Minute
			if actualExpiration.Before(expectedExpiration.Add(-tolerance)) ||
				actualExpiration.After(expectedExpiration.Add(tolerance)) {
				t.Errorf("%s: token should expire in ~%d hours, expires at %v", tt.description, expectedHours, actualExpiration)
			}
		})
	}
}

func TestGenerateJWTDefault(t *testing.T) {
	user := &models.User{
		ID:       123,
		Username: "testuser",
	}
	secret := "test_secret_key"

	tokenResponse, err := GenerateJWTDefault(user, secret)
	if err != nil {
		t.Fatalf("GenerateJWTDefault failed: %v", err)
	}

	if tokenResponse == nil {
		t.Fatal("Token response should not be nil")
	}

	// Verify default expiration (72 hours)
	expectedExpiration := time.Now().Add(72 * time.Hour)
	actualExpiration := tokenResponse.ExpiresAt

	tolerance := time.Minute
	if actualExpiration.Before(expectedExpiration.Add(-tolerance)) ||
		actualExpiration.After(expectedExpiration.Add(tolerance)) {
		t.Errorf("Default token should expire in ~72 hours, expires at %v", actualExpiration)
	}
}

func TestValidateJWT(t *testing.T) {
	secret := "test_secret_key"
	user := &models.User{
		ID:       123,
		Username: "testuser",
	}

	// Generate a valid token for testing
	validTokenResponse, err := GenerateJWT(user, secret, 24)
	if err != nil {
		t.Fatalf("Failed to generate test token: %v", err)
	}

	// Generate an expired token (manually create with past expiration)
	expiredClaims := &Claims{
		UserID:   user.ID,
		Username: user.Username,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(-time.Hour)), // Expired 1 hour ago
			IssuedAt:  jwt.NewNumericDate(time.Now().Add(-2 * time.Hour)),
		},
	}
	expiredToken := jwt.NewWithClaims(jwt.SigningMethodHS256, expiredClaims)
	expiredTokenString, err := expiredToken.SignedString([]byte(secret))
	if err != nil {
		t.Fatalf("Failed to generate expired test token: %v", err)
	}

	tests := []struct {
		name        string
		token       string
		secret      string
		shouldError bool
		expectedErr error
		description string
	}{
		{
			name:        "valid_token",
			token:       validTokenResponse.Token,
			secret:      secret,
			shouldError: false,
			description: "Should validate correct token successfully",
		},
		{
			name:        "wrong_secret",
			token:       validTokenResponse.Token,
			secret:      "wrong_secret",
			shouldError: true,
			expectedErr: ErrInvalidToken,
			description: "Should reject token with wrong secret",
		},
		{
			name:        "expired_token",
			token:       expiredTokenString,
			secret:      secret,
			shouldError: true,
			expectedErr: ErrTokenExpired,
			description: "Should reject expired token",
		},
		{
			name:        "malformed_token",
			token:       "invalid.token.format",
			secret:      secret,
			shouldError: true,
			expectedErr: ErrTokenMalformed,
			description: "Should reject malformed token",
		},
		{
			name:        "empty_token",
			token:       "",
			secret:      secret,
			shouldError: true,
			expectedErr: ErrInvalidToken,
			description: "Should reject empty token",
		},
		{
			name:        "empty_secret",
			token:       validTokenResponse.Token,
			secret:      "",
			shouldError: true,
			expectedErr: ErrSecretEmpty,
			description: "Should reject empty secret",
		},
		{
			name:        "token_wrong_parts",
			token:       "only.two.parts",
			secret:      secret,
			shouldError: true,
			expectedErr: ErrTokenMalformed,
			description: "Should reject token with wrong number of parts",
		},
		{
			name:        "token_invalid_base64",
			token:       "invalid_base64.invalid_base64.invalid_base64",
			secret:      secret,
			shouldError: true,
			expectedErr: ErrTokenMalformed,
			description: "Should reject token with invalid base64 encoding",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			claims, err := ValidateJWT(tt.token, tt.secret)

			if tt.shouldError {
				if err == nil {
					t.Errorf("%s: expected error but got none", tt.description)
					return
				}

				// Check if we got the expected error type
				if tt.expectedErr != nil && err != tt.expectedErr {
					t.Errorf("%s: expected error %v, got %v", tt.description, tt.expectedErr, err)
				}
				return
			}

			if err != nil {
				t.Errorf("%s: unexpected error: %v", tt.description, err)
				return
			}

			// Verify claims are returned for valid tokens
			if claims == nil {
				t.Errorf("%s: claims should not be nil for valid token", tt.description)
				return
			}

			// Verify claims contain expected data
			if claims.UserID != user.ID {
				t.Errorf("%s: expected UserID %d, got %d", tt.description, user.ID, claims.UserID)
			}

			if claims.Username != user.Username {
				t.Errorf("%s: expected Username %s, got %s", tt.description, user.Username, claims.Username)
			}
		})
	}
}

func TestExtractUserID(t *testing.T) {
	secret := "test_secret_key"

	tests := []struct {
		name        string
		user        *models.User
		secret      string
		shouldError bool
		description string
	}{
		{
			name: "extract_positive_user_id",
			user: &models.User{
				ID:       123,
				Username: "testuser",
			},
			secret:      secret,
			shouldError: false,
			description: "Should extract positive user ID correctly",
		},
		{
			name: "extract_zero_user_id",
			user: &models.User{
				ID:       0,
				Username: "testuser",
			},
			secret:      secret,
			shouldError: false,
			description: "Should extract zero user ID correctly",
		},
		{
			name: "extract_negative_user_id",
			user: &models.User{
				ID:       -1,
				Username: "testuser",
			},
			secret:      secret,
			shouldError: false,
			description: "Should extract negative user ID correctly",
		},
		{
			name: "extract_large_user_id",
			user: &models.User{
				ID:       9223372036854775807, // max int64
				Username: "testuser",
			},
			secret:      secret,
			shouldError: false,
			description: "Should extract large user ID correctly",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Generate token with specific user ID
			tokenResponse, err := GenerateJWT(tt.user, tt.secret, 24)
			if err != nil {
				t.Fatalf("Failed to generate test token: %v", err)
			}

			// Extract user ID
			extractedUserID, err := ExtractUserID(tokenResponse.Token, tt.secret)

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

			if extractedUserID != tt.user.ID {
				t.Errorf("%s: expected UserID %d, got %d", tt.description, tt.user.ID, extractedUserID)
			}
		})
	}

	// Test error cases
	t.Run("invalid_token", func(t *testing.T) {
		_, err := ExtractUserID("invalid.token", secret)
		if err == nil {
			t.Error("Should return error for invalid token")
		}
	})
}

func TestExtractUsername(t *testing.T) {
	secret := "test_secret_key"

	tests := []struct {
		name        string
		username    string
		shouldError bool
		description string
	}{
		{
			name:        "extract_normal_username",
			username:    "testuser",
			shouldError: false,
			description: "Should extract normal username correctly",
		},
		{
			name:        "extract_empty_username",
			username:    "",
			shouldError: false,
			description: "Should extract empty username correctly",
		},
		{
			name:        "extract_unicode_username",
			username:    "пользователь",
			shouldError: false,
			description: "Should extract Unicode username correctly",
		},
		{
			name:        "extract_long_username",
			username:    "very_long_username_with_special_characters_123_!@#",
			shouldError: false,
			description: "Should extract long username correctly",
		},
		{
			name:        "extract_username_with_spaces",
			username:    "user with spaces",
			shouldError: false,
			description: "Should extract username with spaces correctly",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			user := &models.User{
				ID:       123,
				Username: tt.username,
			}

			// Generate token with specific username
			tokenResponse, err := GenerateJWT(user, secret, 24)
			if err != nil {
				t.Fatalf("Failed to generate test token: %v", err)
			}

			// Extract username
			extractedUsername, err := ExtractUsername(tokenResponse.Token, secret)

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

			if extractedUsername != tt.username {
				t.Errorf("%s: expected Username %s, got %s", tt.description, tt.username, extractedUsername)
			}
		})
	}

	// Test error cases
	t.Run("invalid_token", func(t *testing.T) {
		_, err := ExtractUsername("invalid.token", secret)
		if err == nil {
			t.Error("Should return error for invalid token")
		}
	})
}

func TestIsTokenExpired(t *testing.T) {
	secret := "test_secret_key"
	user := &models.User{
		ID:       123,
		Username: "testuser",
	}

	// Generate a valid (not expired) token
	validTokenResponse, err := GenerateJWT(user, secret, 24)
	if err != nil {
		t.Fatalf("Failed to generate test token: %v", err)
	}

	// Generate an expired token
	expiredClaims := &Claims{
		UserID:   user.ID,
		Username: user.Username,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(-time.Hour)), // Expired 1 hour ago
			IssuedAt:  jwt.NewNumericDate(time.Now().Add(-2 * time.Hour)),
		},
	}
	expiredToken := jwt.NewWithClaims(jwt.SigningMethodHS256, expiredClaims)
	expiredTokenString, err := expiredToken.SignedString([]byte(secret))
	if err != nil {
		t.Fatalf("Failed to generate expired test token: %v", err)
	}

	tests := []struct {
		name        string
		token       string
		expected    bool
		description string
	}{
		{
			name:        "valid_token_not_expired",
			token:       validTokenResponse.Token,
			expected:    false,
			description: "Valid token should not be expired",
		},
		{
			name:        "expired_token",
			token:       expiredTokenString,
			expected:    true,
			description: "Expired token should be detected as expired",
		},
		{
			name:        "invalid_token",
			token:       "invalid.token",
			expected:    true, // Invalid tokens are considered "expired"
			description: "Invalid token should be considered expired",
		},
		{
			name:        "empty_token",
			token:       "",
			expected:    true,
			description: "Empty token should be considered expired",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsTokenExpired(tt.token)

			if result != tt.expected {
				t.Errorf("%s: expected %v, got %v", tt.description, tt.expected, result)
			}
		})
	}
}

func TestRefreshToken(t *testing.T) {
	secret := "test_secret_key"
	user := &models.User{
		ID:       123,
		Username: "testuser",
	}

	// Generate a valid token for refreshing
	originalTokenResponse, err := GenerateJWT(user, secret, 24)
	if err != nil {
		t.Fatalf("Failed to generate test token: %v", err)
	}

	tests := []struct {
		name            string
		token           string
		secret          string
		expirationHours int
		shouldError     bool
		description     string
	}{
		{
			name:            "refresh_valid_token",
			token:           originalTokenResponse.Token,
			secret:          secret,
			expirationHours: 48,
			shouldError:     false,
			description:     "Should refresh valid token successfully",
		},
		{
			name:            "refresh_with_wrong_secret",
			token:           originalTokenResponse.Token,
			secret:          "wrong_secret",
			expirationHours: 24,
			shouldError:     true,
			description:     "Should fail to refresh token with wrong secret",
		},
		{
			name:            "refresh_invalid_token",
			token:           "invalid.token",
			secret:          secret,
			expirationHours: 24,
			shouldError:     true,
			description:     "Should fail to refresh invalid token",
		},
		{
			name:            "refresh_empty_token",
			token:           "",
			secret:          secret,
			expirationHours: 24,
			shouldError:     true,
			description:     "Should fail to refresh empty token",
		},
		{
			name:            "refresh_with_zero_expiration",
			token:           originalTokenResponse.Token,
			secret:          secret,
			expirationHours: 0,
			shouldError:     false,
			description:     "Should refresh with default expiration for zero hours",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			newTokenResponse, err := RefreshToken(tt.token, tt.secret, tt.expirationHours)

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

			// Verify new token response is not nil
			if newTokenResponse == nil {
				t.Errorf("%s: new token response should not be nil", tt.description)
				return
			}

			// Verify new token is different from original
			if newTokenResponse.Token == tt.token {
				t.Errorf("%s: new token should be different from original", tt.description)
			}

			// Verify new token is valid
			claims, err := ValidateJWT(newTokenResponse.Token, tt.secret)
			if err != nil {
				t.Errorf("%s: refreshed token should be valid: %v", tt.description, err)
				return
			}

			// Verify claims match original
			if claims.UserID != user.ID {
				t.Errorf("%s: expected UserID %d, got %d", tt.description, user.ID, claims.UserID)
			}

			if claims.Username != user.Username {
				t.Errorf("%s: expected Username %s, got %s", tt.description, user.Username, claims.Username)
			}

			// Verify new token has extended expiration
			expectedHours := tt.expirationHours
			if expectedHours <= 0 {
				expectedHours = 72 // Default value
			}

			expectedExpiration := time.Now().Add(time.Duration(expectedHours) * time.Hour)
			actualExpiration := newTokenResponse.ExpiresAt

			// Allow 1 minute tolerance
			tolerance := time.Minute
			if actualExpiration.Before(expectedExpiration.Add(-tolerance)) {
				t.Errorf("%s: refreshed token should have extended expiration", tt.description)
			}
		})
	}
}

func TestJWTWorkflow(t *testing.T) {
	// Test complete JWT workflow: generate -> validate -> extract -> refresh
	secret := "test_secret_key"
	user := &models.User{
		ID:       456,
		Username: "workflowuser",
	}

	// Step 1: Generate token
	tokenResponse, err := GenerateJWT(user, secret, 24)
	if err != nil {
		t.Fatalf("Failed to generate token: %v", err)
	}

	// Step 2: Validate token
	claims, err := ValidateJWT(tokenResponse.Token, secret)
	if err != nil {
		t.Fatalf("Failed to validate token: %v", err)
	}

	if claims.UserID != user.ID || claims.Username != user.Username {
		t.Fatalf("Claims don't match: expected (%d, %s), got (%d, %s)",
			user.ID, user.Username, claims.UserID, claims.Username)
	}

	// Step 3: Extract user ID
	extractedUserID, err := ExtractUserID(tokenResponse.Token, secret)
	if err != nil {
		t.Fatalf("Failed to extract user ID: %v", err)
	}

	if extractedUserID != user.ID {
		t.Fatalf("Extracted user ID doesn't match: expected %d, got %d", user.ID, extractedUserID)
	}

	// Step 4: Extract username
	extractedUsername, err := ExtractUsername(tokenResponse.Token, secret)
	if err != nil {
		t.Fatalf("Failed to extract username: %v", err)
	}

	if extractedUsername != user.Username {
		t.Fatalf("Extracted username doesn't match: expected %s, got %s", user.Username, extractedUsername)
	}

	// Step 5: Check expiration status
	if IsTokenExpired(tokenResponse.Token) {
		t.Fatal("Newly generated token should not be expired")
	}

	// Step 6: Refresh token
	newTokenResponse, err := RefreshToken(tokenResponse.Token, secret, 48)
	if err != nil {
		t.Fatalf("Failed to refresh token: %v", err)
	}

	// Step 7: Verify refreshed token works
	newClaims, err := ValidateJWT(newTokenResponse.Token, secret)
	if err != nil {
		t.Fatalf("Failed to validate refreshed token: %v", err)
	}

	if newClaims.UserID != user.ID || newClaims.Username != user.Username {
		t.Fatalf("Refreshed token claims don't match: expected (%d, %s), got (%d, %s)",
			user.ID, user.Username, newClaims.UserID, newClaims.Username)
	}
}

// Benchmark tests
func TestGenerateRefreshToken(t *testing.T) {
	tests := []struct {
		name        string
		user        *models.User
		secret      string
		wantErr     bool
		wantErrType error
	}{
		{
			name: "valid refresh token generation",
			user: &models.User{
				ID:       1,
				Username: "testuser",
			},
			secret:  "test-secret-key-that-is-long-enough",
			wantErr: false,
		},
		{
			name:        "nil user",
			user:        nil,
			secret:      "test-secret",
			wantErr:     true,
			wantErrType: ErrUserEmpty,
		},
		{
			name: "empty secret",
			user: &models.User{
				ID:       1,
				Username: "testuser",
			},
			secret:      "",
			wantErr:     true,
			wantErrType: ErrSecretEmpty,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token, err := GenerateRefreshToken(tt.user, tt.secret)

			if (err != nil) != tt.wantErr {
				t.Errorf("GenerateRefreshToken() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.wantErr {
				if tt.wantErrType != nil && !errors.Is(err, tt.wantErrType) {
					t.Errorf("Expected error type %v, got %v", tt.wantErrType, err)
				}
				return
			}

			// Validate token format
			if token == "" {
				t.Error("Generated token is empty")
			}

			// Validate token can be parsed
			claims, err := ValidateRefreshToken(token, tt.secret)
			if err != nil {
				t.Errorf("Failed to validate generated refresh token: %v", err)
			}

			if claims.UserID != tt.user.ID {
				t.Errorf("UserID = %v, want %v", claims.UserID, tt.user.ID)
			}

			if claims.Username != tt.user.Username {
				t.Errorf("Username = %v, want %v", claims.Username, tt.user.Username)
			}

			// Check expiration is about 7 days from now
			expectedExp := time.Now().Add(7 * 24 * time.Hour)
			if claims.ExpiresAt.Time.Before(expectedExp.Add(-time.Minute)) ||
				claims.ExpiresAt.Time.After(expectedExp.Add(time.Minute)) {
				t.Errorf("Token expiration = %v, expected around %v", claims.ExpiresAt.Time, expectedExp)
			}
		})
	}
}

func TestValidateRefreshToken(t *testing.T) {
	user := &models.User{ID: 1, Username: "testuser"}
	secret := "test-secret-key-that-is-long-enough"

	// Generate a valid refresh token for testing
	validToken, err := GenerateRefreshToken(user, secret)
	if err != nil {
		t.Fatalf("Failed to generate test token: %v", err)
	}

	tests := []struct {
		name        string
		token       string
		secret      string
		wantErr     bool
		wantErrType error
	}{
		{
			name:    "valid refresh token",
			token:   validToken,
			secret:  secret,
			wantErr: false,
		},
		{
			name:        "empty token",
			token:       "",
			secret:      secret,
			wantErr:     true,
			wantErrType: ErrInvalidToken,
		},
		{
			name:        "empty secret",
			token:       validToken,
			secret:      "",
			wantErr:     true,
			wantErrType: ErrSecretEmpty,
		},
		{
			name:        "invalid token format",
			token:       "invalid.token.format",
			secret:      secret,
			wantErr:     true,
			wantErrType: ErrTokenMalformed,
		},
		{
			name:        "wrong secret",
			token:       validToken,
			secret:      "wrong-secret",
			wantErr:     true,
			wantErrType: ErrInvalidToken,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			claims, err := ValidateRefreshToken(tt.token, tt.secret)

			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateRefreshToken() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.wantErr {
				if tt.wantErrType != nil && !errors.Is(err, tt.wantErrType) {
					t.Errorf("Expected error type %v, got %v", tt.wantErrType, err)
				}
				return
			}

			// Validate claims
			if claims.UserID != user.ID {
				t.Errorf("UserID = %v, want %v", claims.UserID, user.ID)
			}

			if claims.Username != user.Username {
				t.Errorf("Username = %v, want %v", claims.Username, user.Username)
			}

			if claims.TokenID == "" {
				t.Error("TokenID should not be empty")
			}
		})
	}
}

func TestRefreshAccessToken(t *testing.T) {
	user := &models.User{ID: 1, Username: "testuser"}
	secret := "test-secret-key-that-is-long-enough"

	// Generate a valid refresh token for testing
	refreshToken, err := GenerateRefreshToken(user, secret)
	if err != nil {
		t.Fatalf("Failed to generate test refresh token: %v", err)
	}

	tests := []struct {
		name              string
		refreshToken      string
		secret            string
		accessTokenExpiry int
		wantErr           bool
	}{
		{
			name:              "valid refresh token exchange",
			refreshToken:      refreshToken,
			secret:            secret,
			accessTokenExpiry: 1,
			wantErr:           false,
		},
		{
			name:              "invalid refresh token",
			refreshToken:      "invalid.token.format",
			secret:            secret,
			accessTokenExpiry: 1,
			wantErr:           true,
		},
		{
			name:              "wrong secret",
			refreshToken:      refreshToken,
			secret:            "wrong-secret",
			accessTokenExpiry: 1,
			wantErr:           true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tokenResponse, err := RefreshAccessToken(tt.refreshToken, tt.secret, tt.accessTokenExpiry)

			if (err != nil) != tt.wantErr {
				t.Errorf("RefreshAccessToken() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.wantErr {
				return
			}

			// Validate the new access token
			claims, err := ValidateJWT(tokenResponse.Token, tt.secret)
			if err != nil {
				t.Errorf("Failed to validate new access token: %v", err)
			}

			if claims.UserID != user.ID {
				t.Errorf("UserID = %v, want %v", claims.UserID, user.ID)
			}

			if claims.Username != user.Username {
				t.Errorf("Username = %v, want %v", claims.Username, user.Username)
			}

			// Check that refresh token is preserved
			if tokenResponse.RefreshToken != tt.refreshToken {
				t.Error("Refresh token should be preserved in response")
			}
		})
	}
}

func TestGenerateTokenPair(t *testing.T) {
	tests := []struct {
		name        string
		user        *models.User
		secret      string
		expiration  int
		wantErr     bool
		wantErrType error
	}{
		{
			name: "valid token pair generation",
			user: &models.User{
				ID:       1,
				Username: "testuser",
			},
			secret:     "test-secret-key-that-is-long-enough",
			expiration: 1,
			wantErr:    false,
		},
		{
			name:        "nil user",
			user:        nil,
			secret:      "test-secret",
			expiration:  1,
			wantErr:     true,
			wantErrType: ErrUserEmpty,
		},
		{
			name: "empty secret",
			user: &models.User{
				ID:       1,
				Username: "testuser",
			},
			secret:      "",
			expiration:  1,
			wantErr:     true,
			wantErrType: ErrSecretEmpty,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tokenResponse, err := GenerateTokenPair(tt.user, tt.secret, tt.expiration)

			if (err != nil) != tt.wantErr {
				t.Errorf("GenerateTokenPair() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.wantErr {
				if tt.wantErrType != nil && !errors.Is(err, tt.wantErrType) {
					t.Errorf("Expected error type %v, got %v", tt.wantErrType, err)
				}
				return
			}

			// Validate access token
			accessClaims, err := ValidateJWT(tokenResponse.Token, tt.secret)
			if err != nil {
				t.Errorf("Failed to validate access token: %v", err)
			}

			if accessClaims.UserID != tt.user.ID {
				t.Errorf("Access token UserID = %v, want %v", accessClaims.UserID, tt.user.ID)
			}

			// Validate refresh token
			refreshClaims, err := ValidateRefreshToken(tokenResponse.RefreshToken, tt.secret)
			if err != nil {
				t.Errorf("Failed to validate refresh token: %v", err)
			}

			if refreshClaims.UserID != tt.user.ID {
				t.Errorf("Refresh token UserID = %v, want %v", refreshClaims.UserID, tt.user.ID)
			}

			// Check token types and format
			if tokenResponse.TokenType != "Bearer" {
				t.Errorf("TokenType = %v, want Bearer", tokenResponse.TokenType)
			}

			if tokenResponse.RefreshToken == "" {
				t.Error("RefreshToken should not be empty")
			}
		})
	}
}

func BenchmarkGenerateJWT(b *testing.B) {
	user := &models.User{
		ID:       123,
		Username: "benchuser",
	}
	secret := "bench_secret"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := GenerateJWT(user, secret, 24)
		if err != nil {
			b.Fatalf("GenerateJWT failed: %v", err)
		}
	}
}

func BenchmarkValidateJWT(b *testing.B) {
	user := &models.User{
		ID:       123,
		Username: "benchuser",
	}
	secret := "bench_secret"

	tokenResponse, err := GenerateJWT(user, secret, 24)
	if err != nil {
		b.Fatalf("Failed to generate test token: %v", err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := ValidateJWT(tokenResponse.Token, secret)
		if err != nil {
			b.Fatalf("ValidateJWT failed: %v", err)
		}
	}
}
