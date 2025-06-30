package auth

import (
	"testing"
	"time"

	"github.com/facuhernandez99/library/pkg/models"
)

func TestMemoryTokenStorage(t *testing.T) {
	storage := NewMemoryTokenStorage()
	defer storage.Close()

	// Test BlacklistToken
	t.Run("BlacklistToken", func(t *testing.T) {
		tokenID := "test-token-123"
		expiresAt := time.Now().Add(time.Hour)

		err := storage.BlacklistToken(tokenID, expiresAt)
		if err != nil {
			t.Errorf("BlacklistToken() error = %v", err)
		}

		// Check if token is blacklisted
		blacklisted, err := storage.IsBlacklisted(tokenID)
		if err != nil {
			t.Errorf("IsBlacklisted() error = %v", err)
		}
		if !blacklisted {
			t.Error("Token should be blacklisted")
		}
	})

	// Test IsBlacklisted with non-existent token
	t.Run("IsBlacklisted_NonExistent", func(t *testing.T) {
		blacklisted, err := storage.IsBlacklisted("non-existent-token")
		if err != nil {
			t.Errorf("IsBlacklisted() error = %v", err)
		}
		if blacklisted {
			t.Error("Non-existent token should not be blacklisted")
		}
	})

	// Test expired token cleanup
	t.Run("ExpiredTokenCleanup", func(t *testing.T) {
		expiredTokenID := "expired-token"
		pastTime := time.Now().Add(-time.Hour)

		// Add expired token
		err := storage.BlacklistToken(expiredTokenID, pastTime)
		if err != nil {
			t.Errorf("BlacklistToken() error = %v", err)
		}

		// Check if expired token is not blacklisted
		blacklisted, err := storage.IsBlacklisted(expiredTokenID)
		if err != nil {
			t.Errorf("IsBlacklisted() error = %v", err)
		}
		if blacklisted {
			t.Error("Expired token should not be blacklisted")
		}
	})

	// Test CleanupExpired
	t.Run("CleanupExpired", func(t *testing.T) {
		// Add some tokens
		storage.BlacklistToken("token1", time.Now().Add(time.Hour))
		storage.BlacklistToken("token2", time.Now().Add(-time.Hour)) // expired

		err := storage.CleanupExpired()
		if err != nil {
			t.Errorf("CleanupExpired() error = %v", err)
		}

		// Check that valid token is still there
		blacklisted, _ := storage.IsBlacklisted("token1")
		if !blacklisted {
			t.Error("Valid token should still be blacklisted")
		}
	})

	// Test GetStats
	t.Run("GetStats", func(t *testing.T) {
		stats := storage.GetStats()
		if stats["storage_type"] != "memory" {
			t.Error("Storage type should be 'memory'")
		}
		if _, ok := stats["blacklisted_tokens"]; !ok {
			t.Error("Stats should include blacklisted_tokens count")
		}
	})
}

func TestLogoutFunctionality(t *testing.T) {
	// Setup
	storage := NewMemoryTokenStorage()
	defer storage.Close()
	SetTokenStorage(storage)

	user := &models.User{ID: 123, Username: "testuser"}
	secret := "test-secret-key-that-is-long-enough"

	// Generate token pair
	tokenPair, err := GenerateTokenPair(user, secret, 1)
	if err != nil {
		t.Fatalf("Failed to generate token pair: %v", err)
	}

	t.Run("LogoutToken", func(t *testing.T) {
		// Token should be valid initially
		_, err := ValidateJWTWithBlacklist(tokenPair.Token, secret)
		if err != nil {
			t.Errorf("Token should be valid initially: %v", err)
		}

		// Logout the token
		err = LogoutToken(tokenPair.Token, secret)
		if err != nil {
			t.Errorf("LogoutToken() error = %v", err)
		}

		// Token should now be blacklisted
		_, err = ValidateJWTWithBlacklist(tokenPair.Token, secret)
		if err != ErrTokenBlacklisted {
			t.Errorf("Expected ErrTokenBlacklisted, got %v", err)
		}
	})

	t.Run("LogoutRefreshToken", func(t *testing.T) {
		// Refresh token should be valid initially
		_, err := ValidateRefreshTokenWithBlacklist(tokenPair.RefreshToken, secret)
		if err != nil {
			t.Errorf("Refresh token should be valid initially: %v", err)
		}

		// Logout the refresh token
		err = LogoutRefreshToken(tokenPair.RefreshToken, secret)
		if err != nil {
			t.Errorf("LogoutRefreshToken() error = %v", err)
		}

		// Refresh token should now be blacklisted
		_, err = ValidateRefreshTokenWithBlacklist(tokenPair.RefreshToken, secret)
		if err != ErrTokenBlacklisted {
			t.Errorf("Expected ErrTokenBlacklisted, got %v", err)
		}
	})

	t.Run("LogoutAll", func(t *testing.T) {
		// Create fresh storage for this test
		freshStorage := NewMemoryTokenStorage()
		defer freshStorage.Close()
		SetTokenStorage(freshStorage)

		// Generate new token pair for this test
		newTokenPair, err := GenerateTokenPair(user, secret, 1)
		if err != nil {
			t.Fatalf("Failed to generate token pair: %v", err)
		}

		// Both tokens should be valid initially
		_, err = ValidateJWTWithBlacklist(newTokenPair.Token, secret)
		if err != nil {
			t.Errorf("Access token should be valid initially: %v", err)
		}

		_, err = ValidateRefreshTokenWithBlacklist(newTokenPair.RefreshToken, secret)
		if err != nil {
			t.Errorf("Refresh token should be valid initially: %v", err)
		}

		// Logout all tokens
		err = LogoutAll(newTokenPair.Token, newTokenPair.RefreshToken, secret)
		if err != nil {
			t.Errorf("LogoutAll() error = %v", err)
		}

		// Both tokens should now be blacklisted
		_, err = ValidateJWTWithBlacklist(newTokenPair.Token, secret)
		if err != ErrTokenBlacklisted {
			t.Errorf("Expected ErrTokenBlacklisted for access token, got %v", err)
		}

		_, err = ValidateRefreshTokenWithBlacklist(newTokenPair.RefreshToken, secret)
		if err != ErrTokenBlacklisted {
			t.Errorf("Expected ErrTokenBlacklisted for refresh token, got %v", err)
		}
	})

	t.Run("LogoutWithoutStorage", func(t *testing.T) {
		// Clear token storage
		SetTokenStorage(nil)

		err := LogoutToken(tokenPair.Token, secret)
		if err == nil {
			t.Error("LogoutToken() should fail when storage is not configured")
		}

		// Restore storage
		SetTokenStorage(storage)
	})

	t.Run("LogoutInvalidToken", func(t *testing.T) {
		err := LogoutToken("invalid.token.format", secret)
		if err == nil {
			t.Error("LogoutToken() should fail for invalid token")
		}
	})
}

func TestValidateWithBlacklist(t *testing.T) {
	storage := NewMemoryTokenStorage()
	defer storage.Close()
	SetTokenStorage(storage)

	user := &models.User{ID: 123, Username: "testuser"}
	secret := "test-secret-key-that-is-long-enough"

	t.Run("ValidateJWTWithBlacklist_Valid", func(t *testing.T) {
		tokenResponse, err := GenerateJWT(user, secret, 1)
		if err != nil {
			t.Fatalf("Failed to generate token: %v", err)
		}

		claims, err := ValidateJWTWithBlacklist(tokenResponse.Token, secret)
		if err != nil {
			t.Errorf("ValidateJWTWithBlacklist() error = %v", err)
		}

		if claims.UserID != user.ID {
			t.Errorf("UserID = %v, want %v", claims.UserID, user.ID)
		}
	})

	t.Run("ValidateJWTWithBlacklist_Blacklisted", func(t *testing.T) {
		tokenResponse, err := GenerateJWT(user, secret, 1)
		if err != nil {
			t.Fatalf("Failed to generate token: %v", err)
		}

		// Blacklist the token
		err = LogoutToken(tokenResponse.Token, secret)
		if err != nil {
			t.Errorf("LogoutToken() error = %v", err)
		}

		// Validation should fail
		_, err = ValidateJWTWithBlacklist(tokenResponse.Token, secret)
		if err != ErrTokenBlacklisted {
			t.Errorf("Expected ErrTokenBlacklisted, got %v", err)
		}
	})

	t.Run("ValidateWithoutStorage", func(t *testing.T) {
		// Clear storage
		SetTokenStorage(nil)

		tokenResponse, err := GenerateJWT(user, secret, 1)
		if err != nil {
			t.Fatalf("Failed to generate token: %v", err)
		}

		// Should validate normally without blacklist check
		claims, err := ValidateJWTWithBlacklist(tokenResponse.Token, secret)
		if err != nil {
			t.Errorf("ValidateJWTWithBlacklist() should work without storage: %v", err)
		}

		if claims.UserID != user.ID {
			t.Errorf("UserID = %v, want %v", claims.UserID, user.ID)
		}

		// Restore storage
		SetTokenStorage(storage)
	})
}

func TestTokenStorageInterface(t *testing.T) {
	// Test that MemoryTokenStorage implements TokenStorage interface
	var _ TokenStorage = (*MemoryTokenStorage)(nil)

	storage := NewMemoryTokenStorage()
	defer storage.Close()

	// Test all interface methods
	tokenID := "test-token"
	expiresAt := time.Now().Add(time.Hour)

	err := storage.BlacklistToken(tokenID, expiresAt)
	if err != nil {
		t.Errorf("BlacklistToken() error = %v", err)
	}

	blacklisted, err := storage.IsBlacklisted(tokenID)
	if err != nil {
		t.Errorf("IsBlacklisted() error = %v", err)
	}
	if !blacklisted {
		t.Error("Token should be blacklisted")
	}

	err = storage.CleanupExpired()
	if err != nil {
		t.Errorf("CleanupExpired() error = %v", err)
	}

	err = storage.Close()
	if err != nil {
		t.Errorf("Close() error = %v", err)
	}
}

func TestHashString(t *testing.T) {
	// Test hash function
	hash1 := hashString("test-string")
	hash2 := hashString("test-string")
	hash3 := hashString("different-string")

	if hash1 != hash2 {
		t.Error("Same strings should produce same hash")
	}

	if hash1 == hash3 {
		t.Error("Different strings should produce different hashes")
	}
}

func TestExtractTokenID(t *testing.T) {
	tokenID1 := extractTokenID("test-token-1")
	tokenID2 := extractTokenID("test-token-1")
	tokenID3 := extractTokenID("test-token-2")

	if tokenID1 != tokenID2 {
		t.Error("Same tokens should produce same token ID")
	}

	if tokenID1 == tokenID3 {
		t.Error("Different tokens should produce different token IDs")
	}

	// Should have "access_" prefix
	if len(tokenID1) < 8 || tokenID1[:7] != "access_" {
		t.Error("Token ID should have 'access_' prefix")
	}
}
