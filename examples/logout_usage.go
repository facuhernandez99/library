package main

import (
	"fmt"
	"log"
	"time"

	"github.com/facuhernandez99/blog/pkg/auth"
	"github.com/facuhernandez99/blog/pkg/models"
)

func main() {
	fmt.Println("=== Token Storage and Logout Example ===\n")

	// Mock user for demonstration
	user := &models.User{
		ID:       456,
		Username: "jane_doe",
	}

	secret := "super-secret-jwt-key-for-blog-service"

	// 1. Setup token storage (using memory storage)
	fmt.Println("1. Setting up token storage...")
	storage := auth.NewMemoryTokenStorage()
	defer storage.Close()

	auth.SetTokenStorage(storage)
	fmt.Println("   ✓ Memory token storage configured\n")

	// 2. Generate token pair
	fmt.Println("2. Generating token pair...")
	tokenPair, err := auth.GenerateTokenPair(user, secret, 1) // 1 hour access token
	if err != nil {
		log.Fatalf("Failed to generate token pair: %v", err)
	}

	fmt.Printf("   Access Token: %s...\n", tokenPair.Token[:50])
	fmt.Printf("   Refresh Token: %s...\n", tokenPair.RefreshToken[:50])
	fmt.Printf("   Token Type: %s\n\n", tokenPair.TokenType)

	// 3. Validate tokens (should work initially)
	fmt.Println("3. Validating tokens (before logout)...")

	accessClaims, err := auth.ValidateJWTWithBlacklist(tokenPair.Token, secret)
	if err != nil {
		log.Fatalf("Failed to validate access token: %v", err)
	}
	fmt.Printf("   ✓ Access token valid - User: %s (ID: %d)\n", accessClaims.Username, accessClaims.UserID)

	refreshClaims, err := auth.ValidateRefreshTokenWithBlacklist(tokenPair.RefreshToken, secret)
	if err != nil {
		log.Fatalf("Failed to validate refresh token: %v", err)
	}
	fmt.Printf("   ✓ Refresh token valid - Token ID: %s\n\n", refreshClaims.TokenID)

	// 4. Demonstrate individual token logout
	fmt.Println("4. Logging out access token...")
	err = auth.LogoutToken(tokenPair.Token, secret)
	if err != nil {
		log.Fatalf("Failed to logout access token: %v", err)
	}
	fmt.Println("   ✓ Access token blacklisted")

	// Try to validate the access token again
	_, err = auth.ValidateJWTWithBlacklist(tokenPair.Token, secret)
	if err == auth.ErrTokenBlacklisted {
		fmt.Println("   ✓ Access token validation correctly rejected (blacklisted)")
	} else {
		log.Fatalf("Expected blacklisted error, got: %v", err)
	}

	// Refresh token should still work
	_, err = auth.ValidateRefreshTokenWithBlacklist(tokenPair.RefreshToken, secret)
	if err != nil {
		log.Fatalf("Refresh token should still be valid: %v", err)
	}
	fmt.Println("   ✓ Refresh token still valid\n")

	// 5. Generate new token pair for logout all demo
	fmt.Println("5. Generating new token pair for logout all demo...")
	newTokenPair, err := auth.GenerateTokenPair(user, secret, 2)
	if err != nil {
		log.Fatalf("Failed to generate new token pair: %v", err)
	}
	fmt.Printf("   New Access Token: %s...\n", newTokenPair.Token[:50])
	fmt.Printf("   New Refresh Token: %s...\n", newTokenPair.RefreshToken[:50])

	// Validate both are working
	_, err = auth.ValidateJWTWithBlacklist(newTokenPair.Token, secret)
	if err != nil {
		log.Fatalf("New access token should be valid: %v", err)
	}

	_, err = auth.ValidateRefreshTokenWithBlacklist(newTokenPair.RefreshToken, secret)
	if err != nil {
		log.Fatalf("New refresh token should be valid: %v", err)
	}
	fmt.Println("   ✓ Both new tokens validated successfully\n")

	// 6. Logout all tokens
	fmt.Println("6. Logging out all tokens...")
	err = auth.LogoutAll(newTokenPair.Token, newTokenPair.RefreshToken, secret)
	if err != nil {
		log.Fatalf("Failed to logout all tokens: %v", err)
	}
	fmt.Println("   ✓ All tokens blacklisted")

	// Verify both tokens are now blacklisted
	_, err = auth.ValidateJWTWithBlacklist(newTokenPair.Token, secret)
	if err == auth.ErrTokenBlacklisted {
		fmt.Println("   ✓ Access token validation correctly rejected (blacklisted)")
	} else {
		log.Fatalf("Expected blacklisted error for access token, got: %v", err)
	}

	_, err = auth.ValidateRefreshTokenWithBlacklist(newTokenPair.RefreshToken, secret)
	if err == auth.ErrTokenBlacklisted {
		fmt.Println("   ✓ Refresh token validation correctly rejected (blacklisted)")
	} else {
		log.Fatalf("Expected blacklisted error for refresh token, got: %v", err)
	}

	// 7. Storage statistics
	fmt.Println("\n7. Token storage statistics...")
	stats := storage.GetStats()
	fmt.Printf("   Storage Type: %s\n", stats["storage_type"])
	fmt.Printf("   Blacklisted Tokens: %d\n", stats["blacklisted_tokens"])

	// 8. Test token refresh with blacklisted token
	fmt.Println("\n8. Testing token refresh with blacklisted refresh token...")
	_, err = auth.RefreshAccessToken(newTokenPair.RefreshToken, secret, 1)
	if err != nil {
		fmt.Printf("   ✓ Token refresh correctly rejected: %v\n", err)
	} else {
		log.Fatal("Token refresh should have failed with blacklisted token")
	}

	// 9. Demonstrate Redis storage setup (commented out as it requires Redis)
	fmt.Println("\n9. Redis storage example (commented - requires Redis server):")
	fmt.Println("   // redisStorage, err := auth.NewRedisTokenStorageFromURL(\"redis://localhost:6379\")")
	fmt.Println("   // if err != nil {")
	fmt.Println("   //     log.Fatalf(\"Failed to connect to Redis: %v\", err)")
	fmt.Println("   // }")
	fmt.Println("   // defer redisStorage.Close()")
	fmt.Println("   // auth.SetTokenStorage(redisStorage)")

	// 10. Cleanup demonstration
	fmt.Println("\n10. Cleanup demonstration...")

	// Blacklist a token with short expiration
	tokenID := fmt.Sprintf("short_lived_%d", time.Now().Unix())
	err = storage.BlacklistToken(tokenID, time.Now().Add(2*time.Second))
	if err != nil {
		log.Fatalf("Failed to blacklist short-lived token: %v", err)
	}

	fmt.Printf("   Added token to blacklist with 2-second expiration\n")

	blacklisted, err := storage.IsBlacklisted(tokenID)
	if err != nil {
		log.Fatalf("Failed to check blacklist: %v", err)
	}
	fmt.Printf("   Token blacklisted: %t\n", blacklisted)

	// Wait for expiration
	fmt.Println("   Waiting 3 seconds for token to expire...")
	time.Sleep(3 * time.Second)

	blacklisted, err = storage.IsBlacklisted(tokenID)
	if err != nil {
		log.Fatalf("Failed to check blacklist after expiration: %v", err)
	}
	fmt.Printf("   Token blacklisted after expiration: %t (should be false)\n", blacklisted)

	fmt.Println("\n=== Token Storage and Logout Example Complete ===")
}
