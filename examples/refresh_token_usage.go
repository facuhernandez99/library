package main

import (
	"fmt"
	"log"
	"time"

	"github.com/facuhernandez99/blog/pkg/auth"
	"github.com/facuhernandez99/blog/pkg/models"
)

func main() {
	fmt.Println("=== Refresh Token Workflow Example ===\n")

	// Mock user for demonstration
	user := &models.User{
		ID:       123,
		Username: "john_doe",
	}

	secret := "super-secret-jwt-key-for-blog-service"

	// 1. Generate a token pair (access + refresh tokens)
	fmt.Println("1. Generating token pair...")
	tokenPair, err := auth.GenerateTokenPair(user, secret, 1) // 1 hour access token
	if err != nil {
		log.Fatalf("Failed to generate token pair: %v", err)
	}

	fmt.Printf("   Access Token: %s...\n", tokenPair.Token[:50])
	fmt.Printf("   Expires At: %s\n", tokenPair.ExpiresAt.Format(time.RFC3339))
	fmt.Printf("   Refresh Token: %s...\n", tokenPair.RefreshToken[:50])
	fmt.Printf("   Token Type: %s\n\n", tokenPair.TokenType)

	// 2. Validate the access token
	fmt.Println("2. Validating access token...")
	claims, err := auth.ValidateJWT(tokenPair.Token, secret)
	if err != nil {
		log.Fatalf("Failed to validate access token: %v", err)
	}

	fmt.Printf("   User ID: %d\n", claims.UserID)
	fmt.Printf("   Username: %s\n", claims.Username)
	fmt.Printf("   Subject: %s\n", claims.Subject)
	fmt.Printf("   Issuer: %s\n\n", claims.Issuer)

	// 3. Validate the refresh token
	fmt.Println("3. Validating refresh token...")
	refreshClaims, err := auth.ValidateRefreshToken(tokenPair.RefreshToken, secret)
	if err != nil {
		log.Fatalf("Failed to validate refresh token: %v", err)
	}

	fmt.Printf("   User ID: %d\n", refreshClaims.UserID)
	fmt.Printf("   Username: %s\n", refreshClaims.Username)
	fmt.Printf("   Token ID: %s\n", refreshClaims.TokenID)
	fmt.Printf("   Subject: %s\n", refreshClaims.Subject)
	fmt.Printf("   Issuer: %s\n", refreshClaims.Issuer)
	fmt.Printf("   Expires: %s\n\n", refreshClaims.ExpiresAt.Time.Format(time.RFC3339))

	// 4. Simulate token refresh scenario
	fmt.Println("4. Refreshing access token using refresh token...")

	// Wait a moment to ensure new token has different timestamp
	time.Sleep(1 * time.Second)

	newTokenResponse, err := auth.RefreshAccessToken(tokenPair.RefreshToken, secret, 2) // 2 hours
	if err != nil {
		log.Fatalf("Failed to refresh access token: %v", err)
	}

	fmt.Printf("   New Access Token: %s...\n", newTokenResponse.Token[:50])
	fmt.Printf("   New Expires At: %s\n", newTokenResponse.ExpiresAt.Format(time.RFC3339))
	fmt.Printf("   Preserved Refresh Token: %s...\n", newTokenResponse.RefreshToken[:50])

	// Verify the new token is different
	if newTokenResponse.Token == tokenPair.Token {
		log.Fatal("ERROR: New token should be different from original!")
	}
	fmt.Println("   ✓ New access token is different from original\n")

	// 5. Validate the new access token
	fmt.Println("5. Validating new access token...")
	newClaims, err := auth.ValidateJWT(newTokenResponse.Token, secret)
	if err != nil {
		log.Fatalf("Failed to validate new access token: %v", err)
	}

	fmt.Printf("   User ID: %d\n", newClaims.UserID)
	fmt.Printf("   Username: %s\n", newClaims.Username)
	fmt.Printf("   New Expiration: %s\n\n", newClaims.ExpiresAt.Time.Format(time.RFC3339))

	// 6. Demonstrate token expiration differences
	fmt.Println("6. Token expiration comparison...")
	accessTokenDuration := newTokenResponse.ExpiresAt.Sub(time.Now())
	refreshTokenDuration := refreshClaims.ExpiresAt.Time.Sub(time.Now())

	fmt.Printf("   Access token expires in: %s\n", accessTokenDuration.Round(time.Minute))
	fmt.Printf("   Refresh token expires in: %s\n", refreshTokenDuration.Round(time.Hour))
	fmt.Printf("   Refresh token lasts %dx longer than access token\n\n",
		int(refreshTokenDuration/accessTokenDuration))

	// 7. Demonstrate individual refresh token generation
	fmt.Println("7. Generating standalone refresh token...")
	standaloneRefreshToken, err := auth.GenerateRefreshToken(user, secret)
	if err != nil {
		log.Fatalf("Failed to generate standalone refresh token: %v", err)
	}

	standaloneClaims, err := auth.ValidateRefreshToken(standaloneRefreshToken, secret)
	if err != nil {
		log.Fatalf("Failed to validate standalone refresh token: %v", err)
	}

	fmt.Printf("   Refresh Token: %s...\n", standaloneRefreshToken[:50])
	fmt.Printf("   Token ID: %s\n", standaloneClaims.TokenID)
	fmt.Printf("   Expires: %s\n\n", standaloneClaims.ExpiresAt.Time.Format(time.RFC3339))

	// 8. Error handling examples
	fmt.Println("8. Error handling examples...")

	// Invalid refresh token
	_, err = auth.ValidateRefreshToken("invalid.token.format", secret)
	if err != nil {
		fmt.Printf("   ✓ Invalid token error: %v\n", err)
	}

	// Wrong secret
	_, err = auth.ValidateRefreshToken(tokenPair.RefreshToken, "wrong-secret")
	if err != nil {
		fmt.Printf("   ✓ Wrong secret error: %v\n", err)
	}

	// Nil user
	_, err = auth.GenerateRefreshToken(nil, secret)
	if err != nil {
		fmt.Printf("   ✓ Nil user error: %v\n", err)
	}

	fmt.Println("\n=== Refresh Token Workflow Complete ===")
}
