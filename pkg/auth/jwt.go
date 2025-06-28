package auth

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/facuhernandez99/blog/pkg/models"
	"github.com/golang-jwt/jwt/v5"
)

// JWT-related errors
var (
	ErrInvalidToken     = errors.New("invalid token")
	ErrTokenExpired     = errors.New("token has expired")
	ErrTokenMalformed   = errors.New("token is malformed")
	ErrInvalidSignature = errors.New("invalid token signature")
	ErrSecretEmpty      = errors.New("JWT secret cannot be empty")
	ErrUserEmpty        = errors.New("user cannot be nil")
	ErrTokenBlacklisted = errors.New("token has been blacklisted")
)

// Global token storage for logout functionality
var defaultTokenStorage TokenStorage

// SetTokenStorage sets the global token storage
func SetTokenStorage(storage TokenStorage) {
	defaultTokenStorage = storage
}

// GetTokenStorage returns the current token storage
func GetTokenStorage() TokenStorage {
	return defaultTokenStorage
}

// Custom claims structure
type Claims struct {
	UserID   int64  `json:"user_id"`
	Username string `json:"username"`
	jwt.RegisteredClaims
}

// RefreshClaims structure for refresh tokens
type RefreshClaims struct {
	UserID   int64  `json:"user_id"`
	Username string `json:"username"`
	TokenID  string `json:"token_id"` // Unique identifier for this refresh token
	jwt.RegisteredClaims
}

// GenerateJWT creates a new JWT token for a given user.
func GenerateJWT(user *models.User, secret string, expirationHours int) (*models.TokenResponse, error) {
	if user == nil {
		return nil, ErrUserEmpty
	}
	if secret == "" {
		return nil, ErrSecretEmpty
	}
	if expirationHours <= 0 {
		expirationHours = 72 // Default to 72 hours
	}

	// Calculate expiration time
	expiresAt := time.Now().Add(time.Duration(expirationHours) * time.Hour)

	// Create the claims
	claims := Claims{
		UserID:   user.ID,
		Username: user.Username,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   fmt.Sprintf("%d", user.ID),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			ExpiresAt: jwt.NewNumericDate(expiresAt),
			NotBefore: jwt.NewNumericDate(time.Now()),
			Issuer:    "blog-microservice",
		},
	}

	// Create token with claims
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	// Sign token with secret
	signedToken, err := token.SignedString([]byte(secret))
	if err != nil {
		return nil, fmt.Errorf("failed to sign token: %w", err)
	}

	return &models.TokenResponse{
		Token:     signedToken,
		ExpiresAt: expiresAt,
		TokenType: "Bearer",
	}, nil
}

// GenerateJWTDefault creates a JWT token with default 72-hour expiration.
func GenerateJWTDefault(user *models.User, secret string) (*models.TokenResponse, error) {
	return GenerateJWT(user, secret, 72)
}

// ValidateJWT validates a JWT token and returns the claims.
func ValidateJWT(tokenString, secret string) (*Claims, error) {
	if tokenString == "" {
		return nil, ErrInvalidToken
	}
	if secret == "" {
		return nil, ErrSecretEmpty
	}

	// Parse the token
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		// Validate the signing method
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, ErrInvalidSignature
		}
		return []byte(secret), nil
	})

	if err != nil {
		// Handle specific JWT errors
		if errors.Is(err, jwt.ErrTokenMalformed) {
			return nil, ErrTokenMalformed
		}
		if errors.Is(err, jwt.ErrTokenExpired) {
			return nil, ErrTokenExpired
		}
		return nil, ErrInvalidToken
	}

	// Extract and validate claims
	if claims, ok := token.Claims.(*Claims); ok && token.Valid {
		return claims, nil
	}

	return nil, ErrInvalidToken
}

// ExtractUserID extracts the user ID from a JWT token.
func ExtractUserID(tokenString, secret string) (int64, error) {
	claims, err := ValidateJWT(tokenString, secret)
	if err != nil {
		return 0, err
	}
	return claims.UserID, nil
}

// ExtractUsername extracts the username from a JWT token.
func ExtractUsername(tokenString, secret string) (string, error) {
	claims, err := ValidateJWT(tokenString, secret)
	if err != nil {
		return "", err
	}
	return claims.Username, nil
}

// IsTokenExpired checks if a token is expired without validating the signature.
// Useful for checking expiration before attempting validation.
func IsTokenExpired(tokenString string) bool {
	token, _ := jwt.ParseWithClaims(tokenString, &Claims{}, nil)
	if token == nil {
		return true
	}

	if claims, ok := token.Claims.(*Claims); ok {
		return claims.ExpiresAt.Before(time.Now())
	}

	return true
}

// GenerateRefreshToken creates a new refresh token for a given user.
func GenerateRefreshToken(user *models.User, secret string) (string, error) {
	if user == nil {
		return "", ErrUserEmpty
	}
	if secret == "" {
		return "", ErrSecretEmpty
	}

	// Generate unique token ID for tracking
	tokenID := fmt.Sprintf("%d_%d", user.ID, time.Now().Unix())

	// Refresh tokens have longer expiration (7 days)
	expiresAt := time.Now().Add(7 * 24 * time.Hour)

	// Create the refresh token claims
	claims := RefreshClaims{
		UserID:   user.ID,
		Username: user.Username,
		TokenID:  tokenID,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   fmt.Sprintf("refresh_%d", user.ID),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			ExpiresAt: jwt.NewNumericDate(expiresAt),
			NotBefore: jwt.NewNumericDate(time.Now()),
			Issuer:    "blog-microservice-refresh",
		},
	}

	// Create token with claims
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	// Sign token with secret
	signedToken, err := token.SignedString([]byte(secret))
	if err != nil {
		return "", fmt.Errorf("failed to sign refresh token: %w", err)
	}

	return signedToken, nil
}

// ValidateRefreshToken validates a refresh token and returns the claims.
func ValidateRefreshToken(tokenString, secret string) (*RefreshClaims, error) {
	if tokenString == "" {
		return nil, ErrInvalidToken
	}
	if secret == "" {
		return nil, ErrSecretEmpty
	}

	// Parse the refresh token
	token, err := jwt.ParseWithClaims(tokenString, &RefreshClaims{}, func(token *jwt.Token) (interface{}, error) {
		// Validate the signing method
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, ErrInvalidSignature
		}
		return []byte(secret), nil
	})

	if err != nil {
		// Handle specific JWT errors
		if errors.Is(err, jwt.ErrTokenMalformed) {
			return nil, ErrTokenMalformed
		}
		if errors.Is(err, jwt.ErrTokenExpired) {
			return nil, ErrTokenExpired
		}
		return nil, ErrInvalidToken
	}

	// Extract and validate claims
	if claims, ok := token.Claims.(*RefreshClaims); ok && token.Valid {
		return claims, nil
	}

	return nil, ErrInvalidToken
}

// RefreshAccessToken generates a new access token from a valid refresh token.
func RefreshAccessToken(refreshTokenString, secret string, accessTokenExpirationHours int) (*models.TokenResponse, error) {
	// Validate the refresh token and check blacklist
	refreshClaims, err := ValidateRefreshTokenWithBlacklist(refreshTokenString, secret)
	if err != nil {
		return nil, fmt.Errorf("invalid refresh token: %w", err)
	}

	// Create a user object from refresh token claims
	user := &models.User{
		ID:       refreshClaims.UserID,
		Username: refreshClaims.Username,
	}

	// Generate new access token
	tokenResponse, err := GenerateJWT(user, secret, accessTokenExpirationHours)
	if err != nil {
		return nil, fmt.Errorf("failed to generate new access token: %w", err)
	}

	// Keep the same refresh token (don't generate a new one)
	tokenResponse.RefreshToken = refreshTokenString

	return tokenResponse, nil
}

// GenerateTokenPair generates both access and refresh tokens for a user.
func GenerateTokenPair(user *models.User, secret string, accessTokenExpirationHours int) (*models.TokenResponse, error) {
	// Generate access token
	tokenResponse, err := GenerateJWT(user, secret, accessTokenExpirationHours)
	if err != nil {
		return nil, fmt.Errorf("failed to generate access token: %w", err)
	}

	// Generate refresh token
	refreshToken, err := GenerateRefreshToken(user, secret)
	if err != nil {
		return nil, fmt.Errorf("failed to generate refresh token: %w", err)
	}

	// Add refresh token to response
	tokenResponse.RefreshToken = refreshToken

	return tokenResponse, nil
}

// RefreshToken generates a new token for a user if the current token is valid.
func RefreshToken(tokenString, secret string, expirationHours int) (*models.TokenResponse, error) {
	claims, err := ValidateJWT(tokenString, secret)
	if err != nil {
		return nil, err
	}

	// Create a user object from claims for token generation
	user := &models.User{
		ID:       claims.UserID,
		Username: claims.Username,
	}

	return GenerateJWT(user, secret, expirationHours)
}

// ValidateJWTWithBlacklist validates a JWT token and checks if it's blacklisted
func ValidateJWTWithBlacklist(tokenString, secret string) (*Claims, error) {
	// First validate the token normally
	claims, err := ValidateJWT(tokenString, secret)
	if err != nil {
		return nil, err
	}

	// Check if token is blacklisted (if storage is available)
	if defaultTokenStorage != nil {
		tokenID := extractTokenID(tokenString)
		if blacklisted, err := defaultTokenStorage.IsBlacklisted(tokenID); err != nil {
			return nil, fmt.Errorf("failed to check blacklist: %w", err)
		} else if blacklisted {
			return nil, ErrTokenBlacklisted
		}
	}

	return claims, nil
}

// ValidateRefreshTokenWithBlacklist validates a refresh token and checks if it's blacklisted
func ValidateRefreshTokenWithBlacklist(tokenString, secret string) (*RefreshClaims, error) {
	// First validate the token normally
	claims, err := ValidateRefreshToken(tokenString, secret)
	if err != nil {
		return nil, err
	}

	// Check if token is blacklisted (if storage is available)
	if defaultTokenStorage != nil {
		if blacklisted, err := defaultTokenStorage.IsBlacklisted(claims.TokenID); err != nil {
			return nil, fmt.Errorf("failed to check blacklist: %w", err)
		} else if blacklisted {
			return nil, ErrTokenBlacklisted
		}
	}

	return claims, nil
}

// LogoutToken blacklists a token to prevent its further use
func LogoutToken(tokenString, secret string) error {
	if defaultTokenStorage == nil {
		return errors.New("token storage not configured")
	}

	// Validate the token first
	claims, err := ValidateJWT(tokenString, secret)
	if err != nil {
		return fmt.Errorf("invalid token for logout: %w", err)
	}

	// Extract token ID and add to blacklist
	tokenID := extractTokenID(tokenString)
	return defaultTokenStorage.BlacklistToken(tokenID, claims.ExpiresAt.Time)
}

// LogoutRefreshToken blacklists a refresh token to prevent its further use
func LogoutRefreshToken(tokenString, secret string) error {
	if defaultTokenStorage == nil {
		return errors.New("token storage not configured")
	}

	// Validate the refresh token first
	claims, err := ValidateRefreshToken(tokenString, secret)
	if err != nil {
		return fmt.Errorf("invalid refresh token for logout: %w", err)
	}

	// Add refresh token to blacklist
	return defaultTokenStorage.BlacklistToken(claims.TokenID, claims.ExpiresAt.Time)
}

// LogoutAll blacklists both access and refresh tokens
func LogoutAll(accessToken, refreshToken, secret string) error {
	var errs []string

	// Logout access token
	if err := LogoutToken(accessToken, secret); err != nil {
		errs = append(errs, fmt.Sprintf("access token: %v", err))
	}

	// Logout refresh token
	if err := LogoutRefreshToken(refreshToken, secret); err != nil {
		errs = append(errs, fmt.Sprintf("refresh token: %v", err))
	}

	if len(errs) > 0 {
		return fmt.Errorf("logout errors: %s", strings.Join(errs, "; "))
	}

	return nil
}

// extractTokenID extracts a unique identifier from a token for blacklisting
func extractTokenID(tokenString string) string {
	// For access tokens, use the full token string as ID
	// This ensures uniqueness for different tokens
	return fmt.Sprintf("access_%s", tokenString)
}

// hashString creates a simple hash of a string (for token ID generation)
func hashString(s string) uint32 {
	h := uint32(0)
	for _, c := range s {
		h = h*31 + uint32(c)
	}
	return h
}
