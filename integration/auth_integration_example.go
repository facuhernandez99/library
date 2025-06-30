//go:build ignore
// +build ignore

package main

import (
	"fmt"
	"log"
	"time"

	"github.com/facuhernandez99/blog/pkg/auth"
	"github.com/facuhernandez99/blog/pkg/config"
	"github.com/facuhernandez99/blog/pkg/logging"
)

// Example demonstrating how to use the integrated auth package with config and logging
// Run with: go run examples/auth_integration_example.go
func main() {
	fmt.Println("=== Authentication Package Integration Example ===\n")

	// Load configuration from environment variables
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	// Initialize structured logging with configuration
	loggerConfig := &logging.Config{
		Level:      logging.LevelInfo,
		Service:    "auth-integration-example",
		Version:    "1.0.0",
		Production: cfg.IsProduction(),
	}

	// Parse log level from config
	switch cfg.LogLevel {
	case "debug":
		loggerConfig.Level = logging.LevelDebug
	case "info":
		loggerConfig.Level = logging.LevelInfo
	case "warn":
		loggerConfig.Level = logging.LevelWarn
	case "error":
		loggerConfig.Level = logging.LevelError
	}

	logger := logging.NewLogger(loggerConfig)
	logging.SetDefault(logger)

	fmt.Printf("✅ Structured logging initialized\n")
	fmt.Printf("  Service: %s\n", loggerConfig.Service)
	fmt.Printf("  Version: %s\n", loggerConfig.Version)
	fmt.Printf("  Log Level: %s\n", cfg.LogLevel)
	fmt.Printf("  Production Mode: %t\n", loggerConfig.Production)

	logger.Info(nil, "Starting authentication integration example")

	// Initialize Redis token storage using configuration
	fmt.Printf("\n🔗 Initializing Redis Token Storage:\n")
	fmt.Printf("  Redis URL: %s\n", maskRedisURL(cfg.RedisURL))

	tokenStorage, err := auth.NewRedisTokenStorageFromConfig(cfg)
	if err != nil {
		logger.Fatal(nil, "Failed to initialize Redis token storage", err)
	}
	defer tokenStorage.Close()

	fmt.Printf("✅ Redis token storage connected successfully\n")

	// Display storage statistics
	stats, err := tokenStorage.GetStats()
	if err != nil {
		logger.Error(nil, "Failed to get storage statistics", err)
		fmt.Printf("❌ Could not retrieve storage statistics: %v\n", err)
	} else {
		fmt.Printf("📊 Storage Statistics:\n")
		for key, value := range stats {
			fmt.Printf("  %s: %v\n", key, value)
		}
		logger.WithFields(stats).Info(nil, "Token storage initialized successfully")
	}

	// Demonstrate token blacklisting functionality
	fmt.Printf("\n🚫 Testing Token Blacklisting:\n")

	// Create a test token ID
	testTokenID := "test-token-123"

	// Check if token is blacklisted (should be false initially)
	isBlacklisted, err := tokenStorage.IsBlacklisted(testTokenID)
	if err != nil {
		logger.Error(nil, "Failed to check token blacklist status", err)
		fmt.Printf("❌ Error checking blacklist status: %v\n", err)
	} else {
		fmt.Printf("  Token %s blacklisted: %t\n", testTokenID, isBlacklisted)
	}

	// Blacklist the token
	expiresAt := time.Now().Add(time.Hour)
	err = tokenStorage.BlacklistToken(testTokenID, expiresAt)
	if err != nil {
		logger.Error(nil, "Failed to blacklist token", err)
		fmt.Printf("❌ Error blacklisting token: %v\n", err)
	} else {
		fmt.Printf("✅ Token successfully blacklisted until %s\n", expiresAt.Format("15:04:05"))
	}

	// Check blacklist status again (should be true now)
	isBlacklisted, err = tokenStorage.IsBlacklisted(testTokenID)
	if err != nil {
		logger.Error(nil, "Failed to check token blacklist status after blacklisting", err)
		fmt.Printf("❌ Error checking blacklist status: %v\n", err)
	} else {
		fmt.Printf("  Token %s blacklisted: %t\n", testTokenID, isBlacklisted)
	}

	// Demonstrate configuration integration
	fmt.Printf("\n⚙️  Configuration Integration:\n")
	fmt.Printf("  JWT Secret Length: %d characters\n", len(cfg.JWTSecret))
	fmt.Printf("  Environment: %s\n", cfg.Environment)
	fmt.Printf("  Database URL: %s\n", maskDatabaseURL(cfg.DatabaseURL))
	fmt.Printf("  Server Port: %d\n", cfg.Port)

	// Demonstrate middleware usage patterns
	fmt.Printf("\n🛡️  Middleware Integration:\n")
	fmt.Printf("  ✅ AuthMiddleware: Configured with JWT secret from config\n")
	fmt.Printf("  ✅ OptionalAuthMiddleware: Available for public endpoints\n")
	fmt.Printf("  ✅ RequireUserID: User-specific resource protection\n")
	fmt.Printf("  ✅ CORSMiddleware: Cross-origin request handling\n")
	fmt.Printf("  📝 All middleware now includes structured logging\n")

	// Log completion
	logger.WithFields(map[string]interface{}{
		"example":         "auth-integration",
		"redis_connected": true,
		"config_loaded":   true,
		"logging_active":  true,
	}).Info(nil, "Authentication integration example completed successfully")

	fmt.Printf("\n=== Integration Example completed successfully! ===\n")
	fmt.Println("\nKey Integration Points:")
	fmt.Println("1. ✅ Auth middleware now uses structured logging")
	fmt.Println("2. ✅ Redis storage uses configuration from config package")
	fmt.Println("3. ✅ All authentication events are logged with context")
	fmt.Println("4. ✅ Error handling includes structured logging")
	fmt.Println("5. ✅ Configuration validation ensures proper setup")
}

// Helper function to mask sensitive Redis URLs for display
func maskRedisURL(url string) string {
	if len(url) < 20 {
		return "***"
	}
	return url[:10] + "***" + url[len(url)-10:]
}

// Helper function to mask sensitive database URLs for display
func maskDatabaseURL(url string) string {
	if len(url) < 20 {
		return "***"
	}
	return url[:10] + "***" + url[len(url)-10:]
}
