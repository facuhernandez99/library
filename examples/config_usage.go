package main

import (
	"fmt"
	"log"
	"time"

	"github.com/facuhernandez99/blog/pkg/config"
	"github.com/facuhernandez99/blog/pkg/http"
)

// Example demonstrating how to use the config package
// Run with: go run examples/config_usage.go
func main() {
	fmt.Println("=== Blog Service Configuration Example ===\n")

	// Load configuration
	cfg, err := config.Load()
	if err != nil {
		log.Fatal("Failed to load configuration:", err)
	}

	// Display loaded configuration
	fmt.Printf("✅ Configuration loaded successfully!\n\n")
	fmt.Printf("Server Configuration:\n")
	fmt.Printf("  Port: %d\n", cfg.Port)
	fmt.Printf("  Environment: %s\n", cfg.Environment)
	fmt.Printf("  Log Level: %s\n", cfg.LogLevel)
	fmt.Printf("  Database URL: %s\n", maskDatabaseURL(cfg.DatabaseURL))
	fmt.Printf("  Redis URL: %s\n", cfg.RedisURL)
	fmt.Printf("  JWT Secret: %s\n", maskSecret(cfg.JWTSecret))

	// Environment detection
	fmt.Printf("\nEnvironment Detection:\n")
	fmt.Printf("  Is Development: %t\n", cfg.IsDevelopment())
	fmt.Printf("  Is Production: %t\n", cfg.IsProduction())

	// Integration with HTTP client
	fmt.Printf("\nHTTP Client Integration:\n")
	httpConfig := &http.ClientConfig{
		BaseURL:       fmt.Sprintf("http://localhost:%d", cfg.Port),
		Timeout:       30 * time.Second,
		RetryAttempts: 3,
	}

	client := http.NewClient(httpConfig)
	fmt.Printf("  HTTP Client configured for: %s\n", httpConfig.BaseURL)
	fmt.Printf("  Timeout: %v\n", httpConfig.Timeout)
	fmt.Printf("  Retry Attempts: %d\n", httpConfig.RetryAttempts)
	fmt.Printf("  Client ready: %t\n", client != nil)

	// Database configuration
	fmt.Printf("\nDatabase Integration:\n")
	dbConfig := cfg.GetDatabaseConfig()
	fmt.Printf("  Database DSN: %s\n", maskDatabaseURL(dbConfig["dsn"].(string)))
	fmt.Printf("  Environment: %s\n", dbConfig["environment"])

	fmt.Printf("\n=== Example completed successfully! ===\n")

	// Example of what would happen with invalid configuration
	fmt.Printf("\n=== Validation Example ===\n")
	invalidConfig := &config.Config{
		Port:        0,         // Invalid port
		DatabaseURL: "",        // Missing required field
		JWTSecret:   "short",   // Too short
		Environment: "invalid", // Invalid environment
		LogLevel:    "invalid", // Invalid log level
	}

	if err := invalidConfig.Validate(); err != nil {
		fmt.Printf("❌ Invalid configuration detected:\n%s\n", err)
	}
}

// Helper function to mask sensitive database URLs for display
func maskDatabaseURL(url string) string {
	if len(url) < 20 {
		return "***"
	}
	return url[:10] + "***" + url[len(url)-10:]
}

// Helper function to mask JWT secret for display
func maskSecret(secret string) string {
	if len(secret) < 8 {
		return "***"
	}
	return secret[:4] + "***" + secret[len(secret)-4:]
}
