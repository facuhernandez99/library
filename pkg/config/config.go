package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

// Config holds all application configuration
type Config struct {
	Port        int    `json:"port"`
	DatabaseURL string `json:"database_url"`
	JWTSecret   string `json:"jwt_secret"`
	Environment string `json:"environment"`
	LogLevel    string `json:"log_level"`
	RedisURL    string `json:"redis_url"`
}

// Load reads configuration from environment variables with defaults
func Load() (*Config, error) {
	config := &Config{
		Port:        getEnvAsInt("PORT", 8080),
		DatabaseURL: getEnv("DATABASE_URL", ""),
		JWTSecret:   getEnv("JWT_SECRET", ""),
		Environment: getEnv("ENVIRONMENT", "development"),
		LogLevel:    getEnv("LOG_LEVEL", "info"),
		RedisURL:    getEnv("REDIS_URL", "redis://localhost:6379"),
	}

	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("configuration validation failed: %w", err)
	}

	return config, nil
}

// Validate checks if the configuration is valid
func (c *Config) Validate() error {
	var errors []string

	// Validate port
	if c.Port <= 0 || c.Port > 65535 {
		errors = append(errors, "PORT must be between 1 and 65535")
	}

	// Validate database URL
	if c.DatabaseURL == "" {
		errors = append(errors, "DATABASE_URL is required")
	}

	// Validate JWT secret
	if c.JWTSecret == "" {
		errors = append(errors, "JWT_SECRET is required")
	} else if len(c.JWTSecret) < 32 {
		errors = append(errors, "JWT_SECRET must be at least 32 characters long")
	}

	// Validate environment
	validEnvs := []string{"development", "staging", "production"}
	if !isValidEnvironment(c.Environment, validEnvs) {
		errors = append(errors, fmt.Sprintf("ENVIRONMENT must be one of: %s", strings.Join(validEnvs, ", ")))
	}

	// Validate log level
	validLogLevels := []string{"debug", "info", "warn", "error"}
	if !isValidLogLevel(c.LogLevel, validLogLevels) {
		errors = append(errors, fmt.Sprintf("LOG_LEVEL must be one of: %s", strings.Join(validLogLevels, ", ")))
	}

	if len(errors) > 0 {
		return fmt.Errorf("validation errors:\n  - %s", strings.Join(errors, "\n  - "))
	}

	return nil
}

// IsDevelopment returns true if running in development environment
func (c *Config) IsDevelopment() bool {
	return c.Environment == "development"
}

// IsProduction returns true if running in production environment
func (c *Config) IsProduction() bool {
	return c.Environment == "production"
}

// GetDatabaseConfig returns database configuration for the database package
func (c *Config) GetDatabaseConfig() map[string]interface{} {
	return map[string]interface{}{
		"dsn":         c.DatabaseURL,
		"environment": c.Environment,
	}
}

// Helper functions

// getEnv gets an environment variable with a default value
func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

// getEnvAsInt gets an environment variable as integer with a default value
func getEnvAsInt(key string, defaultValue int) int {
	if value := os.Getenv(key); value != "" {
		if intValue, err := strconv.Atoi(value); err == nil {
			return intValue
		}
	}
	return defaultValue
}

// isValidEnvironment checks if environment is in the list of valid environments
func isValidEnvironment(env string, validEnvs []string) bool {
	for _, validEnv := range validEnvs {
		if env == validEnv {
			return true
		}
	}
	return false
}

// isValidLogLevel checks if log level is in the list of valid log levels
func isValidLogLevel(level string, validLevels []string) bool {
	for _, validLevel := range validLevels {
		if level == validLevel {
			return true
		}
	}
	return false
}
