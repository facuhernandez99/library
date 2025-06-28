package config

import (
	"os"
	"testing"
)

func TestLoad(t *testing.T) {
	tests := []struct {
		name     string
		envVars  map[string]string
		wantErr  bool
		expected *Config
	}{
		{
			name: "valid configuration with all env vars set",
			envVars: map[string]string{
				"PORT":         "8081",
				"DATABASE_URL": "postgres://user:pass@localhost/blog",
				"JWT_SECRET":   "this-is-a-very-long-secret-key-for-jwt-tokens",
				"ENVIRONMENT":  "production",
				"LOG_LEVEL":    "warn",
				"REDIS_URL":    "redis://localhost:6380",
			},
			wantErr: false,
			expected: &Config{
				Port:        8081,
				DatabaseURL: "postgres://user:pass@localhost/blog",
				JWTSecret:   "this-is-a-very-long-secret-key-for-jwt-tokens",
				Environment: "production",
				LogLevel:    "warn",
				RedisURL:    "redis://localhost:6380",
			},
		},
		{
			name: "valid configuration with minimal required env vars",
			envVars: map[string]string{
				"DATABASE_URL": "postgres://user:pass@localhost/blog",
				"JWT_SECRET":   "this-is-a-very-long-secret-key-for-jwt-tokens",
			},
			wantErr: false,
			expected: &Config{
				Port:        8080, // default
				DatabaseURL: "postgres://user:pass@localhost/blog",
				JWTSecret:   "this-is-a-very-long-secret-key-for-jwt-tokens",
				Environment: "development",            // default
				LogLevel:    "info",                   // default
				RedisURL:    "redis://localhost:6379", // default
			},
		},
		{
			name: "missing DATABASE_URL",
			envVars: map[string]string{
				"JWT_SECRET": "this-is-a-very-long-secret-key-for-jwt-tokens",
			},
			wantErr:  true,
			expected: nil,
		},
		{
			name: "missing JWT_SECRET",
			envVars: map[string]string{
				"DATABASE_URL": "postgres://user:pass@localhost/blog",
			},
			wantErr:  true,
			expected: nil,
		},
		{
			name: "JWT_SECRET too short",
			envVars: map[string]string{
				"DATABASE_URL": "postgres://user:pass@localhost/blog",
				"JWT_SECRET":   "short",
			},
			wantErr:  true,
			expected: nil,
		},
		{
			name: "invalid environment",
			envVars: map[string]string{
				"DATABASE_URL": "postgres://user:pass@localhost/blog",
				"JWT_SECRET":   "this-is-a-very-long-secret-key-for-jwt-tokens",
				"ENVIRONMENT":  "invalid",
			},
			wantErr:  true,
			expected: nil,
		},
		{
			name: "invalid log level",
			envVars: map[string]string{
				"DATABASE_URL": "postgres://user:pass@localhost/blog",
				"JWT_SECRET":   "this-is-a-very-long-secret-key-for-jwt-tokens",
				"LOG_LEVEL":    "invalid",
			},
			wantErr:  true,
			expected: nil,
		},
		{
			name: "invalid port",
			envVars: map[string]string{
				"PORT":         "0",
				"DATABASE_URL": "postgres://user:pass@localhost/blog",
				"JWT_SECRET":   "this-is-a-very-long-secret-key-for-jwt-tokens",
			},
			wantErr:  true,
			expected: nil,
		},
		{
			name: "port too high",
			envVars: map[string]string{
				"PORT":         "70000",
				"DATABASE_URL": "postgres://user:pass@localhost/blog",
				"JWT_SECRET":   "this-is-a-very-long-secret-key-for-jwt-tokens",
			},
			wantErr:  true,
			expected: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Clear environment variables
			clearEnv()

			// Set test environment variables
			for key, value := range tt.envVars {
				os.Setenv(key, value)
			}

			// Load configuration
			config, err := Load()

			// Check error expectation
			if (err != nil) != tt.wantErr {
				t.Errorf("Load() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			// If no error expected, check the configuration
			if !tt.wantErr && tt.expected != nil {
				if config.Port != tt.expected.Port {
					t.Errorf("Port = %v, want %v", config.Port, tt.expected.Port)
				}
				if config.DatabaseURL != tt.expected.DatabaseURL {
					t.Errorf("DatabaseURL = %v, want %v", config.DatabaseURL, tt.expected.DatabaseURL)
				}
				if config.JWTSecret != tt.expected.JWTSecret {
					t.Errorf("JWTSecret = %v, want %v", config.JWTSecret, tt.expected.JWTSecret)
				}
				if config.Environment != tt.expected.Environment {
					t.Errorf("Environment = %v, want %v", config.Environment, tt.expected.Environment)
				}
				if config.LogLevel != tt.expected.LogLevel {
					t.Errorf("LogLevel = %v, want %v", config.LogLevel, tt.expected.LogLevel)
				}
				if config.RedisURL != tt.expected.RedisURL {
					t.Errorf("RedisURL = %v, want %v", config.RedisURL, tt.expected.RedisURL)
				}
			}

			// Clean up
			clearEnv()
		})
	}
}

func TestConfig_Validate(t *testing.T) {
	tests := []struct {
		name    string
		config  *Config
		wantErr bool
	}{
		{
			name: "valid configuration",
			config: &Config{
				Port:        8080,
				DatabaseURL: "postgres://user:pass@localhost/blog",
				JWTSecret:   "this-is-a-very-long-secret-key-for-jwt-tokens",
				Environment: "development",
				LogLevel:    "info",
				RedisURL:    "redis://localhost:6379",
			},
			wantErr: false,
		},
		{
			name: "invalid port - zero",
			config: &Config{
				Port:        0,
				DatabaseURL: "postgres://user:pass@localhost/blog",
				JWTSecret:   "this-is-a-very-long-secret-key-for-jwt-tokens",
				Environment: "development",
				LogLevel:    "info",
			},
			wantErr: true,
		},
		{
			name: "invalid port - negative",
			config: &Config{
				Port:        -1,
				DatabaseURL: "postgres://user:pass@localhost/blog",
				JWTSecret:   "this-is-a-very-long-secret-key-for-jwt-tokens",
				Environment: "development",
				LogLevel:    "info",
			},
			wantErr: true,
		},
		{
			name: "invalid port - too high",
			config: &Config{
				Port:        70000,
				DatabaseURL: "postgres://user:pass@localhost/blog",
				JWTSecret:   "this-is-a-very-long-secret-key-for-jwt-tokens",
				Environment: "development",
				LogLevel:    "info",
			},
			wantErr: true,
		},
		{
			name: "empty database URL",
			config: &Config{
				Port:        8080,
				DatabaseURL: "",
				JWTSecret:   "this-is-a-very-long-secret-key-for-jwt-tokens",
				Environment: "development",
				LogLevel:    "info",
			},
			wantErr: true,
		},
		{
			name: "empty JWT secret",
			config: &Config{
				Port:        8080,
				DatabaseURL: "postgres://user:pass@localhost/blog",
				JWTSecret:   "",
				Environment: "development",
				LogLevel:    "info",
			},
			wantErr: true,
		},
		{
			name: "JWT secret too short",
			config: &Config{
				Port:        8080,
				DatabaseURL: "postgres://user:pass@localhost/blog",
				JWTSecret:   "short",
				Environment: "development",
				LogLevel:    "info",
			},
			wantErr: true,
		},
		{
			name: "invalid environment",
			config: &Config{
				Port:        8080,
				DatabaseURL: "postgres://user:pass@localhost/blog",
				JWTSecret:   "this-is-a-very-long-secret-key-for-jwt-tokens",
				Environment: "invalid",
				LogLevel:    "info",
			},
			wantErr: true,
		},
		{
			name: "invalid log level",
			config: &Config{
				Port:        8080,
				DatabaseURL: "postgres://user:pass@localhost/blog",
				JWTSecret:   "this-is-a-very-long-secret-key-for-jwt-tokens",
				Environment: "development",
				LogLevel:    "invalid",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Config.Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestConfig_IsDevelopment(t *testing.T) {
	tests := []struct {
		name        string
		environment string
		want        bool
	}{
		{"development environment", "development", true},
		{"production environment", "production", false},
		{"staging environment", "staging", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &Config{Environment: tt.environment}
			if got := c.IsDevelopment(); got != tt.want {
				t.Errorf("Config.IsDevelopment() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestConfig_IsProduction(t *testing.T) {
	tests := []struct {
		name        string
		environment string
		want        bool
	}{
		{"production environment", "production", true},
		{"development environment", "development", false},
		{"staging environment", "staging", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &Config{Environment: tt.environment}
			if got := c.IsProduction(); got != tt.want {
				t.Errorf("Config.IsProduction() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestConfig_GetDatabaseConfig(t *testing.T) {
	config := &Config{
		DatabaseURL: "postgres://user:pass@localhost/blog",
		Environment: "development",
	}

	dbConfig := config.GetDatabaseConfig()

	if dbConfig["dsn"] != config.DatabaseURL {
		t.Errorf("DatabaseConfig dsn = %v, want %v", dbConfig["dsn"], config.DatabaseURL)
	}

	if dbConfig["environment"] != config.Environment {
		t.Errorf("DatabaseConfig environment = %v, want %v", dbConfig["environment"], config.Environment)
	}
}

func TestGetEnv(t *testing.T) {
	tests := []struct {
		name         string
		key          string
		defaultValue string
		envValue     string
		want         string
	}{
		{"environment variable exists", "TEST_KEY", "default", "env_value", "env_value"},
		{"environment variable doesn't exist", "NONEXISTENT_KEY", "default", "", "default"},
		{"empty environment variable", "EMPTY_KEY", "default", "", "default"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Clear the key first
			os.Unsetenv(tt.key)

			// Set if not empty
			if tt.envValue != "" {
				os.Setenv(tt.key, tt.envValue)
			}

			got := getEnv(tt.key, tt.defaultValue)
			if got != tt.want {
				t.Errorf("getEnv() = %v, want %v", got, tt.want)
			}

			// Clean up
			os.Unsetenv(tt.key)
		})
	}
}

func TestGetEnvAsInt(t *testing.T) {
	tests := []struct {
		name         string
		key          string
		defaultValue int
		envValue     string
		want         int
	}{
		{"valid integer environment variable", "TEST_INT", 8080, "9090", 9090},
		{"invalid integer environment variable", "TEST_INT", 8080, "invalid", 8080},
		{"environment variable doesn't exist", "NONEXISTENT_INT", 8080, "", 8080},
		{"empty environment variable", "EMPTY_INT", 8080, "", 8080},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Clear the key first
			os.Unsetenv(tt.key)

			// Set if not empty
			if tt.envValue != "" {
				os.Setenv(tt.key, tt.envValue)
			}

			got := getEnvAsInt(tt.key, tt.defaultValue)
			if got != tt.want {
				t.Errorf("getEnvAsInt() = %v, want %v", got, tt.want)
			}

			// Clean up
			os.Unsetenv(tt.key)
		})
	}
}

// Helper function to clear environment variables used in tests
func clearEnv() {
	envVars := []string{
		"PORT", "DATABASE_URL", "JWT_SECRET", "ENVIRONMENT", "LOG_LEVEL", "REDIS_URL",
	}
	for _, env := range envVars {
		os.Unsetenv(env)
	}
}
