//go:build ignore
// +build ignore

package main

import (
	"bytes"
	"context"
	"database/sql"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/facuhernandez99/library/pkg/config"
	"github.com/facuhernandez99/library/pkg/database"
	"github.com/facuhernandez99/library/pkg/logging"
	testingpkg "github.com/facuhernandez99/library/pkg/testing"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestDatabaseConfigLoggingIntegration tests database operations with configuration and logging integration
// Run with: go test examples/database_config_logging_integration_test.go
func TestDatabaseConfigLoggingIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	fmt.Println("=== Database Operations with Configuration and Logging Integration Test ===")

	// === Step 1: Setup Configuration ===
	fmt.Println("\n1. Setting up configuration from environment...")

	// Set test environment variables for database configuration
	os.Setenv("DATABASE_URL", "postgres://postgres:postgres@localhost:5432/postgres")
	os.Setenv("JWT_SECRET", "test_jwt_secret_key_that_is_long_enough_for_validation_requirements")
	os.Setenv("LOG_LEVEL", "debug")
	os.Setenv("ENVIRONMENT", "development")
	os.Setenv("REDIS_URL", "redis://localhost:6379/1")

	cfg, err := config.Load()
	require.NoError(t, err, "Failed to load configuration")
	fmt.Printf("   ✅ Configuration loaded: Environment=%s, LogLevel=%s\n", cfg.Environment, cfg.LogLevel)
	fmt.Printf("   ✅ Database URL configured: %s\n", maskDatabaseURL(cfg.DatabaseURL))

	// === Step 2: Setup Structured Logging with Buffer Capture ===
	fmt.Println("\n2. Setting up structured logging with buffer capture...")

	logBuffer := &bytes.Buffer{}
	loggerConfig := &logging.Config{
		Level:      logging.LevelDebug,
		Output:     logBuffer,
		Service:    "database-integration-test",
		Version:    "test-1.0.0",
		Production: cfg.IsProduction(),
	}

	logger := logging.NewLogger(loggerConfig)
	logging.SetDefault(logger)
	fmt.Printf("   ✅ Structured logging initialized: Service=%s, Level=debug\n", loggerConfig.Service)

	// === Step 3: Test Database Connection with Configuration ===
	fmt.Println("\n3. Testing database connection using configuration...")

	// Skip if PostgreSQL is not available
	if !testingpkg.IsPostgreSQLAvailable() {
		t.Skip("PostgreSQL is not available - skipping database integration test")
	}

	// Clear log buffer to capture connection logs
	logBuffer.Reset()

	// Connect using shared config
	db, err := database.Connect(cfg)
	require.NoError(t, err, "Failed to connect to database using configuration")
	defer db.Close()

	// Test connection health
	ctx := context.Background()
	err = db.HealthCheck(ctx)
	require.NoError(t, err, "Database health check failed")
	fmt.Printf("   ✅ Database connection established and healthy\n")

	// Verify connection logs
	logOutput := logBuffer.String()
	if len(logOutput) > 0 {
		fmt.Printf("   ✅ Database connection events logged\n")
	}

	// === Step 4: Test Migration System with Logging ===
	fmt.Println("\n4. Testing migration system with logging integration...")

	// Create migrator with our logger
	migrator := database.NewMigratorWithLogger(db, logger)

	// Clear log buffer to capture migration logs
	logBuffer.Reset()

	// Initialize migrations table
	err = migrator.Initialize(ctx)
	require.NoError(t, err, "Failed to initialize migrations table")
	fmt.Printf("   ✅ Migrations table initialized\n")

	// Verify migration initialization was logged
	logOutput = logBuffer.String()
	assert.Contains(t, logOutput, "Initializing migrations table", "Migration initialization should be logged")
	assert.Contains(t, logOutput, "Migrations table initialized successfully", "Migration success should be logged")
	fmt.Printf("   ✅ Migration initialization properly logged\n")

	// === Step 5: Test Database Operations with Logging ===
	fmt.Println("\n5. Testing database operations with structured logging...")

	// Clear log buffer for operation logs
	logBuffer.Reset()

	// Create a test table for operations
	testTableSQL := `
		CREATE TABLE IF NOT EXISTS test_integration_users (
			id SERIAL PRIMARY KEY,
			username VARCHAR(255) UNIQUE NOT NULL,
			email VARCHAR(255) UNIQUE NOT NULL,
			created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
			updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
		)
	`

	_, err = db.Exec(ctx, testTableSQL)
	require.NoError(t, err, "Failed to create test table")
	fmt.Printf("   ✅ Test table created\n")

	// Test INSERT operation with logging
	logger.WithFields(map[string]interface{}{
		"operation": "insert",
		"table":     "test_integration_users",
	}).Info(ctx, "Performing database insert operation")

	insertSQL := "INSERT INTO test_integration_users (username, email) VALUES ($1, $2) RETURNING id"
	var userID int
	err = db.QueryRow(ctx, insertSQL, "testuser123", "testuser123@example.com").Scan(&userID)
	require.NoError(t, err, "Failed to insert test user")
	require.Greater(t, userID, 0, "User ID should be greater than 0")

	logger.WithFields(map[string]interface{}{
		"operation": "insert",
		"table":     "test_integration_users",
		"user_id":   userID,
		"result":    "success",
	}).Info(ctx, "Database insert operation completed successfully")

	fmt.Printf("   ✅ INSERT operation completed with ID: %d\n", userID)

	// Test SELECT operation with logging
	logger.WithFields(map[string]interface{}{
		"operation": "select",
		"table":     "test_integration_users",
		"user_id":   userID,
	}).Info(ctx, "Performing database select operation")

	selectSQL := "SELECT username, email FROM test_integration_users WHERE id = $1"
	var username, email string
	err = db.QueryRow(ctx, selectSQL, userID).Scan(&username, &email)
	require.NoError(t, err, "Failed to select test user")
	assert.Equal(t, "testuser123", username)
	assert.Equal(t, "testuser123@example.com", email)

	logger.WithFields(map[string]interface{}{
		"operation": "select",
		"table":     "test_integration_users",
		"user_id":   userID,
		"username":  username,
		"result":    "success",
	}).Info(ctx, "Database select operation completed successfully")

	fmt.Printf("   ✅ SELECT operation completed for user: %s\n", username)

	// === Step 6: Test Transaction Operations with Logging ===
	fmt.Println("\n6. Testing transaction operations with logging...")

	logger.Info(ctx, "Starting database transaction test")

	err = db.WithTransaction(ctx, func(tx *sql.Tx) error {
		logger.WithField("transaction", "active").Info(ctx, "Inside database transaction")

		// Update operation within transaction
		updateSQL := "UPDATE test_integration_users SET email = $1 WHERE id = $2"
		_, err := tx.ExecContext(ctx, updateSQL, "updated@example.com", userID)
		if err != nil {
			logger.WithField("transaction", "failed").Error(ctx, "Transaction update failed", err)
			return err
		}

		logger.WithFields(map[string]interface{}{
			"transaction": "active",
			"operation":   "update",
			"user_id":     userID,
		}).Info(ctx, "Transaction update completed")

		return nil
	})
	require.NoError(t, err, "Transaction failed")

	logger.WithField("transaction", "committed").Info(ctx, "Database transaction completed successfully")
	fmt.Printf("   ✅ Transaction operation completed successfully\n")

	// Verify the update
	err = db.QueryRow(ctx, selectSQL, userID).Scan(&username, &email)
	require.NoError(t, err, "Failed to verify update")
	assert.Equal(t, "updated@example.com", email)
	fmt.Printf("   ✅ Transaction update verified: %s\n", email)

	// === Step 7: Test Error Handling with Logging ===
	fmt.Println("\n7. Testing error handling with structured logging...")

	// Test duplicate insert (should fail)
	logger.WithField("test_scenario", "duplicate_insert").Info(ctx, "Testing error handling with duplicate insert")

	_, err = db.Exec(ctx, insertSQL, "testuser123", "different@example.com")
	assert.Error(t, err, "Duplicate insert should fail")

	if err != nil {
		logger.WithFields(map[string]interface{}{
			"test_scenario": "duplicate_insert",
			"error_type":    "constraint_violation",
		}).Error(ctx, "Expected error occurred during duplicate insert test", err)
		fmt.Printf("   ✅ Duplicate insert error properly handled and logged\n")
	}

	// === Step 8: Test Migration Status with Logging ===
	fmt.Println("\n8. Testing migration status reporting with logging...")

	// Get current migration version
	version, err := migrator.GetCurrentVersion(ctx)
	require.NoError(t, err, "Failed to get current migration version")

	logger.WithFields(map[string]interface{}{
		"migration_version": version,
		"operation":         "status_check",
	}).Info(ctx, "Retrieved current migration version")

	fmt.Printf("   ✅ Current migration version: %d\n", version)

	// Get applied migrations
	migrations, err := migrator.GetAppliedMigrations(ctx)
	require.NoError(t, err, "Failed to get applied migrations")

	logger.WithFields(map[string]interface{}{
		"migration_count": len(migrations),
		"operation":       "status_check",
	}).Info(ctx, "Retrieved applied migrations list")

	fmt.Printf("   ✅ Applied migrations count: %d\n", len(migrations))

	// === Step 9: Verify All Logging Output ===
	fmt.Println("\n9. Verifying structured logging captured all database operations...")

	logOutput = logBuffer.String()
	fmt.Printf("   [DEBUG] Total log output length: %d characters\n", len(logOutput))

	// Verify key database operations were logged
	requiredLogEntries := []string{
		"Initializing migrations table",
		"Migrations table initialized successfully",
		"Performing database insert operation",
		"Database insert operation completed successfully",
		"Performing database select operation",
		"Database select operation completed successfully",
		"Starting database transaction test",
		"Inside database transaction",
		"Transaction update completed",
		"Database transaction completed successfully",
		"Testing error handling with duplicate insert",
		"Expected error occurred during duplicate insert test",
		"Retrieved current migration version",
		"Retrieved applied migrations list",
	}

	missingEntries := []string{}
	for _, entry := range requiredLogEntries {
		if !strings.Contains(logOutput, entry) {
			missingEntries = append(missingEntries, entry)
		}
	}

	if len(missingEntries) > 0 {
		fmt.Printf("   ❌ Missing log entries:\n")
		for _, entry := range missingEntries {
			fmt.Printf("      - %s\n", entry)
		}
		t.Errorf("Missing %d expected log entries", len(missingEntries))
	} else {
		fmt.Printf("   ✅ All database operations properly logged with structured data\n")
	}

	// Verify structured fields are present
	structuredFields := []string{
		"\"operation\":",
		"\"table\":",
		"\"user_id\":",
		"\"migration_version\":",
		"\"transaction\":",
		"\"test_scenario\":",
	}

	foundFields := 0
	for _, field := range structuredFields {
		if strings.Contains(logOutput, field) {
			foundFields++
		}
	}

	fmt.Printf("   ✅ Structured fields found: %d/%d\n", foundFields, len(structuredFields))
	if foundFields < len(structuredFields)/2 { // Allow some flexibility
		t.Errorf("Not enough structured fields found in logs")
	}

	// === Step 10: Cleanup ===
	fmt.Println("\n10. Cleaning up test data...")

	_, err = db.Exec(ctx, "DROP TABLE IF EXISTS test_integration_users")
	require.NoError(t, err, "Failed to cleanup test table")

	logger.Info(ctx, "Integration test cleanup completed")
	fmt.Printf("   ✅ Test cleanup completed\n")

	fmt.Println("\n=== Database Operations Integration Test Completed Successfully ===")
}

// maskDatabaseURL masks sensitive information in database URL for logging
func maskDatabaseURL(url string) string {
	if strings.Contains(url, "@") {
		parts := strings.Split(url, "@")
		if len(parts) == 2 {
			return "postgres://***:***@" + parts[1]
		}
	}
	return url
}

func main() {
	// This file is meant to be run as a test
	// Usage: go test examples/database_config_logging_integration_test.go
	fmt.Println("This file should be run as a test:")
	fmt.Println("go test examples/database_config_logging_integration_test.go")
}
