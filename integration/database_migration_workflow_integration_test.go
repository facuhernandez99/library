//go:build integration
// +build integration

package integration

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"testing"

	"github.com/facuhernandez99/blog/pkg/config"
	"github.com/facuhernandez99/blog/pkg/database"
	"github.com/facuhernandez99/blog/pkg/logging"
	testingpkg "github.com/facuhernandez99/blog/pkg/testing"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestDatabaseMigrationWorkflowIntegration tests the complete database migration workflow
// with comprehensive logging and configuration integration
func TestDatabaseMigrationWorkflowIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	fmt.Println("=== Database Migration Workflow with Configuration and Logging Integration Test ===")

	// === Step 1: Setup Configuration ===
	fmt.Println("\n1. Setting up configuration for migration workflow...")

	// Set test environment variables
	os.Setenv("DATABASE_URL", "postgres://postgres:postgres@localhost:5432/postgres")
	os.Setenv("JWT_SECRET", "test_migration_jwt_secret_key_for_comprehensive_workflow_testing")
	os.Setenv("LOG_LEVEL", "debug")
	os.Setenv("ENVIRONMENT", "development")
	os.Setenv("REDIS_URL", "redis://localhost:6379/2")

	cfg, err := config.Load()
	require.NoError(t, err, "Failed to load configuration")
	fmt.Printf("   ✅ Configuration loaded: Environment=%s, LogLevel=%s\n", cfg.Environment, cfg.LogLevel)

	// === Step 2: Setup Enhanced Logging for Migration Workflow ===
	fmt.Println("\n2. Setting up enhanced structured logging for migration workflow...")

	logBuffer := &bytes.Buffer{}
	loggerConfig := &logging.Config{
		Level:      logging.LevelDebug,
		Output:     logBuffer,
		Service:    "migration-workflow-test",
		Version:    "test-2.0.0",
		Production: false,
	}

	logger := logging.NewLogger(loggerConfig)
	logging.SetDefault(logger)
	fmt.Printf("   ✅ Enhanced logging initialized: Service=%s, Level=%s\n", loggerConfig.Service, loggerConfig.Level)

	// === Step 3: Database Connection with Configuration ===
	fmt.Println("\n3. Establishing database connection using configuration...")

	// Skip if PostgreSQL is not available
	if !testingpkg.IsPostgreSQLAvailable() {
		t.Skip("PostgreSQL is not available - skipping migration workflow test")
	}

	// Clear log buffer for connection logs
	logBuffer.Reset()

	// Connect using configuration
	db, err := database.Connect(cfg)
	require.NoError(t, err, "Failed to connect to database")
	defer db.Close()

	// Test connection health
	ctx := context.Background()
	err = db.HealthCheck(ctx)
	require.NoError(t, err, "Database health check failed")
	fmt.Printf("   ✅ Database connection established and verified\n")

	// === Step 4: Initialize Migration System ===
	fmt.Println("\n4. Initializing migration system with custom logger...")

	// Create migrator with enhanced logging
	migrator := database.NewMigratorWithLogger(db, logger)

	// Clear log buffer for migration initialization
	logBuffer.Reset()

	// Initialize migrations table
	err = migrator.Initialize(ctx)
	require.NoError(t, err, "Failed to initialize migration system")
	fmt.Printf("   ✅ Migration system initialized successfully\n")

	// Verify initialization logging
	logOutput := logBuffer.String()
	assert.Contains(t, logOutput, "Initializing migrations table", "Migration initialization should be logged")
	assert.Contains(t, logOutput, "Migrations table initialized successfully", "Migration success should be logged")
	fmt.Printf("   ✅ Migration initialization properly logged\n")

	// === Step 5: Create Test Migrations ===
	fmt.Println("\n5. Creating test migrations for workflow demonstration...")

	migrations := []database.Migration{
		{
			Version:      1,
			Name:         "create_users_table",
			UpSQL:        createUsersTableUp,
			DownSQL:      createUsersTableDown,
			ChecksumUp:   calculateChecksum(createUsersTableUp),
			ChecksumDown: calculateChecksum(createUsersTableDown),
		},
		{
			Version:      2,
			Name:         "add_user_email_index",
			UpSQL:        addEmailIndexUp,
			DownSQL:      addEmailIndexDown,
			ChecksumUp:   calculateChecksum(addEmailIndexUp),
			ChecksumDown: calculateChecksum(addEmailIndexDown),
		},
		{
			Version:      3,
			Name:         "create_posts_table",
			UpSQL:        createPostsTableUp,
			DownSQL:      createPostsTableDown,
			ChecksumUp:   calculateChecksum(createPostsTableUp),
			ChecksumDown: calculateChecksum(createPostsTableDown),
		},
	}

	fmt.Printf("   ✅ Created %d test migrations for workflow\n", len(migrations))

	// === Step 6: Test Migration Application Workflow ===
	fmt.Println("\n6. Testing complete migration application workflow...")

	// Apply all migrations
	err = migrator.MigrateUp(ctx, migrations)
	require.NoError(t, err, "Failed to apply migrations")

	// Verify current version
	currentVersion, err := migrator.GetCurrentVersion(ctx)
	require.NoError(t, err, "Failed to get current version")
	assert.Equal(t, 3, currentVersion, "Current version should be 3")
	fmt.Printf("   ✅ All migrations applied, current version: %d\n", currentVersion)

	// === Step 7: Test Migration Status and Logging ===
	fmt.Println("\n7. Testing migration status reporting with logging...")

	// Get migration status
	status, err := migrator.Status(ctx, migrations)
	require.NoError(t, err, "Failed to get migration status")

	// Verify all migrations are applied
	for _, s := range status {
		assert.True(t, s.Applied, "Migration %d should be applied", s.Version)
		fmt.Printf("   📋 Migration %d (%s): Applied ✅\n", s.Version, s.Name)
	}

	// === Step 8: Test Migration Rollback ===
	fmt.Println("\n8. Testing migration rollback workflow...")

	// Rollback to version 1
	err = migrator.MigrateDown(ctx, 1, migrations)
	require.NoError(t, err, "Failed to rollback migrations")

	// Verify current version after rollback
	currentVersion, err = migrator.GetCurrentVersion(ctx)
	require.NoError(t, err, "Failed to get version after rollback")
	assert.Equal(t, 1, currentVersion, "Current version should be 1 after rollback")
	fmt.Printf("   ✅ Successfully rolled back to version 1\n")

	// === Final Summary ===
	fmt.Println("\n=== Migration Workflow Integration Test Summary ===")
	fmt.Println("✅ Configuration loading and validation")
	fmt.Println("✅ Structured logging with migration context")
	fmt.Println("✅ Database connection with configuration")
	fmt.Println("✅ Migration system initialization with logging")
	fmt.Println("✅ Migration application workflow (MigrateUp)")
	fmt.Println("✅ Migration status reporting")
	fmt.Println("✅ Migration rollback workflow (MigrateDown)")
	fmt.Println("✅ Comprehensive logging throughout all operations")
	fmt.Println("\n🎉 Database migration workflow integration test completed successfully!")
}

// Helper functions
func calculateChecksum(content string) string {
	// Simple hash for testing
	hash := 0
	for _, char := range content {
		hash = hash*31 + int(char)
	}
	return fmt.Sprintf("%x", hash)
}

// Test Migration SQL
const (
	createUsersTableUp = `
		CREATE TABLE users (
			id BIGSERIAL PRIMARY KEY,
			username VARCHAR(50) UNIQUE NOT NULL,
			email VARCHAR(100) UNIQUE NOT NULL,
			password_hash VARCHAR(255) NOT NULL,
			created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
			updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
		);
		CREATE INDEX idx_users_username ON users(username);
	`

	createUsersTableDown = `
		DROP INDEX IF EXISTS idx_users_username;
		DROP TABLE IF EXISTS users;
	`

	addEmailIndexUp = `
		CREATE INDEX idx_users_email ON users(email);
	`

	addEmailIndexDown = `
		DROP INDEX IF EXISTS idx_users_email;
	`

	createPostsTableUp = `
		CREATE TABLE posts (
			id BIGSERIAL PRIMARY KEY,
			title VARCHAR(200) NOT NULL,
			content TEXT,
			author_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
			created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
			updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
		);
		CREATE INDEX idx_posts_author ON posts(author_id);
	`

	createPostsTableDown = `
		DROP INDEX IF EXISTS idx_posts_author;
		DROP TABLE IF EXISTS posts;
	`
)
